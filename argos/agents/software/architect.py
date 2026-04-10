"""
argos/agents/software/architect.py

ArchitectAgent — structural vulnerability analysis.

Finds design-level security issues that no line-level scanner can detect.
Rather than reading individual files, it reads the org's asset graph (services,
dependencies, ports, trust boundaries) and uses Claude to reason about topology-
level threats: missing mTLS, over-privileged service accounts, admin APIs exposed
on public subnets, etc.

Findings here span the system — they don't have a single file or line.  They
represent architectural debt that requires design-level remediation.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.events import AssetType, Finding, FindingStatus, Severity

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM = """\
You are a senior security architect with deep expertise in distributed systems, zero-trust networking,
and cloud-native security design.

Your task: analyze a system's asset graph — which includes services, their dependencies, exposed ports,
service accounts, and network topology — and identify structural security vulnerabilities that arise
from the design, not from individual lines of code.

Focus areas:
1. Missing authentication boundaries
   - Services exposed on public subnets without an authentication gateway
   - Internal services directly reachable from the internet
   - Services with unauthenticated health/debug/metrics endpoints exposed externally

2. Admin API exposure
   - Admin interfaces on the same port/hostname as public APIs
   - Management interfaces (actuator, /admin, /__debug__) reachable from public subnets

3. Shared secrets and credentials between services
   - Database passwords shared across multiple services (single compromise = full blast radius)
   - Shared API keys with no per-service isolation
   - Secrets in environment variables that are available to multiple containers

4. Missing mTLS between services
   - Service-to-service calls using plain HTTP internally
   - Missing certificate pinning for high-value service calls
   - Overly broad trust: any service in the cluster can call any other

5. Over-privileged service accounts
   - Services with more IAM permissions than needed (write access when read-only is sufficient)
   - Service accounts with wildcard resource permissions
   - Shared service accounts across multiple services (audit trail pollution)

6. Network segmentation failures
   - Absence of network policies between namespaces / VPCs
   - Flat network topologies where lateral movement is trivial
   - Services that shouldn't communicate but can (no deny-by-default policy)

7. Single points of failure in auth infrastructure
   - No fallback for identity provider outages
   - Hardcoded emergency bypass credentials

For each structural finding:
- Describe the structural flaw precisely
- Explain the blast radius (what can an attacker do once they exploit this?)
- Provide a remediation outline (what design change fixes this?)
- Assign severity: Critical (Internet-exposed without auth, wildcard permissions),
  High (mTLS missing on critical path, privilege escalation possible),
  Medium (single points of failure, shared secrets), Low (defense-in-depth gaps)

Return ONLY valid JSON (no markdown fences):
{
  "findings": [
    {
      "title": "<short title>",
      "description": "<2-4 sentence structural description>",
      "severity": "Critical|High|Medium|Low",
      "confidence": <float 0.0-1.0>,
      "affected_services": ["<service1>", "<service2>"],
      "exploitation_path": "<attacker path from initial access to impact>",
      "remediation": "<design-level fix>",
      "category": "missing_auth|admin_exposure|shared_secrets|missing_mtls|overprivilege|network_segmentation|single_point_of_failure"
    }
  ]
}
Return {"findings": []} if no structural vulnerabilities are found."""


# ---------------------------------------------------------------------------
# ArchitectAgent
# ---------------------------------------------------------------------------


class ArchitectAgent(ArgosAgent):
    """
    Structural vulnerability analysis agent.

    Consumes the knowledge graph's asset context for a given org/repo and
    uses Claude to reason about design-level security gaps.

    Parameters
    ----------
    memory:
        ArgosMemory instance.  graph.get_asset_context() is called to fetch
        service topology.
    producer:
        Kafka producer for publishing findings.
    """

    name = "architect"

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Analyze system topology for structural vulnerabilities.

        Context keys
        ------------
        repo : str
            Primary repository or service group to analyze.
        asset_graph : dict
            Pre-built asset context (services, dependencies, ports, etc.).
            If not supplied, the agent fetches it from graph memory.
        platform : str
            Platform hint (bitbucket/github/gitlab) — used for metadata only.
        org : str
            Organisation name — used to scope multi-service topology queries.
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        repo: str = context.get("repo", "")
        platform: str = context.get("platform", "bitbucket")
        org: str = context.get("org", repo.split("/")[0] if "/" in repo else repo)
        asset_graph: dict[str, Any] = context.get("asset_graph", {})

        self.log.info("architect.analysis_start", repo=repo, org=org)

        try:
            # 1. Fetch asset context from graph memory if not provided.
            if not asset_graph:
                asset_graph = await self._fetch_asset_context(repo)

            # 2. Augment with multi-service topology if memory is available.
            topology = await self._build_topology(org, asset_graph)

            # 3. Ask Claude to reason about structural vulnerabilities.
            findings = await self._analyze_topology(repo, topology)

            # 4. Persist findings to graph memory.
            await self._persist_findings(repo, findings)

        except Exception as exc:  # noqa: BLE001
            self.log.exception("architect.analysis_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "architect.analysis_complete",
            repo=repo,
            findings=len(findings),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[f.model_dump() for f in findings],
            metadata={
                "repo": repo,
                "org": org,
                "platform": platform,
                "services_analyzed": len(topology.get("services", [])),
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Topology construction
    # ------------------------------------------------------------------

    async def _fetch_asset_context(self, repo: str) -> dict[str, Any]:
        """Fetch asset context from graph memory."""
        if self.memory is None or not hasattr(self.memory, "graph"):
            self.log.warning("architect.no_graph_memory", repo=repo)
            return {}
        try:
            return await self.memory.graph.get_asset_context(repo)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("architect.graph_fetch_error", repo=repo, error=str(exc))
            return {}

    async def _build_topology(
        self, org: str, primary_asset_context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Build a topology summary from the primary asset context and any
        additional services discovered for the same org.

        Returns a topology dict suitable for passing to Claude.
        """
        topology: dict[str, Any] = {
            "org": org,
            "primary_repo": primary_asset_context.get("repo", ""),
            "services": [],
            "network_policies_present": False,
            "mtls_enforced": False,
            "service_mesh": None,
        }

        # Add primary service info
        primary: dict[str, Any] = {
            "name": primary_asset_context.get("repo", ""),
            "dependencies": primary_asset_context.get("dependencies", []),
            "known_cves": primary_asset_context.get("cves", []),
            "open_findings": [
                f for f in primary_asset_context.get("findings", [])
                if f.get("status") == "open"
            ],
            "hardware_assets": primary_asset_context.get("hardware_assets", []),
        }
        topology["services"].append(primary)

        # If graph memory is available, try to fetch related services
        if self.memory is not None and hasattr(self.memory, "graph"):
            try:
                # Fetch cross-repo context for same org prefix
                org_prefix = org.split("/")[0] if "/" in org else org
                related_repos = await self.memory.graph.find_cross_repo_pattern(org_prefix)
                for related_repo in related_repos[:10]:  # cap to avoid massive prompts
                    if related_repo == primary_asset_context.get("repo"):
                        continue
                    ctx = await self.memory.graph.get_asset_context(related_repo)
                    topology["services"].append({
                        "name": related_repo,
                        "dependencies": ctx.get("dependencies", []),
                        "known_cves": ctx.get("cves", []),
                        "open_findings_count": len([
                            f for f in ctx.get("findings", [])
                            if f.get("status") == "open"
                        ]),
                    })
            except Exception as exc:  # noqa: BLE001
                self.log.warning("architect.topology_expand_error", error=str(exc))

        return topology

    # ------------------------------------------------------------------
    # Claude analysis
    # ------------------------------------------------------------------

    async def _analyze_topology(
        self, repo: str, topology: dict[str, Any]
    ) -> list[Finding]:
        """Call Claude with the topology and parse structural findings."""
        topology_json = json.dumps(topology, indent=2, default=str)

        user_msg = f"""\
Analyze the following system topology for structural security vulnerabilities.
Primary repository: {repo}

System topology:
{topology_json}

Identify all structural security issues. Return the JSON findings now."""

        try:
            raw = await self._call_claude(
                system=_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("architect.claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_findings(self, raw: str, repo: str) -> list[Finding]:
        """Parse Claude's JSON into Finding objects."""
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.log.warning("architect.json_parse_error", error=str(exc))
            return []

        results: list[Finding] = []
        for item in data.get("findings", []):
            try:
                sev_str = item.get("severity", "Medium")
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = Severity.MEDIUM

                affected = item.get("affected_services", [])
                # Structural findings don't have a single file — use the category as file
                finding = Finding(
                    finding_id=str(uuid.uuid4())[:16],
                    repo=repo,
                    file=f"[architecture] {item.get('category', 'structural')}",
                    line=0,
                    vuln_class=item.get("category", "structural_vulnerability"),
                    title=item.get("title", "Structural vulnerability"),
                    severity=severity,
                    confidence=float(item.get("confidence", 0.7)),
                    layer_hit="architecture",
                    exploitation_path=item.get("exploitation_path", ""),
                    agent=self.name,
                    metadata={
                        "description": item.get("description", ""),
                        "remediation": item.get("remediation", ""),
                        "affected_services": affected,
                        "category": item.get("category", ""),
                    },
                )
                results.append(finding)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("architect.finding_parse_error", error=str(exc), item=item)

        self.log.info("architect.findings_parsed", count=len(results))
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def _persist_findings(self, repo: str, findings: list[Finding]) -> None:
        """Record findings in graph memory."""
        if self.memory is None or not hasattr(self.memory, "graph"):
            return
        for finding in findings:
            try:
                await self.memory.graph.mark_finding(
                    repo=repo,
                    finding_id=finding.finding_id,
                    severity=finding.severity.value.lower(),
                    status=finding.status.value,
                )
            except Exception as exc:  # noqa: BLE001
                self.log.warning(
                    "architect.persist_error",
                    finding_id=finding.finding_id,
                    error=str(exc),
                )
