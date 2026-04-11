"""
argos/agents/radar/navigator.py

NavigatorAgent — the central event router for the ARGOS platform.

Receives scan/push/CVE events and uses Claude (with adaptive thinking) to
decide which agents to activate, how many parallel instances, in what order,
and at what priority.  Publishes activation events to Kafka for downstream
consumers.

Decision logic
--------------
1. Calculate a priority score for the event.
2. Classify changed files by type (code, VHDL, KiCad, firmware, IaC, docs).
3. Ask Claude to reason about which agents to activate and in what order.
4. Publish activation events via the producer.
5. Return the routing decision as an AgentResult.

Claude's role
-------------
Given the event context and the classified file list, Claude reasons about
which agents to activate and returns a JSON object:

  {
    "agents": [
      {"name": "sentinel",      "priority": 9.2, "batch": ["src/auth.java"]},
      {"name": "oracle",        "priority": 8.5, "batch": ["pom.xml"]},
      {"name": "cartographer",  "priority": 5.0, "batch": []}
    ],
    "reasoning": "The changed files include a POM update and Java source ..."
  }
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# File-type classification
# ---------------------------------------------------------------------------

_VHDL_EXTS = {".vhd", ".vhdl"}
_KICAD_EXTS = {".kicad_sch", ".kicad_pcb", ".sch", ".kicad_pro"}
_FIRMWARE_EXTS = {".bin", ".hex", ".elf", ".srec", ".ihex"}
_CODE_EXTS = {".java", ".py", ".js", ".ts", ".go", ".rb", ".cpp", ".c", ".cs", ".rs", ".kt"}
_IAC_EXTS = {".tf", ".yml", ".yaml", ".json"}  # narrowed by name patterns below
_MANIFEST_NAMES = {
    "pom.xml", "package.json", "go.mod", "requirements.txt",
    "cargo.toml", "gemfile", "build.gradle", "pyproject.toml",
    "package-lock.json", "yarn.lock", "go.sum", "pipfile.lock",
}
_IAC_PATTERNS = {"jenkinsfile", ".github", ".gitlab-ci", "dockerfile", ".tf", "ansible"}


def _classify_files(files: list[str]) -> dict[str, list[str]]:
    """
    Classify a list of changed file paths into agent-relevant buckets.

    Returns a dict with keys:
      vhdl, kicad, firmware, code, iac, manifests, docs, other
    """
    buckets: dict[str, list[str]] = {
        "vhdl": [], "kicad": [], "firmware": [], "code": [],
        "iac": [], "manifests": [], "docs": [], "other": [],
    }

    for f in files:
        p = PurePosixPath(f)
        ext = p.suffix.lower()
        name = p.name.lower()
        stem = p.stem.lower()

        if ext in _VHDL_EXTS:
            buckets["vhdl"].append(f)
        elif ext in _KICAD_EXTS:
            buckets["kicad"].append(f)
        elif ext in _FIRMWARE_EXTS:
            buckets["firmware"].append(f)
        elif name in _MANIFEST_NAMES:
            buckets["manifests"].append(f)
        elif ext in _CODE_EXTS:
            # Terraform and CI/CD YAML sit inside code extensions; re-classify.
            if ext in (".yml", ".yaml") and any(
                pat in str(p).lower() for pat in _IAC_PATTERNS
            ):
                buckets["iac"].append(f)
            else:
                buckets["code"].append(f)
        elif ext in (".tf",) or any(pat in str(p).lower() for pat in _IAC_PATTERNS):
            buckets["iac"].append(f)
        elif ext in (".md", ".rst", ".txt", ".adoc"):
            buckets["docs"].append(f)
        else:
            buckets["other"].append(f)

    return buckets


# ---------------------------------------------------------------------------
# NavigatorAgent
# ---------------------------------------------------------------------------


class NavigatorAgent(ArgosAgent):
    """
    Central event router.

    Inherits from ArgosAgent; exposes run() as the primary entry point.
    """

    name = "navigator"

    # Registry maps short agent names to their dotted module paths.
    # Used to build Kafka activation events; not used for Python imports here.
    AGENT_REGISTRY: dict[str, str] = {
        "sentinel":     "software.sentinel.SentinelAgent",
        "silicon":      "hardware.silicon.SiliconAgent",
        "pcb":          "hardware.pcb.PCBAgent",
        "necromancer":  "hardware.necromancer.NecromancerAgent",
        "cartographer": "radar.cartographer.CartographerAgent",
        "oracle":       "radar.oracle.OracleAgent",
        "archaeologist":"radar.archaeologist.ArchaeologistAgent",
        "genealogist":  "radar.genealogist.GeneaologistAgent",
        "prophet":      "intelligence.prophet.ProphetAgent",
        "alchemist":    "action.alchemist.AlchemistAgent",
    }

    # Default asset criticality used when not provided in context.
    _DEFAULT_CRITICALITY = 5.0
    # Default exposure score (public-facing = 1.0, internal = 0.3).
    _DEFAULT_EXPOSURE = 0.5

    # ------------------------------------------------------------------
    # System prompt
    # ------------------------------------------------------------------

    _SYSTEM = """\
You are the Navigator, the central routing intelligence for the ARGOS security platform.

Your task: given a code-change event and a classified list of changed files, decide:
  1. Which security agents to activate.
  2. In what order (lower "batch" number = runs first / in parallel with same-batch peers).
  3. At what priority (0.0 – 10.0, higher = more urgent).
  4. Which specific files each agent should process.

Available agents and their roles:
  sentinel     – SAST for .java/.py/.js/.go/.ts source code; also handles IaC (Terraform/YAML CI)
  silicon      – VHDL/FPGA/RTL security analysis
  pcb          – KiCad schematic/PCB hardware review
  necromancer  – Binary/firmware reverse engineering (.bin/.hex/.elf)
  cartographer – Asset graph maintenance; should run on every push
  oracle       – CVE/NVD threat intel; activate when manifests or lockfiles change
  archaeologist– Git history blame analysis; activate when a confirmed finding needs history context
  genealogist  – Supply-chain trust scoring; activate with oracle when new libraries appear
  prophet      – Trend and predictive threat analysis; activate on cve_published events
  alchemist    – Automated remediation; activate after other agents confirm findings

Routing rules (hard constraints):
  - .vhd/.vhdl           → silicon
  - .kicad_sch/.kicad_pcb/.sch → pcb
  - .bin/.hex/.elf        → necromancer
  - .tf / CI YAML         → sentinel (iac_mode: true)
  - .java/.py/.js/.go     → sentinel
  - pom.xml / package.json / go.mod / requirements.txt → oracle + sentinel
  - Any push              → cartographer (always)
  - PR merged             → alchemist may be triggered if findings exist
  - cve_published event   → oracle + prophet + potentially alchemist

You MUST return ONLY valid JSON (no markdown, no code fences) in this exact schema:
{
  "agents": [
    {
      "name": "<agent_name>",
      "priority": <float 0.0-10.0>,
      "batch": <int, 1=first>,
      "files": ["<file_path>", ...]
    }
  ],
  "reasoning": "<one or two sentence explanation>"
}
"""

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Route an event to the appropriate agents.

        Context keys
        ------------
        event_type : str
            "push" | "pr_merged" | "cve_published" | "scheduled"
        repo : str
            Repository slug / name.
        changed_files : list[str]
            Files changed in this event (empty list for cve_published).
        platform : str
            "bitbucket" | "github"
        priority_override : float | None
            When set, overrides the computed priority score for all agents.
        asset_criticality : float
            0.0–10.0 asset importance (default 5.0).
        recency_hours : float
            Hours since the event (default 0.1 for brand-new events).
        exposure : float
            0.0–1.0 internet exposure (default 0.5).
        cve_id : str | None
            For cve_published events, the CVE identifier.
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        event_type: str = context.get("event_type", "push")
        repo: str = context.get("repo", "unknown")
        changed_files: list[str] = context.get("changed_files", [])
        platform: str = context.get("platform", "bitbucket")
        priority_override: float | None = context.get("priority_override")
        cve_id: str | None = context.get("cve_id")

        criticality: float = float(context.get("asset_criticality", self._DEFAULT_CRITICALITY))
        recency_hours: float = float(context.get("recency_hours", 0.1))
        exposure: float = float(context.get("exposure", self._DEFAULT_EXPOSURE))

        self.log.info(
            "navigator.routing",
            event_type=event_type,
            repo=repo,
            file_count=len(changed_files),
            platform=platform,
        )

        # 1. Compute base priority.
        base_priority = (
            priority_override
            if priority_override is not None
            else self._priority_score(criticality, recency_hours, exposure)
        )

        # 2. Classify changed files.
        file_buckets = _classify_files(changed_files)
        self.log.debug(
            "navigator.file_buckets",
            **{k: len(v) for k, v in file_buckets.items()},
        )

        # 3. Ask Claude to produce the routing decision.
        routing_decision = await self._ask_claude_for_routing(
            event_type=event_type,
            repo=repo,
            platform=platform,
            file_buckets=file_buckets,
            changed_files=changed_files,
            base_priority=base_priority,
            cve_id=cve_id,
        )

        if routing_decision is None:
            # Fallback: safe minimum routing on any push event.
            routing_decision = self._fallback_routing(
                event_type, file_buckets, base_priority
            )

        agents_to_run: list[dict[str, Any]] = routing_decision.get("agents", [])
        reasoning: str = routing_decision.get("reasoning", "")

        self.log.info(
            "navigator.decision",
            agents=[a["name"] for a in agents_to_run],
            reasoning=reasoning,
        )

        # 4. Publish activation events to Kafka (if producer available).
        publish_errors: list[str] = []
        if self.producer is not None:
            for agent_spec in agents_to_run:
                try:
                    await self._publish_activation(
                        repo=repo,
                        platform=platform,
                        event_type=event_type,
                        agent_spec=agent_spec,
                    )
                except Exception as exc:  # noqa: BLE001
                    publish_errors.append(f"{agent_spec['name']}: {exc}")
                    self.log.error(
                        "navigator.publish_failed",
                        agent=agent_spec["name"],
                        error=str(exc),
                    )

        duration_ms = int((time.monotonic() - t0) * 1000)

        return AgentResult(
            agent=self.name,
            success=len(publish_errors) == 0 or self.producer is None,
            findings=[],
            metadata={
                "routing_decision": routing_decision,
                "base_priority": base_priority,
                "file_buckets": {k: len(v) for k, v in file_buckets.items()},
                "publish_errors": publish_errors,
                "event_type": event_type,
                "repo": repo,
                "platform": platform,
            },
            error="; ".join(publish_errors),
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Claude routing call
    # ------------------------------------------------------------------

    async def _ask_claude_for_routing(
        self,
        event_type: str,
        repo: str,
        platform: str,
        file_buckets: dict[str, list[str]],
        changed_files: list[str],
        base_priority: float,
        cve_id: str | None,
    ) -> dict[str, Any] | None:
        """
        Call Claude with adaptive thinking to produce a routing decision JSON.

        Returns the parsed dict or None on failure.
        """
        # Build a compact file summary to keep the prompt focused.
        bucket_summary = {k: v for k, v in file_buckets.items() if v}
        file_summary = json.dumps(bucket_summary, indent=2)

        # Include a truncated raw file list (max 200 entries) to give Claude
        # concrete paths to reason about.
        file_list_sample = changed_files[:200]

        user_content = f"""Event: {event_type}
Repository: {repo}
Platform: {platform}
Base priority: {base_priority:.2f}
CVE ID: {cve_id or "N/A"}

Changed files by type:
{file_summary}

Full file paths (sample, up to 200):
{json.dumps(file_list_sample, indent=2)}

Return the routing JSON now."""

        try:
            text = await self._call_claude(
                system=self._SYSTEM,
                messages=[{"role": "user", "content": user_content}],
                max_tokens=4096,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("navigator.claude_call_failed", error=str(exc))
            return None

        # Strip any accidental markdown fencing.
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            decision = json.loads(text)
        except json.JSONDecodeError as exc:
            self.log.error(
                "navigator.json_parse_failed",
                error=str(exc),
                raw_text=text[:500],
            )
            return None

        # Validate: each agent must have a name we know.
        known = set(self.AGENT_REGISTRY.keys())
        valid_agents = [
            a for a in decision.get("agents", [])
            if a.get("name") in known
        ]
        decision["agents"] = valid_agents
        return decision

    # ------------------------------------------------------------------
    # Kafka publishing
    # ------------------------------------------------------------------

    async def _publish_activation(
        self,
        repo: str,
        platform: str,
        event_type: str,
        agent_spec: dict[str, Any],
    ) -> None:
        """
        Publish an agent activation event to the argos.agent.activations topic.

        The producer is expected to expose an async send() method:
            await producer.send(topic, value: dict)
        """
        event = {
            "schema_version": "1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "repo": repo,
            "platform": platform,
            "agent_name": agent_spec["name"],
            "agent_class": self.AGENT_REGISTRY.get(agent_spec["name"], ""),
            "priority": agent_spec.get("priority", 5.0),
            "batch": agent_spec.get("batch", 1),
            "files": agent_spec.get("files", []),
        }
        await self.producer.send("argos.agent.activations", value=event)
        self.log.debug(
            "navigator.activation_published",
            agent=agent_spec["name"],
            priority=event["priority"],
        )

    # ------------------------------------------------------------------
    # Fallback routing (Claude unavailable)
    # ------------------------------------------------------------------

    def _fallback_routing(
        self,
        event_type: str,
        file_buckets: dict[str, list[str]],
        base_priority: float,
    ) -> dict[str, Any]:
        """
        Rule-based fallback when Claude is unavailable.

        Applies the hard routing rules from the system prompt deterministically.
        """
        agents: list[dict[str, Any]] = []
        batch = 1

        # Cartographer always runs on push events.
        if event_type in ("push", "pr_merged"):
            agents.append({
                "name": "cartographer",
                "priority": max(base_priority * 0.5, 3.0),
                "batch": batch,
                "files": [],
            })

        batch = 2

        if file_buckets.get("vhdl"):
            agents.append({
                "name": "silicon",
                "priority": base_priority,
                "batch": batch,
                "files": file_buckets["vhdl"],
            })
        if file_buckets.get("kicad"):
            agents.append({
                "name": "pcb",
                "priority": base_priority,
                "batch": batch,
                "files": file_buckets["kicad"],
            })
        if file_buckets.get("firmware"):
            agents.append({
                "name": "necromancer",
                "priority": base_priority,
                "batch": batch,
                "files": file_buckets["firmware"],
            })
        if file_buckets.get("code") or file_buckets.get("iac"):
            agents.append({
                "name": "sentinel",
                "priority": base_priority,
                "batch": batch,
                "files": file_buckets.get("code", []) + file_buckets.get("iac", []),
            })
        if file_buckets.get("manifests"):
            agents.append({
                "name": "oracle",
                "priority": base_priority,
                "batch": batch,
                "files": file_buckets["manifests"],
            })

        if event_type == "cve_published":
            agents.append({
                "name": "oracle",
                "priority": min(base_priority + 2.0, 10.0),
                "batch": 1,
                "files": [],
            })
            agents.append({
                "name": "prophet",
                "priority": base_priority,
                "batch": 2,
                "files": [],
            })

        return {
            "agents": agents,
            "reasoning": "Fallback rule-based routing (Claude unavailable).",
        }
