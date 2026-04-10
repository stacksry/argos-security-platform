"""
argos/agents/action/reporter.py

ReporterAgent — stakeholder-specific security report generator.

Produces tailored reports for four distinct audiences:

  executive   Business risk language, no code, financial impact estimates,
              trend charts (textual), remediation timelines.
  engineering Full technical detail — code snippets, exploitation paths,
              fix PR links, reproduction steps.
  auditor     Compliance mapping, evidence references, control status tables,
              framework-specific pass rates.
  vendor      CVE-ready disclosure format with commitment hashes, 90-day
              timeline, affected version ranges.

Also provides:
  hygiene_score()   0-100 weighted score reflecting org security health.
  generate_sbom()   CycloneDX SBOM for a software repo.
  generate_hbom()   CycloneDX HBOM for hardware assets.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.events import Finding, Severity

log = structlog.get_logger(__name__)

REPORT_AUDIENCES: list[str] = ["executive", "engineering", "auditor", "vendor"]

# ---------------------------------------------------------------------------
# Severity weights for hygiene score
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    "Critical": 10.0,
    "High":     4.0,
    "Medium":   1.5,
    "Low":      0.5,
    "Info":     0.1,
}


# ---------------------------------------------------------------------------
# ReporterAgent
# ---------------------------------------------------------------------------


class ReporterAgent(ArgosAgent):
    """
    Multi-audience security report generator.

    Parameters
    ----------
    memory:
        ArgosMemory for hygiene score computations and SBOM data.
    producer:
        Kafka producer.
    """

    name = "reporter"

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Generate a full org security posture report for all audiences.

        Context keys
        ------------
        findings : list[dict]
            All findings in scope for the report period.
        org : str
            Organisation name.
        repo : str
            Primary repository (optional — used for repo-scoped reports).
        period_days : int
            Reporting window in days (default 30).
        audiences : list[str]
            Audiences to generate reports for (default: all four).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        findings_raw: list[dict[str, Any]] = context.get("findings", [])
        org: str = context.get("org", "")
        repo: str = context.get("repo", "")
        period_days: int = int(context.get("period_days", 30))
        audiences: list[str] = context.get("audiences", REPORT_AUDIENCES)

        self.log.info(
            "reporter.run_start",
            org=org,
            findings=len(findings_raw),
            audiences=audiences,
        )

        try:
            findings = [Finding(**f) if isinstance(f, dict) else f for f in findings_raw]

            reports: dict[str, str] = {}
            for audience in audiences:
                if audience in REPORT_AUDIENCES:
                    reports[audience] = await self.generate_report(
                        audience=audience,
                        findings=findings,
                        org=org,
                        period_days=period_days,
                    )

            hygiene = await self.hygiene_score(org)

            sbom: dict[str, Any] = {}
            if repo:
                sbom = await self.generate_sbom(repo)

        except Exception as exc:  # noqa: BLE001
            self.log.exception("reporter.run_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info("reporter.run_complete", org=org, duration_ms=duration_ms)

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[f.model_dump() for f in findings],
            metadata={
                "org": org,
                "repo": repo,
                "period_days": period_days,
                "reports": reports,
                "hygiene_score": hygiene,
                "sbom": sbom,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # generate_report()
    # ------------------------------------------------------------------

    async def generate_report(
        self,
        audience: str,
        findings: list[Finding],
        org: str,
        period_days: int = 30,
    ) -> str:
        """
        Generate a stakeholder-specific security report.

        Parameters
        ----------
        audience : str
            One of: ``executive``, ``engineering``, ``auditor``, ``vendor``.
        findings : list[Finding]
            Findings in scope.
        org : str
            Organisation name.
        period_days : int
            Reporting window.

        Returns
        -------
        str
            Formatted report text (Markdown for engineering/auditor/vendor,
            plain prose for executive).
        """
        if audience == "executive":
            return await self._report_executive(findings, org, period_days)
        if audience == "engineering":
            return await self._report_engineering(findings, org, period_days)
        if audience == "auditor":
            return await self._report_auditor(findings, org, period_days)
        if audience == "vendor":
            return await self._report_vendor(findings, org, period_days)
        return f"Unknown audience: {audience}"

    # ------------------------------------------------------------------
    # Executive report
    # ------------------------------------------------------------------

    async def _report_executive(
        self, findings: list[Finding], org: str, period_days: int
    ) -> str:
        sev_counts = self._count_by_severity(findings)
        fixed_count = sum(1 for f in findings if f.status.value in ("fixed", "false_positive"))

        system = """\
You are a Chief Information Security Officer preparing an executive security briefing.

Your audience: C-suite executives and board members with no technical background.

Rules:
- Use business risk language exclusively. No code. No CVE numbers in body text.
- Quantify risk in business terms: data exposure risk, regulatory fine exposure,
  customer trust impact, operational disruption probability.
- Be direct about what is alarming and what is under control.
- Reference remediation timelines in business-week units.
- End with 3-5 concrete executive actions (approve budget, mandate policy, etc.)

Format: flowing prose with section headers. Max 600 words."""

        user_msg = (
            f"Organisation: {org}\n"
            f"Reporting period: last {period_days} days\n"
            f"Total findings: {len(findings)}\n"
            f"  Critical: {sev_counts.get('Critical', 0)}\n"
            f"  High:     {sev_counts.get('High', 0)}\n"
            f"  Medium:   {sev_counts.get('Medium', 0)}\n"
            f"  Low:      {sev_counts.get('Low', 0)}\n"
            f"Resolved this period: {fixed_count}\n"
            f"CISA KEV findings: {sum(1 for f in findings if f.cisa_kev)}\n\n"
            f"Top critical findings (titles only):\n"
            + "\n".join(
                f"- {f.title} ({f.repo})"
                for f in findings
                if f.severity == Severity.CRITICAL
            )[:10]
            + "\n\nGenerate the executive report now."
        )

        try:
            return await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=2048,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("reporter.executive_claude_error", error=str(exc))
            return f"Executive report generation failed: {exc}"

    # ------------------------------------------------------------------
    # Engineering report
    # ------------------------------------------------------------------

    async def _report_engineering(
        self, findings: list[Finding], org: str, period_days: int
    ) -> str:
        # Sort by severity then confidence
        sorted_findings = sorted(
            findings,
            key=lambda f: (_SEVERITY_WEIGHTS.get(f.severity.value, 0) * f.confidence),
            reverse=True,
        )

        finding_details = "\n\n".join(
            f"### [{f.severity.value}] {f.title}\n"
            f"- **ID:** `{f.finding_id}`\n"
            f"- **Repo:** `{f.repo}` | **File:** `{f.file}:{f.line}`\n"
            f"- **Class:** `{f.vuln_class}` | **Layer:** `{f.layer_hit}`\n"
            f"- **Confidence:** {f.confidence:.0%}\n"
            f"- **CVEs:** {', '.join(f.cve_ids) if f.cve_ids else 'None'}\n"
            f"- **CISA KEV:** {'Yes ⚠' if f.cisa_kev else 'No'}\n"
            f"- **Status:** `{f.status.value}`\n"
            f"- **Exploitation path:** {f.exploitation_path}\n"
            f"- **Description:** {f.metadata.get('description', 'N/A')}\n"
            for f in sorted_findings[:30]
        )

        system = """\
You are a senior security engineer writing a technical vulnerability report for the development team.

Include:
1. Summary statistics and trend (is the org improving or regressing?)
2. Prioritised finding list with actionable remediation guidance per finding
3. Patterns across findings (e.g. "authentication is systematically weak")
4. Recommended tooling or process changes
5. Patch velocity analysis (if data available)

Use precise technical language. Include code-level fix hints. Format as Markdown."""

        user_msg = (
            f"Organisation: {org}\n"
            f"Period: {period_days} days\n"
            f"Total findings: {len(findings)} | "
            f"Critical: {sum(1 for f in findings if f.severity == Severity.CRITICAL)} | "
            f"High: {sum(1 for f in findings if f.severity == Severity.HIGH)}\n\n"
            f"Findings (top 30 by risk score):\n\n{finding_details}\n\n"
            f"Generate the engineering report now."
        )

        try:
            return await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("reporter.engineering_claude_error", error=str(exc))
            return f"Engineering report generation failed: {exc}"

    # ------------------------------------------------------------------
    # Auditor report
    # ------------------------------------------------------------------

    async def _report_auditor(
        self, findings: list[Finding], org: str, period_days: int
    ) -> str:
        system = """\
You are an external compliance auditor preparing a formal assessment report.

Structure:
1. Audit scope and methodology
2. Executive compliance summary table (framework, controls tested, pass rate, risk rating)
3. Detailed control failure analysis with finding evidence references
4. Compensating controls inventory
5. Remediation commitments with timeline
6. Auditor attestation statement placeholder

Use formal audit language. Reference finding IDs as evidence. Format as Markdown."""

        finding_summary = json.dumps(
            [
                {
                    "id": f.finding_id,
                    "severity": f.severity.value,
                    "vuln_class": f.vuln_class,
                    "title": f.title,
                    "status": f.status.value,
                    "commitment_hash": f.commitment_hash,
                    "cve_ids": f.cve_ids,
                }
                for f in findings[:60]
            ],
            indent=2,
        )

        user_msg = (
            f"Organisation: {org}\n"
            f"Audit period: {period_days} days\n"
            f"Total findings: {len(findings)}\n\n"
            f"Findings (evidence):\n{finding_summary}\n\n"
            f"Generate the auditor report now."
        )

        try:
            return await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("reporter.auditor_claude_error", error=str(exc))
            return f"Auditor report generation failed: {exc}"

    # ------------------------------------------------------------------
    # Vendor disclosure report
    # ------------------------------------------------------------------

    async def _report_vendor(
        self, findings: list[Finding], org: str, period_days: int
    ) -> str:
        system = """\
You are a security researcher preparing a coordinated vulnerability disclosure to a software vendor.

Format: CVE-ready coordinated disclosure document.

Include:
1. Disclosure header (reporter, date, CVE candidate status)
2. Vulnerability summary (one paragraph per finding)
3. Technical details: affected versions, reproduction steps, CVSS vector string
4. Proof-of-concept description (no working exploit code)
5. Commitment hash (prior discovery proof)
6. Proposed remediation
7. Disclosure timeline (Day 0 = today, Day 45 = escalation, Day 90 = public)
8. Researcher contact placeholder

Be precise and professional. Format as Markdown."""

        disc_findings = [f for f in findings if f.cve_ids or f.severity in (Severity.CRITICAL, Severity.HIGH)]
        finding_details = "\n\n".join(
            f"**Finding {i+1}:** {f.title}\n"
            f"- Severity: {f.severity.value} | CVSS: {f.cvss_score} | Vector: {f.cvss_vector}\n"
            f"- CVEs: {', '.join(f.cve_ids) if f.cve_ids else 'Pending assignment'}\n"
            f"- Affected library: {f.affected_library or 'N/A'}\n"
            f"- Commitment hash: {f.commitment_hash or 'N/A'}\n"
            f"- Exploitation: {f.exploitation_path}\n"
            for i, f in enumerate(disc_findings[:10])
        )

        user_msg = (
            f"Reporting organisation: {org}\n"
            f"Disclosure date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n\n"
            f"Findings for disclosure:\n\n{finding_details}\n\n"
            f"Generate the vendor disclosure report now."
        )

        try:
            return await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("reporter.vendor_claude_error", error=str(exc))
            return f"Vendor disclosure report generation failed: {exc}"

    # ------------------------------------------------------------------
    # hygiene_score()
    # ------------------------------------------------------------------

    async def hygiene_score(self, org: str) -> dict[str, Any]:
        """
        Calculate a 0-100 security hygiene score for the org.

        Weighted by:
        - Open finding severity (negative)
        - Patch velocity (positive)
        - False positive rate (negative — indicates scanner noise)
        - CISA KEV exposure (heavily negative)

        Returns
        -------
        dict
            Keys: score (0-100), grade (A-F), breakdown, org.
        """
        base_score = 100.0
        breakdown: dict[str, float] = {}

        if self.memory is not None and hasattr(self.memory, "episodic"):
            try:
                # Fetch FP rate for sentinel (primary scanner)
                fp_rate = await self.memory.episodic.get_false_positive_rate("sentinel", days=30)
                fp_penalty = fp_rate * 15.0  # up to -15 points
                base_score -= fp_penalty
                breakdown["false_positive_penalty"] = round(-fp_penalty, 2)

                # Patch velocity: mean time to fix (lower is better)
                mttf = await self.memory.episodic.get_mean_time_to_fix("all")
                if mttf > 0:
                    if mttf <= 7:
                        velocity_bonus = 10.0
                    elif mttf <= 30:
                        velocity_bonus = 5.0
                    elif mttf <= 90:
                        velocity_bonus = 0.0
                    else:
                        velocity_bonus = -10.0
                    base_score += velocity_bonus
                    breakdown["patch_velocity_adjustment"] = round(velocity_bonus, 2)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("reporter.hygiene_episodic_error", error=str(exc))

        # Ask Claude to refine the score based on qualitative factors
        try:
            refined = await self._refine_hygiene_score(org, base_score, breakdown)
            base_score = refined.get("score", base_score)
            breakdown.update(refined.get("breakdown", {}))
        except Exception as exc:  # noqa: BLE001
            self.log.warning("reporter.hygiene_claude_error", error=str(exc))

        final_score = max(0.0, min(100.0, base_score))
        grade = self._score_to_grade(final_score)

        return {
            "org": org,
            "score": round(final_score, 1),
            "grade": grade,
            "breakdown": breakdown,
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _refine_hygiene_score(
        self, org: str, base_score: float, breakdown: dict[str, float]
    ) -> dict[str, Any]:
        """Ask Claude to apply qualitative adjustments to the hygiene score."""
        system = """\
You are a security programme analyst computing a 0-100 security hygiene score.

Given a base score and breakdown, apply qualitative adjustments based on:
- Presence of CISA KEV findings (-15 per KEV finding, max -30)
- Breadth of scanning coverage (are all repos scanned?)
- Time since last full audit
- Presence of critical open findings

Return ONLY valid JSON:
{
  "score": <float 0-100>,
  "breakdown": {
    "<adjustment_name>": <float delta>
  },
  "rationale": "<1-2 sentences>"
}"""

        user_msg = (
            f"Organisation: {org}\n"
            f"Base score: {base_score:.1f}\n"
            f"Current breakdown: {json.dumps(breakdown, indent=2)}\n\n"
            f"Apply qualitative adjustments and return the refined score."
        )

        raw = await self._call_claude(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            max_tokens=1024,
        )

        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"score": base_score, "breakdown": {}}

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    # ------------------------------------------------------------------
    # generate_sbom()
    # ------------------------------------------------------------------

    async def generate_sbom(self, repo: str) -> dict[str, Any]:
        """
        Generate a CycloneDX SBOM for a software repository.

        Pulls dependency data from the asset graph. If graph memory is
        unavailable, returns a minimal skeleton SBOM.

        Parameters
        ----------
        repo : str
            Repository name.

        Returns
        -------
        dict
            CycloneDX 1.5 SBOM in dict form (serialisable to JSON).
        """
        components: list[dict[str, Any]] = []

        if self.memory is not None and hasattr(self.memory, "graph"):
            try:
                ctx = await self.memory.graph.get_asset_context(repo)
                for dep in ctx.get("dependencies", []):
                    if not dep.get("library"):
                        continue
                    components.append({
                        "type": "library",
                        "name": dep["library"],
                        "version": dep.get("version", "unknown"),
                        "scope": "required" if dep.get("dep_type") == "direct" else "optional",
                        "purl": self._build_purl(dep["library"], dep.get("version", "")),
                    })
            except Exception as exc:  # noqa: BLE001
                self.log.warning("reporter.sbom_graph_error", error=str(exc))

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"name": "ARGOS ReporterAgent", "version": "1.0.0"}],
                "component": {
                    "type": "application",
                    "name": repo,
                    "bom-ref": f"pkg:generic/{repo}",
                },
            },
            "components": components,
        }

        self.log.info("reporter.sbom_generated", repo=repo, components=len(components))
        return sbom

    # ------------------------------------------------------------------
    # generate_hbom()
    # ------------------------------------------------------------------

    async def generate_hbom(self, repo: str) -> dict[str, Any]:
        """
        Generate a CycloneDX HBOM for hardware assets associated with a repo.

        Parameters
        ----------
        repo : str
            Repository name.

        Returns
        -------
        dict
            CycloneDX 1.5 HBOM in dict form.
        """
        hardware_components: list[dict[str, Any]] = []

        if self.memory is not None and hasattr(self.memory, "graph"):
            try:
                ctx = await self.memory.graph.get_asset_context(repo)
                for hw in ctx.get("hardware_assets", []):
                    if not hw.get("name"):
                        continue
                    hardware_components.append({
                        "type": "hardware",
                        "name": hw["name"],
                        "version": hw.get("version", "1.0"),
                        "description": hw.get("asset_type", ""),
                        "bom-ref": f"hardware/{hw['name']}",
                        "properties": [
                            {"name": "asset_type", "value": hw.get("asset_type", "unknown")},
                        ],
                    })
            except Exception as exc:  # noqa: BLE001
                self.log.warning("reporter.hbom_graph_error", error=str(exc))

        hbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"name": "ARGOS ReporterAgent", "version": "1.0.0"}],
                "component": {
                    "type": "application",
                    "name": repo,
                    "description": "Hardware Bill of Materials",
                },
            },
            "components": hardware_components,
        }

        self.log.info("reporter.hbom_generated", repo=repo, components=len(hardware_components))
        return hbom

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @staticmethod
    def _build_purl(name: str, version: str) -> str:
        """Build a minimal package URL. Ecosystem detection is best-effort."""
        name_lower = name.lower()
        if ":" in name:
            # Maven-style groupId:artifactId
            group, artifact = name.split(":", 1)
            return f"pkg:maven/{group}/{artifact}@{version}"
        if "/" in name:
            return f"pkg:npm/{name}@{version}"
        if name_lower.endswith(".gem"):
            return f"pkg:gem/{name}@{version}"
        return f"pkg:generic/{name}@{version}"
