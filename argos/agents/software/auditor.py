"""
argos/agents/software/auditor.py

AuditorAgent — compliance mapping and evidence generation.

Maps security findings to regulatory controls across six major frameworks
and detects compliance drift (code changes that violate controls even when
no CVE is involved).

Supported frameworks
--------------------
soc2        SOC 2 Type II — Trust Services Criteria
pci_dss     PCI DSS 4.0 — Payment Card Industry Data Security Standard
hipaa       HIPAA Security Rule — Electronic Protected Health Information
fips_140    FIPS 140-2 / 140-3 — Cryptographic Module Validation
nist_800_53 NIST SP 800-53 Rev 5 — Security and Privacy Controls
cis         CIS Benchmarks — Center for Internet Security
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


# ---------------------------------------------------------------------------
# Control framework definitions
# ---------------------------------------------------------------------------

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "soc2": {
        "name": "SOC 2 Type II",
        "version": "2017 Trust Services Criteria",
        "controls": {
            "CC6.1": "Logical and physical access controls",
            "CC6.2": "New access and modification to access",
            "CC6.3": "Role-based access control",
            "CC6.6": "Logical access security measures — network protection",
            "CC6.7": "Transmission and disposal of data",
            "CC6.8": "Unauthorized or malicious software prevention",
            "CC7.1": "Detection of vulnerabilities",
            "CC7.2": "Monitoring for anomalies",
            "CC8.1": "Change management",
            "CC9.2": "Assessment and monitoring of third-party risk",
            "A1.1": "Capacity and availability",
            "C1.1": "Confidentiality commitments",
            "P1.1": "Privacy commitments",
        },
        "vuln_class_map": {
            "sql_injection":          ["CC6.1", "CC6.6", "CC7.1"],
            "xss":                    ["CC6.1", "CC7.1"],
            "ssrf":                   ["CC6.6", "CC7.1"],
            "auth_authz":             ["CC6.2", "CC6.3"],
            "crypto_weakness":        ["CC6.7", "C1.1"],
            "hardcoded_secret":       ["CC6.2", "CC6.7"],
            "dependency_vulnerability":["CC9.2", "CC7.1"],
            "business_logic":         ["CC8.1"],
            "structural_vulnerability":["CC6.6", "CC9.2"],
        },
    },
    "pci_dss": {
        "name": "PCI DSS 4.0",
        "version": "March 2022",
        "controls": {
            "1.3": "Network access controls",
            "2.2": "System components are configured and managed securely",
            "3.4": "Primary account number (PAN) protection",
            "3.5": "Cryptographic key management",
            "4.2": "PAN protected with strong cryptography during transmission",
            "6.2": "Bespoke and custom software are developed securely",
            "6.3": "Security vulnerabilities identified and addressed",
            "6.4": "Public-facing web applications are protected",
            "7.2": "Access to system components is appropriately defined",
            "8.2": "User identification and authentication",
            "8.3": "User authentication for all users",
            "8.6": "Passwords and passphrases for user accounts",
            "10.2": "Audit logs capture all individual access",
            "11.3": "External and internal vulnerability scans",
            "12.3": "Targeted risk analysis",
        },
        "vuln_class_map": {
            "sql_injection":          ["6.2", "6.3", "6.4"],
            "xss":                    ["6.2", "6.4"],
            "auth_authz":             ["7.2", "8.2", "8.3"],
            "crypto_weakness":        ["3.4", "3.5", "4.2"],
            "hardcoded_secret":       ["3.5", "8.6"],
            "ssrf":                   ["1.3"],
            "dependency_vulnerability":["6.3", "11.3"],
            "structural_vulnerability":["1.3", "2.2"],
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "version": "45 CFR Parts 160 and 164",
        "controls": {
            "164.308(a)(1)": "Security management process — risk analysis",
            "164.308(a)(3)": "Workforce security",
            "164.308(a)(4)": "Information access management",
            "164.308(a)(5)": "Security awareness and training",
            "164.310(a)(2)": "Facility access controls",
            "164.312(a)(1)": "Access control",
            "164.312(a)(2)": "Unique user identification",
            "164.312(b)":    "Audit controls",
            "164.312(c)(1)": "Integrity controls",
            "164.312(c)(2)": "Mechanism to authenticate ePHI",
            "164.312(d)":    "Person or entity authentication",
            "164.312(e)(1)": "Transmission security",
            "164.312(e)(2)": "Encryption and decryption",
        },
        "vuln_class_map": {
            "auth_authz":             ["164.312(a)(1)", "164.312(d)", "164.308(a)(4)"],
            "crypto_weakness":        ["164.312(e)(1)", "164.312(e)(2)"],
            "sql_injection":          ["164.312(c)(1)", "164.308(a)(1)"],
            "hardcoded_secret":       ["164.312(a)(2)", "164.312(e)(2)"],
            "dependency_vulnerability":["164.308(a)(1)"],
            "structural_vulnerability":["164.312(a)(1)", "164.308(a)(4)"],
            "business_logic":         ["164.312(c)(1)", "164.312(b)"],
        },
    },
    "fips_140": {
        "name": "FIPS 140-2/3",
        "version": "FIPS 140-3 (2019)",
        "controls": {
            "L1": "Level 1 — basic security",
            "L2": "Level 2 — tamper-evident physical security",
            "L3": "Level 3 — tamper-resistant physical security",
            "4.1": "Approved security functions",
            "4.2": "Approved cryptographic algorithms",
            "4.3": "Key management",
            "4.4": "Self-tests",
            "4.5": "Design assurance",
            "4.9": "Cryptographic module interfaces",
        },
        "vuln_class_map": {
            "crypto_weakness": ["4.1", "4.2", "4.3"],
            "hardcoded_secret": ["4.3"],
            "structural_vulnerability": ["4.9"],
        },
    },
    "nist_800_53": {
        "name": "NIST SP 800-53 Rev 5",
        "version": "September 2020",
        "controls": {
            "AC-1":  "Access Control Policy and Procedures",
            "AC-2":  "Account Management",
            "AC-3":  "Access Enforcement",
            "AC-17": "Remote Access",
            "AU-2":  "Event Logging",
            "CA-7":  "Continuous Monitoring",
            "CM-6":  "Configuration Settings",
            "IA-2":  "Identification and Authentication",
            "IA-5":  "Authenticator Management",
            "RA-5":  "Vulnerability Monitoring and Scanning",
            "SA-11": "Developer Testing and Evaluation",
            "SC-5":  "Denial of Service Protection",
            "SC-8":  "Transmission Confidentiality and Integrity",
            "SC-28": "Protection of Information at Rest",
            "SI-2":  "Flaw Remediation",
            "SI-3":  "Malicious Code Protection",
            "SI-10": "Information Input Validation",
        },
        "vuln_class_map": {
            "sql_injection":          ["SI-10", "SA-11", "RA-5"],
            "xss":                    ["SI-10", "SA-11"],
            "auth_authz":             ["AC-2", "AC-3", "IA-2", "IA-5"],
            "crypto_weakness":        ["SC-8", "SC-28", "IA-5"],
            "hardcoded_secret":       ["IA-5", "CM-6"],
            "ssrf":                   ["SC-5", "AC-17"],
            "dependency_vulnerability":["SI-2", "RA-5"],
            "structural_vulnerability":["AC-3", "CA-7"],
            "business_logic":         ["SA-11", "SI-10"],
        },
    },
    "cis": {
        "name": "CIS Benchmarks",
        "version": "CIS Controls v8",
        "controls": {
            "1.1":  "Establish and maintain detailed enterprise asset inventory",
            "2.2":  "Ensure authorized software is currently supported",
            "3.11": "Encrypt sensitive data at rest",
            "3.14": "Log sensitive data access",
            "4.1":  "Establish and maintain a secure configuration process",
            "5.2":  "Use unique passwords",
            "5.3":  "Disable dormant accounts",
            "6.2":  "Establish an access-granting process",
            "7.1":  "Establish and maintain a vulnerability management process",
            "7.4":  "Perform automated application patch management",
            "8.2":  "Collect audit logs",
            "9.2":  "Use DNS filtering services",
            "16.1": "Establish and maintain a secure application development process",
            "16.4": "Establish and manage an inventory of third-party software components",
            "16.10":"Apply security training for developers",
            "16.12":"Implement code-level security checks",
        },
        "vuln_class_map": {
            "sql_injection":          ["16.12", "16.1"],
            "xss":                    ["16.12", "16.1"],
            "auth_authz":             ["5.2", "6.2"],
            "crypto_weakness":        ["3.11"],
            "hardcoded_secret":       ["5.2", "4.1"],
            "dependency_vulnerability":["2.2", "7.4", "16.4"],
            "structural_vulnerability":["4.1", "1.1"],
        },
    },
}


# ---------------------------------------------------------------------------
# AuditorAgent
# ---------------------------------------------------------------------------


class AuditorAgent(ArgosAgent):
    """
    Compliance mapping and evidence generation agent.

    Receives a list of findings and produces framework-specific compliance
    reports, evidence packages, and drift detection results.
    """

    name = "auditor"

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Map findings to compliance controls and generate an evidence summary.

        Context keys
        ------------
        findings : list[dict]
            List of Finding dicts (as produced by other agents).
        frameworks : list[str]
            Which frameworks to evaluate. Defaults to all supported frameworks.
        org : str
            Organisation name — used in report metadata.
        repo : str
            Repository in scope.
        period_days : int
            Look-back window for drift detection (default 30).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        findings_raw: list[dict[str, Any]] = context.get("findings", [])
        frameworks: list[str] = context.get("frameworks", list(FRAMEWORKS.keys()))
        org: str = context.get("org", "")
        repo: str = context.get("repo", "")
        period_days: int = int(context.get("period_days", 30))

        self.log.info(
            "auditor.run_start",
            repo=repo,
            findings=len(findings_raw),
            frameworks=frameworks,
        )

        try:
            findings = [Finding(**f) if isinstance(f, dict) else f for f in findings_raw]

            # 1. Map findings to controls per framework
            control_mapping = self._map_findings_to_controls(findings, frameworks)

            # 2. Ask Claude to generate a compliance narrative and gap analysis
            compliance_analysis = await self._analyze_compliance(
                org=org,
                repo=repo,
                findings=findings,
                control_mapping=control_mapping,
                frameworks=frameworks,
            )

            # 3. Detect compliance drift (code changes without CVE)
            drift_items: list[dict[str, Any]] = []
            if repo:
                drift_items = await self.detect_compliance_drift(repo, frameworks[0] if frameworks else "nist_800_53")

            evidence: dict[str, Any] = {
                "org": org,
                "repo": repo,
                "period_days": period_days,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "control_mapping": control_mapping,
                "compliance_analysis": compliance_analysis,
                "drift_items": drift_items,
                "frameworks_evaluated": frameworks,
                "finding_count": len(findings),
                "critical_count": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high_count": sum(1 for f in findings if f.severity == Severity.HIGH),
            }

        except Exception as exc:  # noqa: BLE001
            self.log.exception("auditor.run_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info("auditor.run_complete", repo=repo, duration_ms=duration_ms)

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[f.model_dump() for f in findings],
            metadata=evidence,
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Control mapping (heuristic, no Claude)
    # ------------------------------------------------------------------

    def _map_findings_to_controls(
        self,
        findings: list[Finding],
        frameworks: list[str],
    ) -> dict[str, dict[str, Any]]:
        """
        Map each finding to framework controls using the static vuln_class_map.

        Returns a dict keyed by framework name, each containing:
          - failing_controls: list of control IDs with findings
          - control_details: {control_id: {control_name, findings: [finding_id, ...]}}
        """
        result: dict[str, dict[str, Any]] = {}

        for fw_key in frameworks:
            fw = FRAMEWORKS.get(fw_key)
            if not fw:
                continue

            vuln_map = fw.get("vuln_class_map", {})
            controls = fw.get("controls", {})
            failing: dict[str, list[str]] = {}  # control_id -> [finding_id, ...]

            for finding in findings:
                matched_controls = vuln_map.get(finding.vuln_class, [])
                # Also try partial matches (e.g. "injection" matches "sql_injection")
                if not matched_controls:
                    for vc_key, ctl_list in vuln_map.items():
                        if vc_key in finding.vuln_class or finding.vuln_class in vc_key:
                            matched_controls = ctl_list
                            break

                for ctl_id in matched_controls:
                    if ctl_id not in failing:
                        failing[ctl_id] = []
                    failing[ctl_id].append(finding.finding_id)

            result[fw_key] = {
                "framework_name": fw["name"],
                "failing_controls": list(failing.keys()),
                "passing_controls": [c for c in controls if c not in failing],
                "control_details": {
                    ctl_id: {
                        "control_name": controls.get(ctl_id, ctl_id),
                        "finding_ids": finding_ids,
                        "status": "FAIL",
                    }
                    for ctl_id, finding_ids in failing.items()
                },
                "pass_rate": (
                    round((len(controls) - len(failing)) / len(controls), 3)
                    if controls
                    else 1.0
                ),
            }

        return result

    # ------------------------------------------------------------------
    # Claude compliance analysis
    # ------------------------------------------------------------------

    async def _analyze_compliance(
        self,
        org: str,
        repo: str,
        findings: list[Finding],
        control_mapping: dict[str, dict[str, Any]],
        frameworks: list[str],
    ) -> str:
        """Use Claude to produce a narrative compliance gap analysis."""
        finding_summary = json.dumps(
            [
                {
                    "finding_id": f.finding_id,
                    "vuln_class": f.vuln_class,
                    "severity": f.severity.value,
                    "title": f.title,
                    "file": f.file,
                }
                for f in findings[:50]  # cap to avoid context overflow
            ],
            indent=2,
        )

        mapping_summary = json.dumps(
            {
                fw: {
                    "pass_rate": data.get("pass_rate", 0),
                    "failing_controls": data.get("failing_controls", []),
                }
                for fw, data in control_mapping.items()
            },
            indent=2,
        )

        system = """\
You are a compliance auditor with expertise in SOC 2, PCI DSS 4.0, HIPAA, FIPS 140, NIST 800-53, and CIS Controls.

Your task: given a set of security findings and their framework control mappings, produce:
1. An executive summary of compliance posture (3-5 sentences)
2. Framework-by-framework gap analysis with specific remediation priorities
3. Risk prioritization: which failing controls represent the highest regulatory risk
4. Recommended remediation sequence with estimated effort (High/Medium/Low)

Be specific and actionable. Reference control IDs. Avoid generic statements."""

        user_msg = f"""\
Organization: {org}
Repository: {repo}
Frameworks in scope: {', '.join(frameworks)}

Security findings ({len(findings)} total):
{finding_summary}

Framework control mapping:
{mapping_summary}

Produce the compliance gap analysis now."""

        try:
            analysis = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=4096,
            )
            return analysis
        except Exception as exc:  # noqa: BLE001
            self.log.error("auditor.claude_analysis_error", error=str(exc))
            return f"Claude analysis unavailable: {exc}"

    # ------------------------------------------------------------------
    # Evidence package generation
    # ------------------------------------------------------------------

    async def generate_evidence_package(
        self, framework: str, findings: list[Any]
    ) -> dict[str, Any]:
        """
        Generate an auditor-ready evidence package for a specific framework.

        Parameters
        ----------
        framework : str
            One of the FRAMEWORKS keys (e.g. ``soc2``, ``pci_dss``).
        findings : list
            List of Finding objects or dicts.

        Returns
        -------
        dict
            Evidence package containing: framework metadata, control status,
            evidence artifacts per control, and a Claude-generated summary.
        """
        fw = FRAMEWORKS.get(framework)
        if not fw:
            return {"error": f"Unknown framework: {framework}"}

        normalized: list[Finding] = [
            Finding(**f) if isinstance(f, dict) else f for f in findings
        ]

        control_mapping = self._map_findings_to_controls(normalized, [framework])
        fw_mapping = control_mapping.get(framework, {})

        # Build evidence artifacts per control
        artifacts: dict[str, list[dict[str, Any]]] = {}
        for ctl_id, ctl_data in fw_mapping.get("control_details", {}).items():
            evidence_items = []
            for finding_id in ctl_data.get("finding_ids", []):
                # Find the actual finding object
                matching = [f for f in normalized if f.finding_id == finding_id]
                for f in matching:
                    evidence_items.append({
                        "evidence_id": str(uuid.uuid4())[:12],
                        "type": "security_finding",
                        "finding_id": f.finding_id,
                        "severity": f.severity.value,
                        "title": f.title,
                        "file": f.file,
                        "vuln_class": f.vuln_class,
                        "discovery_ts": f.discovery_ts.isoformat(),
                        "status": f.status.value,
                        "commitment_hash": f.commitment_hash,
                    })
            artifacts[ctl_id] = evidence_items

        # Generate narrative summary via Claude
        summary = await self._generate_evidence_summary(framework, fw, normalized, fw_mapping)

        return {
            "package_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework": framework,
            "framework_name": fw["name"],
            "framework_version": fw.get("version", ""),
            "total_controls": len(fw.get("controls", {})),
            "failing_controls": len(fw_mapping.get("failing_controls", [])),
            "passing_controls": len(fw_mapping.get("passing_controls", [])),
            "pass_rate": fw_mapping.get("pass_rate", 0.0),
            "control_details": fw_mapping.get("control_details", {}),
            "evidence_artifacts": artifacts,
            "executive_summary": summary,
        }

    async def _generate_evidence_summary(
        self,
        framework: str,
        fw: dict[str, Any],
        findings: list[Finding],
        fw_mapping: dict[str, Any],
    ) -> str:
        """Claude-generated narrative for the evidence package."""
        system = f"""\
You are a {fw['name']} compliance auditor generating an evidence summary for external auditors.

Write a concise (3-4 paragraph) evidence summary that:
1. States the overall compliance posture and pass rate
2. Identifies the highest-risk control failures with specific CVEs / vulnerability classes
3. Describes remediation timeline commitments
4. Notes any mitigating controls that reduce risk despite open findings

Use formal auditor language. Reference specific control IDs."""

        fail_details = "\n".join(
            f"- {ctl_id} ({fw['controls'].get(ctl_id, '')}): {len(data['finding_ids'])} finding(s)"
            for ctl_id, data in fw_mapping.get("control_details", {}).items()
        )

        user_msg = f"""\
Framework: {fw['name']} ({fw.get('version', '')})
Pass rate: {fw_mapping.get('pass_rate', 0.0):.1%}
Total findings: {len(findings)}
Critical/High: {sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))}

Failing controls:
{fail_details or 'None — all controls passing'}

Generate the evidence summary now."""

        try:
            return await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=2048,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("auditor.evidence_summary_error", error=str(exc))
            return f"Summary generation failed: {exc}"

    # ------------------------------------------------------------------
    # Compliance drift detection
    # ------------------------------------------------------------------

    async def detect_compliance_drift(
        self, repo: str, framework: str
    ) -> list[dict[str, Any]]:
        """
        Identify code changes that violate compliance controls — even without a CVE.

        This relies on episodic memory's scan history to detect patterns like:
        - Removing authentication middleware
        - Disabling encryption at rest
        - Adding insecure configuration flags
        - Downgrading TLS versions
        - Adding hardcoded credentials
        - Disabling audit logging

        Parameters
        ----------
        repo : str
            Repository to inspect for drift.
        framework : str
            Compliance framework key to scope the drift check.

        Returns
        -------
        list[dict]
            Drift items: {control_id, description, change_ts, severity, file}
        """
        fw = FRAMEWORKS.get(framework)
        if not fw:
            return []

        # Fetch recent scan history from episodic memory
        recent_findings: list[dict[str, Any]] = []
        if self.memory is not None and hasattr(self.memory, "episodic"):
            try:
                trend = await self.memory.episodic.get_vulnerability_trend(repo, days=30)
                recent_findings = trend
            except Exception as exc:  # noqa: BLE001
                self.log.warning("auditor.drift_episodic_error", error=str(exc))

        # Ask Claude to reason about drift from scan history
        system = f"""\
You are a compliance drift analyst for {fw['name']}.

Compliance drift occurs when code changes introduce control violations independent of known CVEs.
Examples: removing auth middleware, disabling encryption, hardcoding credentials, downgrading TLS,
disabling audit logs, weakening password policies.

Given recent scan history for a repository, identify patterns that suggest compliance drift.
For each drift item, specify:
- Which control it violates
- What change likely caused it
- Severity (Critical/High/Medium/Low)

Return ONLY valid JSON:
{{
  "drift_items": [
    {{
      "control_id": "<framework control ID>",
      "control_name": "<control name>",
      "description": "<what changed and why it violates the control>",
      "severity": "Critical|High|Medium|Low",
      "file": "<suspected file or 'unknown'>",
      "evidence": "<specific signal from scan history>"
    }}
  ]
}}
Return {{"drift_items": []}} if no drift detected."""

        user_msg = f"""\
Repository: {repo}
Framework: {fw['name']}
Framework controls: {json.dumps(fw.get('controls', {}), indent=2)}

Recent scan history (30 days):
{json.dumps(recent_findings[:50], indent=2, default=str)}

Identify compliance drift now."""

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=4096,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("auditor.drift_claude_error", error=str(exc))
            return []

        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            data = json.loads(raw)
            drift_items: list[dict[str, Any]] = data.get("drift_items", [])
            self.log.info("auditor.drift_detected", repo=repo, framework=framework, items=len(drift_items))
            return drift_items
        except json.JSONDecodeError as exc:
            self.log.warning("auditor.drift_json_error", error=str(exc))
            return []
