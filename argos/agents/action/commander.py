"""
argos/agents/action/commander.py

CommanderAgent — human-in-the-loop gateway for Critical findings.

For every Critical (and optionally High) finding that passes confirmation,
CommanderAgent:

1. Fires alerts across all configured channels (Slack, email, PagerDuty)
   — all channels fire independently (one failure doesn't block others).
2. Records a pending decision in episodic memory with a unique decision_id.
3. Returns the decision_id so downstream systems can await human approval.

When a human responds (via API, Slack interactive, or email reply):
4. record_decision() logs the outcome and feeds CVSS calibration memory.

Decisions (approve/reject) feed back to CVSS calibration:
- "approve" (escalate/exploit) → confirms severity, raises confidence
- "reject" (false positive) → lowers confidence, queues for FP analysis

All alert channels are independent: a Slack failure never prevents PagerDuty
from firing.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
import time
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.config import settings
from argos.events import Finding, Severity

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Alert severity threshold — only alert at or above this level
# ---------------------------------------------------------------------------

_ALERT_THRESHOLD: set[Severity] = {Severity.CRITICAL, Severity.HIGH}


# ---------------------------------------------------------------------------
# CommanderAgent
# ---------------------------------------------------------------------------


class CommanderAgent(ArgosAgent):
    """
    Human-in-the-loop gateway for Critical findings.

    Parameters
    ----------
    memory:
        ArgosMemory for recording decisions.
    producer:
        Kafka producer.
    alert_channels:
        Override which channels to use (default: slack, email, pagerduty).
    alert_threshold:
        Minimum severity to trigger human review (default: Critical).
    """

    name = "commander"

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
        alert_channels: list[str] | None = None,
        alert_threshold: Severity = Severity.CRITICAL,
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._alert_channels: list[str] = alert_channels or ["slack", "email", "pagerduty"]
        self._alert_threshold = alert_threshold

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Route Critical findings to human review.

        Context keys
        ------------
        findings : list[dict]
            Findings to evaluate.  Only Critical (and High, if threshold is set)
            findings trigger alerts.
        commitment_hash : str
            SHA-3 commitment hash for the finding batch (proof of prior discovery).
        org : str
            Organisation name (used in alert messages).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        findings_raw: list[dict[str, Any]] = context.get("findings", [])
        commitment_hash: str = context.get("commitment_hash", "")
        org: str = context.get("org", "")

        self.log.info(
            "commander.run_start",
            findings=len(findings_raw),
            org=org,
        )

        try:
            findings = [Finding(**f) if isinstance(f, dict) else f for f in findings_raw]
            alert_findings = [
                f for f in findings
                if f.severity in _ALERT_THRESHOLD
            ]

            decisions: list[dict[str, Any]] = []
            for finding in alert_findings:
                # Use per-finding commitment hash if available
                fhash = finding.commitment_hash or commitment_hash
                decision_info = await self.request_human_decision(finding, fhash)
                decisions.append(decision_info)

            # Claude reasoning: analyse the full finding set and recommend
            # escalation priority order
            escalation_advice = ""
            if alert_findings:
                escalation_advice = await self._generate_escalation_advice(
                    alert_findings, org
                )

        except Exception as exc:  # noqa: BLE001
            self.log.exception("commander.run_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "commander.run_complete",
            alerted=len(decisions),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[f.model_dump() for f in findings],
            metadata={
                "org": org,
                "alert_count": len(decisions),
                "pending_decisions": decisions,
                "escalation_advice": escalation_advice,
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # request_human_decision()
    # ------------------------------------------------------------------

    async def request_human_decision(
        self, finding: Finding, commitment_hash: str
    ) -> dict[str, Any]:
        """
        Fire alerts and record a pending decision in episodic memory.

        Parameters
        ----------
        finding : Finding
            The finding requiring human review.
        commitment_hash : str
            SHA-3 hash proving prior discovery.

        Returns
        -------
        dict
            Keys: decision_id, finding_id, status, alerted_channels, error.
        """
        decision_id = str(uuid.uuid4())

        self.log.info(
            "commander.decision_requested",
            decision_id=decision_id,
            finding_id=finding.finding_id,
            severity=finding.severity.value,
        )

        # Fire all alert channels independently
        channel_results = await self._fire_alerts(finding, commitment_hash, decision_id)

        # Record pending decision in episodic memory
        await self._record_pending_decision(decision_id, finding, commitment_hash, channel_results)

        return {
            "decision_id": decision_id,
            "finding_id": finding.finding_id,
            "status": "pending",
            "alerted_channels": [ch for ch, ok in channel_results.items() if ok],
            "failed_channels": [ch for ch, ok in channel_results.items() if not ok],
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # record_decision()
    # ------------------------------------------------------------------

    async def record_decision(
        self,
        decision_id: str,
        approved: bool,
        reviewer: str,
        notes: str,
    ) -> None:
        """
        Record a human decision and feed CVSS calibration memory.

        Parameters
        ----------
        decision_id : str
            UUID returned by request_human_decision().
        approved : bool
            True if the human approved escalation (finding is real/critical).
            False if rejected (false positive or severity downgrade).
        reviewer : str
            Identity of the reviewer (email or username).
        notes : str
            Free-form reviewer notes.
        """
        outcome = "approved" if approved else "rejected"
        self.log.info(
            "commander.decision_recorded",
            decision_id=decision_id,
            outcome=outcome,
            reviewer=reviewer,
        )

        record = {
            "event_type": "human_decision",
            "decision_id": decision_id,
            "outcome": outcome,
            "approved": approved,
            "reviewer": reviewer,
            "notes": notes,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }

        # Write to episodic memory
        if self.memory is not None:
            try:
                await self.memory.write_episodic(record)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("commander.memory_write_error", error=str(exc))

        # Feed CVSS calibration vector memory
        if self.memory is not None and hasattr(self.memory, "vector"):
            try:
                calibration_text = (
                    f"decision:{outcome} reviewer:{reviewer} notes:{notes} decision_id:{decision_id}"
                )
                vector = await self.memory.vector.embed_code(calibration_text)
                await self.memory.vector.upsert(
                    collection="vulnerabilities",
                    id=f"decision-{decision_id}",
                    vector=vector,
                    payload={
                        "type": "human_decision",
                        "decision_id": decision_id,
                        "outcome": outcome,
                        "approved": approved,
                        "reviewer": reviewer,
                        "notes": notes,
                        "ts": datetime.now(timezone.utc).isoformat(),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                self.log.warning("commander.calibration_write_error", error=str(exc))

        # Publish decision event to Kafka if producer available
        if self.producer is not None:
            try:
                await self.producer.send(
                    "argos.decision.recorded",
                    value=record,
                )
            except Exception as exc:  # noqa: BLE001
                self.log.warning("commander.kafka_publish_error", error=str(exc))

    # ------------------------------------------------------------------
    # _fire_alerts()
    # ------------------------------------------------------------------

    async def _fire_alerts(
        self, finding: Finding, commitment_hash: str, decision_id: str
    ) -> dict[str, bool]:
        """
        Fire all alert channels independently.

        All channels execute concurrently. A failure in one does not prevent
        others from firing.

        Returns
        -------
        dict[str, bool]
            Channel name → True (success) / False (failure).
        """
        tasks: dict[str, Any] = {}
        if "slack" in self._alert_channels:
            tasks["slack"] = self._alert_slack(finding, commitment_hash, decision_id)
        if "email" in self._alert_channels:
            tasks["email"] = self._alert_email(finding, commitment_hash, decision_id)
        if "pagerduty" in self._alert_channels:
            tasks["pagerduty"] = self._alert_pagerduty(finding, commitment_hash, decision_id)

        results: dict[str, bool] = {}
        if not tasks:
            return results

        # Run all channels concurrently
        channel_names = list(tasks.keys())
        coros = [tasks[ch] for ch in channel_names]
        outcomes = await asyncio.gather(*coros, return_exceptions=True)

        for name, outcome in zip(channel_names, outcomes):
            if isinstance(outcome, Exception):
                self.log.error(f"commander.alert_{name}_error", error=str(outcome))
                results[name] = False
            else:
                results[name] = bool(outcome)

        return results

    # ------------------------------------------------------------------
    # Slack alert
    # ------------------------------------------------------------------

    async def _alert_slack(
        self, finding: Finding, commitment_hash: str, decision_id: str
    ) -> bool:
        """Send a Slack webhook alert. Returns True on success."""
        webhook_url = settings.slack_webhook_url.get_secret_value()
        if not webhook_url:
            self.log.warning("commander.slack_not_configured")
            return False

        color = "#FF0000" if finding.severity == Severity.CRITICAL else "#FF8C00"
        payload = {
            "text": f":rotating_light: *ARGOS {finding.severity.value} Finding* — Human Decision Required",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Finding ID",   "value": finding.finding_id,       "short": True},
                        {"title": "Decision ID",  "value": decision_id,              "short": True},
                        {"title": "Repository",   "value": finding.repo,             "short": True},
                        {"title": "Severity",     "value": finding.severity.value,   "short": True},
                        {"title": "Vulnerability","value": finding.title,            "short": False},
                        {"title": "File",         "value": f"`{finding.file}:{finding.line}`", "short": False},
                        {"title": "Vuln Class",   "value": finding.vuln_class,       "short": True},
                        {"title": "CISA KEV",     "value": "Yes" if finding.cisa_kev else "No", "short": True},
                        {"title": "Exploitation", "value": finding.exploitation_path[:300], "short": False},
                        {"title": "Commitment Hash", "value": f"`{commitment_hash[:16]}...`" if commitment_hash else "N/A", "short": False},
                    ],
                    "footer": "ARGOS Commander | Approve or Reject via /argos decision",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(webhook_url, json=payload)
                resp.raise_for_status()
            self.log.info("commander.slack_sent", finding_id=finding.finding_id)
            return True
        except Exception as exc:  # noqa: BLE001
            self.log.error("commander.slack_error", error=str(exc))
            return False

    # ------------------------------------------------------------------
    # Email alert
    # ------------------------------------------------------------------

    async def _alert_email(
        self, finding: Finding, commitment_hash: str, decision_id: str
    ) -> bool:
        """Send an email alert via SMTP. Returns True on success."""
        if not settings.smtp_host or not settings.alert_email_to:
            self.log.warning("commander.email_not_configured")
            return False

        subject = (
            f"[ARGOS] {finding.severity.value} Finding — Decision Required: {finding.title}"
        )
        body = f"""\
ARGOS Security Alert — Human Decision Required
{'=' * 60}

Finding ID:      {finding.finding_id}
Decision ID:     {decision_id}
Severity:        {finding.severity.value}
Vulnerability:   {finding.title}
Vuln Class:      {finding.vuln_class}
Repository:      {finding.repo}
File:            {finding.file}:{finding.line}
CISA KEV:        {"Yes ⚠" if finding.cisa_kev else "No"}
CVEs:            {', '.join(finding.cve_ids) if finding.cve_ids else "None"}
CVSS Score:      {finding.cvss_score}
Confidence:      {finding.confidence:.0%}
Commitment Hash: {commitment_hash or "N/A"}

Exploitation Path
-----------------
{finding.exploitation_path}

Description
-----------
{finding.metadata.get('description', 'N/A')}

Action Required
---------------
Approve or reject this finding at your ARGOS dashboard.
Decision ID: {decision_id}

--
ARGOS CommanderAgent | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
"""

        loop = asyncio.get_event_loop()

        def _send_smtp() -> bool:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = settings.smtp_user
                msg["To"] = settings.alert_email_to
                msg.attach(MIMEText(body, "plain"))

                with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
                    server.starttls()
                    if settings.smtp_user and settings.smtp_pass.get_secret_value():
                        server.login(settings.smtp_user, settings.smtp_pass.get_secret_value())
                    server.send_message(msg)
                return True
            except Exception as exc:  # noqa: BLE001
                log.error("commander.smtp_send_error", error=str(exc))
                return False

        result = await loop.run_in_executor(None, _send_smtp)
        if result:
            self.log.info("commander.email_sent", finding_id=finding.finding_id)
        return result

    # ------------------------------------------------------------------
    # PagerDuty alert
    # ------------------------------------------------------------------

    async def _alert_pagerduty(
        self, finding: Finding, commitment_hash: str, decision_id: str
    ) -> bool:
        """Send a PagerDuty Events API v2 alert. Returns True on success."""
        routing_key = settings.pagerduty_routing_key.get_secret_value()
        if not routing_key:
            self.log.warning("commander.pagerduty_not_configured")
            return False

        severity_map = {
            Severity.CRITICAL: "critical",
            Severity.HIGH:     "error",
            Severity.MEDIUM:   "warning",
            Severity.LOW:      "info",
            Severity.INFO:     "info",
        }
        pd_severity = severity_map.get(finding.severity, "error")

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": f"argos-{finding.finding_id}",
            "payload": {
                "summary": f"[ARGOS] {finding.severity.value}: {finding.title} in {finding.repo}",
                "severity": pd_severity,
                "source": f"argos/commander/{finding.repo}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": finding.vuln_class,
                "group": finding.repo,
                "class": finding.vuln_class,
                "custom_details": {
                    "finding_id":       finding.finding_id,
                    "decision_id":      decision_id,
                    "file":             f"{finding.file}:{finding.line}",
                    "confidence":       f"{finding.confidence:.0%}",
                    "cisa_kev":         finding.cisa_kev,
                    "cve_ids":          ", ".join(finding.cve_ids) if finding.cve_ids else "None",
                    "cvss_score":       finding.cvss_score,
                    "commitment_hash":  commitment_hash[:32] if commitment_hash else "N/A",
                    "exploitation_path": finding.exploitation_path[:500],
                },
            },
            "links": [],
            "images": [],
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
            self.log.info(
                "commander.pagerduty_sent",
                finding_id=finding.finding_id,
                dedup_key=f"argos-{finding.finding_id}",
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self.log.error("commander.pagerduty_error", error=str(exc))
            return False

    # ------------------------------------------------------------------
    # Escalation advice (Claude)
    # ------------------------------------------------------------------

    async def _generate_escalation_advice(
        self, findings: list[Finding], org: str
    ) -> str:
        """
        Ask Claude to reason about which findings to escalate first and why.

        Returns a short prioritised escalation memo.
        """
        system = """\
You are a senior security incident commander.

Given a list of Critical/High findings requiring human decision, produce:
1. A prioritised escalation order (most urgent first) with justification
2. A recommended decision owner for each finding (CISO, VP Eng, Security team, etc.)
3. Key questions each reviewer should answer before approving/rejecting

Keep it concise — this is a live triage brief. Max 400 words. Plain text, no markdown."""

        finding_list = "\n".join(
            f"- [{f.severity.value}] {f.title} | {f.repo} | CISA KEV: {f.cisa_kev} | "
            f"Confidence: {f.confidence:.0%} | Class: {f.vuln_class}"
            for f in findings
        )

        user_msg = (
            f"Organisation: {org}\n"
            f"Alert timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            f"Findings requiring human decision:\n{finding_list}\n\n"
            f"Produce the escalation triage brief now."
        )

        try:
            return await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=1024,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("commander.escalation_advice_error", error=str(exc))
            return f"Escalation advice generation failed: {exc}"

    # ------------------------------------------------------------------
    # Pending decision recording
    # ------------------------------------------------------------------

    async def _record_pending_decision(
        self,
        decision_id: str,
        finding: Finding,
        commitment_hash: str,
        channel_results: dict[str, bool],
    ) -> None:
        """Write the pending decision to episodic memory."""
        record = {
            "event_type": "pending_decision",
            "decision_id": decision_id,
            "finding_id": finding.finding_id,
            "repo": finding.repo,
            "severity": finding.severity.value,
            "vuln_class": finding.vuln_class,
            "title": finding.title,
            "commitment_hash": commitment_hash,
            "alerted_channels": channel_results,
            "status": "pending",
            "requested_at": datetime.now(timezone.utc).isoformat(),
        }

        if self.memory is not None:
            try:
                await self.memory.write_episodic(record)
            except Exception as exc:  # noqa: BLE001
                self.log.warning(
                    "commander.pending_record_error",
                    decision_id=decision_id,
                    error=str(exc),
                )

        if self.producer is not None:
            try:
                await self.producer.send("argos.decision.pending", value=record)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("commander.kafka_pending_error", error=str(exc))
