"""
argos/agents/intelligence/diplomat.py

DiplomatAgent — Coordinated disclosure lifecycle coordinator.

Manages the full 90-day coordinated disclosure process:
  D+1:  Vendor notification email (CVSS, impact, reproduction steps)
  D+45: Escalation email if no vendor acknowledgement
  D+90: Public advisory publication

Reads from ``triage_records`` and ``disclosure_docs`` PostgreSQL tables.
Writes disclosure documents back to ``disclosure_docs``.
Sends email via SMTP (configured in argos.config.settings).

Schedule: every hour (orchestrated externally via APScheduler / cron).
"""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import asyncpg
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.config import settings

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Disclosure timeline constants (driven by settings for overridability)
# ---------------------------------------------------------------------------

_DAY_NOTIFY: int = settings.disclosure_vendor_notify_day      # default 1
_DAY_ESCALATE: int = settings.disclosure_escalation_day        # default 45
_DAY_PUBLIC: int = settings.disclosure_public_day              # default 90

# ---------------------------------------------------------------------------
# SQL queries
# ---------------------------------------------------------------------------

_SQL_PENDING_DISCLOSURES = """
SELECT
    t.finding_id,
    t.repo,
    t.vuln_class,
    t.severity,
    t.cvss_score,
    t.cvss_vector,
    t.title,
    t.description,
    t.vendor_email,
    t.vendor_name,
    t.exploitation_path,
    t.discovery_ts,
    t.status,
    t.contact_email,
    COALESCE(d.notification_sent_at, NULL)  AS notification_sent_at,
    COALESCE(d.escalation_sent_at, NULL)    AS escalation_sent_at,
    COALESCE(d.public_published_at, NULL)   AS public_published_at,
    COALESCE(d.vendor_acknowledged_at, NULL) AS vendor_acknowledged_at
FROM triage_records t
LEFT JOIN disclosure_docs d ON d.finding_id = t.finding_id
WHERE t.status NOT IN ('disclosed', 'false_positive', 'fixed')
  AND t.discovery_ts IS NOT NULL
ORDER BY t.discovery_ts ASC;
"""

_SQL_UPSERT_DISCLOSURE_DOC = """
INSERT INTO disclosure_docs (
    finding_id, document_type, content, generated_at, sent_at
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (finding_id, document_type)
DO UPDATE SET
    content      = EXCLUDED.content,
    generated_at = EXCLUDED.generated_at,
    sent_at      = EXCLUDED.sent_at;
"""

_SQL_MARK_NOTIFICATION_SENT = """
INSERT INTO disclosure_docs (finding_id, document_type, content, generated_at, sent_at)
VALUES ($1, 'notification_meta', $2, NOW(), NOW())
ON CONFLICT (finding_id, document_type)
DO UPDATE SET sent_at = NOW(), content = EXCLUDED.content;
"""


class DiplomatAgent(ArgosAgent):
    """
    Coordinated disclosure lifecycle agent.

    On each hourly run, Diplomat:
      1. Reads all open triage records from PostgreSQL.
      2. For each, determines which disclosure milestone is due.
      3. Uses Claude to generate professional disclosure documents.
      4. Sends via SMTP and records the send in ``disclosure_docs``.
    """

    name: str = "diplomat"

    def __init__(self, memory: Any | None = None, producer: Any | None = None) -> None:
        super().__init__(memory=memory, producer=producer)
        self._pg_dsn: str = settings.postgres_dsn

    # -----------------------------------------------------------------------
    # Main entrypoint
    # -----------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute one Diplomat hourly cycle.

        Context keys (all optional):
            dry_run (bool): if True, generate documents but do not send emails.
        """
        self._total_tokens = 0
        t0 = time.monotonic()
        dry_run: bool = bool(context.get("dry_run", False))

        self.log.info("diplomat.cycle_start", dry_run=dry_run)

        try:
            conn = await asyncpg.connect(self._pg_dsn)
        except Exception as exc:  # noqa: BLE001
            self.log.error("diplomat.db_connect_failed", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=f"DB connect failed: {exc}",
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        actions_taken: list[dict[str, Any]] = []

        try:
            rows = await conn.fetch(_SQL_PENDING_DISCLOSURES)
            now = datetime.now(timezone.utc)

            for row in rows:
                rec = dict(row)
                finding_id = rec["finding_id"]
                discovery_ts: datetime = rec["discovery_ts"]
                if discovery_ts.tzinfo is None:
                    discovery_ts = discovery_ts.replace(tzinfo=timezone.utc)

                days_elapsed = (now - discovery_ts).days

                # ── D+1: Vendor notification ───────────────────────────────
                if (
                    days_elapsed >= _DAY_NOTIFY
                    and rec.get("notification_sent_at") is None
                ):
                    action = await self._handle_notification(rec, conn, dry_run)
                    if action:
                        actions_taken.append(action)

                # ── D+45: Escalation ───────────────────────────────────────
                elif (
                    days_elapsed >= _DAY_ESCALATE
                    and rec.get("notification_sent_at") is not None
                    and rec.get("escalation_sent_at") is None
                    and rec.get("vendor_acknowledged_at") is None
                ):
                    action = await self._handle_escalation(rec, conn, dry_run)
                    if action:
                        actions_taken.append(action)

                # ── D+90: Public advisory ──────────────────────────────────
                elif (
                    days_elapsed >= _DAY_PUBLIC
                    and rec.get("public_published_at") is None
                ):
                    action = await self._handle_public_advisory(rec, conn, dry_run)
                    if action:
                        actions_taken.append(action)

        except Exception as exc:  # noqa: BLE001
            self.log.exception("diplomat.cycle_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )
        finally:
            await conn.close()

        self.log.info(
            "diplomat.cycle_complete",
            actions=len(actions_taken),
            tokens=self._total_tokens,
        )
        return AgentResult(
            agent=self.name,
            success=True,
            findings=[],
            metadata={"actions_taken": actions_taken},
            duration_ms=int((time.monotonic() - t0) * 1000),
            tokens_used=self._total_tokens,
        )

    # -----------------------------------------------------------------------
    # Milestone handlers
    # -----------------------------------------------------------------------

    async def _handle_notification(
        self,
        rec: dict[str, Any],
        conn: asyncpg.Connection,
        dry_run: bool,
    ) -> dict[str, Any] | None:
        """Generate and send the initial vendor notification email."""
        finding_id = rec["finding_id"]
        self.log.info("diplomat.notification_due", finding_id=finding_id)

        doc = await self._generate_vendor_notification(rec)
        await self._store_disclosure_doc(conn, finding_id, "vendor_notification", doc)

        recipient = rec.get("vendor_email") or rec.get("contact_email") or settings.alert_email_to
        if recipient and not dry_run:
            subject = f"[ARGOS Security] Vulnerability Notification – {rec.get('title', finding_id)}"
            await self._send_email(recipient, subject, doc)

        # Mark notification sent
        await conn.execute(
            _SQL_MARK_NOTIFICATION_SENT,
            finding_id,
            json.dumps({"action": "notification_sent", "dry_run": dry_run}),
        )
        return {"finding_id": finding_id, "action": "notification_sent", "dry_run": dry_run}

    async def _handle_escalation(
        self,
        rec: dict[str, Any],
        conn: asyncpg.Connection,
        dry_run: bool,
    ) -> dict[str, Any] | None:
        """Generate and send the D+45 escalation email."""
        finding_id = rec["finding_id"]
        self.log.info("diplomat.escalation_due", finding_id=finding_id)

        doc = await self._generate_escalation(rec)
        await self._store_disclosure_doc(conn, finding_id, "escalation", doc)

        recipient = rec.get("vendor_email") or rec.get("contact_email") or settings.alert_email_to
        if recipient and not dry_run:
            subject = f"[ARGOS Security][ESCALATION] No Response – {rec.get('title', finding_id)}"
            await self._send_email(recipient, subject, doc)

        await conn.execute(
            "UPDATE disclosure_docs SET sent_at = NOW() "
            "WHERE finding_id = $1 AND document_type = 'escalation'",
            finding_id,
        )
        return {"finding_id": finding_id, "action": "escalation_sent", "dry_run": dry_run}

    async def _handle_public_advisory(
        self,
        rec: dict[str, Any],
        conn: asyncpg.Connection,
        dry_run: bool,
    ) -> dict[str, Any] | None:
        """Generate and store the D+90 public advisory."""
        finding_id = rec["finding_id"]
        self.log.info("diplomat.public_advisory_due", finding_id=finding_id)

        doc = await self._generate_public_advisory(rec)
        await self._store_disclosure_doc(conn, finding_id, "public_advisory", doc)

        # Mark as disclosed in triage_records
        if not dry_run:
            try:
                await conn.execute(
                    "UPDATE triage_records SET status = 'disclosed' WHERE finding_id = $1",
                    finding_id,
                )
            except Exception as exc:  # noqa: BLE001
                self.log.warning("diplomat.status_update_failed", error=str(exc))

        await conn.execute(
            "UPDATE disclosure_docs SET sent_at = NOW() "
            "WHERE finding_id = $1 AND document_type = 'public_advisory'",
            finding_id,
        )
        return {"finding_id": finding_id, "action": "public_advisory_published", "dry_run": dry_run}

    # -----------------------------------------------------------------------
    # Claude document generation
    # -----------------------------------------------------------------------

    async def _generate_vendor_notification(self, rec: dict[str, Any]) -> str:
        system = (
            "You are Diplomat, a security disclosure coordinator for the ARGOS platform. "
            "You draft professional, accurate, and legally careful coordinated disclosure "
            "communications. Write in clear English suitable for a corporate security team."
        )
        prompt = (
            "Generate a professional vendor security notification email body (plain text) for "
            "the following vulnerability finding. Include: vulnerability summary, CVSS score "
            "and vector, affected product/component, exploitation path, reproduction steps "
            "(if available), proposed remediation guidance, and a 90-day disclosure deadline. "
            "Sign as 'ARGOS Security Research Team'.\n\n"
            f"Finding ID:       {rec.get('finding_id', 'N/A')}\n"
            f"Title:            {rec.get('title', 'N/A')}\n"
            f"Vulnerability:    {rec.get('vuln_class', 'N/A')}\n"
            f"Severity:         {rec.get('severity', 'N/A')}\n"
            f"CVSS Score:       {rec.get('cvss_score', 'N/A')}\n"
            f"CVSS Vector:      {rec.get('cvss_vector', 'N/A')}\n"
            f"Repository:       {rec.get('repo', 'N/A')}\n"
            f"Description:      {rec.get('description', 'N/A')}\n"
            f"Exploitation Path:{rec.get('exploitation_path', 'N/A')}\n"
            f"Discovery Date:   {rec.get('discovery_ts', 'N/A')}\n"
            f"Vendor:           {rec.get('vendor_name', 'N/A')}\n"
        )
        return await self._call_claude(
            system=system,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
        )

    async def _generate_escalation(self, rec: dict[str, Any]) -> str:
        system = (
            "You are Diplomat, a security disclosure coordinator. Draft a professional "
            "escalation email noting 45 days have passed with no vendor acknowledgement. "
            "Maintain a firm but respectful tone. Remind the vendor of the 90-day deadline."
        )
        prompt = (
            "Generate a D+45 escalation email body for this unacknowledged vulnerability "
            "notification. Reference the original disclosure date and state that public "
            "disclosure will proceed at D+90 if no response is received.\n\n"
            f"Finding ID:    {rec.get('finding_id', 'N/A')}\n"
            f"Title:         {rec.get('title', 'N/A')}\n"
            f"Severity:      {rec.get('severity', 'N/A')}\n"
            f"CVSS Score:    {rec.get('cvss_score', 'N/A')}\n"
            f"Discovery Date:{rec.get('discovery_ts', 'N/A')}\n"
            f"Vendor:        {rec.get('vendor_name', 'N/A')}\n"
        )
        return await self._call_claude(
            system=system,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1536,
        )

    async def _generate_public_advisory(self, rec: dict[str, Any]) -> str:
        system = (
            "You are Diplomat, a security disclosure coordinator. Draft a public security "
            "advisory suitable for publication on a security blog or CVE database. "
            "Be technically precise, include CVSS details, affected versions, and mitigation "
            "guidance. Format in Markdown."
        )
        prompt = (
            "Generate a public security advisory in Markdown for the following vulnerability. "
            "Include: title, summary, affected component, CVSS score/vector, technical details, "
            "exploitation scenario, remediation, timeline of disclosure.\n\n"
            f"Finding ID:       {rec.get('finding_id', 'N/A')}\n"
            f"Title:            {rec.get('title', 'N/A')}\n"
            f"Vulnerability:    {rec.get('vuln_class', 'N/A')}\n"
            f"Severity:         {rec.get('severity', 'N/A')}\n"
            f"CVSS Score:       {rec.get('cvss_score', 'N/A')}\n"
            f"CVSS Vector:      {rec.get('cvss_vector', 'N/A')}\n"
            f"Repository:       {rec.get('repo', 'N/A')}\n"
            f"Description:      {rec.get('description', 'N/A')}\n"
            f"Exploitation Path:{rec.get('exploitation_path', 'N/A')}\n"
            f"Discovery Date:   {rec.get('discovery_ts', 'N/A')}\n"
            f"Vendor:           {rec.get('vendor_name', 'N/A')}\n"
        )
        return await self._call_claude(
            system=system,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=3072,
        )

    # -----------------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------------

    async def _store_disclosure_doc(
        self,
        conn: asyncpg.Connection,
        finding_id: str,
        document_type: str,
        content: str,
    ) -> None:
        """Write a generated disclosure document to the disclosure_docs table."""
        try:
            await conn.execute(
                _SQL_UPSERT_DISCLOSURE_DOC,
                finding_id,
                document_type,
                content,
                datetime.now(timezone.utc),
                None,  # sent_at — set later after actual send
            )
            self.log.debug(
                "diplomat.doc_stored",
                finding_id=finding_id,
                document_type=document_type,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "diplomat.doc_store_failed",
                finding_id=finding_id,
                document_type=document_type,
                error=str(exc),
            )

    # -----------------------------------------------------------------------
    # SMTP delivery
    # -----------------------------------------------------------------------

    async def _send_email(self, to: str, subject: str, body: str) -> None:
        """
        Send an email via configured SMTP settings.

        Runs the blocking smtplib call in a thread executor to avoid
        blocking the event loop.
        """
        host = settings.smtp_host
        port = settings.smtp_port
        user = settings.smtp_user
        password = settings.smtp_pass.get_secret_value()
        from_addr = user or settings.alert_email_to

        if not host:
            self.log.warning("diplomat.smtp_not_configured", to=to, subject=subject)
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to
        msg.attach(MIMEText(body, "plain"))

        def _send() -> None:
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port) as server:
                server.ehlo()
                if port == 587:
                    server.starttls(context=context)
                if user and password:
                    server.login(user, password)
                server.sendmail(from_addr, [to], msg.as_string())

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, _send)
            self.log.info("diplomat.email_sent", to=to, subject=subject)
        except Exception as exc:  # noqa: BLE001
            self.log.error("diplomat.email_failed", to=to, error=str(exc))
