"""
argos/agents/intelligence/prophet.py

ProphetAgent — Predictive vulnerability intelligence.

Reads historical scan data from TimescaleDB (scans, findings_timeline,
agent_metrics hypertables) and uses Claude with adaptive thinking to
identify repos and files that are statistically and semantically likely
to harbour new vulnerabilities.

Outputs:
  - Priority-boost recommendations embedded in RepoScanEvent.priority
  - High-risk file predictions stored in procedural memory
  - Published RepoScanEvent messages for at-risk repos

Schedule: every 6 hours (orchestrated externally via APScheduler / cron).
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.config import settings
from argos.events import EventType, Platform, RepoScanEvent

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# SQL queries against TimescaleDB hypertables
# ---------------------------------------------------------------------------

_SQL_INCREASING_FINDING_RATE = """
SELECT
    repo,
    COUNT(*) FILTER (WHERE time > NOW() - INTERVAL '7 days')  AS findings_last_7d,
    COUNT(*) FILTER (WHERE time > NOW() - INTERVAL '14 days'
                       AND time <= NOW() - INTERVAL '7 days') AS findings_prev_7d,
    COUNT(*)                                                    AS findings_total
FROM findings_timeline
WHERE time > NOW() - INTERVAL '30 days'
GROUP BY repo
HAVING
    COUNT(*) FILTER (WHERE time > NOW() - INTERVAL '7 days') >
    COUNT(*) FILTER (WHERE time > NOW() - INTERVAL '14 days'
                       AND time <= NOW() - INTERVAL '7 days')
ORDER BY findings_last_7d DESC
LIMIT 50;
"""

_SQL_HIGH_VULN_FILES = """
SELECT
    repo,
    file_path,
    COUNT(*)        AS historical_findings,
    MAX(time)       AS last_finding_ts
FROM findings_timeline
WHERE time > NOW() - INTERVAL '90 days'
  AND file_path IS NOT NULL
GROUP BY repo, file_path
ORDER BY historical_findings DESC
LIMIT 100;
"""

_SQL_RISKY_DEPENDENCY_PATTERNS = """
SELECT
    s.repo,
    COUNT(DISTINCT s.scan_id) AS scan_count,
    SUM(s.findings)           AS total_findings,
    AVG(s.findings)           AS avg_findings_per_scan
FROM scans s
WHERE s.time > NOW() - INTERVAL '90 days'
GROUP BY s.repo
HAVING AVG(s.findings) > 2
ORDER BY avg_findings_per_scan DESC
LIMIT 50;
"""

_SQL_RECENT_AGENT_METRICS = """
SELECT
    repo,
    metric_name,
    AVG(value) AS avg_value,
    MAX(time)  AS latest
FROM agent_metrics
WHERE time > NOW() - INTERVAL '7 days'
GROUP BY repo, metric_name
ORDER BY repo, metric_name;
"""


class ProphetAgent(ArgosAgent):
    """
    Predictive vulnerability intelligence agent.

    Analyses historical TimescaleDB data to surface repos and files most
    likely to yield new findings, then publishes elevated-priority
    RepoScanEvent messages so Navigator routes scanners there first.
    """

    name: str = "prophet"

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def __init__(self, memory: Any | None = None, producer: Any | None = None) -> None:
        super().__init__(memory=memory, producer=producer)
        self._pg_dsn: str = settings.postgres_dsn

    # -----------------------------------------------------------------------
    # Main entrypoint
    # -----------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute one Prophet cycle.

        Context keys (all optional):
            platform (str): default "bitbucket"
            branch   (str): default "main"
        """
        self._total_tokens = 0
        t0 = time.monotonic()

        platform_str: str = context.get("platform", "bitbucket")
        branch: str = context.get("branch", "main")

        try:
            platform = Platform(platform_str)
        except ValueError:
            platform = Platform.BITBUCKET

        self.log.info("prophet.cycle_start")

        try:
            # 1. Pull historical data from TimescaleDB
            scan_data = await self._fetch_timescale_data()

            if not any(scan_data.values()):
                self.log.info("prophet.no_data", reason="hypertables empty or unreachable")
                return AgentResult(
                    agent=self.name,
                    success=True,
                    findings=[],
                    metadata={"reason": "no_timescale_data"},
                    duration_ms=int((time.monotonic() - t0) * 1000),
                    tokens_used=self._total_tokens,
                )

            # 2. Ask Claude to reason about vulnerability trends
            predictions = await self._predict_with_claude(scan_data)

            # 3. Publish elevated-priority scan events for at-risk repos
            published: list[str] = []
            for pred in predictions.get("high_risk_repos", []):
                repo = pred.get("repo", "")
                priority = float(pred.get("priority_boost", 7.0))
                if not repo:
                    continue

                event = RepoScanEvent(
                    event_type=EventType.SCHEDULED,
                    platform=platform,
                    repo=repo,
                    branch=branch,
                    priority=min(priority, 10.0),
                    trigger="prophet_prediction",
                    changed_files=pred.get("high_risk_files", []),
                )
                if self.producer:
                    await self.producer.publish("argos.scan.requested", event)
                published.append(repo)
                self.log.info(
                    "prophet.scan_event_published",
                    repo=repo,
                    priority=event.priority,
                )

            # 4. Persist high-risk file predictions to procedural memory
            if self.memory:
                for pred in predictions.get("high_risk_repos", []):
                    for f in pred.get("high_risk_files", []):
                        await self.memory.record_confirmed_pattern(
                            vuln_class="predicted_high_risk",
                            pattern=f,
                            language="unknown",
                            confirmed_by=self.name,
                        )

            findings = [
                {
                    "finding_id": str(uuid.uuid4())[:16],
                    "severity": "Info",
                    "description": f"Prophet: {r} flagged as high-risk",
                    "repo": r,
                }
                for r in published
            ]

            self.log.info(
                "prophet.cycle_complete",
                repos_flagged=len(published),
                tokens=self._total_tokens,
            )
            return AgentResult(
                agent=self.name,
                success=True,
                findings=findings,
                metadata={
                    "repos_flagged": published,
                    "raw_predictions": predictions,
                },
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        except Exception as exc:  # noqa: BLE001
            self.log.exception("prophet.cycle_failed", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

    # -----------------------------------------------------------------------
    # Data fetching
    # -----------------------------------------------------------------------

    async def _fetch_timescale_data(self) -> dict[str, list[dict[str, Any]]]:
        """Query TimescaleDB hypertables and return raw rows as dicts."""
        results: dict[str, list[dict[str, Any]]] = {
            "increasing_rate": [],
            "high_vuln_files": [],
            "risky_deps": [],
            "agent_metrics": [],
        }
        try:
            conn: asyncpg.Connection = await asyncpg.connect(self._pg_dsn)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("prophet.db_connect_failed", error=str(exc))
            return results

        try:
            for key, sql in [
                ("increasing_rate", _SQL_INCREASING_FINDING_RATE),
                ("high_vuln_files", _SQL_HIGH_VULN_FILES),
                ("risky_deps", _SQL_RISKY_DEPENDENCY_PATTERNS),
                ("agent_metrics", _SQL_RECENT_AGENT_METRICS),
            ]:
                try:
                    rows = await conn.fetch(sql)
                    results[key] = [dict(r) for r in rows]
                    self.log.debug("prophet.query_ok", key=key, rows=len(results[key]))
                except Exception as exc:  # noqa: BLE001
                    self.log.warning("prophet.query_failed", key=key, error=str(exc))
        finally:
            await conn.close()

        return results

    # -----------------------------------------------------------------------
    # Claude reasoning
    # -----------------------------------------------------------------------

    async def _predict_with_claude(
        self,
        scan_data: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """
        Use Claude (adaptive thinking) to derive vulnerability predictions
        from raw TimescaleDB data.

        Returns a dict with:
            high_risk_repos: list of {repo, priority_boost, high_risk_files, rationale}
        """
        system = (
            "You are Prophet, a predictive security intelligence agent inside the ARGOS "
            "platform. You receive historical vulnerability scan data from TimescaleDB and "
            "must identify which repositories and files are most likely to contain new "
            "vulnerabilities. Reason carefully about trends, rates of change, and historical "
            "patterns. Return ONLY valid JSON — no prose outside the JSON block."
        )

        def _truncate(rows: list[dict], limit: int = 30) -> list[dict]:
            return rows[:limit]

        payload = {
            "repos_with_increasing_finding_rate": _truncate(scan_data["increasing_rate"]),
            "historically_high_vuln_files": _truncate(scan_data["high_vuln_files"]),
            "repos_with_risky_dependency_patterns": _truncate(scan_data["risky_deps"]),
            "recent_agent_metrics_sample": _truncate(scan_data["agent_metrics"], 20),
        }

        prompt = (
            "Analyse the following historical scan data and identify the top repositories "
            "and files most likely to harbour undiscovered vulnerabilities.\n\n"
            f"```json\n{json.dumps(payload, default=str, indent=2)}\n```\n\n"
            "Return a JSON object with this exact shape:\n"
            "{\n"
            '  "high_risk_repos": [\n'
            "    {\n"
            '      "repo": "<repo name>",\n'
            '      "priority_boost": <float 0-10>,\n'
            '      "high_risk_files": ["<file path>", ...],\n'
            '      "rationale": "<one sentence>"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "Limit to the top 10 repos. Use the priority_boost field to indicate urgency "
            "(10 = immediate rescan required, 5 = elevated, 3 = slightly elevated)."
        )

        raw = await self._call_claude(
            system=system,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096,
        )

        # Extract JSON from response (may be wrapped in a code fence)
        return _parse_json_response(raw, fallback={"high_risk_repos": []})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_json_response(text: str, fallback: Any = None) -> Any:
    """Extract and parse the first JSON object from a Claude text response."""
    text = text.strip()
    # Strip markdown code fences if present
    if "```" in text:
        import re
        match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
        if match:
            text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("prophet.json_parse_failed", snippet=text[:200])
        return fallback if fallback is not None else {}
