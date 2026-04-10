"""
argos/agents/evolution/benchmarker.py

BenchmarkerAgent — Agent performance evaluator.

Reads agent_performance_log from PostgreSQL and computes precision, recall,
F1, and false positive rate per agent. Identifies underperforming agents
(precision < 0.7 over 20+ scans) and publishes AgentRetiredEvent for them.
Uses Claude to interpret trends and propose targeted improvements.

Schedule: configurable interval (suggested: every 6 hours or daily).
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
from argos.events import AgentRetiredEvent

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_MIN_SCANS_FOR_EVALUATION: int = 20
_PRECISION_RETIREMENT_THRESHOLD: float = 0.70
_PRECISION_WARNING_THRESHOLD: float = 0.80

# ---------------------------------------------------------------------------
# SQL queries
# ---------------------------------------------------------------------------

_SQL_AGENT_STATS = """
SELECT
    agent_name,
    COUNT(*)                                                AS scan_count,
    AVG(precision)                                          AS avg_precision,
    AVG(recall)                                             AS avg_recall,
    AVG(false_positive_rate)                                AS avg_fpr,
    -- F1 = 2 * (precision * recall) / (precision + recall), handle div-by-zero
    CASE
        WHEN AVG(precision) + AVG(recall) > 0
        THEN 2.0 * AVG(precision) * AVG(recall) / (AVG(precision) + AVG(recall))
        ELSE 0
    END                                                     AS f1_score,
    MIN(evaluated_at)                                       AS first_seen,
    MAX(evaluated_at)                                       AS last_seen,
    SUM(findings_count)                                     AS total_findings
FROM agent_performance_log
WHERE evaluated_at > NOW() - INTERVAL '30 days'
GROUP BY agent_name
ORDER BY avg_precision ASC;
"""

_SQL_RECENT_TREND = """
SELECT
    agent_name,
    DATE_TRUNC('day', evaluated_at) AS day,
    AVG(precision)                  AS daily_precision,
    AVG(recall)                     AS daily_recall,
    AVG(false_positive_rate)        AS daily_fpr,
    COUNT(*)                        AS daily_scans
FROM agent_performance_log
WHERE evaluated_at > NOW() - INTERVAL '14 days'
GROUP BY agent_name, day
ORDER BY agent_name, day;
"""

_SQL_WRITE_SNAPSHOT = """
INSERT INTO agent_performance_log (
    agent_name, scan_id, precision, recall, false_positive_rate,
    findings_count, duration_ms, evaluated_at, supervised, promoted
) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9);
"""


class BenchmarkerAgent(ArgosAgent):
    """
    Evaluates the performance of all active ARGOS scanning agents.

    Workflow each cycle:
      1. Read agent_performance_log for the last 30 days.
      2. Compute aggregate metrics per agent (precision, recall, F1, FPR).
      3. Use Claude to analyse performance trends and suggest improvements.
      4. Retire agents with precision < 0.70 over 20+ scans by publishing
         AgentRetiredEvent.
      5. Write a performance snapshot to agent_performance_log for this run.
    """

    name: str = "benchmarker"

    def __init__(self, memory: Any | None = None, producer: Any | None = None) -> None:
        super().__init__(memory=memory, producer=producer)
        self._pg_dsn: str = settings.postgres_dsn

    # -----------------------------------------------------------------------
    # Main entrypoint
    # -----------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute one Benchmarker evaluation cycle.

        Context keys (all optional):
            dry_run (bool): analyse but do not publish AgentRetiredEvents.
        """
        self._total_tokens = 0
        t0 = time.monotonic()
        dry_run: bool = bool(context.get("dry_run", False))

        self.log.info("benchmarker.cycle_start", dry_run=dry_run)

        try:
            conn = await asyncpg.connect(self._pg_dsn)
        except Exception as exc:  # noqa: BLE001
            self.log.error("benchmarker.db_connect_failed", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=f"DB connect failed: {exc}",
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        retired_agents: list[str] = []
        warnings: list[str] = []
        improvement_suggestions: list[dict[str, Any]] = []

        try:
            # ── 1. Aggregate per-agent stats ──────────────────────────────
            stats_rows = await conn.fetch(_SQL_AGENT_STATS)
            trend_rows = await conn.fetch(_SQL_RECENT_TREND)

            agent_stats: list[dict[str, Any]] = [dict(r) for r in stats_rows]
            agent_trends: list[dict[str, Any]] = [dict(r) for r in trend_rows]

            if not agent_stats:
                self.log.info("benchmarker.no_data")
                return AgentResult(
                    agent=self.name,
                    success=True,
                    findings=[],
                    metadata={"reason": "no_performance_data"},
                    duration_ms=int((time.monotonic() - t0) * 1000),
                    tokens_used=self._total_tokens,
                )

            # ── 2. Claude analysis ────────────────────────────────────────
            improvement_suggestions = await self._analyse_with_claude(
                agent_stats, agent_trends
            )

            # ── 3. Identify underperformers and retire them ───────────────
            for row in agent_stats:
                agent_name: str = row["agent_name"]
                scan_count: int = int(row["scan_count"])
                avg_precision: float = float(row["avg_precision"] or 0.0)

                if scan_count < _MIN_SCANS_FOR_EVALUATION:
                    continue  # not enough data yet

                if avg_precision < _PRECISION_RETIREMENT_THRESHOLD:
                    self.log.warning(
                        "benchmarker.agent_underperforming",
                        agent=agent_name,
                        precision=avg_precision,
                        scans=scan_count,
                    )
                    if not dry_run and self.producer:
                        event = AgentRetiredEvent(
                            agent_name=agent_name,
                            reason="poor_precision",
                            final_precision=avg_precision,
                            final_recall=float(row["avg_recall"] or 0.0),
                        )
                        await self.producer.publish("argos.agent.retired", event)
                    retired_agents.append(agent_name)

                elif avg_precision < _PRECISION_WARNING_THRESHOLD:
                    warnings.append(agent_name)
                    self.log.warning(
                        "benchmarker.agent_warning",
                        agent=agent_name,
                        precision=avg_precision,
                        scans=scan_count,
                    )

            # ── 4. Write benchmarker's own performance snapshot ───────────
            if not dry_run:
                try:
                    await conn.execute(
                        _SQL_WRITE_SNAPSHOT,
                        self.name,
                        str(uuid.uuid4()),
                        1.0,   # benchmarker itself: precision = 1 (meta-agent)
                        1.0,   # recall = 1
                        0.0,   # FPR = 0
                        len(agent_stats),  # findings_count = agents evaluated
                        int((time.monotonic() - t0) * 1000),
                        False,  # supervised
                        True,   # promoted
                    )
                except Exception as exc:  # noqa: BLE001
                    self.log.warning("benchmarker.snapshot_write_failed", error=str(exc))

        except Exception as exc:  # noqa: BLE001
            self.log.exception("benchmarker.cycle_error", error=str(exc))
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
            "benchmarker.cycle_complete",
            agents_evaluated=len(agent_stats),
            retired=len(retired_agents),
            warnings=len(warnings),
            tokens=self._total_tokens,
        )

        findings = [
            {
                "finding_id": str(uuid.uuid4())[:16],
                "severity": "High",
                "description": f"Benchmarker: agent '{a}' retired due to poor precision",
                "agent": a,
            }
            for a in retired_agents
        ]

        return AgentResult(
            agent=self.name,
            success=True,
            findings=findings,
            metadata={
                "agents_evaluated": len(agent_stats),
                "retired_agents": retired_agents,
                "warning_agents": warnings,
                "improvement_suggestions": improvement_suggestions,
            },
            duration_ms=int((time.monotonic() - t0) * 1000),
            tokens_used=self._total_tokens,
        )

    # -----------------------------------------------------------------------
    # Claude trend analysis
    # -----------------------------------------------------------------------

    async def _analyse_with_claude(
        self,
        agent_stats: list[dict[str, Any]],
        agent_trends: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Use Claude (adaptive thinking) to analyse agent performance trends and
        generate actionable improvement suggestions.

        Returns a list of {agent_name, suggestion, priority} dicts.
        """
        system = (
            "You are Benchmarker, a meta-evaluator agent for the ARGOS security platform. "
            "You receive performance metrics for all active vulnerability scanning agents "
            "and must identify trends, root causes of poor performance, and specific "
            "actionable improvements. Return ONLY valid JSON."
        )

        payload = {
            "agent_statistics_30d": [
                {k: float(v) if hasattr(v, "__float__") else v for k, v in row.items()}
                for row in agent_stats[:20]
            ],
            "daily_trends_14d_sample": [
                {k: str(v) if not isinstance(v, (int, float, str, bool, type(None))) else v
                 for k, v in row.items()}
                for row in agent_trends[:60]
            ],
        }

        prompt = (
            "Analyse the agent performance data below and return improvement suggestions.\n\n"
            f"```json\n{json.dumps(payload, default=str, indent=2)}\n```\n\n"
            "Return a JSON array where each element has this shape:\n"
            "{\n"
            '  "agent_name": "<agent>",\n'
            '  "issue": "<brief description of the performance issue>",\n'
            '  "suggestion": "<specific actionable improvement>",\n'
            '  "priority": "high|medium|low"\n'
            "}\n"
            "Focus on agents with worsening trends or consistently poor metrics. "
            "Limit to the 10 most actionable suggestions."
        )

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=3072,
            )
            result = _parse_json_response(raw)
            if isinstance(result, list):
                return result
            return []
        except Exception as exc:  # noqa: BLE001
            self.log.warning("benchmarker.claude_analysis_failed", error=str(exc))
            return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_json_response(text: str, fallback: Any = None) -> Any:
    """Extract and parse the first JSON value from a Claude text response."""
    import re
    text = text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
        if match:
            text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("benchmarker.json_parse_failed", snippet=text[:200])
        return fallback if fallback is not None else []
