"""
argos/memory/episodic.py

TimescaleDB (PostgreSQL + timescaledb extension) episodic memory for ARGOS.

Stores scan history, per-metric time-series data, and finding lifecycle events.
All hypertables are partitioned on ``time`` for efficient range queries.

Schema
------
  scans              – one row per scan invocation
  findings_timeline  – one row per finding status change
  agent_metrics      – free-form numeric metrics per agent / repo
"""

from __future__ import annotations

from typing import Any

import asyncpg
import structlog

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    time          TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    repo          TEXT           NOT NULL,
    scan_id       TEXT           NOT NULL,
    agent         TEXT           NOT NULL,
    findings_count INT           NOT NULL DEFAULT 0,
    duration_ms   INT            NOT NULL DEFAULT 0,
    trigger       TEXT           NOT NULL DEFAULT 'manual'
);
"""

_DDL_SCANS_HT = """
SELECT create_hypertable('scans', 'time', if_not_exists => TRUE);
"""

_DDL_FINDINGS_TIMELINE = """
CREATE TABLE IF NOT EXISTS findings_timeline (
    time        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    repo        TEXT         NOT NULL,
    finding_id  TEXT         NOT NULL,
    vuln_class  TEXT         NOT NULL,
    severity    TEXT         NOT NULL,
    status      TEXT         NOT NULL,
    agent       TEXT         NOT NULL
);
"""

_DDL_FINDINGS_TIMELINE_HT = """
SELECT create_hypertable('findings_timeline', 'time', if_not_exists => TRUE);
"""

_DDL_AGENT_METRICS = """
CREATE TABLE IF NOT EXISTS agent_metrics (
    time        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    agent       TEXT         NOT NULL,
    metric_name TEXT         NOT NULL,
    value       FLOAT        NOT NULL,
    repo        TEXT         NOT NULL DEFAULT ''
);
"""

_DDL_AGENT_METRICS_HT = """
SELECT create_hypertable('agent_metrics', 'time', if_not_exists => TRUE);
"""

# ---------------------------------------------------------------------------
# EpisodicMemory
# ---------------------------------------------------------------------------


class EpisodicMemory:
    """
    Async TimescaleDB adapter for scan history and agent performance metrics.

    Parameters
    ----------
    dsn:
        asyncpg DSN string, e.g.
        ``postgresql://argos:secret@localhost:5432/argos``.
    """

    def __init__(self, dsn: str = "postgresql://argos:argos@localhost:5432/argos") -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Create the asyncpg connection pool."""
        self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=10)
        logger.info("episodic.connected", dsn=self._dsn)

    async def close(self) -> None:
        """Drain and close the connection pool."""
        if self._pool:
            await self._pool.close()
            logger.info("episodic.disconnected")

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("EpisodicMemory not connected — call connect() first.")
        return self._pool

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    async def init_schema(self) -> None:
        """
        Create tables and hypertables if they do not already exist.

        Requires the TimescaleDB extension to be installed in the target
        PostgreSQL instance. The ``create_hypertable`` call is idempotent via
        ``if_not_exists => TRUE``.
        """
        async with self.pool.acquire() as conn:
            # Scans
            await conn.execute(_DDL_SCANS)
            await conn.execute(_DDL_SCANS_HT)

            # Findings timeline
            await conn.execute(_DDL_FINDINGS_TIMELINE)
            await conn.execute(_DDL_FINDINGS_TIMELINE_HT)

            # Agent metrics
            await conn.execute(_DDL_AGENT_METRICS)
            await conn.execute(_DDL_AGENT_METRICS_HT)

        logger.info("episodic.schema_initialized")

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    async def record_scan(
        self,
        repo: str,
        scan_id: str,
        agent: str,
        findings: int,
        duration_ms: int,
        trigger: str = "manual",
    ) -> None:
        """
        Append a scan event to the ``scans`` hypertable.

        Parameters
        ----------
        repo:
            Repository name, e.g. ``acme/payments-service``.
        scan_id:
            Unique scan run identifier (UUID or job ID).
        agent:
            Agent that ran the scan, e.g. ``sast_agent``.
        findings:
            Number of findings emitted by this scan.
        duration_ms:
            Wall-clock duration of the scan in milliseconds.
        trigger:
            What initiated the scan: ``manual``, ``push``, ``schedule``,
            ``pr``, etc.
        """
        sql = """
        INSERT INTO scans (time, repo, scan_id, agent, findings_count, duration_ms, trigger)
        VALUES (NOW(), $1, $2, $3, $4, $5, $6)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, repo, scan_id, agent, findings, duration_ms, trigger)
        logger.debug(
            "episodic.scan_recorded",
            repo=repo,
            scan_id=scan_id,
            agent=agent,
            findings=findings,
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    async def record_metric(
        self,
        repo: str,
        metric_name: str,
        value: float,
        agent: str = "",
    ) -> None:
        """
        Record an arbitrary numeric metric for a repo/agent pair.

        Parameters
        ----------
        repo:
            Repository name.
        metric_name:
            Metric key, e.g. ``false_positive_rate``, ``lines_scanned``.
        value:
            Numeric value.
        agent:
            Originating agent (optional).
        """
        sql = """
        INSERT INTO agent_metrics (time, agent, metric_name, value, repo)
        VALUES (NOW(), $1, $2, $3, $4)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, agent, metric_name, value, repo)
        logger.debug(
            "episodic.metric_recorded",
            repo=repo,
            metric_name=metric_name,
            value=value,
        )

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------

    async def get_vulnerability_trend(
        self,
        repo: str,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Return daily findings counts for a repo over the last *days* days.

        Returns
        -------
        list[dict]
            Sorted ascending by day. Each entry:
            ``{"day": date, "findings": int, "agent": str}``.
        """
        sql = """
        SELECT
            time_bucket('1 day', time) AS day,
            agent,
            SUM(findings_count)        AS findings
        FROM scans
        WHERE repo = $1
          AND time >= NOW() - ($2 || ' days')::INTERVAL
        GROUP BY day, agent
        ORDER BY day ASC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, repo, str(days))

        trend = [dict(row) for row in rows]
        logger.debug(
            "episodic.vulnerability_trend",
            repo=repo,
            days=days,
            data_points=len(trend),
        )
        return trend

    # ------------------------------------------------------------------
    # Mean time to fix
    # ------------------------------------------------------------------

    async def get_mean_time_to_fix(self, vuln_class: str) -> float:
        """
        Calculate average days between a finding being opened and resolved
        for a given vulnerability class.

        Returns
        -------
        float
            Mean days to fix. Returns ``-1.0`` if insufficient data.
        """
        sql = """
        WITH opened AS (
            SELECT finding_id, MIN(time) AS opened_at
            FROM findings_timeline
            WHERE vuln_class = $1 AND status = 'open'
            GROUP BY finding_id
        ),
        resolved AS (
            SELECT finding_id, MIN(time) AS resolved_at
            FROM findings_timeline
            WHERE vuln_class = $1 AND status = 'resolved'
            GROUP BY finding_id
        )
        SELECT AVG(
            EXTRACT(EPOCH FROM (r.resolved_at - o.opened_at)) / 86400.0
        ) AS mean_days
        FROM opened o
        JOIN resolved r USING (finding_id)
        WHERE r.resolved_at > o.opened_at
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, vuln_class)

        mean_days: float = float(row["mean_days"]) if row and row["mean_days"] is not None else -1.0
        logger.debug(
            "episodic.mean_time_to_fix",
            vuln_class=vuln_class,
            mean_days=mean_days,
        )
        return mean_days

    # ------------------------------------------------------------------
    # False positive rate
    # ------------------------------------------------------------------

    async def get_false_positive_rate(
        self,
        agent: str,
        days: int = 30,
    ) -> float:
        """
        Compute the false positive rate for an agent over the last *days* days.

        FP rate = FP findings / total findings with a terminal status.

        Returns
        -------
        float
            Value in [0, 1]. Returns ``0.0`` if no data.
        """
        sql = """
        SELECT
            COUNT(*) FILTER (WHERE status = 'false_positive') AS fp_count,
            COUNT(*) FILTER (WHERE status IN ('resolved', 'false_positive', 'confirmed')) AS total_terminal
        FROM findings_timeline
        WHERE agent = $1
          AND time >= NOW() - ($2 || ' days')::INTERVAL
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, agent, str(days))

        if not row or not row["total_terminal"]:
            return 0.0

        rate: float = row["fp_count"] / row["total_terminal"]
        logger.debug(
            "episodic.false_positive_rate",
            agent=agent,
            days=days,
            rate=rate,
            fp_count=row["fp_count"],
            total=row["total_terminal"],
        )
        return rate

    # ------------------------------------------------------------------
    # Agent performance
    # ------------------------------------------------------------------

    async def get_agent_performance(self, agent: str) -> dict[str, Any]:
        """
        Aggregate performance statistics for a given agent.

        Derived from the ``agent_metrics`` hypertable. Assumes individual
        scan runs emit ``precision``, ``recall``, and ``throughput_rps``
        metrics via :meth:`record_metric`.

        Returns
        -------
        dict
            Keys: ``agent``, ``precision_avg``, ``recall_avg``,
            ``throughput_avg``, ``scan_count``, ``total_findings``.
        """
        metrics_sql = """
        SELECT
            metric_name,
            AVG(value) AS avg_value
        FROM agent_metrics
        WHERE agent = $1
          AND metric_name IN ('precision', 'recall', 'throughput_rps')
        GROUP BY metric_name
        """
        scans_sql = """
        SELECT
            COUNT(*)           AS scan_count,
            SUM(findings_count) AS total_findings
        FROM scans
        WHERE agent = $1
        """
        async with self.pool.acquire() as conn:
            metric_rows = await conn.fetch(metrics_sql, agent)
            scan_row = await conn.fetchrow(scans_sql, agent)

        metrics = {row["metric_name"]: row["avg_value"] for row in metric_rows}
        result: dict[str, Any] = {
            "agent": agent,
            "precision_avg": metrics.get("precision", None),
            "recall_avg": metrics.get("recall", None),
            "throughput_avg": metrics.get("throughput_rps", None),
            "scan_count": scan_row["scan_count"] if scan_row else 0,
            "total_findings": scan_row["total_findings"] if scan_row else 0,
        }
        logger.debug("episodic.agent_performance", **result)
        return result

    # ------------------------------------------------------------------
    # Finding lifecycle helper
    # ------------------------------------------------------------------

    async def record_finding_event(
        self,
        repo: str,
        finding_id: str,
        vuln_class: str,
        severity: str,
        status: str,
        agent: str,
    ) -> None:
        """
        Append a finding lifecycle event to the ``findings_timeline`` hypertable.

        Call this whenever a finding transitions state (open → confirmed →
        resolved / false_positive).
        """
        sql = """
        INSERT INTO findings_timeline (time, repo, finding_id, vuln_class, severity, status, agent)
        VALUES (NOW(), $1, $2, $3, $4, $5, $6)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, repo, finding_id, vuln_class, severity, status, agent)
        logger.debug(
            "episodic.finding_event_recorded",
            repo=repo,
            finding_id=finding_id,
            status=status,
        )
