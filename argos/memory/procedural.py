"""
argos/memory/procedural.py

PostgreSQL-backed procedural memory for ARGOS.

Evolved from the Glasswing memory_agent.py — significantly expanded to support
the full ARGOS self-learning loop.

What lives here
---------------
  fix_patterns            – examples of vulnerable code → fix, per language
  false_positive_signals  – signals that a finding is a FP in a given context
  cvss_corrections        – agent-observed discrepancies between computed and
                            validated CVSS scores
  ranker_calibrations     – lessons learned when the file ranker mis-prioritised
  confirmed_scan_patterns – regex / AST patterns confirmed as true positives
  agent_performance_log   – precision / recall snapshots over time

All tables are created with IF NOT EXISTS so init_schema() is idempotent.
All queries are parameterised — no string interpolation of user data.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import asyncpg
import structlog

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
-- Fix patterns: code examples of vulnerable → fixed pairs
CREATE TABLE IF NOT EXISTS fix_patterns (
    id                  SERIAL PRIMARY KEY,
    vuln_class          TEXT    NOT NULL,           -- e.g. 'sql_injection', 'buffer_overflow'
    language            TEXT    NOT NULL,           -- e.g. 'python', 'c', 'javascript'
    file_extension      TEXT    NOT NULL DEFAULT '',
    vulnerable_snippet  TEXT    NOT NULL,
    fix_snippet         TEXT    NOT NULL,
    repo                TEXT    NOT NULL DEFAULT '',
    confirmed_by        TEXT    NOT NULL DEFAULT 'agent',
    confidence          INT     NOT NULL DEFAULT 1, -- incremented on each confirmation
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS fix_patterns_vuln_lang
    ON fix_patterns (vuln_class, language);

CREATE UNIQUE INDEX IF NOT EXISTS fix_patterns_unique
    ON fix_patterns (vuln_class, language, vulnerable_snippet);

-- False positive signals: context clues that make a finding a FP
CREATE TABLE IF NOT EXISTS false_positive_signals (
    id              SERIAL PRIMARY KEY,
    vuln_class      TEXT    NOT NULL,
    file_pattern    TEXT    NOT NULL,   -- glob / regex matching files where this FP occurs
    rejection_reason TEXT   NOT NULL,
    signal          TEXT    NOT NULL,   -- what the agent should look for to suppress
    count           INT     NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS fp_signals_vuln
    ON false_positive_signals (vuln_class);

-- CVSS corrections: observed drift between computed and analyst-validated scores
CREATE TABLE IF NOT EXISTS cvss_corrections (
    id              SERIAL PRIMARY KEY,
    vuln_class      TEXT    NOT NULL,
    original_score  FLOAT   NOT NULL,
    corrected_score FLOAT   NOT NULL,
    reason          TEXT    NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cvss_corrections_vuln
    ON cvss_corrections (vuln_class);

-- Ranker calibrations: lessons from when the file ranker got it wrong
CREATE TABLE IF NOT EXISTS ranker_calibrations (
    id               SERIAL PRIMARY KEY,
    file_path_pattern TEXT   NOT NULL,
    extension        TEXT    NOT NULL DEFAULT '',
    ranked_score     FLOAT   NOT NULL,   -- what the ranker scored the file
    actual_severity  TEXT    NOT NULL,   -- what the human / oracle decided
    lesson           TEXT    NOT NULL,   -- free-text lesson to incorporate
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Confirmed scan patterns: patterns verified as true positives
CREATE TABLE IF NOT EXISTS confirmed_scan_patterns (
    id               SERIAL PRIMARY KEY,
    vuln_class       TEXT    NOT NULL,
    pattern          TEXT    NOT NULL,   -- regex or AST pattern string
    language         TEXT    NOT NULL,
    crash_indicator  BOOLEAN NOT NULL DEFAULT FALSE,
    count            INT     NOT NULL DEFAULT 1,
    confirmed_by     TEXT    NOT NULL DEFAULT 'agent',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS confirmed_patterns_unique
    ON confirmed_scan_patterns (vuln_class, pattern, language);

-- Agent performance log: point-in-time precision/recall snapshots
CREATE TABLE IF NOT EXISTS agent_performance_log (
    id          SERIAL PRIMARY KEY,
    agent_name  TEXT   NOT NULL,
    precision   FLOAT  NOT NULL DEFAULT 0.0,   -- TP / (TP + FP)
    recall      FLOAT  NOT NULL DEFAULT 0.0,   -- TP / (TP + FN)
    fp_rate     FLOAT  NOT NULL DEFAULT 0.0,   -- FP / (FP + TN)
    fn_rate     FLOAT  NOT NULL DEFAULT 0.0,   -- FN / (FN + TP)
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agent_perf_name
    ON agent_performance_log (agent_name, recorded_at DESC);
"""


# ---------------------------------------------------------------------------
# ProceduralMemory
# ---------------------------------------------------------------------------


class ProceduralMemory:
    """
    Async PostgreSQL adapter for ARGOS structured learned knowledge.

    Parameters
    ----------
    dsn:
        asyncpg connection string, e.g.
        ``postgresql://argos:secret@localhost:5432/argos``.
    """

    def __init__(
        self,
        dsn: str = "postgresql://argos:argos@localhost:5432/argos",
    ) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Create the asyncpg connection pool."""
        self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=10)
        logger.info("procedural.connected", dsn=self._dsn)

    async def close(self) -> None:
        """Drain and close the connection pool."""
        if self._pool:
            await self._pool.close()
            logger.info("procedural.disconnected")

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError(
                "ProceduralMemory not connected — call connect() first."
            )
        return self._pool

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    async def init_schema(self) -> None:
        """
        Create all procedural memory tables if they do not already exist.

        Safe to call at every startup — all statements use IF NOT EXISTS.
        """
        async with self.pool.acquire() as conn:
            await conn.execute(_DDL)
        logger.info("procedural.schema_initialized")

    # ==================================================================
    # Fix patterns
    # ==================================================================

    async def record_fix_pattern(
        self,
        vuln_class: str,
        language: str,
        vulnerable: str,
        fix: str,
        repo: str = "",
        file_extension: str = "",
        confirmed_by: str = "agent",
        confidence: int = 1,
    ) -> None:
        """
        Store a vulnerable → fix code pair for a given vulnerability class.

        If an identical (vuln_class, language, vulnerable_snippet) triple
        already exists the confidence counter is incremented and the fix
        snippet is updated in place.

        Parameters
        ----------
        vuln_class:
            Vulnerability category, e.g. ``sql_injection``.
        language:
            Programming language of the snippet.
        vulnerable:
            The insecure code fragment.
        fix:
            The corrected replacement.
        repo:
            Source repository (for provenance).
        file_extension:
            File extension of the source file, e.g. ``py``.
        confirmed_by:
            Who confirmed this fix (agent slug or analyst name).
        confidence:
            Initial confidence weight (1 = one observation).
        """
        sql = """
        INSERT INTO fix_patterns
            (vuln_class, language, file_extension, vulnerable_snippet, fix_snippet, repo, confirmed_by, confidence)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (vuln_class, language, vulnerable_snippet) DO UPDATE
            SET confidence   = fix_patterns.confidence + EXCLUDED.confidence,
                fix_snippet  = EXCLUDED.fix_snippet,
                confirmed_by = EXCLUDED.confirmed_by,
                updated_at   = NOW()
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                sql,
                vuln_class,
                language,
                file_extension,
                vulnerable,
                fix,
                repo,
                confirmed_by,
                confidence,
            )

        logger.debug(
            "procedural.fix_pattern_recorded",
            vuln_class=vuln_class,
            language=language,
        )

    async def get_fix_examples(
        self,
        vuln_class: str,
        language: str,
        limit: int = 3,
    ) -> str:
        """
        Return the top fix examples for a vuln class / language, formatted
        as a prompt-ready string for injection into an LLM context.

        Results are sorted by confidence descending so the most-confirmed
        patterns are shown first.

        Returns
        -------
        str
            Markdown-formatted block, or an empty string if no examples exist.
        """
        sql = """
        SELECT vulnerable_snippet, fix_snippet, confidence, confirmed_by
        FROM fix_patterns
        WHERE vuln_class = $1
          AND language   = $2
        ORDER BY confidence DESC
        LIMIT $3
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, vuln_class, language, limit)

        if not rows:
            logger.debug(
                "procedural.fix_examples_empty",
                vuln_class=vuln_class,
                language=language,
            )
            return ""

        parts: list[str] = [
            f"## Fix Examples for `{vuln_class}` in `{language}`\n"
        ]
        for i, row in enumerate(rows, start=1):
            parts.append(
                f"### Example {i} (confidence={row['confidence']}, "
                f"confirmed_by={row['confirmed_by']})\n"
                f"**Vulnerable:**\n```{language}\n{row['vulnerable_snippet']}\n```\n"
                f"**Fixed:**\n```{language}\n{row['fix_snippet']}\n```\n"
            )

        logger.debug(
            "procedural.fix_examples_fetched",
            vuln_class=vuln_class,
            language=language,
            count=len(rows),
        )
        return "\n".join(parts)

    # ==================================================================
    # False positive signals
    # ==================================================================

    async def record_false_positive(
        self,
        vuln_class: str,
        file_pattern: str,
        reason: str,
        signal: str,
    ) -> None:
        """
        Record a false positive suppression signal.

        If the same (vuln_class, file_pattern, signal) triple is seen again
        its occurrence counter is incremented.

        Parameters
        ----------
        vuln_class:
            Vulnerability class this signal applies to.
        file_pattern:
            Glob or regex matching the files where this FP occurs (e.g.
            ``tests/**``, ``*_mock.py``).
        reason:
            Human-readable explanation.
        signal:
            Machine-readable trigger string (e.g. function name, import, comment).
        """
        sql = """
        INSERT INTO false_positive_signals (vuln_class, file_pattern, rejection_reason, signal, count)
        VALUES ($1, $2, $3, $4, 1)
        ON CONFLICT (vuln_class, file_pattern, signal) DO UPDATE
            SET count      = false_positive_signals.count + 1,
                updated_at = NOW()
        """
        # The ON CONFLICT above requires a unique index; create it if absent.
        ensure_index = """
        CREATE UNIQUE INDEX IF NOT EXISTS fp_signals_unique
            ON false_positive_signals (vuln_class, file_pattern, signal)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(ensure_index)
            await conn.execute(sql, vuln_class, file_pattern, reason, signal)

        logger.debug(
            "procedural.false_positive_recorded",
            vuln_class=vuln_class,
            file_pattern=file_pattern,
        )

    async def get_false_positive_signals(self, vuln_class: str) -> str:
        """
        Return all known FP signals for a vuln class, formatted for LLM injection.

        Returns
        -------
        str
            Markdown list, or empty string if none recorded.
        """
        sql = """
        SELECT file_pattern, rejection_reason, signal, count
        FROM false_positive_signals
        WHERE vuln_class = $1
        ORDER BY count DESC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, vuln_class)

        if not rows:
            return ""

        lines = [f"## False Positive Signals for `{vuln_class}`\n"]
        for row in rows:
            lines.append(
                f"- **Pattern:** `{row['file_pattern']}` | "
                f"**Signal:** `{row['signal']}` | "
                f"**Reason:** {row['rejection_reason']} "
                f"(seen {row['count']}x)"
            )

        logger.debug(
            "procedural.fp_signals_fetched",
            vuln_class=vuln_class,
            count=len(rows),
        )
        return "\n".join(lines)

    # ==================================================================
    # CVSS corrections
    # ==================================================================

    async def record_cvss_correction(
        self,
        vuln_class: str,
        original: float,
        corrected: float,
        reason: str,
    ) -> None:
        """
        Record an observed CVSS score correction for calibration.

        Parameters
        ----------
        vuln_class:
            Vulnerability class the correction applies to.
        original:
            Score initially assigned by the agent or feed.
        corrected:
            Analyst-validated score.
        reason:
            Explanation of the discrepancy.
        """
        sql = """
        INSERT INTO cvss_corrections (vuln_class, original_score, corrected_score, reason)
        VALUES ($1, $2, $3, $4)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, vuln_class, original, corrected, reason)

        logger.debug(
            "procedural.cvss_correction_recorded",
            vuln_class=vuln_class,
            original=original,
            corrected=corrected,
        )

    async def get_cvss_calibrations(self, vuln_class: str) -> str:
        """
        Return CVSS correction history for a vuln class, formatted for LLM injection.

        Includes the average delta so agents can apply a systematic correction
        when assigning scores to new findings.

        Returns
        -------
        str
            Markdown block with calibration data, or empty string if none.
        """
        sql = """
        SELECT
            original_score,
            corrected_score,
            (corrected_score - original_score) AS delta,
            reason,
            created_at
        FROM cvss_corrections
        WHERE vuln_class = $1
        ORDER BY created_at DESC
        LIMIT 20
        """
        avg_sql = """
        SELECT AVG(corrected_score - original_score) AS avg_delta
        FROM cvss_corrections
        WHERE vuln_class = $1
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, vuln_class)
            avg_row = await conn.fetchrow(avg_sql, vuln_class)

        if not rows:
            return ""

        avg_delta = float(avg_row["avg_delta"]) if avg_row and avg_row["avg_delta"] is not None else 0.0
        lines = [
            f"## CVSS Calibrations for `{vuln_class}`",
            f"**Average delta (corrected − original):** {avg_delta:+.2f}\n",
        ]
        for row in rows:
            lines.append(
                f"- original={row['original_score']:.1f} → "
                f"corrected={row['corrected_score']:.1f} "
                f"(Δ{row['delta']:+.1f}): {row['reason']}"
            )

        logger.debug(
            "procedural.cvss_calibrations_fetched",
            vuln_class=vuln_class,
            count=len(rows),
            avg_delta=avg_delta,
        )
        return "\n".join(lines)

    # ==================================================================
    # Ranker calibrations
    # ==================================================================

    async def record_ranker_miss(
        self,
        file_pattern: str,
        extension: str,
        ranked: int,
        actual: str,
        lesson: str,
    ) -> None:
        """
        Record a case where the file ranker assigned the wrong priority.

        Parameters
        ----------
        file_pattern:
            Glob / regex matching the mis-ranked file.
        extension:
            File extension (e.g. ``c``, ``py``).
        ranked:
            Rank score assigned by the ranker (higher = more suspicious).
        actual:
            Actual severity string discovered post-triage.
        lesson:
            Free-text calibration lesson.
        """
        sql = """
        INSERT INTO ranker_calibrations (file_path_pattern, extension, ranked_score, actual_severity, lesson)
        VALUES ($1, $2, $3, $4, $5)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, file_pattern, extension, float(ranked), actual, lesson)

        logger.debug(
            "procedural.ranker_miss_recorded",
            file_pattern=file_pattern,
            extension=extension,
            ranked=ranked,
            actual=actual,
        )

    async def get_ranker_calibrations(self) -> str:
        """
        Return all ranker calibration lessons, formatted for LLM injection.

        Returns
        -------
        str
            Markdown block, or empty string.
        """
        sql = """
        SELECT file_path_pattern, extension, ranked_score, actual_severity, lesson, created_at
        FROM ranker_calibrations
        ORDER BY created_at DESC
        LIMIT 50
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql)

        if not rows:
            return ""

        lines = ["## Ranker Calibration Lessons\n"]
        for row in rows:
            lines.append(
                f"- `{row['file_path_pattern']}` (`.{row['extension']}`): "
                f"ranked={row['ranked_score']:.1f}, actual=`{row['actual_severity']}` — "
                f"{row['lesson']}"
            )

        logger.debug("procedural.ranker_calibrations_fetched", count=len(rows))
        return "\n".join(lines)

    # ==================================================================
    # Confirmed scan patterns
    # ==================================================================

    async def record_confirmed_pattern(
        self,
        vuln_class: str,
        pattern: str,
        language: str,
        confirmed_by: str = "agent",
        crash_indicator: bool = False,
    ) -> None:
        """
        Store or increment a confirmed vulnerability detection pattern.

        If the same (vuln_class, pattern, language) triple already exists
        its count is incremented.

        Parameters
        ----------
        vuln_class:
            Vulnerability class this pattern detects.
        pattern:
            Regex or AST pattern string.
        language:
            Target language.
        confirmed_by:
            Agent or analyst that confirmed the pattern.
        crash_indicator:
            True if this pattern indicates a potential crash / exploitable path.
        """
        sql = """
        INSERT INTO confirmed_scan_patterns
            (vuln_class, pattern, language, confirmed_by, crash_indicator, count)
        VALUES ($1, $2, $3, $4, $5, 1)
        ON CONFLICT (vuln_class, pattern, language) DO UPDATE
            SET count        = confirmed_scan_patterns.count + 1,
                confirmed_by = EXCLUDED.confirmed_by,
                updated_at   = NOW()
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, vuln_class, pattern, language, confirmed_by, crash_indicator)

        logger.debug(
            "procedural.confirmed_pattern_recorded",
            vuln_class=vuln_class,
            language=language,
        )

    async def get_confirmed_patterns(self, vuln_class: str) -> list[str]:
        """
        Return all confirmed pattern strings for a vuln class, sorted by
        confirmation count descending.

        Returns
        -------
        list[str]
            Pattern strings only (no metadata).
        """
        sql = """
        SELECT pattern
        FROM confirmed_scan_patterns
        WHERE vuln_class = $1
        ORDER BY count DESC
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, vuln_class)

        patterns = [row["pattern"] for row in rows]
        logger.debug(
            "procedural.confirmed_patterns_fetched",
            vuln_class=vuln_class,
            count=len(patterns),
        )
        return patterns

    # ==================================================================
    # Agent performance log
    # ==================================================================

    async def record_agent_performance(
        self,
        agent_name: str,
        precision: float,
        recall: float,
        fp_rate: float,
        fn_rate: float,
    ) -> None:
        """
        Append a point-in-time performance snapshot for an agent.

        Parameters
        ----------
        agent_name:
            Agent identifier slug.
        precision:
            TP / (TP + FP).
        recall:
            TP / (TP + FN).
        fp_rate:
            FP / (FP + TN).
        fn_rate:
            FN / (FN + TP).
        """
        sql = """
        INSERT INTO agent_performance_log
            (agent_name, precision, recall, fp_rate, fn_rate)
        VALUES ($1, $2, $3, $4, $5)
        """
        async with self.pool.acquire() as conn:
            await conn.execute(sql, agent_name, precision, recall, fp_rate, fn_rate)

        logger.debug(
            "procedural.agent_performance_recorded",
            agent=agent_name,
            precision=precision,
            recall=recall,
        )

    # ==================================================================
    # Stats / introspection
    # ==================================================================

    async def memory_stats(self) -> dict[str, Any]:
        """
        Return row counts for every procedural memory table.

        Useful for health checks and dashboards.

        Returns
        -------
        dict
            Keys match table names; values are integer row counts.
        """
        tables = [
            "fix_patterns",
            "false_positive_signals",
            "cvss_corrections",
            "ranker_calibrations",
            "confirmed_scan_patterns",
            "agent_performance_log",
        ]
        stats: dict[str, Any] = {}
        async with self.pool.acquire() as conn:
            for table in tables:
                row = await conn.fetchrow(f"SELECT COUNT(*) AS n FROM {table}")  # noqa: S608
                stats[table] = row["n"] if row else 0

        logger.debug("procedural.memory_stats", **stats)
        return stats
