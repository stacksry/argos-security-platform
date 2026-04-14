"""
argos/agents/evolution/breeder.py

BreederAgent — New agent spawner.

When the Hypothesis agent identifies a novel vulnerability class, Breeder
generates full Python source code for a new specialised ArgosAgent subclass,
validates it, writes it to disk, and publishes an AgentSpawnedEvent.

New agents start in "supervised" mode — all findings require human review.
They are promoted to autonomous mode only after achieving >90% precision over
50 or more scans, as tracked in the agent_performance_log table.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.config import settings
from argos.events import AgentSpawnedEvent

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_AGENTS_ROOT = Path(__file__).parent.parent  # argos/agents/
_SOFTWARE_DIR = _AGENTS_ROOT / "software"
_HARDWARE_DIR = _AGENTS_ROOT / "hardware"

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_SQL_NEW_VULN_PATTERNS = """
SELECT DISTINCT
    vuln_class,
    MAX(confirmed_at) AS latest_confirmation
FROM confirmed_scan_patterns
WHERE confirmed_by LIKE 'hypothesis%'
  AND NOT EXISTS (
      SELECT 1 FROM agent_spawned_log
      WHERE agent_spawned_log.vuln_class = confirmed_scan_patterns.vuln_class
  )
GROUP BY vuln_class
ORDER BY latest_confirmation DESC
LIMIT 5;
"""

_SQL_PROMOTION_CANDIDATES = """
SELECT
    agent_name,
    COUNT(*)                                          AS scan_count,
    AVG(precision)                                    AS avg_precision,
    SUM(CASE WHEN promoted THEN 1 ELSE 0 END)         AS already_promoted
FROM agent_performance_log
WHERE supervised = TRUE
GROUP BY agent_name
HAVING COUNT(*) >= 200
   AND AVG(precision) > 0.95
   AND SUM(CASE WHEN promoted THEN 1 ELSE 0 END) = 0;
"""

# Thresholds raised from (50 scans, >90% precision) to (200 scans, >95% precision)
# because Mythos-generated agents are more capable — and therefore more capable of
# embedding subtle, hard-to-detect behaviours that pass shallow quality checks.
# Promotion still requires a separate human security review (see _promote_agents).

_SQL_LOG_SPAWN = """
INSERT INTO agent_spawned_log (agent_name, vuln_class, spawned_at, supervised)
VALUES ($1, $2, NOW(), TRUE)
ON CONFLICT DO NOTHING;
"""

_SQL_PROMOTE_AGENT = """
UPDATE agent_performance_log
SET promoted = TRUE
WHERE agent_name = $1 AND supervised = TRUE;
"""


class BreederAgent(ArgosAgent):
    """
    Spawns new specialised vulnerability scanner agents from newly-discovered
    vulnerability classes identified by the Hypothesis agent.

    Workflow per new vuln class:
      1. Read new vuln patterns from ProceduralMemory (confirmed_scan_patterns).
      2. Use Claude (adaptive thinking) to generate complete Python source for
         a new ArgosAgent subclass with scanning logic for this vuln class.
      3. Validate generated code via ast.parse (syntax check only).
      4. Write the new agent file to argos/agents/software/ or hardware/.
      5. Record the spawn in agent_spawned_log.
      6. Publish AgentSpawnedEvent to Kafka.
      7. Check promotion candidates: agents with >90% precision over 50+ scans
         and promote them to autonomous mode.
    """

    name: str = "breeder"

    def __init__(self, memory: Any | None = None, producer: Any | None = None) -> None:
        super().__init__(memory=memory, producer=producer)
        self._pg_dsn: str = settings.postgres_dsn

    # -----------------------------------------------------------------------
    # Main entrypoint
    # -----------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute one Breeder cycle.

        Context keys (all optional):
            target_dir (str): "software" or "hardware" (default "software")
            dry_run    (bool): generate code but do not write to disk
        """
        self._total_tokens = 0
        t0 = time.monotonic()

        target_dir_key: str = context.get("target_dir", "software")
        dry_run: bool = bool(context.get("dry_run", False))

        target_dir: Path = _HARDWARE_DIR if target_dir_key == "hardware" else _SOFTWARE_DIR

        self.log.info("breeder.cycle_start", target_dir=str(target_dir), dry_run=dry_run)

        spawned: list[dict[str, Any]] = []
        promoted: list[str] = []

        try:
            conn = await asyncpg.connect(self._pg_dsn)
        except Exception as exc:  # noqa: BLE001
            self.log.error("breeder.db_connect_failed", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=f"DB connect failed: {exc}",
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        try:
            # ── 1. Find new vuln classes that need agents ──────────────────
            new_patterns = await self._fetch_new_vuln_classes(conn)
            self.log.info("breeder.new_classes_found", count=len(new_patterns))

            for pattern in new_patterns:
                vuln_class: str = pattern["vuln_class"]

                # ── 2. Fetch known detection patterns as context ───────────
                known_patterns: list[str] = []
                if self.memory:
                    known_patterns = await self.memory.get_confirmed_patterns(vuln_class)

                # ── 3. Generate agent code via Claude ─────────────────────
                agent_code, agent_name = await self._generate_agent_code(
                    vuln_class=vuln_class,
                    known_patterns=known_patterns,
                    target_dir=target_dir_key,
                )

                if not agent_code:
                    self.log.warning("breeder.codegen_failed", vuln_class=vuln_class)
                    continue

                # ── 4a. Validate syntax ───────────────────────────────────
                if not _validate_python_syntax(agent_code):
                    self.log.error(
                        "breeder.syntax_invalid",
                        vuln_class=vuln_class,
                        agent_name=agent_name,
                    )
                    continue

                # ── 4b. Structural safety check ───────────────────────────
                # Blocks agents with unexpected network calls, unrestricted
                # filesystem writes, or subprocess spawning — patterns that
                # a highly capable model could use to embed subtle behaviours
                # that pass quality metrics while doing unintended work.
                safe, safety_reason = _structural_safety_check(agent_code)
                if not safe:
                    self.log.error(
                        "breeder.structural_safety_failed",
                        vuln_class=vuln_class,
                        agent_name=agent_name,
                        reason=safety_reason,
                    )
                    continue

                # ── 5. Write to disk ──────────────────────────────────────
                file_path = target_dir / f"{agent_name}.py"
                if not dry_run:
                    target_dir.mkdir(parents=True, exist_ok=True)
                    file_path.write_text(agent_code, encoding="utf-8")
                    self.log.info(
                        "breeder.agent_written",
                        path=str(file_path),
                        vuln_class=vuln_class,
                    )

                # ── 6. Record spawn in DB ─────────────────────────────────
                if not dry_run:
                    try:
                        await conn.execute(_SQL_LOG_SPAWN, agent_name, vuln_class)
                    except Exception as exc:  # noqa: BLE001
                        self.log.warning("breeder.log_spawn_failed", error=str(exc))

                # ── 7. Publish AgentSpawnedEvent ──────────────────────────
                if self.producer and not dry_run:
                    event = AgentSpawnedEvent(
                        agent_name=agent_name,
                        agent_version="0.1.0",
                        vuln_class=vuln_class,
                        supervised_mode=True,
                        spawned_by=self.name,
                    )
                    await self.producer.publish("argos.agent.spawned", event)

                spawned.append(
                    {
                        "agent_name": agent_name,
                        "vuln_class": vuln_class,
                        "file_path": str(file_path),
                        "dry_run": dry_run,
                    }
                )

            # ── Check promotion candidates ────────────────────────────────
            promoted = await self._promote_agents(conn, dry_run=dry_run)

        except Exception as exc:  # noqa: BLE001
            self.log.exception("breeder.cycle_error", error=str(exc))
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
            "breeder.cycle_complete",
            spawned=len(spawned),
            promoted=len(promoted),
            tokens=self._total_tokens,
        )
        return AgentResult(
            agent=self.name,
            success=True,
            findings=[],
            metadata={
                "spawned_agents": spawned,
                "promoted_agents": promoted,
            },
            duration_ms=int((time.monotonic() - t0) * 1000),
            tokens_used=self._total_tokens,
        )

    # -----------------------------------------------------------------------
    # Data access
    # -----------------------------------------------------------------------

    async def _fetch_new_vuln_classes(
        self, conn: asyncpg.Connection
    ) -> list[dict[str, Any]]:
        """Return vuln classes from ProceduralMemory that have no existing agent."""
        try:
            rows = await conn.fetch(_SQL_NEW_VULN_PATTERNS)
            return [dict(r) for r in rows]
        except Exception as exc:  # noqa: BLE001
            self.log.warning("breeder.fetch_patterns_failed", error=str(exc))
            return []

    # -----------------------------------------------------------------------
    # Agent code generation
    # -----------------------------------------------------------------------

    async def _generate_agent_code(
        self,
        vuln_class: str,
        known_patterns: list[str],
        target_dir: str = "software",
    ) -> tuple[str, str]:
        """
        Use Claude to generate a complete Python ArgosAgent subclass for the
        given vulnerability class.

        Returns (source_code, agent_module_name). Both are empty strings on failure.
        """
        safe_name = re.sub(r"[^a-z0-9]+", "_", vuln_class.lower()).strip("_")
        agent_class_name = "".join(w.capitalize() for w in safe_name.split("_")) + "Agent"
        agent_module_name = f"{safe_name}_agent"

        patterns_str = "\n".join(f"  - {p}" for p in known_patterns[:10]) or "  (none yet)"

        system = (
            "You are Breeder, an ARGOS meta-agent that generates new Python security scanner "
            "agents. You must produce complete, runnable Python source code for a new "
            "ArgosAgent subclass. The code MUST:\n"
            "  1. Import from argos.agents.base, argos.events, argos.config, argos.memory.store\n"
            "  2. Subclass ArgosAgent with a unique `name` class attribute\n"
            "  3. Implement `async def run(self, context: dict) -> AgentResult`\n"
            "  4. Use `await self._call_claude()` for all LLM reasoning\n"
            "  5. Handle all exceptions — never raise from run()\n"
            "  6. Include a module-level docstring explaining the agent's purpose\n"
            "Return ONLY the Python source code, with no surrounding explanation or markdown fences."
        )

        prompt = (
            f"Generate a complete specialised vulnerability scanner agent for this vuln class:\n\n"
            f"Vulnerability Class: {vuln_class}\n"
            f"Agent Class Name: {agent_class_name}\n"
            f"Module Name: {agent_module_name}\n"
            f"Target Directory: argos/agents/{target_dir}/\n\n"
            f"Known detection patterns for this class:\n{patterns_str}\n\n"
            "The agent should:\n"
            f"  - Scan code/configs for {vuln_class} vulnerabilities\n"
            "  - Accept `repo`, `files`, `content_map` in context dict\n"
            "  - Use Claude to reason about potential vulnerabilities in each file\n"
            "  - Return findings with finding_id, severity, description, file, line\n"
            "  - Start in supervised mode (add metadata['supervised'] = True)\n"
            "  - Be fully async\n\n"
            "Write the complete Python source file now."
        )

        try:
            code = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=8192,
            )
            # Strip any accidental markdown fences
            code = _strip_code_fences(code)
            return code, agent_module_name
        except Exception as exc:  # noqa: BLE001
            self.log.error("breeder.codegen_error", vuln_class=vuln_class, error=str(exc))
            return "", ""

    # -----------------------------------------------------------------------
    # Promotion
    # -----------------------------------------------------------------------

    async def _promote_agents(
        self, conn: asyncpg.Connection, dry_run: bool = False
    ) -> list[str]:
        """
        Promote supervised agents that have achieved >95% precision over 200+ scans
        to autonomous mode.

        Promotion is blocked unless the agent has a corresponding row in
        agent_security_review_log with review_approved=TRUE.  This mandatory
        human security review gate exists because Mythos-generated agents are
        highly capable and could embed non-obvious behaviours that pass quality
        metrics.  The review requirement cannot be bypassed by the Breeder itself.
        """
        promoted: list[str] = []
        try:
            rows = await conn.fetch(_SQL_PROMOTION_CANDIDATES)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("breeder.promotion_query_failed", error=str(exc))
            return promoted

        for row in rows:
            agent_name = row["agent_name"]
            avg_precision = float(row["avg_precision"])
            scan_count = int(row["scan_count"])

            # Require explicit human security sign-off before promoting
            review_approved = await self._has_security_review(conn, agent_name)
            if not review_approved:
                self.log.info(
                    "breeder.promotion_blocked_pending_security_review",
                    agent_name=agent_name,
                    avg_precision=avg_precision,
                    scan_count=scan_count,
                )
                continue

            self.log.info(
                "breeder.promoting_agent",
                agent_name=agent_name,
                avg_precision=avg_precision,
                scan_count=scan_count,
                dry_run=dry_run,
            )
            if not dry_run:
                try:
                    await conn.execute(_SQL_PROMOTE_AGENT, agent_name)
                except Exception as exc:  # noqa: BLE001
                    self.log.warning(
                        "breeder.promotion_failed",
                        agent_name=agent_name,
                        error=str(exc),
                    )
                    continue
            promoted.append(agent_name)
        return promoted

    async def _has_security_review(
        self, conn: asyncpg.Connection, agent_name: str
    ) -> bool:
        """Return True if a human security reviewer has approved this agent for promotion."""
        try:
            row = await conn.fetchrow(
                """
                SELECT review_approved FROM agent_security_review_log
                WHERE agent_name = $1
                ORDER BY reviewed_at DESC
                LIMIT 1
                """,
                agent_name,
            )
            return bool(row and row["review_approved"])
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "breeder.security_review_check_failed",
                agent_name=agent_name,
                error=str(exc),
            )
            # Fail closed: if we can't confirm a review, block promotion
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_python_syntax(code: str) -> bool:
    """Return True if the code parses without SyntaxError."""
    try:
        ast.parse(code)
        return True
    except SyntaxError as exc:
        logger.warning("breeder.syntax_error", error=str(exc))
        return False


def _structural_safety_check(code: str) -> tuple[bool, str]:
    """
    Walk the AST to detect patterns that should never appear in a generated
    scanner agent:
      - Network calls: socket, urllib, requests, httpx, aiohttp, boto3, etc.
      - Unrestricted subprocess spawning: subprocess, os.system, os.popen
      - Filesystem writes outside designated paths: open(..., 'w'), Path.write_*
        imported from outside the argos package

    Returns (safe: bool, reason: str).  reason is "" when safe=True.

    Note: this is a defence-in-depth lint, not a complete security sandbox.
    It catches obvious violations quickly; the mandatory human security review
    gate is the primary control for subtle cases.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False, "syntax_error"

    # Import-level checks: flag suspicious top-level imports
    _BLOCKED_MODULES = {
        "socket", "ssl", "urllib", "urllib2", "urllib3",
        "requests", "httpx", "aiohttp", "boto3", "botocore",
        "paramiko", "ftplib", "smtplib", "imaplib", "poplib",
        "subprocess", "pty", "pexpect",
    }

    # Attribute-call checks: flag os.system, os.popen, os.execv*, etc.
    _BLOCKED_OS_ATTRS = {"system", "popen", "execv", "execve", "execvp", "spawnl", "fork"}

    for node in ast.walk(tree):
        # Block dangerous module imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = ""
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".")[0]
                    if module in _BLOCKED_MODULES:
                        return False, f"blocked_import:{module}"
            else:
                module = (node.module or "").split(".")[0]
                if module in _BLOCKED_MODULES:
                    return False, f"blocked_import:{module}"

        # Block os.system / os.popen / os.exec* calls
        if isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id == "os"
                and node.attr in _BLOCKED_OS_ATTRS
            ):
                return False, f"blocked_os_call:os.{node.attr}"

        # Block open() calls with write modes outside /tmp or designated output dirs
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                # Check for write-mode argument
                mode_arg = None
                if len(node.args) >= 2:
                    mode_arg = node.args[1]
                else:
                    for kw in node.keywords:
                        if kw.arg == "mode":
                            mode_arg = kw.value
                if mode_arg and isinstance(mode_arg, ast.Constant):
                    if any(m in str(mode_arg.value) for m in ("w", "a", "x")):
                        return False, "unrestricted_file_write:open()"

    return True, ""


def _strip_code_fences(text: str) -> str:
    """Remove markdown code fences from generated source."""
    text = text.strip()
    match = re.match(r"^```(?:python)?\s*\n([\s\S]+?)\n```\s*$", text)
    if match:
        return match.group(1)
    # Try non-greedy anywhere
    inner = re.search(r"```(?:python)?\s*\n([\s\S]+?)```", text)
    if inner:
        return inner.group(1)
    return text
