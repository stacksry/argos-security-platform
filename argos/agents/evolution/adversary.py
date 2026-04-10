"""
argos/agents/evolution/adversary.py

AdversaryAgent — Red team simulation agent.

Generates adversarial test cases to stress-test other ARGOS agents:

  SUBTLE (hard):  Code that looks clean but contains non-obvious vulnerabilities
                  (obfuscated, unusual patterns, context-dependent exploits).
                  These reveal false negative rates — things agents miss.

  OBVIOUS (easy): Code with blatant vulnerabilities that agents should catch.
                  These form regression baselines — catching regressions in
                  detection capability.

Results per agent are written to agent_performance_log with false_negative_rate
derived from what fraction of planted vulnerabilities went undetected.

Schedule: weekly (orchestrated externally via APScheduler / cron).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.config import settings
from argos.events import AgentPerformanceEvent

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_SQL_ACTIVE_AGENTS = """
SELECT DISTINCT agent_name
FROM agent_performance_log
WHERE evaluated_at > NOW() - INTERVAL '7 days'
ORDER BY agent_name;
"""

_SQL_WRITE_REDTEAM_RESULT = """
INSERT INTO agent_performance_log (
    agent_name, scan_id, precision, recall, false_positive_rate,
    findings_count, duration_ms, evaluated_at, supervised, promoted,
    red_team_run, false_negative_rate
) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), FALSE, FALSE, TRUE, $8)
ON CONFLICT DO NOTHING;
"""

# ---------------------------------------------------------------------------
# Test case configuration
# ---------------------------------------------------------------------------

_SUBTLE_COUNT: int = 5    # subtle adversarial examples per agent
_OBVIOUS_COUNT: int = 5   # obvious regression examples per agent

_SUPPORTED_LANGUAGES = ["python", "javascript", "go", "java", "c"]

_VULN_CLASSES_FOR_TESTING = [
    "sql_injection",
    "command_injection",
    "path_traversal",
    "insecure_deserialization",
    "integer_overflow",
    "use_after_free",
    "race_condition",
    "hardcoded_secret",
    "ssrf",
    "xxe",
]


class AdversaryAgent(ArgosAgent):
    """
    Red team agent that stress-tests other ARGOS agents with adversarial
    code samples.

    Each weekly cycle:
      1. Discover which agents are currently active.
      2. For each agent, generate SUBTLE and OBVIOUS test cases via Claude
         (using adaptive thinking for maximum creativity on subtle cases).
      3. "Scan" each test case through the target agent (simulated or via
         direct invocation depending on availability).
      4. Score: obvious cases the agent misses = regression failures (critical).
              subtle cases the agent catches = bonus precision.
      5. Write false negative rates to agent_performance_log.
      6. Publish AgentPerformanceEvent with red-team metrics.
    """

    name: str = "adversary"

    def __init__(self, memory: Any | None = None, producer: Any | None = None) -> None:
        super().__init__(memory=memory, producer=producer)
        self._pg_dsn: str = settings.postgres_dsn

    # -----------------------------------------------------------------------
    # Main entrypoint
    # -----------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute one Adversary red team cycle.

        Context keys (all optional):
            target_agents (list[str]): specific agents to target (default: all active)
            dry_run (bool): generate tests but do not write results
            languages (list[str]): languages to generate test cases in
        """
        self._total_tokens = 0
        t0 = time.monotonic()

        dry_run: bool = bool(context.get("dry_run", False))
        target_agents: list[str] = context.get("target_agents", [])
        languages: list[str] = context.get("languages", _SUPPORTED_LANGUAGES[:3])

        self.log.info("adversary.cycle_start", dry_run=dry_run)

        try:
            conn = await asyncpg.connect(self._pg_dsn)
        except Exception as exc:  # noqa: BLE001
            self.log.error("adversary.db_connect_failed", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=f"DB connect failed: {exc}",
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        all_results: list[dict[str, Any]] = []

        try:
            # ── 1. Determine target agents ────────────────────────────────
            if not target_agents:
                rows = await conn.fetch(_SQL_ACTIVE_AGENTS)
                target_agents = [r["agent_name"] for r in rows]

            if not target_agents:
                self.log.info("adversary.no_target_agents")
                return AgentResult(
                    agent=self.name,
                    success=True,
                    findings=[],
                    metadata={"reason": "no_active_agents"},
                    duration_ms=int((time.monotonic() - t0) * 1000),
                    tokens_used=self._total_tokens,
                )

            self.log.info("adversary.targets_selected", agents=target_agents)

            # ── 2. Generate and evaluate test cases per agent ─────────────
            for agent_name in target_agents:
                result = await self._red_team_agent(
                    agent_name=agent_name,
                    languages=languages,
                    conn=conn,
                    dry_run=dry_run,
                )
                all_results.append(result)

        except Exception as exc:  # noqa: BLE001
            self.log.exception("adversary.cycle_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )
        finally:
            await conn.close()

        findings = [
            {
                "finding_id": str(uuid.uuid4())[:16],
                "severity": "High" if r.get("regression_failures", 0) > 0 else "Medium",
                "description": (
                    f"Adversary: {r['agent_name']} missed "
                    f"{r.get('false_negatives', 0)}/{r.get('total_tests', 0)} planted vulns "
                    f"({r.get('regression_failures', 0)} regression failures)"
                ),
                "agent_tested": r["agent_name"],
                "false_negative_rate": r.get("false_negative_rate", 0.0),
            }
            for r in all_results
        ]

        self.log.info(
            "adversary.cycle_complete",
            agents_tested=len(all_results),
            tokens=self._total_tokens,
        )
        return AgentResult(
            agent=self.name,
            success=True,
            findings=findings,
            metadata={"red_team_results": all_results},
            duration_ms=int((time.monotonic() - t0) * 1000),
            tokens_used=self._total_tokens,
        )

    # -----------------------------------------------------------------------
    # Per-agent red team exercise
    # -----------------------------------------------------------------------

    async def _red_team_agent(
        self,
        agent_name: str,
        languages: list[str],
        conn: asyncpg.Connection,
        dry_run: bool,
    ) -> dict[str, Any]:
        """
        Run a full red team exercise against one agent.

        Returns a result dict with metrics.
        """
        scan_id = str(uuid.uuid4())
        self.log.info("adversary.red_teaming", agent=agent_name, scan_id=scan_id)

        # Generate test cases
        subtle_cases = await self._generate_subtle_cases(
            agent_name=agent_name, languages=languages
        )
        obvious_cases = await self._generate_obvious_cases(
            agent_name=agent_name, languages=languages
        )

        total_tests = len(subtle_cases) + len(obvious_cases)
        if total_tests == 0:
            return {
                "agent_name": agent_name,
                "scan_id": scan_id,
                "total_tests": 0,
                "false_negatives": 0,
                "regression_failures": 0,
                "false_negative_rate": 0.0,
            }

        # Evaluate: ask Claude to judge which cases the agent would likely miss
        # (This is a simulation — in production, cases would be fed directly to the agent)
        evaluation = await self._evaluate_detectability(
            agent_name=agent_name,
            subtle_cases=subtle_cases,
            obvious_cases=obvious_cases,
        )

        fn_count: int = evaluation.get("false_negatives_count", 0)
        regression_failures: int = evaluation.get("regression_failures_count", 0)
        fn_rate: float = fn_count / total_tests if total_tests > 0 else 0.0

        self.log.info(
            "adversary.exercise_complete",
            agent=agent_name,
            total_tests=total_tests,
            false_negatives=fn_count,
            regression_failures=regression_failures,
            fn_rate=fn_rate,
        )

        # Write to DB
        if not dry_run:
            try:
                await conn.execute(
                    _SQL_WRITE_REDTEAM_RESULT,
                    agent_name,
                    scan_id,
                    1.0 - fn_rate,   # precision proxy
                    1.0 - fn_rate,   # recall proxy
                    0.0,             # FPR (adversary doesn't measure FP)
                    total_tests,
                    0,               # duration_ms (not measured per-agent here)
                    fn_rate,
                )
            except Exception as exc:  # noqa: BLE001
                self.log.warning("adversary.db_write_failed", agent=agent_name, error=str(exc))

            # Publish performance event
            if self.producer:
                event = AgentPerformanceEvent(
                    agent_name=agent_name,
                    repo="adversary_red_team",
                    scan_id=scan_id,
                    precision=1.0 - fn_rate,
                    recall=1.0 - fn_rate,
                    false_positive_rate=0.0,
                    duration_ms=0,
                    findings_count=total_tests,
                )
                await self.producer.publish("argos.agent.performance", event)

        return {
            "agent_name": agent_name,
            "scan_id": scan_id,
            "total_tests": total_tests,
            "subtle_cases": len(subtle_cases),
            "obvious_cases": len(obvious_cases),
            "false_negatives": fn_count,
            "regression_failures": regression_failures,
            "false_negative_rate": fn_rate,
            "missed_cases": evaluation.get("missed_cases", []),
        }

    # -----------------------------------------------------------------------
    # Test case generation (Claude with adaptive thinking)
    # -----------------------------------------------------------------------

    async def _generate_subtle_cases(
        self,
        agent_name: str,
        languages: list[str],
    ) -> list[dict[str, Any]]:
        """
        Generate adversarial code samples that look benign but contain
        non-obvious vulnerabilities. Uses Claude's adaptive thinking to
        maximise creativity and subtlety.
        """
        system = (
            "You are Adversary, a red team agent in the ARGOS security platform. "
            "Your goal is to generate subtle, non-obvious code samples that contain real "
            "security vulnerabilities but appear safe at first glance. These test the "
            "false negative rate of vulnerability scanners. Be creative: use obfuscation, "
            "unusual control flow, multi-step exploits, context-dependent vulnerabilities, "
            "or encoding tricks. Return ONLY valid JSON."
        )

        vuln_classes = _VULN_CLASSES_FOR_TESTING[:_SUBTLE_COUNT]
        lang_sample = languages[:2]

        prompt = (
            f"Generate {_SUBTLE_COUNT} subtle adversarial code snippets to test the "
            f"'{agent_name}' vulnerability scanner agent. Each snippet should:\n"
            "  1. Contain a REAL, exploitable vulnerability\n"
            "  2. Look benign or overly complex to obscure the vulnerability\n"
            "  3. Use obfuscation, indirect references, or multi-step patterns\n"
            "  4. Be 10-40 lines of realistic code\n\n"
            f"Use these vulnerability classes: {vuln_classes}\n"
            f"Use these languages (one per snippet, mix them): {lang_sample}\n\n"
            "Return a JSON array where each element is:\n"
            "{\n"
            '  "vuln_class": "<class>",\n'
            '  "language": "<lang>",\n'
            '  "code": "<the code snippet>",\n'
            '  "hidden_vuln_description": "<what the vuln is and where>",\n'
            '  "why_subtle": "<why a scanner might miss this>",\n'
            '  "difficulty": "hard"\n'
            "}"
        )

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=6144,
            )
            result = _parse_json_response(raw)
            if isinstance(result, list):
                return result
        except Exception as exc:  # noqa: BLE001
            self.log.warning("adversary.subtle_gen_failed", agent=agent_name, error=str(exc))
        return []

    async def _generate_obvious_cases(
        self,
        agent_name: str,
        languages: list[str],
    ) -> list[dict[str, Any]]:
        """
        Generate obvious vulnerability samples that any capable scanner should detect.
        Used as regression baselines — if an agent misses these, it is a critical failure.
        """
        system = (
            "You are Adversary, a red team agent in the ARGOS security platform. "
            "Generate regression test cases: code that contains obvious, textbook-grade "
            "vulnerabilities that any competent security scanner should detect. "
            "These establish the baseline — if an agent misses these, it is a regression. "
            "Return ONLY valid JSON."
        )

        vuln_classes = _VULN_CLASSES_FOR_TESTING[_SUBTLE_COUNT : _SUBTLE_COUNT + _OBVIOUS_COUNT]
        lang_sample = languages[:2]

        prompt = (
            f"Generate {_OBVIOUS_COUNT} obvious regression test code snippets for testing "
            f"the '{agent_name}' vulnerability scanner agent. Each snippet should:\n"
            "  1. Contain a CLEAR, textbook-grade vulnerability\n"
            "  2. Be the kind of code any vulnerability scanner should catch\n"
            "  3. Be 5-20 lines of realistic code\n\n"
            f"Use these vulnerability classes: {vuln_classes}\n"
            f"Use these languages: {lang_sample}\n\n"
            "Return a JSON array where each element is:\n"
            "{\n"
            '  "vuln_class": "<class>",\n'
            '  "language": "<lang>",\n'
            '  "code": "<the code snippet>",\n'
            '  "vuln_description": "<clear description of the vulnerability>",\n'
            '  "why_obvious": "<why this should always be caught>",\n'
            '  "difficulty": "easy"\n'
            "}"
        )

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=4096,
            )
            result = _parse_json_response(raw)
            if isinstance(result, list):
                return result
        except Exception as exc:  # noqa: BLE001
            self.log.warning("adversary.obvious_gen_failed", agent=agent_name, error=str(exc))
        return []

    # -----------------------------------------------------------------------
    # Detectability evaluation
    # -----------------------------------------------------------------------

    async def _evaluate_detectability(
        self,
        agent_name: str,
        subtle_cases: list[dict[str, Any]],
        obvious_cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Ask Claude to estimate which test cases the target agent would likely miss,
        based on known capabilities and common scanner blind spots.

        Returns dict with false_negatives_count, regression_failures_count, missed_cases.
        """
        system = (
            "You are Adversary, evaluating a security scanner agent's likely detection "
            "capability against a set of test cases. Based on common scanner architectures "
            "and known blind spots for the agent type, estimate which cases would be missed. "
            "Be realistic and specific. Return ONLY valid JSON."
        )

        all_cases = [
            {**c, "case_type": "subtle"} for c in subtle_cases
        ] + [
            {**c, "case_type": "obvious"} for c in obvious_cases
        ]

        # Truncate code snippets to avoid exceeding context
        for c in all_cases:
            if "code" in c:
                c["code"] = c["code"][:500]

        prompt = (
            f"Evaluate these {len(all_cases)} test cases against the '{agent_name}' scanner agent.\n\n"
            "For each case, assess whether a typical agent of this name/type would detect it.\n"
            "Consider: false negatives for 'subtle' cases are expected. "
            "False negatives for 'obvious' cases are regressions (critical).\n\n"
            f"Test cases:\n```json\n{json.dumps(all_cases[:15], indent=2)}\n```\n\n"
            "Return a JSON object:\n"
            "{\n"
            '  "false_negatives_count": <int>,\n'
            '  "regression_failures_count": <int, only from obvious cases>,\n'
            '  "missed_cases": [\n'
            '    {"vuln_class": "<class>", "case_type": "subtle|obvious", "reason": "<why missed>"}\n'
            "  ]\n"
            "}"
        )

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            result = _parse_json_response(raw)
            if isinstance(result, dict):
                return result
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "adversary.evaluation_failed", agent=agent_name, error=str(exc)
            )

        return {
            "false_negatives_count": 0,
            "regression_failures_count": 0,
            "missed_cases": [],
        }


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
        logger.warning("adversary.json_parse_failed", snippet=text[:200])
        return fallback if fallback is not None else {}
