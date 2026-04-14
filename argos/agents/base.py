"""
argos/agents/base.py

Base class and shared data structures for all ARGOS agents.

Every concrete agent inherits from ArgosAgent, implements run(), and calls
_call_claude() / _call_claude_agentic() for all LLM interactions.  The base
class wires up:
  - A shared anthropic.Anthropic client (ANTHROPIC_API_KEY from env)
  - Structlog bound with the agent name
  - Standard adaptive-thinking Claude calls
  - Priority scoring formula used by the Navigator
  - Episodic memory write-back for performance telemetry
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import anthropic
import structlog

# ---------------------------------------------------------------------------
# Model routing
# ---------------------------------------------------------------------------

# Set CLAUDE_MODEL_ID to override the default analysis model (e.g. a Glasswing
# partner model ID once access is granted).  All agents inherit this default.
_DEFAULT_MODEL = os.environ.get("CLAUDE_MODEL_ID", "claude-opus-4-6")

# Set CLAUDE_MYTHOS_MODEL_ID to the partner-specific Mythos endpoint once
# Glasswing access is obtained.  Falls back to the default model when unset
# so the platform runs correctly without Mythos access.
_MYTHOS_MODEL = os.environ.get("CLAUDE_MYTHOS_MODEL_ID", _DEFAULT_MODEL)

# Haiku for cheap, high-volume gating tasks (ranking, L1-L5 pre-screening).
_HAIKU_MODEL = os.environ.get("CLAUDE_HAIKU_MODEL_ID", "claude-haiku-4-5-20251001")

# Feature flag: set USE_MYTHOS=true to route deep-semantic tasks to Mythos.
# When false (default), all tasks use the default model — safe for environments
# without Glasswing partner access.
_USE_MYTHOS: bool = os.environ.get("USE_MYTHOS", "false").lower() == "true"

# Maximum attempts when the Claude API returns a rate-limit (429) response.
_API_MAX_RETRIES = 6
_API_RETRY_BASE_DELAY = 2.0  # seconds; doubles each attempt (2, 4, 8, 16, 32, 64)


class ModelRouter:
    """
    Select the appropriate Claude model based on task type and feature flags.

    Task tiers:
      "deep_semantic"   — Mythos (if USE_MYTHOS=true); else default.
                          For: validator, triage, novel-vuln-class identification.
      "code_generation" — Default model (Opus-class).
                          For: Breeder, Alchemist fix generation. Never use Mythos here —
                          a model that can escape sandboxes must not auto-generate
                          deployable agent code without elevated human review.
      "gating"          — Haiku (cheap, high-volume pre-screening).
                          For: file ranking, L1-L5 infrastructure/language gating.
      "default"         — Default model for everything else.
    """

    @staticmethod
    def select(task_type: str = "default") -> str:
        if task_type == "deep_semantic" and _USE_MYTHOS:
            return _MYTHOS_MODEL
        if task_type == "gating":
            return _HAIKU_MODEL
        return _DEFAULT_MODEL


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class AgentResult:
    """
    Uniform return type for every agent's run() method.

    Attributes
    ----------
    agent:
        Name of the agent that produced this result.
    success:
        True when the agent completed without an unhandled error.
    findings:
        Zero or more structured findings.  Schema varies per agent but each
        finding should include at least ``finding_id``, ``severity``, and
        ``description``.
    metadata:
        Free-form dict for routing, telemetry, or downstream consumer hints.
    error:
        Non-empty string when success=False; empty otherwise.
    duration_ms:
        Wall-clock milliseconds the agent spent in run().
    tokens_used:
        Total input + output tokens consumed across all Claude calls made
        during this run().
    """

    agent: str
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    duration_ms: int = 0
    tokens_used: int = 0


# ---------------------------------------------------------------------------
# ArgosAgent base
# ---------------------------------------------------------------------------


class ArgosAgent(ABC):
    """
    Abstract base class for all ARGOS agents.

    Subclasses must:
      - Set a unique class-level ``name`` attribute.
      - Implement ``async def run(self, context: dict) -> AgentResult``.

    Subclasses may optionally:
      - Override ``__init__`` and call ``super().__init__(memory, producer)``.

    Parameters
    ----------
    memory:
        An ArgosMemory instance (graph + vector + episodic).  May be None in
        unit-test scenarios.
    producer:
        An ArgosProducer instance for publishing Kafka events.  May be None in
        unit-test scenarios.
    """

    name: str = "base"
    model: str = _DEFAULT_MODEL

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
    ) -> None:
        self.memory = memory
        self.producer = producer
        self.client = anthropic.Anthropic()
        self.log: structlog.BoundLogger = structlog.get_logger(agent=self.name)
        self._total_tokens: int = 0  # accumulated across all Claude calls in a run()

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Main entry point.  context contains all inputs for this agent.

        Implementations should:
          1. Extract needed fields from context (with safe defaults).
          2. Call _call_claude() or _call_claude_agentic() for LLM reasoning.
          3. Return an AgentResult; never raise — catch exceptions and set
             success=False with a descriptive error string.
        """
        ...

    # ------------------------------------------------------------------
    # Claude helpers
    # ------------------------------------------------------------------

    async def _api_call_with_retry(self, fn, loop: asyncio.AbstractEventLoop):
        """
        Run a synchronous Claude API call in the thread executor with exponential
        backoff on rate-limit (429) errors.

        Parameters
        ----------
        fn:
            A zero-argument callable that performs the synchronous API call and
            returns an anthropic.types.Message.
        loop:
            The running event loop (passed in to avoid calling get_event_loop
            redundantly in callers).

        Returns
        -------
        anthropic.types.Message
        """
        delay = _API_RETRY_BASE_DELAY
        for attempt in range(1, _API_MAX_RETRIES + 1):
            try:
                return await loop.run_in_executor(None, fn)
            except anthropic.RateLimitError:
                if attempt == _API_MAX_RETRIES:
                    raise
                self.log.warning(
                    "claude.rate_limited",
                    attempt=attempt,
                    retry_in_seconds=delay,
                )
                await asyncio.sleep(delay)
                delay *= 2

    async def _call_claude(
        self,
        system: str,
        messages: list[dict[str, Any]],
        max_tokens: int = 8192,
        tools: list[dict[str, Any]] | None = None,
    ) -> str:
        """
        Standard Claude call with adaptive thinking.

        Uses streaming internally (avoids HTTP timeouts on large max_tokens)
        and collects the final message via get_final_message().  Only the first
        text block is returned — thinking blocks are discarded.

        Parameters
        ----------
        system:
            System prompt.
        messages:
            Anthropic-format message list (role/content pairs).
        max_tokens:
            Upper bound on output tokens.  Defaults to 8192.
        tools:
            Optional list of tool definitions.  When provided, Claude may emit
            tool_use blocks; this helper discards them and returns only text.
            For agentic tool loops use _call_claude_agentic().

        Returns
        -------
        str
            The first text block from Claude's response, or "" if none.
        """
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "thinking": {"type": "adaptive"},
            "system": system,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools

        self.log.debug("claude.call", max_tokens=max_tokens)

        loop = asyncio.get_event_loop()
        # The SDK's streaming helper is synchronous; run it in the default
        # thread executor to avoid blocking the event loop.
        def _stream() -> anthropic.types.Message:
            with self.client.messages.stream(**kwargs) as stream:
                return stream.get_final_message()

        response = await self._api_call_with_retry(_stream, loop)

        usage = response.usage
        tokens = (usage.input_tokens or 0) + (usage.output_tokens or 0)
        self._total_tokens += tokens
        self.log.debug(
            "claude.call_complete",
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
        )

        for block in response.content:
            if block.type == "text":
                return block.text

        return ""

    async def _call_claude_agentic(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 8192,
    ) -> tuple[str, list[dict[str, Any]]]:
        """
        Agentic tool-use loop.

        Calls Claude repeatedly, executing any tool_use blocks, until
        stop_reason is "end_turn".  Tool execution is delegated to
        _execute_tool() which subclasses may override.

        Parameters
        ----------
        system:
            System prompt.
        messages:
            Initial message list.
        tools:
            Tool definitions.  Claude will call these as needed.
        max_tokens:
            Per-call max tokens.

        Returns
        -------
        (final_text, all_tool_calls)
            final_text: The last text block emitted by Claude.
            all_tool_calls: Every tool_use block observed across all iterations,
                            each as ``{"name": str, "input": dict, "result": str}``.
        """
        history = list(messages)
        all_tool_calls: list[dict[str, Any]] = []
        final_text = ""

        loop = asyncio.get_event_loop()

        for _iteration in range(20):  # hard cap — prevents infinite loops
            kwargs: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max_tokens,
                "thinking": {"type": "adaptive"},
                "system": system,
                "messages": history,
                "tools": tools,
            }

            def _stream() -> anthropic.types.Message:
                with self.client.messages.stream(**kwargs) as s:
                    return s.get_final_message()

            response = await self._api_call_with_retry(_stream, loop)

            usage = response.usage
            tokens = (usage.input_tokens or 0) + (usage.output_tokens or 0)
            self._total_tokens += tokens

            # Append assistant turn to history.
            history.append({"role": "assistant", "content": response.content})

            # Collect text from this turn.
            for block in response.content:
                if block.type == "text":
                    final_text = block.text

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason != "tool_use":
                self.log.warning(
                    "claude.unexpected_stop_reason",
                    stop_reason=response.stop_reason,
                )
                break

            # Execute all tool_use blocks and collect results.
            tool_results: list[dict[str, Any]] = []
            for block in response.content:
                if block.type != "tool_use":
                    continue

                tool_input: dict[str, Any] = block.input  # type: ignore[assignment]
                self.log.debug("claude.tool_call", tool=block.name, input=tool_input)

                result_str = await self._execute_tool(block.name, tool_input)

                all_tool_calls.append(
                    {"name": block.name, "input": tool_input, "result": result_str}
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_str,
                    }
                )

            history.append({"role": "user", "content": tool_results})

        return final_text, all_tool_calls

    async def _execute_tool(self, name: str, tool_input: dict[str, Any]) -> str:
        """
        Execute a named tool and return its result as a string.

        The base implementation returns a JSON-encoded stub.  Override in
        concrete agents to wire up real tool implementations.
        """
        self.log.warning("claude.tool_not_implemented", tool=name)
        return json.dumps({"error": f"Tool '{name}' not implemented by {self.name}"})

    # ------------------------------------------------------------------
    # Priority scoring
    # ------------------------------------------------------------------

    def _priority_score(
        self,
        asset_criticality: float,
        recency_hours: float,
        exposure: float,
    ) -> float:
        """
        Navigator priority score.

        Formula:  score = criticality × (1 / max(recency_hours, 0.1)) × exposure
        Clamped to [0.0, 10.0].

        Parameters
        ----------
        asset_criticality:
            0.0 – 10.0 reflecting business importance of the asset.
        recency_hours:
            Hours since the triggering event.  A recent event (0.1 h) yields
            a high multiplier; an old event (168 h = 1 week) yields a low one.
        exposure:
            0.0 – 1.0 reflecting internet exposure / attack surface.

        Returns
        -------
        float
            Priority in [0.0, 10.0].
        """
        recency_hours = max(recency_hours, 0.1)
        raw = asset_criticality * (1.0 / recency_hours) * exposure
        return round(min(raw, 10.0), 2)

    # ------------------------------------------------------------------
    # Performance telemetry
    # ------------------------------------------------------------------

    async def _record_performance(self, result: AgentResult) -> None:
        """
        Write agent performance metrics to episodic memory.

        Stores a structured event so the platform can track per-agent latency,
        success rates, and token consumption over time.  Silently skips if
        memory is not configured.
        """
        if self.memory is None:
            return

        record = {
            "event_type": "agent_performance",
            "agent": result.agent,
            "success": result.success,
            "finding_count": len(result.findings),
            "duration_ms": result.duration_ms,
            "tokens_used": result.tokens_used,
            "error": result.error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            # ArgosMemory is expected to expose an async write_episodic() method.
            await self.memory.write_episodic(record)
            self.log.debug("agent.performance_recorded", agent=result.agent)
        except Exception as exc:  # noqa: BLE001
            # Never let telemetry failures surface as agent errors.
            self.log.warning(
                "agent.performance_record_failed",
                agent=result.agent,
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Run wrapper helper
    # ------------------------------------------------------------------

    async def _timed_run(self, context: dict[str, Any]) -> AgentResult:
        """
        Convenience wrapper: calls run(), records timing + tokens, stores perf.

        Prefer calling run() directly in orchestration code that handles its
        own timing.  _timed_run() is for the Navigator calling sub-agents.
        """
        self._total_tokens = 0
        t0 = time.monotonic()

        try:
            result = await self.run(context)
        except Exception as exc:  # noqa: BLE001
            self.log.exception("agent.unhandled_exception", error=str(exc))
            result = AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
            )

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        result.duration_ms = elapsed_ms
        result.tokens_used = self._total_tokens

        await self._record_performance(result)
        return result
