"""
argos/api/routes/agents.py

Agent management endpoints.

GET  /api/v1/agents                        — list all agents and their metrics
GET  /api/v1/agents/{agent_name}/stats     — precision/recall/FP rate for an agent
POST /api/v1/agents/{agent_name}/retire    — retire an underperforming agent
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from argos.events import AgentRetiredEvent
from argos.ingestion.kafka_producer import ArgosProducer
from argos.config import settings

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(prefix="/agents", tags=["agents"])

# ---------------------------------------------------------------------------
# Known agents (name → module path)
# ---------------------------------------------------------------------------

KNOWN_AGENTS: list[str] = [
    "navigator",
    "oracle",
    "archaeologist",
    "cartographer",
    "sentinel",
    "architect",
]

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RetireRequest(BaseModel):
    reason: str = "manual"


class AgentStats(BaseModel):
    agent_name: str
    precision: float
    recall: float
    false_positive_rate: float
    total_scans: int
    total_findings: int
    avg_duration_ms: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_memory():  # type: ignore[return]
    from argos.api.server import get_memory
    return get_memory()


async def _get_agent_metrics(memory, agent_name: str) -> dict[str, Any]:
    """
    Query episodic memory for performance metrics for a given agent.
    Returns a dict with precision, recall, fp_rate, scan counts, etc.
    """
    try:
        episodic = memory._episodic  # type: ignore[attr-defined]
        if hasattr(episodic, "_pool") and episodic._pool is not None:
            async with episodic._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT
                        COUNT(*)                                           AS total_scans,
                        COALESCE(SUM(findings), 0)                        AS total_findings,
                        COALESCE(AVG(duration_ms), 0)                     AS avg_duration_ms
                    FROM scan_events
                    WHERE agent = $1
                    """,
                    agent_name,
                )
                perf_row = await conn.fetchrow(
                    """
                    SELECT
                        COALESCE(AVG(CASE WHEN metric_name = 'precision'          THEN value END), 0.0) AS precision,
                        COALESCE(AVG(CASE WHEN metric_name = 'recall'             THEN value END), 0.0) AS recall,
                        COALESCE(AVG(CASE WHEN metric_name = 'false_positive_rate' THEN value END), 0.0) AS fp_rate
                    FROM agent_metrics
                    WHERE agent = $1
                    """,
                    agent_name,
                )
                return {
                    "total_scans": int(row["total_scans"] or 0),
                    "total_findings": int(row["total_findings"] or 0),
                    "avg_duration_ms": float(row["avg_duration_ms"] or 0.0),
                    "precision": float(perf_row["precision"] or 0.0),
                    "recall": float(perf_row["recall"] or 0.0),
                    "false_positive_rate": float(perf_row["fp_rate"] or 0.0),
                }
    except Exception as exc:
        log.warning("agents.metrics_query_failed", agent=agent_name, error=str(exc))

    return {
        "total_scans": 0,
        "total_findings": 0,
        "avg_duration_ms": 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "false_positive_rate": 0.0,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[dict[str, Any]])
async def list_agents() -> list[dict[str, Any]]:
    """
    Return all known agents with their current performance metrics.
    """
    memory = _get_memory()
    results: list[dict[str, Any]] = []

    for name in KNOWN_AGENTS:
        metrics = await _get_agent_metrics(memory, name)
        results.append({"agent_name": name, **metrics})

    return results


@router.get("/{agent_name}/stats", response_model=dict[str, Any])
async def get_agent_stats(agent_name: str) -> dict[str, Any]:
    """
    Return precision, recall, and false-positive rate for a specific agent.
    """
    if agent_name not in KNOWN_AGENTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown agent '{agent_name}'. Known agents: {KNOWN_AGENTS}",
        )

    memory = _get_memory()
    metrics = await _get_agent_metrics(memory, agent_name)
    return {"agent_name": agent_name, **metrics}


@router.post("/{agent_name}/retire", status_code=status.HTTP_202_ACCEPTED)
async def retire_agent(agent_name: str, body: RetireRequest) -> dict[str, Any]:
    """
    Retire an underperforming agent by publishing an AgentRetiredEvent to Kafka.
    The Breeder agent will handle clean-up and potential replacement.
    """
    if agent_name not in KNOWN_AGENTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown agent '{agent_name}'",
        )

    # Fetch final metrics for the retirement event.
    memory = _get_memory()
    metrics = await _get_agent_metrics(memory, agent_name)

    event = AgentRetiredEvent(
        agent_name=agent_name,
        reason=body.reason,
        final_precision=metrics["precision"],
        final_recall=metrics["recall"],
    )

    try:
        producer = ArgosProducer(bootstrap_servers=settings.kafka_bootstrap_servers)
        await producer.start()
        try:
            await producer.publish(
                topic_key="agent_spawned",  # reuses existing topic registry key
                payload=event.model_dump(mode="json"),
                key=agent_name,
                source="argos-api",
            )
        finally:
            await producer.stop()
    except Exception as exc:
        log.exception("agents.retire_publish_failed", agent=agent_name)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to publish retirement event: {exc}",
        ) from exc

    log.info("agents.retired", agent=agent_name, reason=body.reason)
    return {
        "agent_name": agent_name,
        "status": "retired",
        "reason": body.reason,
        "final_precision": metrics["precision"],
        "final_recall": metrics["recall"],
    }
