"""
argos/api/routes/scans.py

Scan management endpoints.

POST /api/v1/scans          — trigger a manual scan
GET  /api/v1/scans          — list recent scans from TimescaleDB
GET  /api/v1/scans/{scan_id} — get scan details
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from argos.config import settings
from argos.events import EventType, Platform, RepoScanEvent
from argos.ingestion.kafka_producer import ArgosProducer
from argos.memory.store import ArgosMemory

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# ---------------------------------------------------------------------------
# Shared producer (lazy-initialised)
# ---------------------------------------------------------------------------

_producer: ArgosProducer | None = None


async def _get_producer() -> ArgosProducer:
    global _producer
    if _producer is None:
        _producer = ArgosProducer(bootstrap_servers=settings.kafka_bootstrap_servers)
        await _producer.start()
    return _producer


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    repo: str = Field(..., description="Repository slug, e.g. 'org/backend-service'")
    branch: str = Field("main", description="Branch to scan")
    changed_files: list[str] = Field(
        default_factory=list,
        description="Specific files to scan; empty = full scan",
    )
    priority: float = Field(5.0, ge=0.0, le=10.0, description="Scan priority 0-10")
    platform: Platform = Field(Platform.BITBUCKET)


class ScanResponse(BaseModel):
    scan_id: str
    repo: str
    branch: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(body: ScanRequest) -> ScanResponse:
    """
    Trigger a manual scan by publishing a RepoScanEvent to Kafka.
    The NavigatorAgent will pick it up and dispatch to the appropriate agents.
    """
    scan_id = str(uuid.uuid4())

    event = RepoScanEvent(
        event_type=EventType.MANUAL,
        platform=body.platform,
        repo=body.repo,
        branch=body.branch,
        changed_files=body.changed_files,
        priority=body.priority,
        trigger=f"api:manual:{scan_id}",
    )

    try:
        producer = await _get_producer()
        await producer.publish(
            topic_key="scan_requested",
            payload=event.model_dump(mode="json"),
            key=body.repo,
            source="argos-api",
        )
    except Exception as exc:
        log.exception("scans.publish_failed", repo=body.repo)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to enqueue scan: {exc}",
        ) from exc

    log.info("scans.triggered", repo=body.repo, branch=body.branch, scan_id=scan_id)
    return ScanResponse(
        scan_id=scan_id,
        repo=body.repo,
        branch=body.branch,
        status="queued",
        message="Scan request published to argos.scan.requested",
    )


@router.get("", response_model=list[dict[str, Any]])
async def list_scans(
    repo: str | None = Query(None, description="Filter by repository slug"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    """
    List recent scans from the TimescaleDB episodic memory store.
    Optionally filtered by repo.
    """
    from argos.api.server import get_memory

    memory: ArgosMemory = get_memory()

    target_repo = repo or ""
    days = 30  # default look-back window

    try:
        rows = await memory.get_scan_history(repo=target_repo, days=days)
    except Exception as exc:
        log.exception("scans.list_failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve scan history: {exc}",
        ) from exc

    # Apply offset/limit in Python (episodic API returns full history).
    return rows[offset : offset + limit]


@router.get("/{scan_id}", response_model=dict[str, Any])
async def get_scan(scan_id: str) -> dict[str, Any]:
    """
    Return details for a specific scan run by its ID.
    Scans are stored in the episodic time-series layer.
    """
    from argos.api.server import get_memory

    memory: ArgosMemory = get_memory()

    try:
        # Pull all recent history and filter by scan_id.
        rows = await memory.get_scan_history(repo="", days=90)
    except Exception as exc:
        log.exception("scans.get_failed", scan_id=scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query scan history: {exc}",
        ) from exc

    matched = [r for r in rows if r.get("scan_id") == scan_id]
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    return matched[0]
