"""
argos/api/routes/findings.py

Finding management endpoints.

GET   /api/v1/findings            — list findings (filterable)
GET   /api/v1/findings/stats      — aggregate statistics
GET   /api/v1/findings/{id}       — single finding detail
PATCH /api/v1/findings/{id}       — update status
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from argos.events import FindingStatus, Severity
from argos.memory.store import ArgosMemory

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    reason: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_memory() -> ArgosMemory:
    from argos.api.server import get_memory
    return get_memory()


async def _fetch_all_findings(memory: ArgosMemory) -> list[dict[str, Any]]:
    """
    Pull triage_records from procedural memory.
    The procedural store exposes memory_stats; findings live in its SQL tables.
    Falls back to an empty list on error.
    """
    try:
        # ProceduralMemory is accessed via the private attribute on ArgosMemory.
        # We call the underlying store's raw method if available.
        procedural = memory._procedural  # type: ignore[attr-defined]
        if hasattr(procedural, "get_triage_records"):
            return await procedural.get_triage_records()
        # Fallback: query via the pool directly.
        if hasattr(procedural, "_pool") and procedural._pool is not None:
            async with procedural._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM triage_records ORDER BY discovered_at DESC"
                )
                return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("findings.fetch_error", error=str(exc))
    return []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=dict[str, Any])
async def get_stats() -> dict[str, Any]:
    """
    Aggregate statistics: count by severity, vuln_class, and repo.
    Sourced from the procedural memory (triage_records table).
    """
    memory = _get_memory()
    findings = await _fetch_all_findings(memory)

    by_severity: dict[str, int] = defaultdict(int)
    by_vuln_class: dict[str, int] = defaultdict(int)
    by_repo: dict[str, int] = defaultdict(int)

    for f in findings:
        by_severity[str(f.get("severity", "unknown"))] += 1
        by_vuln_class[str(f.get("vuln_class", "unknown"))] += 1
        by_repo[str(f.get("repo", "unknown"))] += 1

    return {
        "total": len(findings),
        "by_severity": dict(by_severity),
        "by_vuln_class": dict(by_vuln_class),
        "by_repo": dict(by_repo),
    }


@router.get("", response_model=list[dict[str, Any]])
async def list_findings(
    repo: str | None = Query(None),
    severity: Severity | None = Query(None),
    finding_status: FindingStatus | None = Query(None, alias="status"),
    vuln_class: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    """
    List findings from triage_records with optional filters.
    """
    memory = _get_memory()
    findings = await _fetch_all_findings(memory)

    # Apply filters.
    if repo:
        findings = [f for f in findings if f.get("repo") == repo]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.value]
    if finding_status:
        findings = [f for f in findings if f.get("status") == finding_status.value]
    if vuln_class:
        findings = [f for f in findings if f.get("vuln_class") == vuln_class]

    return findings[offset : offset + limit]


@router.get("/{finding_id}", response_model=dict[str, Any])
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Return full detail for a single finding."""
    memory = _get_memory()
    findings = await _fetch_all_findings(memory)

    matched = [f for f in findings if f.get("finding_id") == finding_id]
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found",
        )
    return matched[0]


@router.patch("/{finding_id}", response_model=dict[str, Any])
async def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
) -> dict[str, Any]:
    """
    Update a finding's status (false_positive, in_fix, fixed, etc.).
    Also records the resolution in episodic memory for metric tracking.
    """
    memory = _get_memory()

    # Verify the finding exists.
    findings = await _fetch_all_findings(memory)
    matched = [f for f in findings if f.get("finding_id") == finding_id]
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found",
        )
    finding = matched[0]

    # Persist the new status via procedural memory.
    try:
        procedural = memory._procedural  # type: ignore[attr-defined]
        if hasattr(procedural, "_pool") and procedural._pool is not None:
            async with procedural._pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE triage_records
                       SET status = $1, updated_at = NOW()
                     WHERE finding_id = $2
                    """,
                    body.status.value,
                    finding_id,
                )
    except Exception as exc:
        log.exception("findings.update_failed", finding_id=finding_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update finding: {exc}",
        ) from exc

    # Record resolution event in episodic memory.
    if body.status in (FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE):
        try:
            await memory.record_finding_resolution(
                finding_id=finding_id,
                resolution=body.status.value,
                days_to_fix=0,  # caller may provide via reason field if needed
                repo=str(finding.get("repo", "")),
                vuln_class=str(finding.get("vuln_class", "")),
                severity=str(finding.get("severity", "medium")),
            )
        except Exception:
            log.warning("findings.resolution_record_failed", finding_id=finding_id)

    log.info("findings.updated", finding_id=finding_id, new_status=body.status)
    return {"finding_id": finding_id, "status": body.status.value, "updated": True}
