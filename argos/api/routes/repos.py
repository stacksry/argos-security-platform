"""
argos/api/routes/repos.py

Repository management endpoints.

GET  /api/v1/repos          — list all tracked repositories
GET  /api/v1/repos/{repo}   — get repo metadata and blast radius info
POST /api/v1/repos          — register a repository for tracking
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(prefix="/repos", tags=["repos"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RepoRegistration(BaseModel):
    repo: str
    url: str = ""
    language: str = ""
    team: str = ""
    metadata: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_memory():  # type: ignore[return]
    from argos.api.server import get_memory
    return get_memory()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[dict[str, Any]])
async def list_repos() -> list[dict[str, Any]]:
    """List all repositories tracked in the knowledge graph."""
    memory = _get_memory()
    try:
        graph = memory._graph  # type: ignore[attr-defined]
        if hasattr(graph, "_driver") and graph._driver is not None:
            async with graph._driver.session(database=graph._database) as session:
                result = await session.run(
                    "MATCH (r:Repo) RETURN r.name AS name, r.url AS url, "
                    "r.language AS language, r.team AS team ORDER BY r.name"
                )
                records = await result.data()
                return [dict(r) for r in records]
    except Exception as exc:
        log.warning("repos.list_failed", error=str(exc))
    return []


@router.get("/{repo:path}", response_model=dict[str, Any])
async def get_repo(repo: str) -> dict[str, Any]:
    """Return metadata and blast-radius relationships for a repository."""
    memory = _get_memory()

    repo_data: dict[str, Any] = {"repo": repo}

    try:
        graph = memory._graph  # type: ignore[attr-defined]
        if hasattr(graph, "_driver") and graph._driver is not None:
            async with graph._driver.session(database=graph._database) as session:
                result = await session.run(
                    "MATCH (r:Repo {name: $name}) RETURN r",
                    name=repo,
                )
                record = await result.single()
                if record is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Repository '{repo}' not found",
                    )
                repo_data.update(dict(record["r"]))

                # Dependencies.
                dep_result = await session.run(
                    """
                    MATCH (r:Repo {name: $name})-[:DEPENDS_ON]->(l:Library)
                    RETURN l.name AS library, l.version AS version, l.ecosystem AS ecosystem
                    ORDER BY l.name
                    """,
                    name=repo,
                )
                repo_data["dependencies"] = await dep_result.data()
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("repos.get_failed", repo=repo, error=str(exc))

    return repo_data


@router.post("", status_code=status.HTTP_201_CREATED, response_model=dict[str, Any])
async def register_repo(body: RepoRegistration) -> dict[str, Any]:
    """Register a repository in the ARGOS knowledge graph for tracking."""
    memory = _get_memory()

    meta = {
        "url": body.url,
        "language": body.language,
        "team": body.team,
        **body.metadata,
    }

    try:
        await memory.upsert_repo(repo=body.repo, metadata=meta)
    except Exception as exc:
        log.exception("repos.register_failed", repo=body.repo)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register repository: {exc}",
        ) from exc

    log.info("repos.registered", repo=body.repo)
    return {"repo": body.repo, "status": "registered", **meta}
