"""
argos/api/routes/bom.py

Bill-of-Materials (BOM) endpoints.

GET  /api/v1/bom/{repo}     — get dependency BOM for a repo from the knowledge graph
POST /api/v1/bom/{repo}     — ingest / refresh BOM for a repo (upserts dependencies)
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

log: structlog.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(prefix="/bom", tags=["bom"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class Dependency(BaseModel):
    library: str
    version: str
    ecosystem: str = "unknown"


class BOMIngestion(BaseModel):
    dependencies: list[Dependency]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_memory():  # type: ignore[return]
    from argos.api.server import get_memory
    return get_memory()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/{repo:path}", response_model=dict[str, Any])
async def get_bom(repo: str) -> dict[str, Any]:
    """
    Return the current dependency BOM for a repository, sourced from the
    Neo4j knowledge graph.
    """
    memory = _get_memory()
    deps: list[dict[str, Any]] = []

    try:
        graph = memory._graph  # type: ignore[attr-defined]
        if hasattr(graph, "_driver") and graph._driver is not None:
            async with graph._driver.session(database=graph._database) as session:
                result = await session.run(
                    """
                    MATCH (r:Repo {name: $name})-[:DEPENDS_ON]->(l:Library)
                    RETURN l.name AS library, l.version AS version,
                           l.ecosystem AS ecosystem
                    ORDER BY l.ecosystem, l.name
                    """,
                    name=repo,
                )
                deps = await result.data()
    except Exception as exc:
        log.warning("bom.get_failed", repo=repo, error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve BOM: {exc}",
        ) from exc

    return {"repo": repo, "dependency_count": len(deps), "dependencies": deps}


@router.post("/{repo:path}", status_code=status.HTTP_202_ACCEPTED, response_model=dict[str, Any])
async def ingest_bom(repo: str, body: BOMIngestion) -> dict[str, Any]:
    """
    Ingest or refresh the dependency BOM for a repository.
    Upserts each dependency into the knowledge graph and checks blast radius
    against known CVEs.
    """
    memory = _get_memory()
    upserted = 0
    errors: list[str] = []

    for dep in body.dependencies:
        try:
            await memory.upsert_dependency(
                repo=repo,
                library=dep.library,
                version=dep.version,
                ecosystem=dep.ecosystem,
            )
            upserted += 1
        except Exception as exc:
            err = f"{dep.library}@{dep.version}: {exc}"
            log.warning("bom.upsert_failed", repo=repo, library=dep.library, error=str(exc))
            errors.append(err)

    log.info("bom.ingested", repo=repo, upserted=upserted, errors=len(errors))
    return {
        "repo": repo,
        "upserted": upserted,
        "errors": errors,
        "status": "accepted",
    }
