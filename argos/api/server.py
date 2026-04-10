"""
server.py — ARGOS FastAPI application entry point.
Run: uvicorn argos.api.server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import structlog
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from argos.config import settings
from argos.memory.store import ArgosMemory
from argos.api.routes import scans, findings, agents, repos, bom
from argos.ingestion.webhook import router as webhook_router

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

_memory: ArgosMemory | None = None


def get_memory() -> ArgosMemory:
    if _memory is None:
        raise RuntimeError("Memory not initialised — startup incomplete")
    return _memory


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """Validate Bearer token against the configured API secret key."""
    secret = settings.api_secret_key.get_secret_value()
    if not credentials or credentials.credentials != secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    global _memory

    log.info("argos.startup")
    _memory = await ArgosMemory.create(
        qdrant_host=settings.qdrant_url.split("://")[-1].split(":")[0],
        qdrant_port=int(settings.qdrant_url.split(":")[-1]) if ":" in settings.qdrant_url.split("://")[-1] else 6333,
        qdrant_api_key=settings.qdrant_api_key.get_secret_value() or None,
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password.get_secret_value(),
        pg_dsn=settings.postgres_dsn,
    )
    log.info("argos.memory_ready")

    yield

    log.info("argos.shutdown")
    if _memory is not None:
        await _memory.close()
    log.info("argos.memory_closed")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ARGOS Security Platform",
    version="0.1.0",
    description="Adaptive Reconnaissance & Guard for Organizational Security",
    lifespan=lifespan,
)

# CORS — restrict in production via environment
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.environment == "development" else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(scans.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(repos.router, prefix="/api/v1")
app.include_router(bom.router, prefix="/api/v1")
app.include_router(webhook_router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/", tags=["health"])
async def health_check() -> dict[str, Any]:
    """Platform health check — returns version info and memory status."""
    mem_stats: dict[str, Any] = {}
    if _memory is not None:
        try:
            mem_stats = await _memory.memory_stats()
        except Exception:
            mem_stats = {"error": "unavailable"}

    return {
        "service": "ARGOS Security Platform",
        "version": "0.1.0",
        "environment": settings.environment,
        "memory_stats": mem_stats,
        "status": "ok",
    }
