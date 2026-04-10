"""
argos/memory/vector.py

Qdrant-backed vector memory for ARGOS. Stores and retrieves code embeddings
for vulnerability similarity search, hardware design similarity, and fix pattern
lookup.

Embedding strategy
------------------
Primary:  sentence-transformers with microsoft/codebert-base (768-dim).
Fallback: deterministic hash-based pseudo-vectors so the full system runs
          without a GPU or the transformers stack installed. Fallback vectors
          are consistent for the same input string but carry no semantic
          meaning — similarity scores will be meaningless. Use only in dev/test.
"""

from __future__ import annotations

import hashlib
import logging
import math
import uuid
from typing import Any

import structlog
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Collection registry
# ---------------------------------------------------------------------------

COLLECTIONS: dict[str, dict[str, Any]] = {
    "vulnerabilities": {"size": 768, "distance": Distance.COSINE},
    "hardware_designs": {"size": 768, "distance": Distance.COSINE},
    "fix_patterns": {"size": 768, "distance": Distance.COSINE},
}

# ---------------------------------------------------------------------------
# Embedding helpers
# ---------------------------------------------------------------------------

def _hash_vector(text: str, dim: int = 768) -> list[float]:
    """
    Fallback: produce a deterministic unit-length vector from a SHA-256 hash.

    WARNING: This carries no semantic information. Two similar code snippets
    will produce unrelated vectors. Use only when sentence-transformers is
    unavailable (e.g. CI, lightweight dev environments without GPU).
    """
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    # Repeat digest bytes to fill `dim` floats, then normalise.
    repeated = (digest * math.ceil(dim / len(digest)))[:dim]
    raw = [(b - 127.5) / 127.5 for b in repeated]
    norm = math.sqrt(sum(v * v for v in raw)) or 1.0
    return [v / norm for v in raw]


def _try_load_codebert():
    """Attempt to load CodeBERT via sentence-transformers. Returns model or None."""
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore

        model = SentenceTransformer("microsoft/codebert-base")
        logger.info("vector.embed_model_loaded", model="microsoft/codebert-base")
        return model
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "vector.embed_model_unavailable",
            reason=str(exc),
            fallback="hash_vector",
        )
        return None


# ---------------------------------------------------------------------------
# VectorMemory
# ---------------------------------------------------------------------------


class VectorMemory:
    """
    Thin async wrapper around Qdrant.

    Parameters
    ----------
    host:
        Qdrant host (default ``localhost``).
    port:
        Qdrant gRPC/REST port (default ``6333``).
    api_key:
        Optional Qdrant Cloud API key.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6333,
        api_key: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._api_key = api_key
        self._client: AsyncQdrantClient | None = None
        self._embed_model = None  # lazy-loaded on first embed call

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the async Qdrant client connection."""
        kwargs: dict[str, Any] = {"host": self._host, "port": self._port}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        self._client = AsyncQdrantClient(**kwargs)
        logger.info("vector.connected", host=self._host, port=self._port)

    async def close(self) -> None:
        """Close the Qdrant client."""
        if self._client:
            await self._client.close()
            logger.info("vector.disconnected")

    @property
    def client(self) -> AsyncQdrantClient:
        if self._client is None:
            raise RuntimeError("VectorMemory not connected — call connect() first.")
        return self._client

    # ------------------------------------------------------------------
    # Collection management
    # ------------------------------------------------------------------

    async def init_collections(self) -> None:
        """
        Ensure all registered Qdrant collections exist.

        Safe to call multiple times; skips existing collections.
        """
        existing = {c.name for c in await self.client.get_collections().collections}  # type: ignore[union-attr]
        for name, cfg in COLLECTIONS.items():
            if name in existing:
                logger.debug("vector.collection_exists", collection=name)
                continue
            await self.client.create_collection(
                collection_name=name,
                vectors_config=VectorParams(size=cfg["size"], distance=cfg["distance"]),
            )
            logger.info("vector.collection_created", collection=name, **cfg)

    # ------------------------------------------------------------------
    # Embedding
    # ------------------------------------------------------------------

    async def embed_code(self, text: str) -> list[float]:
        """
        Embed a code or text snippet into a 768-dim vector.

        Tries ``microsoft/codebert-base`` via sentence-transformers first;
        falls back to a deterministic hash vector if unavailable.
        """
        if self._embed_model is None:
            self._embed_model = _try_load_codebert()

        if self._embed_model is not None:
            # encode() is synchronous; run in executor for async compat if needed.
            vector: list[float] = self._embed_model.encode(text).tolist()
            return vector

        # Fallback path — deterministic but semantically meaningless.
        return _hash_vector(text)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def upsert(
        self,
        collection: str,
        id: str,
        vector: list[float],
        payload: dict[str, Any],
    ) -> None:
        """
        Insert or update a point in a collection.

        Parameters
        ----------
        collection:
            Target collection name (must exist in COLLECTIONS).
        id:
            Stable string identifier. Converted to a UUID-5 internally so
            Qdrant's integer/UUID ID constraint is satisfied while preserving
            idempotency.
        vector:
            Pre-computed embedding vector.
        payload:
            Arbitrary metadata stored alongside the vector.
        """
        point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, id))
        point = PointStruct(id=point_id, vector=vector, payload=payload)
        await self.client.upsert(collection_name=collection, points=[point])
        logger.debug("vector.upserted", collection=collection, id=id, point_id=point_id)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    async def search(
        self,
        collection: str,
        query_text: str,
        filter: dict[str, Any] | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Embed *query_text* and return the *limit* nearest neighbours.

        Parameters
        ----------
        collection:
            Collection to search.
        query_text:
            Raw code / text to embed and use as the query vector.
        filter:
            Optional key/value filter applied before ANN search.
            Format: ``{"field": "value"}`` — single equality predicates only.
            For richer filtering extend this method with full Qdrant Filter DSL.
        limit:
            Maximum number of results to return.

        Returns
        -------
        list[dict]
            Each dict contains ``id``, ``score``, and ``payload`` keys.
        """
        query_vector = await self.embed_code(query_text)

        qdrant_filter: Filter | None = None
        if filter:
            conditions = [
                FieldCondition(key=k, match=MatchValue(value=v))
                for k, v in filter.items()
            ]
            qdrant_filter = Filter(must=conditions)

        results = await self.client.search(
            collection_name=collection,
            query_vector=query_vector,
            query_filter=qdrant_filter,
            limit=limit,
            with_payload=True,
        )

        hits = [
            {"id": str(r.id), "score": r.score, "payload": r.payload or {}}
            for r in results
        ]
        logger.debug(
            "vector.search_complete",
            collection=collection,
            hits=len(hits),
            limit=limit,
        )
        return hits
