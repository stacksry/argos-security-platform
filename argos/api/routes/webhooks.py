"""
argos/api/routes/webhooks.py

Webhook route handlers — thin wrappers around argos.ingestion.webhook.

The actual logic (HMAC verification, payload extraction, Kafka publishing)
lives in argos/ingestion/webhook.py which already exposes an APIRouter at
``/webhooks``.  This module re-exports that router so it can be included from
argos.api.routes if callers prefer the routes sub-package import path.

Supported events
----------------
Bitbucket  POST /webhooks/bitbucket  — repo:push / pullrequest:fulfilled
GitHub     POST /webhooks/github     — push / pull_request (closed+merged)
"""

from argos.ingestion.webhook import router  # noqa: F401  re-exported for convenience

__all__ = ["router"]
