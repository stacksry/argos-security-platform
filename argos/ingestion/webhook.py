"""
argos/ingestion/webhook.py

FastAPI webhook handlers for Bitbucket and GitHub git events.

Supported events
----------------
Bitbucket:
  repo:push               -> RepoScanEvent  -> argos.scan.requested
  pullrequest:created     -> logged only (no scan)
  pullrequest:fulfilled   -> PRMergedEvent  -> argos.pr.merged

GitHub:
  push                    -> RepoScanEvent  -> argos.scan.requested
  pull_request.opened     -> logged only (no scan)
  pull_request.closed     (merged) -> PRMergedEvent -> argos.pr.merged

Signature verification
----------------------
Bitbucket : X-Hub-Signature  (HMAC-SHA256, "sha256=<hex>")
GitHub     : X-Hub-Signature-256 (HMAC-SHA256, "sha256=<hex>")

Environment variables
---------------------
ARGOS_BITBUCKET_WEBHOOK_SECRET : shared secret for Bitbucket webhooks.
ARGOS_GITHUB_WEBHOOK_SECRET    : shared secret for GitHub webhooks.
ARGOS_KAFKA_BOOTSTRAP          : comma-separated Kafka bootstrap servers.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request

from argos.ingestion.kafka_producer import ArgosProducer

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level Kafka producer (shared across requests in a single process).
# ---------------------------------------------------------------------------
_producer: ArgosProducer | None = None


async def get_producer() -> ArgosProducer:
    global _producer
    if _producer is None:
        bootstrap = os.environ.get("ARGOS_KAFKA_BOOTSTRAP", "localhost:9092")
        _producer = ArgosProducer(bootstrap_servers=bootstrap)
        await _producer.start()
    return _producer


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------

def _verify_hmac_sha256(secret: str, body: bytes, signature_header: str | None) -> None:
    """
    Verify an HMAC-SHA256 signature of the form ``sha256=<hexdigest>``.

    Raises HTTPException(403) when verification fails.
    """
    if not secret:
        # No secret configured – skip verification (dev/test only).
        log.warning("webhook.signature_check_skipped", reason="no secret configured")
        return

    if not signature_header:
        log.error("webhook.missing_signature")
        raise HTTPException(status_code=403, detail="Missing webhook signature")

    try:
        algo, _, provided_digest = signature_header.partition("=")
    except ValueError:
        raise HTTPException(status_code=403, detail="Malformed signature header")

    if algo.lower() != "sha256":
        raise HTTPException(status_code=403, detail=f"Unsupported signature algorithm: {algo}")

    expected_digest = hmac.new(
        key=secret.encode(),
        msg=body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(provided_digest, expected_digest):
        log.error("webhook.signature_mismatch")
        raise HTTPException(status_code=403, detail="Webhook signature mismatch")


# ---------------------------------------------------------------------------
# Event extraction helpers
# ---------------------------------------------------------------------------

def _extract_bitbucket_push(payload: dict) -> dict:
    """
    Extract normalised push event data from a Bitbucket ``repo:push`` payload.
    """
    repo_info = payload.get("repository", {})
    repo_slug = repo_info.get("full_name", repo_info.get("slug", "unknown"))

    changes: list[dict] = payload.get("push", {}).get("changes", [])
    branch = ""
    commits: list[dict] = []
    changed_files: list[str] = []

    for change in changes:
        new_ref = change.get("new", {})
        if not branch and new_ref:
            branch = new_ref.get("name", "")
        for commit in change.get("commits", []):
            commits.append(
                {
                    "sha": commit.get("hash", ""),
                    "message": commit.get("message", ""),
                    "author": commit.get("author", {}).get("raw", ""),
                }
            )
            # Bitbucket does not include diff in the push payload; the scanner
            # will resolve changed files via the API.

    return {
        "repo": repo_slug,
        "branch": branch,
        "commits": commits,
        "changed_files": changed_files,
        "source": "bitbucket",
    }


def _extract_github_push(payload: dict) -> dict:
    """
    Extract normalised push event data from a GitHub ``push`` payload.
    """
    repo_slug = payload.get("repository", {}).get("full_name", "unknown")
    branch_ref: str = payload.get("ref", "refs/heads/unknown")
    branch = branch_ref.removeprefix("refs/heads/")

    raw_commits: list[dict] = payload.get("commits", [])
    commits: list[dict] = []
    changed_files_set: set[str] = set()

    for commit in raw_commits:
        commits.append(
            {
                "sha": commit.get("id", ""),
                "message": commit.get("message", ""),
                "author": commit.get("author", {}).get("email", ""),
            }
        )
        # GitHub includes added/removed/modified in the push payload.
        for key in ("added", "removed", "modified"):
            changed_files_set.update(commit.get(key, []))

    return {
        "repo": repo_slug,
        "branch": branch,
        "commits": commits,
        "changed_files": sorted(changed_files_set),
        "source": "github",
    }


def _extract_bitbucket_pr(payload: dict, event_key: str) -> dict:
    pr = payload.get("pullrequest", {})
    repo_info = payload.get("repository", {})
    return {
        "pr_id": pr.get("id"),
        "title": pr.get("title", ""),
        "description": pr.get("description", ""),
        "repo": repo_info.get("full_name", repo_info.get("slug", "unknown")),
        "source_branch": pr.get("source", {}).get("branch", {}).get("name", ""),
        "target_branch": pr.get("destination", {}).get("branch", {}).get("name", ""),
        "author": pr.get("author", {}).get("display_name", ""),
        "merged_by": payload.get("actor", {}).get("display_name", ""),
        "merge_commit": pr.get("merge_commit", {}).get("hash", "") if event_key == "pullrequest:fulfilled" else "",
        "source": "bitbucket",
        "event": event_key,
    }


def _extract_github_pr(payload: dict) -> dict:
    pr = payload.get("pull_request", {})
    return {
        "pr_id": pr.get("number"),
        "title": pr.get("title", ""),
        "description": pr.get("body", ""),
        "repo": payload.get("repository", {}).get("full_name", "unknown"),
        "source_branch": pr.get("head", {}).get("ref", ""),
        "target_branch": pr.get("base", {}).get("ref", ""),
        "author": pr.get("user", {}).get("login", ""),
        "merged_by": (pr.get("merged_by") or {}).get("login", ""),
        "merge_commit": pr.get("merge_commit_sha", ""),
        "source": "github",
        "event": "pull_request.closed",
    }


# ---------------------------------------------------------------------------
# Background task publishers
# ---------------------------------------------------------------------------

async def _publish_scan_event(push_data: dict) -> None:
    try:
        producer = await get_producer()
        await producer.publish_scan_request(
            repo=push_data["repo"],
            changed_files=push_data["changed_files"],
            priority=1.0,
            source=push_data["source"],
        )
        log.info(
            "webhook.scan_event_published",
            repo=push_data["repo"],
            branch=push_data.get("branch"),
            changed_files_count=len(push_data["changed_files"]),
        )
    except Exception:
        log.exception("webhook.scan_event_publish_failed", repo=push_data.get("repo"))


async def _publish_pr_merged_event(pr_data: dict) -> None:
    try:
        producer = await get_producer()
        await producer.publish(
            topic_key="pr_merged",
            payload=pr_data,
            key=f"{pr_data['repo']}#{pr_data['pr_id']}",
        )
        log.info(
            "webhook.pr_merged_event_published",
            repo=pr_data["repo"],
            pr_id=pr_data["pr_id"],
        )
    except Exception:
        log.exception("webhook.pr_merged_event_publish_failed", repo=pr_data.get("repo"))


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

_BB_SECRET = os.environ.get("ARGOS_BITBUCKET_WEBHOOK_SECRET", "")
_GH_SECRET = os.environ.get("ARGOS_GITHUB_WEBHOOK_SECRET", "")


@router.post("/bitbucket", status_code=204)
async def bitbucket_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature: str | None = Header(default=None, alias="X-Hub-Signature"),
    x_event_key: str | None = Header(default=None, alias="X-Event-Key"),
) -> None:
    """
    Receive Bitbucket webhook events and publish to Kafka.

    Supported X-Event-Key values:
      - repo:push
      - pullrequest:created
      - pullrequest:fulfilled
    """
    body = await request.body()
    _verify_hmac_sha256(_BB_SECRET, body, x_hub_signature)

    event_key = (x_event_key or "").strip()
    log.info("webhook.bitbucket_received", event_key=event_key)

    payload: dict[str, Any] = await request.json()

    if event_key == "repo:push":
        push_data = _extract_bitbucket_push(payload)
        background_tasks.add_task(_publish_scan_event, push_data)

    elif event_key == "pullrequest:created":
        pr_data = _extract_bitbucket_pr(payload, event_key)
        log.info("webhook.bitbucket_pr_created", repo=pr_data["repo"], pr_id=pr_data["pr_id"])

    elif event_key == "pullrequest:fulfilled":
        pr_data = _extract_bitbucket_pr(payload, event_key)
        background_tasks.add_task(_publish_pr_merged_event, pr_data)

    else:
        log.warning("webhook.bitbucket_unhandled_event", event_key=event_key)


@router.post("/github", status_code=204)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
) -> None:
    """
    Receive GitHub webhook events and publish to Kafka.

    Supported X-GitHub-Event values:
      - push
      - pull_request  (action: opened | closed+merged)
    """
    body = await request.body()
    _verify_hmac_sha256(_GH_SECRET, body, x_hub_signature_256)

    event = (x_github_event or "").strip()
    log.info("webhook.github_received", event=event)

    payload: dict[str, Any] = await request.json()
    action: str = payload.get("action", "")

    if event == "push":
        # Ignore tag pushes and branch deletions (after == "0000...").
        after_sha: str = payload.get("after", "")
        if after_sha.replace("0", "") == "":
            log.info("webhook.github_push_ignored", reason="branch_deleted_or_tag")
            return

        push_data = _extract_github_push(payload)
        background_tasks.add_task(_publish_scan_event, push_data)

    elif event == "pull_request":
        if action == "opened":
            pr_data = _extract_github_pr(payload)
            log.info(
                "webhook.github_pr_opened",
                repo=pr_data["repo"],
                pr_id=pr_data["pr_id"],
            )

        elif action == "closed" and payload.get("pull_request", {}).get("merged"):
            pr_data = _extract_github_pr(payload)
            background_tasks.add_task(_publish_pr_merged_event, pr_data)

        else:
            log.info("webhook.github_pr_action_ignored", action=action)

    else:
        log.warning("webhook.github_unhandled_event", event=event, action=action)
