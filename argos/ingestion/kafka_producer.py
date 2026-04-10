"""
argos/ingestion/kafka_producer.py

Async Kafka producer for the ARGOS security platform.

Every published message is wrapped in a standard envelope::

    {
        "event_id":  "<uuid4>",
        "timestamp": "<ISO-8601 UTC>",
        "source":    "<producer name or caller-supplied value>",
        "topic":     "<logical topic key>",
        "payload":   { ... }
    }

Usage::

    producer = ArgosProducer(bootstrap_servers="kafka:9092")
    await producer.start()

    await producer.publish_scan_request(
        repo="myorg/myrepo",
        changed_files=["src/main.c"],
        priority=0.9,
        source="bitbucket-webhook",
    )

    await producer.stop()

Alternatively use as an async context manager::

    async with ArgosProducer("kafka:9092") as p:
        await p.publish("scan_requested", {"repo": "..."})
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaConnectionError, KafkaError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Topic registry
# ---------------------------------------------------------------------------

TOPICS: dict[str, str] = {
    "scan_requested":   "argos.scan.requested",
    "scan_completed":   "argos.scan.completed",
    "finding_created":  "argos.finding.created",
    "finding_confirmed": "argos.finding.confirmed",
    "pr_merged":        "argos.pr.merged",
    "cve_published":    "argos.cve.published",
    "agent_spawned":    "argos.agent.spawned",
    "alert_required":   "argos.alert.required",
}

# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

_PRODUCER_SOURCE = "argos-producer"


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _build_envelope(topic_key: str, payload: dict, source: str = _PRODUCER_SOURCE) -> dict:
    return {
        "event_id":  str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "source":    source,
        "topic":     topic_key,
        "payload":   payload,
    }


def _json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, default=str).encode("utf-8")


def _key_bytes(key: str | None) -> bytes | None:
    return key.encode("utf-8") if key else None


# ---------------------------------------------------------------------------
# ArgosProducer
# ---------------------------------------------------------------------------


class ArgosProducer:
    """
    Async Kafka producer wrapping ``aiokafka.AIOKafkaProducer``.

    Args:
        bootstrap_servers: Comma-separated Kafka bootstrap servers.
        source:            Default ``source`` field written to every envelope.
                           Defaults to ``"argos-producer"``.
        **kwargs:          Additional keyword arguments forwarded to
                           ``AIOKafkaProducer`` (e.g. ``ssl_context``).
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        source: str = _PRODUCER_SOURCE,
        **kwargs: Any,
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._source = source
        self._extra_kwargs = kwargs
        self._producer: AIOKafkaProducer | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect to Kafka and start the internal send loop."""
        log.info("kafka_producer.starting", bootstrap_servers=self._bootstrap)
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap,
            value_serializer=_json_bytes,
            key_serializer=_key_bytes,
            # Idempotent producer: guarantees exactly-once delivery per partition.
            enable_idempotence=True,
            # Wait for all in-sync replicas before considering a send successful.
            acks="all",
            # Compress messages to reduce network traffic.
            compression_type="lz4",
            **self._extra_kwargs,
        )
        try:
            await self._producer.start()
            log.info("kafka_producer.started")
        except KafkaConnectionError:
            log.exception("kafka_producer.start_failed")
            self._producer = None
            raise

    async def stop(self) -> None:
        """Flush pending messages and close the Kafka connection."""
        if self._producer is not None:
            log.info("kafka_producer.stopping")
            await self._producer.stop()
            self._producer = None
            log.info("kafka_producer.stopped")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "ArgosProducer":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Core publish
    # ------------------------------------------------------------------

    async def publish(
        self,
        topic_key: str,
        payload: dict,
        key: str | None = None,
        source: str | None = None,
    ) -> None:
        """
        Publish a message to a topic identified by its logical key.

        Args:
            topic_key: Key in the ``TOPICS`` registry (e.g. ``"scan_requested"``).
            payload:   Arbitrary dict; will be nested inside the envelope.
            key:       Optional Kafka partition key (string).
            source:    Override the envelope ``source`` field for this message.

        Raises:
            KeyError:    If ``topic_key`` is not found in ``TOPICS``.
            KafkaError:  On send failure.
            RuntimeError: If the producer has not been started.
        """
        if self._producer is None:
            raise RuntimeError("ArgosProducer has not been started; call await producer.start() first.")

        topic_name = TOPICS[topic_key]  # Raises KeyError for unknown keys.
        envelope = _build_envelope(topic_key, payload, source=source or self._source)

        log.debug(
            "kafka_producer.publishing",
            topic=topic_name,
            event_id=envelope["event_id"],
            key=key,
        )

        try:
            await self._producer.send_and_wait(
                topic_name,
                value=envelope,
                key=key,
            )
            log.info(
                "kafka_producer.published",
                topic=topic_name,
                event_id=envelope["event_id"],
            )
        except KafkaError:
            log.exception(
                "kafka_producer.publish_failed",
                topic=topic_name,
                event_id=envelope["event_id"],
            )
            raise

    # ------------------------------------------------------------------
    # Domain-specific helpers
    # ------------------------------------------------------------------

    async def publish_scan_request(
        self,
        repo: str,
        changed_files: list[str],
        priority: float = 1.0,
        source: str = "unknown",
    ) -> None:
        """
        Publish a ``RepoScanEvent`` to ``argos.scan.requested``.

        Args:
            repo:          Full repository slug (e.g. ``"myorg/myrepo"``).
            changed_files: List of file paths that changed.
            priority:      Float in [0.0, 1.0]; higher means scan sooner.
            source:        Origin system (e.g. ``"bitbucket"`` or ``"github"``).
        """
        payload = {
            "repo": repo,
            "changed_files": changed_files,
            "changed_files_count": len(changed_files),
            "priority": priority,
        }
        await self.publish(
            topic_key="scan_requested",
            payload=payload,
            key=repo,
            source=source,
        )

    async def publish_finding(self, finding: dict, source: str | None = None) -> None:
        """
        Publish a security finding to ``argos.finding.created``.

        The ``finding`` dict should contain at minimum:
          - ``repo``       : repository slug
          - ``rule_id``    : identifier of the rule that fired
          - ``severity``   : e.g. ``"CRITICAL"``
          - ``file_path``  : affected file path
          - ``line``       : line number (optional)
          - ``snippet``    : code snippet (optional)
        """
        repo = finding.get("repo", "unknown")
        rule_id = finding.get("rule_id", "unknown")
        await self.publish(
            topic_key="finding_created",
            payload=finding,
            key=f"{repo}::{rule_id}",
            source=source,
        )

    async def publish_alert(self, alert: dict, source: str | None = None) -> None:
        """
        Publish an alert message to ``argos.alert.required``.

        The ``alert`` dict should contain at minimum:
          - ``repo``     : repository slug
          - ``severity`` : e.g. ``"CRITICAL"``
          - ``message``  : human-readable alert description
        """
        repo = alert.get("repo", "unknown")
        await self.publish(
            topic_key="alert_required",
            payload=alert,
            key=repo,
            source=source,
        )

    async def publish_cve(self, cve: dict, source: str | None = None) -> None:
        """
        Publish a CVE event to ``argos.cve.published``.

        The ``cve`` dict should contain at minimum:
          - ``cve_id``   : e.g. ``"CVE-2025-12345"``
          - ``severity`` : CVSS severity string
          - ``packages`` : list of affected package identifiers
        """
        cve_id = cve.get("cve_id", "unknown")
        await self.publish(
            topic_key="cve_published",
            payload=cve,
            key=cve_id,
            source=source,
        )

    async def publish_agent_spawned(self, agent: dict, source: str | None = None) -> None:
        """
        Publish an agent-spawned event to ``argos.agent.spawned``.

        The ``agent`` dict should contain at minimum:
          - ``agent_id``   : unique agent identifier
          - ``agent_type`` : type/class of the agent
          - ``repo``       : repository the agent is working on
        """
        agent_id = agent.get("agent_id", "unknown")
        await self.publish(
            topic_key="agent_spawned",
            payload=agent,
            key=agent_id,
            source=source,
        )
