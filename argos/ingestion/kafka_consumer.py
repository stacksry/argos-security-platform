"""
argos/ingestion/kafka_consumer.py

Async Kafka consumer base class for ARGOS agents.

Features
--------
- Auto-commit after successful handler execution.
- Exponential back-off retry on transient handler failures.
- Dead-letter queue (DLQ) after ``max_failures`` consecutive errors.
- Structured logging via ``structlog``.
- Clean shutdown via ``stop()`` / async context manager.

Usage::

    async def handle_scan(message: dict) -> None:
        print("scanning", message["payload"]["repo"])

    consumer = ArgosConsumer(
        topic="argos.scan.requested",
        group_id="argos-scanner-agent",
        handler=handle_scan,
        bootstrap_servers="kafka:9092",
    )

    async with consumer:
        await consumer.run_forever()   # blocks until stop() is called

Or spawn the process loop as a background task::

    await consumer.start()
    asyncio.create_task(consumer._process_loop())
    ...
    await consumer.stop()
"""

from __future__ import annotations

import asyncio
import json
import traceback
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, ConsumerRecord
from aiokafka.errors import KafkaConnectionError, KafkaError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------

_DLQ_SUFFIX = ".dlq"
_DEFAULT_MAX_FAILURES = 3
_DEFAULT_BACKOFF_BASE = 2.0    # seconds; back-off = base ** attempt
_DEFAULT_MAX_BACKOFF = 60.0    # seconds


MessageHandler = Callable[[dict], Awaitable[None]]


# ---------------------------------------------------------------------------
# ArgosConsumer
# ---------------------------------------------------------------------------


class ArgosConsumer:
    """
    Async Kafka consumer base class.

    Args:
        topic:             Kafka topic to subscribe to.
        group_id:          Kafka consumer group ID.
        handler:           Async callable invoked with the *decoded envelope dict*
                           for each message.
        bootstrap_servers: Comma-separated Kafka bootstrap servers.
        max_failures:      Number of consecutive handler failures before the
                           message is published to the dead-letter queue.
        backoff_base:      Base for exponential back-off in seconds.
        max_backoff:       Maximum back-off duration in seconds.
        dlq_topic:         Dead-letter topic name; defaults to ``{topic}.dlq``.
        **consumer_kwargs: Additional kwargs forwarded to ``AIOKafkaConsumer``.
    """

    def __init__(
        self,
        topic: str,
        group_id: str,
        handler: MessageHandler,
        bootstrap_servers: str = "localhost:9092",
        max_failures: int = _DEFAULT_MAX_FAILURES,
        backoff_base: float = _DEFAULT_BACKOFF_BASE,
        max_backoff: float = _DEFAULT_MAX_BACKOFF,
        dlq_topic: str | None = None,
        **consumer_kwargs: Any,
    ) -> None:
        self._topic = topic
        self._group_id = group_id
        self._handler = handler
        self._bootstrap = bootstrap_servers
        self._max_failures = max_failures
        self._backoff_base = backoff_base
        self._max_backoff = max_backoff
        self._dlq_topic = dlq_topic or f"{topic}{_DLQ_SUFFIX}"
        self._consumer_kwargs = consumer_kwargs

        self._consumer: AIOKafkaConsumer | None = None
        self._dlq_producer: AIOKafkaProducer | None = None
        self._running = False
        self._stopped = asyncio.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect consumer and DLQ producer to Kafka."""
        log.info(
            "kafka_consumer.starting",
            topic=self._topic,
            group_id=self._group_id,
            bootstrap_servers=self._bootstrap,
        )

        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=self._bootstrap,
            group_id=self._group_id,
            # Deserialise raw bytes to Python dict via JSON; fall back to raw bytes on error.
            value_deserializer=self._deserialise,
            # Start from the earliest unread offset for this group.
            auto_offset_reset="earliest",
            # Disable auto-commit so we can commit only after successful processing.
            enable_auto_commit=False,
            **self._consumer_kwargs,
        )

        self._dlq_producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            acks="all",
        )

        try:
            await self._consumer.start()
            await self._dlq_producer.start()
            self._running = True
            self._stopped.clear()
            log.info("kafka_consumer.started", topic=self._topic)
        except KafkaConnectionError:
            log.exception("kafka_consumer.start_failed", topic=self._topic)
            await self._cleanup()
            raise

    async def stop(self) -> None:
        """Signal the processing loop to stop and close all connections."""
        log.info("kafka_consumer.stopping", topic=self._topic)
        self._running = False
        await self._stopped.wait()
        await self._cleanup()
        log.info("kafka_consumer.stopped", topic=self._topic)

    async def _cleanup(self) -> None:
        if self._consumer is not None:
            try:
                await self._consumer.stop()
            except Exception:
                log.exception("kafka_consumer.consumer_close_error")
            self._consumer = None

        if self._dlq_producer is not None:
            try:
                await self._dlq_producer.stop()
            except Exception:
                log.exception("kafka_consumer.dlq_producer_close_error")
            self._dlq_producer = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "ArgosConsumer":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    async def run_forever(self) -> None:
        """
        Block until ``stop()`` is called.

        Convenience wrapper around ``_process_loop``; suitable for use as
        the main coroutine of an agent process.
        """
        await self._process_loop()

    # ------------------------------------------------------------------
    # Internal: deserialisation
    # ------------------------------------------------------------------

    @staticmethod
    def _deserialise(raw: bytes) -> dict | bytes:
        """Attempt JSON decode; return raw bytes on failure."""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal: process loop
    # ------------------------------------------------------------------

    async def _process_loop(self) -> None:
        """
        Main consumer loop.

        For each message:
          1. Invoke the handler.
          2. On success: commit offset.
          3. On failure: retry up to ``max_failures`` times with exponential back-off.
          4. After ``max_failures`` consecutive failures: publish to DLQ and commit.
        """
        if self._consumer is None:
            raise RuntimeError("Consumer has not been started; call await consumer.start() first.")

        log.info("kafka_consumer.process_loop_started", topic=self._topic)

        try:
            async for record in self._consumer:
                if not self._running:
                    break
                await self._handle_record(record)
        except KafkaError:
            log.exception("kafka_consumer.kafka_error", topic=self._topic)
            raise
        except asyncio.CancelledError:
            log.info("kafka_consumer.cancelled", topic=self._topic)
        finally:
            self._stopped.set()
            log.info("kafka_consumer.process_loop_finished", topic=self._topic)

    async def _handle_record(self, record: ConsumerRecord) -> None:
        """
        Process a single Kafka record with retry and DLQ logic.
        """
        message: dict | bytes = record.value
        partition = record.partition
        offset = record.offset
        key = record.key

        bound_log = log.bind(
            topic=self._topic,
            partition=partition,
            offset=offset,
            key=key.decode("utf-8") if isinstance(key, bytes) else key,
        )

        bound_log.debug("kafka_consumer.record_received")

        for attempt in range(1, self._max_failures + 1):
            try:
                if isinstance(message, bytes):
                    # Could not deserialise; wrap in an error envelope.
                    bound_log.warning(
                        "kafka_consumer.deserialise_failed",
                        raw_preview=message[:200],
                    )
                    await self._send_to_dlq(record, error="DeserialiseError: not valid JSON")
                    break

                await self._handler(message)

                # Success – commit this offset.
                await self._consumer.commit()  # type: ignore[union-attr]
                bound_log.debug("kafka_consumer.record_processed", attempt=attempt)
                return

            except asyncio.CancelledError:
                raise  # Do not suppress cancellation.

            except Exception as exc:  # noqa: BLE001
                backoff = min(self._backoff_base ** attempt, self._max_backoff)
                bound_log.warning(
                    "kafka_consumer.handler_error",
                    attempt=attempt,
                    max_failures=self._max_failures,
                    exc_type=type(exc).__name__,
                    exc_msg=str(exc),
                    backoff_seconds=backoff,
                )

                if attempt >= self._max_failures:
                    # All retries exhausted – send to DLQ.
                    bound_log.error(
                        "kafka_consumer.max_failures_exceeded",
                        topic=self._topic,
                        offset=offset,
                    )
                    await self._send_to_dlq(
                        record,
                        error=f"{type(exc).__name__}: {exc}",
                        traceback_str=traceback.format_exc(),
                    )
                    # Commit even failed messages so we don't get stuck.
                    await self._consumer.commit()  # type: ignore[union-attr]
                    return

                await asyncio.sleep(backoff)

    # ------------------------------------------------------------------
    # Internal: dead-letter queue
    # ------------------------------------------------------------------

    async def _send_to_dlq(
        self,
        record: ConsumerRecord,
        error: str = "",
        traceback_str: str = "",
    ) -> None:
        """
        Publish an unprocessable message to the dead-letter topic.

        The DLQ envelope preserves the original value, key, partition, and
        offset alongside diagnostic information.
        """
        if self._dlq_producer is None:
            log.error("kafka_consumer.dlq_producer_unavailable", topic=self._topic)
            return

        original_value = record.value
        dlq_payload = {
            "dlq_meta": {
                "original_topic": self._topic,
                "original_partition": record.partition,
                "original_offset": record.offset,
                "original_timestamp": record.timestamp,
                "failed_at": datetime.now(tz=timezone.utc).isoformat(),
                "error": error,
                "traceback": traceback_str,
                "consumer_group": self._group_id,
            },
            "original_value": original_value if not isinstance(original_value, bytes)
                              else original_value.decode("utf-8", errors="replace"),
        }

        log.warning(
            "kafka_consumer.sending_to_dlq",
            dlq_topic=self._dlq_topic,
            original_offset=record.offset,
            error=error,
        )

        try:
            await self._dlq_producer.send_and_wait(
                self._dlq_topic,
                value=dlq_payload,
                key=record.key,
            )
        except KafkaError:
            log.exception(
                "kafka_consumer.dlq_send_failed",
                dlq_topic=self._dlq_topic,
            )


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def make_consumer(
    topic_key: str,
    group_id: str,
    handler: MessageHandler,
    bootstrap_servers: str = "localhost:9092",
    **kwargs: Any,
) -> ArgosConsumer:
    """
    Create an ``ArgosConsumer`` using the logical topic key from the TOPICS registry.

    Args:
        topic_key:         Key in ``argos.ingestion.kafka_producer.TOPICS``.
        group_id:          Kafka consumer group ID.
        handler:           Async message handler.
        bootstrap_servers: Kafka bootstrap servers.
        **kwargs:          Additional kwargs forwarded to ``ArgosConsumer``.

    Returns:
        Configured (but not yet started) ``ArgosConsumer``.
    """
    # Import here to avoid circular imports at module level.
    from argos.ingestion.kafka_producer import TOPICS  # noqa: PLC0415

    topic = TOPICS[topic_key]
    return ArgosConsumer(
        topic=topic,
        group_id=group_id,
        handler=handler,
        bootstrap_servers=bootstrap_servers,
        **kwargs,
    )
