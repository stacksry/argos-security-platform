"""
worker.py — ARGOS Kafka consumer worker.

Consumes events from all argos.* topics and dispatches to the appropriate
agents.  Each topic gets its own consumer + agent instance running
concurrently via asyncio.gather.

Run:
    python -m argos.worker

Environment variables are read from .env via argos.config.settings.

Topic → Agent routing
---------------------
  argos.scan.requested    → NavigatorAgent   (routes to sub-agents)
  argos.cve.published     → OracleAgent      (threat intel correlation)
  argos.finding.created   → ArchitectAgent   (impact / design analysis)
  argos.finding.confirmed → SentinelAgent    (confirmed exploit follow-up)
  argos.pr.merged         → CartographerAgent (graph / dependency update)
  argos.blast.radius      → ArchaeologistAgent (historical context)
  argos.agent.spawned     → NavigatorAgent   (routing table refresh)
"""

from __future__ import annotations

import asyncio
import signal
import sys
from typing import Any

import structlog

from argos.config import settings
from argos.ingestion.kafka_consumer import ArgosConsumer
from argos.memory.store import ArgosMemory
from argos.ingestion.kafka_producer import ArgosProducer

# ── Agents ────────────────────────────────────────────────────────────────────
from argos.agents.discovery.navigator import NavigatorAgent
from argos.agents.discovery.oracle import OracleAgent
from argos.agents.discovery.archaeologist import ArchaeologistAgent
from argos.agents.discovery.cartographer import CartographerAgent
from argos.agents.software.sentinel import SentinelAgent
from argos.agents.software.architect import ArchitectAgent

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Topic → (consumer group, agent class) mapping
# ---------------------------------------------------------------------------

TOPIC_ROUTING: list[tuple[str, str, type]] = [
    # (kafka_topic, consumer_group_id, AgentClass)
    ("argos.scan.requested",    "argos-navigator",     NavigatorAgent),
    ("argos.cve.published",     "argos-oracle",        OracleAgent),
    ("argos.finding.created",   "argos-architect",     ArchitectAgent),
    ("argos.finding.confirmed", "argos-sentinel",      SentinelAgent),
    ("argos.pr.merged",         "argos-cartographer",  CartographerAgent),
    ("argos.blast.radius",      "argos-archaeologist", ArchaeologistAgent),
    ("argos.agent.spawned",     "argos-navigator-meta", NavigatorAgent),
]


# ---------------------------------------------------------------------------
# Handler factory
# ---------------------------------------------------------------------------

def _make_handler(agent, producer: ArgosProducer):
    """
    Return an async message handler that dispatches a Kafka envelope to the
    given agent's run() method.

    The envelope format is::

        {
            "event_id": "...",
            "timestamp": "...",
            "source": "...",
            "topic": "...",
            "payload": { ... }   ← passed as context to agent.run()
        }
    """
    async def handler(message: dict[str, Any]) -> None:
        payload: dict[str, Any] = message.get("payload", message)
        context: dict[str, Any] = {
            "event_id": message.get("event_id", ""),
            "source": message.get("source", ""),
            "topic": message.get("topic", ""),
            **payload,
        }
        log.debug(
            "worker.dispatching",
            agent=agent.name,
            event_id=context.get("event_id"),
        )
        result = await agent._timed_run(context)
        if not result.success:
            log.error(
                "worker.agent_failed",
                agent=agent.name,
                error=result.error,
                duration_ms=result.duration_ms,
            )
        else:
            log.info(
                "worker.agent_done",
                agent=agent.name,
                findings=len(result.findings),
                duration_ms=result.duration_ms,
            )

    return handler


# ---------------------------------------------------------------------------
# Main worker
# ---------------------------------------------------------------------------

async def run_worker() -> None:
    log.info("worker.initialising")

    # Shared memory and producer for all agent instances.
    memory = await ArgosMemory.create(
        qdrant_host=settings.qdrant_url.split("://")[-1].split(":")[0],
        qdrant_port=int(settings.qdrant_url.split(":")[-1]) if ":" in settings.qdrant_url.split("://")[-1] else 6333,
        qdrant_api_key=settings.qdrant_api_key.get_secret_value() or None,
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password.get_secret_value(),
        pg_dsn=settings.postgres_dsn,
    )

    producer = ArgosProducer(bootstrap_servers=settings.kafka_bootstrap_servers)
    await producer.start()

    # Build one consumer per topic route.
    consumers: list[ArgosConsumer] = []
    for topic, group_id, AgentClass in TOPIC_ROUTING:
        agent = AgentClass(memory=memory, producer=producer)
        handler = _make_handler(agent, producer)
        consumer = ArgosConsumer(
            topic=topic,
            group_id=group_id,
            handler=handler,
            bootstrap_servers=settings.kafka_bootstrap_servers,
        )
        consumers.append(consumer)
        log.info(
            "worker.consumer_registered",
            topic=topic,
            group_id=group_id,
            agent=AgentClass.name,
        )

    # Start all consumers.
    for consumer in consumers:
        await consumer.start()

    log.info("worker.running", consumer_count=len(consumers))

    # Graceful shutdown on SIGINT / SIGTERM.
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        log.info("worker.signal_received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    # Run all consumer process loops concurrently.
    process_tasks = [
        asyncio.create_task(consumer.run_forever(), name=f"consumer-{consumer._topic}")
        for consumer in consumers
    ]

    # Wait until a stop signal is received.
    await stop_event.wait()
    log.info("worker.stopping")

    # Cancel all consumer tasks.
    for task in process_tasks:
        task.cancel()
    await asyncio.gather(*process_tasks, return_exceptions=True)

    # Clean up.
    for consumer in consumers:
        try:
            await consumer.stop()
        except Exception:
            pass

    await producer.stop()
    await memory.close()
    log.info("worker.stopped")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )

    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        sys.exit(0)
