# ARGOS Developer Guide

This guide is for engineers contributing to ARGOS or extending it with new agents, memory backends, or ingestion sources.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Development Workflow](#development-workflow)
3. [Writing a New Agent](#writing-a-new-agent)
4. [Memory System APIs](#memory-system-apis)
5. [Publishing and Consuming Kafka Events](#publishing-and-consuming-kafka-events)
6. [Adding a New Ingestion Source](#adding-a-new-ingestion-source)
7. [Testing](#testing)
8. [Code Style](#code-style)
9. [Adding a New API Endpoint](#adding-a-new-api-endpoint)
10. [The Self-Evolution Contract](#the-self-evolution-contract)

---

## Project Structure

```
argos-security-platform/
├── argos/
│   ├── __init__.py
│   ├── config.py               # All settings (Pydantic BaseSettings)
│   ├── events.py               # All Kafka event schemas (Pydantic models)
│   ├── worker.py               # Entry point: Kafka consumer dispatch loop
│   │
│   ├── ingestion/
│   │   ├── bitbucket.py        # BitbucketClient (Cloud + Data Center)
│   │   ├── webhook.py          # FastAPI webhook router
│   │   ├── kafka_producer.py   # ArgosProducer
│   │   └── kafka_consumer.py   # ArgosConsumer base + make_consumer()
│   │
│   ├── memory/
│   │   ├── store.py            # ArgosMemory — unified facade
│   │   ├── vector.py           # VectorMemory (Qdrant + CodeBERT)
│   │   ├── graph.py            # GraphMemory (Neo4j)
│   │   ├── episodic.py         # EpisodicMemory (TimescaleDB)
│   │   └── procedural.py       # ProceduralMemory (PostgreSQL)
│   │
│   ├── agents/
│   │   ├── base.py             # ArgosAgent ABC + AgentResult
│   │   ├── discovery/          # Navigator, Oracle, Cartographer, Archaeologist, Genealogist
│   │   ├── software/           # Sentinel, Architect, Auditor
│   │   ├── hardware/           # Silicon, PCB, Necromancer
│   │   ├── action/             # Commander, Alchemist, Reporter
│   │   ├── intelligence/       # Prophet, Hypothesis, Diplomat
│   │   └── evolution/          # Breeder, Benchmarker, Adversary
│   │
│   ├── api/
│   │   ├── server.py           # FastAPI app + lifespan
│   │   └── routes/             # scans, findings, agents, repos, bom, webhooks
│   │
│   └── mcp/
│       └── server.py           # FastMCP stdio server for VS Code Copilot
│
├── infra/
│   └── postgres/
│       └── init.sql            # PostgreSQL + TimescaleDB schema
│
├── docs/                       # This documentation
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

---

## Development Workflow

### First-time setup

```bash
git clone https://github.com/stacksry/argos-security-platform.git
cd argos-security-platform
cp .env.example .env            # Add your ANTHROPIC_API_KEY at minimum

# Install uv (if not already installed)
curl -Lsf https://astral.sh/uv/install.sh | sh

# Create virtualenv and install all deps including dev extras
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"

# Start infrastructure (no app containers)
docker compose up -d zookeeper kafka redis postgres neo4j qdrant
```

### Day-to-day development loop

```bash
# Terminal 1 — API server with live reload
uvicorn argos.api.server:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — Kafka worker
python -m argos.worker

# Terminal 3 — your editor / test runner
pytest tests/ -v --tb=short
```

### Running a single agent manually

Every agent can be exercised without the full Kafka pipeline:

```python
import asyncio
from argos.memory.store import ArgosMemory
from argos.agents.software.sentinel import SentinelAgent

async def main():
    memory = await ArgosMemory.create()
    agent = SentinelAgent(memory=memory)

    result = await agent.run({
        "repo": "myorg/backend-service",
        "file": "src/api/auth.py",
        "content": open("src/api/auth.py").read(),
        "branch": "main",
        "head_sha": "abc123",
    })

    print(result.findings)
    await memory.close()

asyncio.run(main())
```

---

## Writing a New Agent

This is the most common extension point. Here is a complete, annotated example of a minimal new agent.

### Step 1 — Create the file

Place software agents in `argos/agents/software/`, hardware in `argos/agents/hardware/`, etc.

```python
# argos/agents/software/my_agent.py
"""
my_agent.py — Scans for <your-vuln-class> vulnerabilities.

Layer hit: L6 (Claude-assisted pattern analysis)
Asset types: SOURCE_CODE
"""
from __future__ import annotations

import logging
from typing import Any

import structlog

from argos.agents.base import ArgosAgent, AgentResult
from argos.events import AssetType, Finding, Severity

log: structlog.BoundLogger = structlog.get_logger(__name__)


class MyAgent(ArgosAgent):
    """
    Detects <your-vuln-class> in Python and JavaScript source files.

    Inherits Claude Opus 4.6 + adaptive thinking from ArgosAgent.
    Reads confirmed patterns from procedural memory as few-shot examples.
    Writes new confirmed patterns back to memory on success.
    """

    # Patterns you want to pre-screen for before calling Claude.
    # Pre-screening is fast (no API call) and reduces false Claude invocations.
    SUSPICIOUS_PATTERNS = [
        r"eval\s*\(",
        r"exec\s*\(",
    ]

    async def run(self, context: dict[str, Any]) -> AgentResult:
        repo = context.get("repo", "")
        file_path = context.get("file", "")
        content = context.get("content", "")
        head_sha = context.get("head_sha", "")

        # ── Step 1: fast pre-screening ─────────────────────────────────────
        import re
        hits = [p for p in self.SUSPICIOUS_PATTERNS if re.search(p, content)]
        if not hits:
            # File looks clean — skip expensive Claude call
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={"reason": "no_suspicious_patterns"},
                error=None,
                duration_ms=0,
                tokens_used=0,
            )

        # ── Step 2: pull few-shot examples from procedural memory ──────────
        examples = await self.memory.get_fix_examples("code_injection", language="python")

        # ── Step 3: build prompt and call Claude ───────────────────────────
        system = """You are a security researcher specialising in code injection vulnerabilities.
Analyse the provided source file for eval/exec injection risks.
Return a JSON array of findings. Each finding must have:
  vuln_class, title, severity (Critical/High/Medium/Low/Info),
  line (integer), cvss_score (float), explanation, fix_suggestion.
If no vulnerabilities found, return [].

Known fix patterns for reference:
""" + examples

        messages = [
            {
                "role": "user",
                "content": f"Repository: {repo}\nFile: {file_path}\n\n```\n{content[:8000]}\n```",
            }
        ]

        response = await self._call_claude(messages, system)
        raw_text = next(
            (b.text for b in response.content if hasattr(b, "text")), ""
        )

        # ── Step 4: parse Claude's response into Finding objects ───────────
        import json, re as _re
        findings: list[Finding] = []
        match = _re.search(r"\[.*?\]", raw_text, _re.DOTALL)
        if match:
            try:
                for item in json.loads(match.group()):
                    findings.append(
                        Finding(
                            repo=repo,
                            file=file_path,
                            line=item.get("line", 0),
                            vuln_class=item.get("vuln_class", "code_injection"),
                            title=item.get("title", "Code Injection"),
                            severity=Severity(item.get("severity", "High")),
                            cvss_score=float(item.get("cvss_score", 7.5)),
                            agent=self.name,
                            commitment_hash=self._sha3_commit(head_sha, file_path),
                        )
                    )
            except (json.JSONDecodeError, KeyError) as exc:
                log.warning("parse_error", agent=self.name, error=str(exc))

        # ── Step 5: record findings to memory and return ───────────────────
        tokens = sum(
            getattr(b, "usage", {}).get("output_tokens", 0)
            for b in [response]
            if hasattr(b, "usage")
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[f.model_dump() for f in findings],
            metadata={"file": file_path, "hits": hits},
            error=None,
            duration_ms=0,   # base class fills this in via _timed_run
            tokens_used=getattr(response, "usage", None) and response.usage.output_tokens or 0,
        )

    @staticmethod
    def _sha3_commit(sha: str, path: str) -> str:
        import hashlib
        return hashlib.sha3_256(f"{sha}:{path}".encode()).hexdigest()
```

### Step 2 — Export from the package

Add your agent to the tier's `__init__.py`:

```python
# argos/agents/software/__init__.py
from .my_agent import MyAgent
__all__ = [..., "MyAgent"]
```

### Step 3 — Register in the worker

Add a consumer route in `argos/worker.py`:

```python
from argos.agents.software.my_agent import MyAgent

# Inside the routes list:
("scan_requested", MyAgent(memory=shared_memory, producer=shared_producer)),
```

### Step 4 — Register in Navigator's routing table

Add the agent to the routing decision prompt in `argos/agents/discovery/navigator.py`:

```python
AGENT_REGISTRY = {
    ...
    "my_agent": "argos.agents.software.my_agent.MyAgent",
}
```

### Important conventions

| Convention | Reason |
|------------|--------|
| Always `await self._call_claude()` — never instantiate `anthropic.AsyncAnthropic` yourself | The base class handles auth, streaming, adaptive thinking, and token counting |
| Parse Claude's JSON output defensively (`try/except`) | Claude occasionally returns malformed JSON or wraps it in prose |
| Truncate file content to ≤ 8000 chars before sending | Prevents hitting context limits on generated files |
| Return `AgentResult(success=True, findings=[])` for clean files | Never raise — the worker must stay up |
| Write successful patterns to procedural memory | This is what makes the platform self-learning |

---

## Memory System APIs

Access memory via the `ArgosMemory` facade in `argos/memory/store.py`. Agents receive the memory object via constructor injection.

### Reading from procedural memory (before scanning)

```python
# Get known fix patterns as a formatted string for prompt injection
examples: str = await self.memory.get_fix_examples(
    vuln_class="sql_injection",
    language="python",        # optional
    limit=5,
)

# Get false positive signals to inject as negative examples
fp_signals: str = await self.memory.get_false_positive_signals(
    vuln_class="sql_injection",
)

# Get confirmed scan patterns from other agents / sandbox
patterns: list[str] = await self.memory.get_confirmed_patterns(
    vuln_class="sql_injection",
)
```

### Writing to procedural memory (after success)

```python
# Record a confirmed fix pattern
await self.memory.record_fix_pattern(
    vuln_class="sql_injection",
    language="python",
    file_extension=".py",
    vulnerable="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
    fix="cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
    repo="myorg/backend-service",
    confirmed_by="my_agent",
)

# Record a false positive signal to suppress future noise
await self.memory.record_false_positive(
    vuln_class="sql_injection",
    file_pattern="tests/",
    signal="test_",
    rejection_reason="Test files use intentionally vulnerable code as fixtures",
)

# Record a CVSS correction from an analyst
await self.memory.record_cvss_correction(
    vuln_class="sql_injection",
    original_score=7.5,
    corrected_score=9.8,
    original_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    corrected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    reason="Query is used for authentication bypass, impact is full compromise",
)
```

### Graph memory (Neo4j)

```python
# Find all repos affected by a vulnerable library version
affected_repos: list[str] = await self.memory.graph.find_blast_radius(
    library_name="lodash",
    version="4.17.20",
)

# Get the full asset context for a repo (dependencies + hardware + findings)
context: dict = await self.memory.graph.get_asset_context(repo="myorg/backend-service")

# Add a dependency relationship
await self.memory.graph.upsert_dependency(
    repo="myorg/backend-service",
    library="express",
    version="4.18.2",
    ecosystem="npm",
)
```

### Semantic search (Qdrant)

```python
# Search for semantically similar past vulnerabilities
similar: list[dict] = await self.memory.search_similar_vulnerabilities(
    code_snippet="cursor.execute(f'SELECT * FROM {table}')",
    vuln_class="sql_injection",  # optional filter
    limit=5,
)

# Index a new finding for future similarity search
await self.memory.index_finding(
    finding_id="abc123",
    code_snippet="...",
    vuln_class="sql_injection",
    metadata={"repo": "myorg/backend-service", "severity": "Critical"},
)
```

### Episodic memory (TimescaleDB)

```python
# Record that a scan completed
await self.memory.episodic.record_scan(
    scan_id="uuid-here",
    repo="myorg/backend-service",
    agent="my_agent",
    findings_count=3,
    duration_ms=4200,
    trigger="push",
    platform="bitbucket",
)

# Query vulnerability trend for a repo (daily buckets, last 30 days)
trend: list[dict] = await self.memory.episodic.get_vulnerability_trend(
    repo="myorg/backend-service",
    days=30,
)
```

---

## Publishing and Consuming Kafka Events

### Publishing from an agent

```python
from argos.ingestion.kafka_producer import ArgosProducer
from argos.events import FindingCreatedEvent, Finding

# Producer is injected via constructor — do not create a new one per agent
producer: ArgosProducer = self.producer

await producer.publish_finding(finding=my_finding)
await producer.publish_scan_request(
    repo="myorg/backend-service",
    branch="main",
    platform="bitbucket",
    priority=8.5,
    trigger="cve_alert",
)
```

### Consuming in the worker

`make_consumer()` wires up a typed consumer for a logical topic key:

```python
from argos.ingestion.kafka_consumer import make_consumer
from argos.events import RepoScanEvent

consumer = make_consumer(
    topic_key="scan_requested",     # maps to "argos.scan.requested"
    group_id="my-agent-group",
    handler=my_async_handler,       # async def handler(msg: dict) -> None
    max_failures=3,
)

await consumer.start()
await consumer.run_forever()       # blocks; handles retries + DLQ internally
```

### Defining a new topic

1. Add the topic name to `TOPICS` in `argos/ingestion/kafka_producer.py`
2. Add the topic → schema mapping to `TOPIC_SCHEMAS` in `argos/events.py`
3. Create a Pydantic model for the payload in `argos/events.py`

---

## Adding a New Ingestion Source

GitLab, Azure DevOps, or a custom webhook are common additions.

### 1. Create a client module

Model after `argos/ingestion/bitbucket.py`. Your client should expose at minimum:

```python
class MyPlatformClient:
    async def list_repos(self, project: str) -> list[dict]: ...
    async def get_file_content(self, repo: str, path: str, ref: str) -> str: ...
    async def get_diff(self, repo: str, base_sha: str, head_sha: str) -> list[str]: ...
    async def create_pull_request(self, repo: str, branch: str, title: str, body: str) -> str: ...
```

### 2. Add a webhook handler

In `argos/ingestion/webhook.py`, add a new router path:

```python
@router.post("/webhooks/myplatform")
async def myplatform_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
):
    # Verify signature
    body = await request.body()
    _verify_hmac_sha256(body, request.headers.get("X-MyPlatform-Signature"), settings.myplatform_webhook_secret.get_secret_value())

    payload = await request.json()
    event_type = request.headers.get("X-MyPlatform-Event")

    if event_type == "push":
        background_tasks.add_task(_publish_scan_event, payload, Platform.MYPLATFORM)

    return {"status": "accepted"}
```

### 3. Add the Platform enum value

In `argos/events.py`:

```python
class Platform(StrEnum):
    BITBUCKET = "bitbucket"
    GITHUB = "github"
    GITLAB = "gitlab"
    MYPLATFORM = "myplatform"  # add this
```

### 4. Update Alchemist for PR creation

In `argos/agents/action/alchemist.py`, add a branch in `_PlatformClient` for your platform's PR API.

---

## Testing

### Test layout

```
tests/
├── unit/
│   ├── test_events.py          # Pydantic model serialisation
│   ├── test_agents/
│   │   ├── test_sentinel.py
│   │   └── test_navigator.py
│   └── test_memory/
│       └── test_procedural.py
├── integration/
│   ├── test_kafka_roundtrip.py # Requires running Kafka
│   └── test_memory_store.py   # Requires running Postgres/Neo4j/Qdrant
└── conftest.py
```

### Running tests

```bash
# Unit tests only (no infrastructure required)
pytest tests/unit/ -v

# Integration tests (requires docker compose up -d)
pytest tests/integration/ -v

# All tests with coverage
pytest --cov=argos --cov-report=html
```

### Testing an agent in isolation

Use `pytest-asyncio` and mock the Claude client:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from argos.agents.software.sentinel import SentinelAgent

@pytest.fixture
def mock_memory():
    memory = MagicMock()
    memory.get_fix_examples = AsyncMock(return_value="")
    memory.get_false_positive_signals = AsyncMock(return_value="")
    memory.get_confirmed_patterns = AsyncMock(return_value=[])
    return memory

@pytest.mark.asyncio
async def test_sentinel_clean_file(mock_memory):
    agent = SentinelAgent(memory=mock_memory)

    result = await agent.run({
        "repo": "test/repo",
        "file": "src/utils.py",
        "content": "def add(a, b):\n    return a + b\n",
        "branch": "main",
        "head_sha": "abc123",
    })

    assert result.success is True
    assert result.findings == []
```

### Mocking Claude responses

```python
from unittest.mock import patch, AsyncMock

MOCK_CLAUDE_RESPONSE = MagicMock()
MOCK_CLAUDE_RESPONSE.content = [
    MagicMock(text='[{"vuln_class": "sql_injection", "title": "SQL Injection", "severity": "Critical", "line": 42, "cvss_score": 9.8, "explanation": "...", "fix_suggestion": "..."}]')
]
MOCK_CLAUDE_RESPONSE.usage.output_tokens = 150

@pytest.mark.asyncio
async def test_sentinel_finds_sqli(mock_memory):
    with patch.object(SentinelAgent, "_call_claude", AsyncMock(return_value=MOCK_CLAUDE_RESPONSE)):
        agent = SentinelAgent(memory=mock_memory)
        result = await agent.run({
            "repo": "test/repo",
            "file": "src/db.py",
            "content": f"cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            "branch": "main",
            "head_sha": "abc123",
        })

    assert len(result.findings) == 1
    assert result.findings[0]["vuln_class"] == "sql_injection"
```

---

## Code Style

ARGOS uses **ruff** for linting and formatting, **mypy** for type checking.

```bash
# Format and lint
ruff format argos/
ruff check argos/ --fix

# Type check
mypy argos/
```

### Configuration (from pyproject.toml)

- Line length: 100 characters
- Python target: 3.12
- mypy: `ignore_missing_imports = true`

### Style conventions

- Use `structlog` for all logging — never `print()` or `logging.getLogger()`
- Use `async/await` throughout — no blocking I/O on the event loop
- Type-annotate all public functions and methods
- Module-level docstring on every file
- Classes without `__init__` beyond what the base provides use `@dataclass` or `BaseModel`

---

## Adding a New API Endpoint

### 1. Add the route to the appropriate module

```python
# argos/api/routes/findings.py
@router.get("/findings/{finding_id}/history")
async def get_finding_history(
    finding_id: str,
    memory: ArgosMemory = Depends(get_memory),
):
    """Return all status changes for a finding from findings_timeline."""
    rows = await memory.episodic.get_finding_history(finding_id)
    return {"finding_id": finding_id, "history": rows}
```

### 2. Add the memory method if needed

In `argos/memory/episodic.py`:

```python
async def get_finding_history(self, finding_id: str) -> list[dict]:
    async with self.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT time, status, agent FROM findings_timeline WHERE finding_id = $1 ORDER BY time",
            finding_id,
        )
    return [dict(r) for r in rows]
```

### 3. Write a test

```python
@pytest.mark.asyncio
async def test_get_finding_history(async_client, seeded_db):
    response = await async_client.get("/api/v1/findings/test-finding-id/history")
    assert response.status_code == 200
    assert "history" in response.json()
```

---

## The Self-Evolution Contract

If you write an agent intended to be spawnable by Breeder, your agent must conform to the following contract so Breeder's generated code validates and integrates cleanly.

### Required interface

```python
class MyNewAgent(ArgosAgent):
    """Single-line description of what this agent scans for."""

    async def run(self, context: dict[str, Any]) -> AgentResult:
        ...
```

### Naming convention

- Class name: `PascalCase`, ending with `Agent`
- Module name: `snake_case`, matching the vuln class (e.g., `riscv_jtag.py` for `RiscVJTAGAgent`)
- `self.name` is derived from the class name automatically by the base class

### Supervised mode behaviour

New agents generated by Breeder start with `supervised_mode=True`. During supervised mode:
- All findings are tagged with `metadata={"supervised": True}`
- Commander always routes them for human review, regardless of CVSS score
- Benchmarker tracks precision separately for supervised vs. autonomous agents
- Promotion to autonomous happens automatically once: `precision > 0.90 AND scan_count >= 50`

You do not need to implement this logic — the base class `_record_performance()` handles the promotion check.
