# ARGOS Setup Guide

This guide takes you from zero to a running ARGOS instance — local development with Docker, then production-ready configuration.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start (Docker)](#quick-start-docker)
3. [Environment Configuration](#environment-configuration)
4. [Starting the Stack](#starting-the-stack)
5. [Verify the Installation](#verify-the-installation)
6. [Local Python Development (no Docker)](#local-python-development-no-docker)
7. [VS Code Copilot Integration](#vs-code-copilot-integration)
8. [Production Deployment Notes](#production-deployment-notes)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Docker Desktop | 24.x | Enable VirtioFS for volume performance on macOS |
| Docker Compose | v2.x | Included with Docker Desktop |
| Python | 3.12+ | Required only for local development without Docker |
| Git | 2.40+ | Used by Archaeologist agent for history analysis |
| `gh` CLI | 2.x | Optional — only needed to re-create the GitHub repo |

**Optional hardware analysis tools** (install locally for the Silicon/Necromancer agents to use native tools instead of pure-Python fallbacks):

```bash
# macOS
brew install ghdl yosys binwalk
pip install pyelftools capstone

# Ubuntu / Debian
apt-get install ghdl yosys binwalk
pip install pyelftools capstone
```

Ghidra headless analysis is also optional. If `analyzeHeadless` is on your `$PATH`, Necromancer uses it automatically for binaries ≤ 32 MB.

---

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/stacksry/argos-security-platform.git
cd argos-security-platform

# 2. Copy and configure the environment file
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY

# 3. Start the full infrastructure stack
docker compose up -d

# 4. Wait for all services to become healthy (~60 seconds)
docker compose ps

# 5. Start the Kafka worker (in a second terminal)
docker compose exec argos-worker python -m argos.worker
```

The API is now available at **http://localhost:8000**.

---

## Environment Configuration

Copy `.env.example` to `.env` and fill in values. The table below explains every variable.

### Required

| Variable | Example | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | `sk-ant-…` | Your Anthropic API key. All agents use Claude Opus 4.6 with adaptive thinking. Get one at console.anthropic.com. |
| `BITBUCKET_TOKEN` | `ATBBxxx…` | Bitbucket personal access token. Needs `repository:read` and `pullrequest:write` scopes. |
| `BITBUCKET_WORKSPACE` | `myorg` | Your Bitbucket Cloud workspace slug (Cloud mode only). |

### Bitbucket Mode

ARGOS supports both Bitbucket Cloud (REST v2.0) and Bitbucket Data Center (REST v1.0). Set `BITBUCKET_MODE` accordingly:

```dotenv
# Cloud (default)
BITBUCKET_MODE=cloud
BITBUCKET_BASE_URL=https://api.bitbucket.org/2.0
BITBUCKET_WORKSPACE=your-workspace-slug

# Data Center / Server
BITBUCKET_MODE=datacenter
BITBUCKET_BASE_URL=https://bitbucket.yourcompany.com
# BITBUCKET_WORKSPACE is not used in datacenter mode
```

### Infrastructure (Docker defaults work out-of-the-box)

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker address |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `POSTGRES_DSN` | `postgresql://argos:argos@localhost:5432/argos` | TimescaleDB/PostgreSQL DSN |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt connection |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `argos` | Neo4j password |
| `QDRANT_URL` | `http://localhost:6333` | Qdrant REST URL |
| `QDRANT_API_KEY` | *(empty)* | Qdrant API key — leave empty for local |

### Alert Channels (all optional)

| Variable | Description |
|----------|-------------|
| `SLACK_WEBHOOK_URL` | Incoming webhook URL for Slack alerts. Commander agent uses this for human-approval requests. |
| `PAGERDUTY_ROUTING_KEY` | PagerDuty Events API v2 integration key for Critical findings. |
| `SMTP_HOST` / `SMTP_PORT` | SMTP relay for email alerts and disclosure notifications. |
| `SMTP_USER` / `SMTP_PASS` | SMTP credentials. Use app passwords with Gmail. |
| `ALERT_EMAIL_TO` | Default recipient for security alerts and disclosure documents. |

### Threat Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(empty)* | NVD 2.0 API key. Without one, NVD rate-limits to ~5 req/30s. With one, 50 req/30s. Free at nvd.nist.gov. |
| `CISA_KEV_URL` | CISA CDN | URL to the CISA Known Exploited Vulnerabilities JSON feed. |

### Scanning Behaviour

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_PARALLEL_WORKERS` | `8` | Maximum concurrent Kafka consumer loops |
| `MIN_RANKER_SCORE` | `3` | Sentinel skips files ranked below this threshold (1–10 scale) |
| `DELTA_SCAN_ENABLED` | `true` | When `true`, push events only scan changed files. Full scan runs on schedule and manual triggers. |
| `CVE_POLL_INTERVAL_HOURS` | `1` | How often Oracle polls NVD for new CVEs |
| `SANDBOX_TIMEOUT_SECONDS` | `30` | Maximum sandbox PoC execution time |

### API

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | FastAPI bind address |
| `API_PORT` | `8000` | FastAPI port |
| `API_SECRET_KEY` | `change-me-in-production` | Bearer token for sensitive API endpoints. Change before any deployment. |

---

## Starting the Stack

### Infrastructure only

```bash
docker compose up -d zookeeper kafka redis postgres neo4j qdrant
```

Wait for all services to show `healthy`:

```bash
docker compose ps
# Every service should show "healthy" in the Status column
```

### Full stack (including API server)

```bash
docker compose up -d
```

### Kafka worker (separate process, can also be local)

```bash
# Inside Docker
docker compose up -d argos-worker

# Or locally (faster iteration during development)
python -m argos.worker
```

### Service ports at a glance

| Service | Port | URL |
|---------|------|-----|
| ARGOS API | 8000 | http://localhost:8000 |
| Kafka UI | 8080 | http://localhost:8080 |
| Neo4j Browser | 7474 | http://localhost:7474 |
| Qdrant Dashboard | 6333 | http://localhost:6333/dashboard |
| PostgreSQL | 5432 | `psql -U argos -h localhost argos` |
| Redis | 6379 | `redis-cli -h localhost` |

---

## Verify the Installation

### 1. Health check

```bash
curl http://localhost:8000/
```

Expected response:

```json
{
  "service": "ARGOS Security Platform",
  "version": "0.1.0",
  "environment": "development",
  "status": "healthy",
  "memory_stats": { ... }
}
```

### 2. Trigger a test scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"repo": "myorg/backend-service", "branch": "main", "trigger": "manual"}'
```

Expected: `202 Accepted` with a `scan_id`.

### 3. Check Kafka is routing events

Open http://localhost:8080 (Kafka UI). You should see the `argos.scan.requested` topic with one message.

### 4. Check the worker is consuming

```bash
docker compose logs argos-worker --tail=20
```

You should see log entries from the NavigatorAgent routing the scan.

---

## Local Python Development (no Docker)

For rapid agent iteration, run the Python code locally against Docker infrastructure.

### 1. Install uv (fast Python package manager)

```bash
curl -Lsf https://astral.sh/uv/install.sh | sh
```

### 2. Create a virtual environment and install dependencies

```bash
cd argos-security-platform
uv venv --python 3.12
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### 3. Start only the infrastructure services

```bash
docker compose up -d zookeeper kafka redis postgres neo4j qdrant
```

### 4. Run the API and worker locally

```bash
# Terminal 1 — API server with hot reload
uvicorn argos.api.server:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — Kafka worker
python -m argos.worker
```

### 5. Run the test suite

```bash
pytest tests/ -v
```

---

## VS Code Copilot Integration

ARGOS ships an MCP server that exposes all platform capabilities to VS Code Copilot's agent mode.

### Prerequisites

- VS Code 1.90+
- GitHub Copilot extension with agent mode enabled

### Setup

The `.vscode/mcp.json` file is already committed to the repository. When you open the project in VS Code, Copilot will detect the MCP server automatically.

If you are using the ARGOS repo as a dependency (not the project root), add this to your own `.vscode/mcp.json`:

```json
{
  "servers": {
    "argos": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "argos.mcp.server"],
      "env": {
        "ANTHROPIC_API_KEY": "${env:ANTHROPIC_API_KEY}"
      }
    }
  }
}
```

### Available Copilot tools

Once registered, the following tools appear in Copilot's agent panel:

| Tool | What it does |
|------|-------------|
| `argos_scan_repo` | Trigger a security scan on any repo |
| `argos_get_findings` | List findings, optionally filtered by severity |
| `argos_get_stats` | Platform-wide security statistics |
| `argos_acknowledge_finding` | Update a finding's status (false_positive, in_fix, fixed) |
| `argos_memory_stats` | Inspect memory system health |
| `argos_get_agent_performance` | View precision/recall per agent |
| `argos_trigger_disclosure` | Start the 90-day coordinated disclosure workflow |
| `argos_correct_cvss` | Submit an analyst CVSS correction for calibration |

**Example Copilot prompt:**

> `@argos scan the myorg/payment-service repo on the main branch and show me any Critical findings`

---

## Production Deployment Notes

### Change the API secret key

```dotenv
API_SECRET_KEY=<random 32+ character string>
```

### Use managed infrastructure

For production, replace the Docker services with managed equivalents:
- Kafka → Amazon MSK, Confluent Cloud, or Azure Event Hubs
- PostgreSQL/TimescaleDB → Amazon RDS, Timescale Cloud
- Neo4j → Neo4j AuraDB
- Qdrant → Qdrant Cloud
- Redis → Amazon ElastiCache, Redis Cloud

Update the corresponding `*_URL`, `*_DSN`, and `*_URI` environment variables.

### Kafka with TLS/SASL

```dotenv
KAFKA_SECURITY_PROTOCOL=SASL_SSL
KAFKA_SASL_MECHANISM=PLAIN
KAFKA_SASL_USERNAME=your-api-key
KAFKA_SASL_PASSWORD=your-api-secret
```

### Scale workers horizontally

The worker process is stateless — run multiple instances and Kafka's consumer group protocol will partition work across them automatically:

```bash
# Each instance joins consumer group "argos-workers"
docker compose scale argos-worker=4
```

### Restrict CORS in production

Set `ENVIRONMENT=production` in `.env`. The API server narrows CORS origins from `*` to your specific frontend domains automatically.

---

## Troubleshooting

### "Connection refused" on startup

Services need 30–60 seconds to become healthy after `docker compose up -d`. Check status:

```bash
docker compose ps
```

If a service is stuck in `starting`, check its logs:

```bash
docker compose logs postgres --tail=50
```

### Kafka consumer not receiving messages

Verify the topic exists:

```bash
docker compose exec kafka kafka-topics --bootstrap-server localhost:9092 --list
```

If `argos.scan.requested` is missing, the producer may not have connected yet. Check the worker logs.

### Neo4j authentication error

The default credentials are `neo4j` / `argos`. If Neo4j was started before with different credentials, the volume has the old password. Reset it:

```bash
docker compose down -v   # WARNING: destroys all data
docker compose up -d neo4j
```

### ANTHROPIC_API_KEY not found

Ensure `.env` exists (not just `.env.example`) and has the key set. The `get_settings()` call will raise a `ValidationError` at startup if it is missing.

### Out of memory during Qdrant embedding

The CodeBERT model (`microsoft/codebert-base`) requires ~500 MB of RAM. If your Docker Desktop memory limit is below 4 GB, either increase it or the vector layer will silently fall back to hash-based embeddings (which disables semantic similarity search but keeps all other functionality).
