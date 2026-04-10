# ARGOS Configuration Reference

All configuration is done through environment variables loaded from `.env`. This page documents every variable with its type, default, and operational implications.

ARGOS uses Pydantic `BaseSettings` (`argos/config.py`), which means:
- Variables are case-insensitive
- Missing required variables raise a `ValidationError` at startup with a clear message
- `SecretStr` fields are never logged or serialised in plaintext

---

## Claude / Anthropic

| Variable | Type | Default | Required |
|----------|------|---------|---------|
| `ANTHROPIC_API_KEY` | SecretStr | — | **Yes** |
| `CLAUDE_MODEL` | string | `claude-opus-4-6` | No |

**`ANTHROPIC_API_KEY`**
Your Anthropic API key. All 17 agents call Claude Opus 4.6 with `thinking={"type": "adaptive"}`. Without this key the platform will not start.

**`CLAUDE_MODEL`**
Model identifier string. Do not change this unless Anthropic releases a successor model — adaptive thinking and tool use are only guaranteed on Opus 4.6+. Using a Haiku or Sonnet model will significantly degrade agent reasoning quality for complex security analysis.

---

## Bitbucket

| Variable | Type | Default | Required |
|----------|------|---------|---------|
| `BITBUCKET_MODE` | `cloud` \| `datacenter` | `cloud` | No |
| `BITBUCKET_BASE_URL` | string | `https://api.bitbucket.org/2.0` | No |
| `BITBUCKET_TOKEN` | SecretStr | — | For Bitbucket scans |
| `BITBUCKET_WORKSPACE` | string | — | Cloud mode only |
| `BITBUCKET_WEBHOOK_SECRET` | SecretStr | — | For webhook verification |

**`BITBUCKET_MODE`**
Switches the API client between Bitbucket Cloud (REST v2.0) and Bitbucket Data Center (REST v1.0). The two APIs have different pagination, authentication, diff, and search endpoints — setting the wrong mode will cause API errors.

**`BITBUCKET_BASE_URL`**
For Data Center, set this to your self-hosted instance URL: `https://bitbucket.yourcompany.com`. Do not include a trailing slash. For Cloud, leave at the default.

**`BITBUCKET_TOKEN`**
Personal Access Token (PAT) or OAuth token. Required scopes:
- Cloud: `repository:read`, `pullrequest:write`
- Data Center: `REPO_READ`, `REPO_WRITE` project permissions

**`BITBUCKET_WORKSPACE`**
Cloud only. The workspace slug (not the workspace name) visible in Bitbucket Cloud URLs: `bitbucket.org/{workspace}/...`. Not used in Data Center mode where projects provide the namespace.

**`BITBUCKET_WEBHOOK_SECRET`**
Used by the webhook handler to verify HMAC-SHA256 signatures on incoming webhook requests. If left empty, webhook signature verification is skipped with a warning (acceptable for local development, never for production).

---

## GitHub (Optional)

| Variable | Type | Default |
|----------|------|---------|
| `GITHUB_TOKEN` | SecretStr | — |
| `GITHUB_WEBHOOK_SECRET` | SecretStr | — |

**`GITHUB_TOKEN`**
Personal access token or GitHub App installation token. Required scopes: `repo` (read), `pull_requests:write`. Required only if GitHub repos are in scope.

**`GITHUB_WEBHOOK_SECRET`**
Verifies `X-Hub-Signature-256` headers on GitHub webhook delivery. Configure the same secret in your GitHub repository/organization webhook settings.

---

## Kafka

| Variable | Type | Default |
|----------|------|---------|
| `KAFKA_BOOTSTRAP_SERVERS` | string | `localhost:9092` |
| `KAFKA_SECURITY_PROTOCOL` | string | `PLAINTEXT` |
| `KAFKA_SASL_MECHANISM` | string | — |
| `KAFKA_SASL_USERNAME` | string | — |
| `KAFKA_SASL_PASSWORD` | SecretStr | — |

**`KAFKA_BOOTSTRAP_SERVERS`**
Comma-separated list of `host:port` broker addresses. For Docker Compose, this is `localhost:9092`. For production MSK/Confluent, use the cluster's bootstrap endpoint.

**TLS + SASL (production):**

```dotenv
KAFKA_SECURITY_PROTOCOL=SASL_SSL
KAFKA_SASL_MECHANISM=PLAIN
KAFKA_SASL_USERNAME=your-api-key
KAFKA_SASL_PASSWORD=your-api-secret
```

For MSK IAM authentication, use `SASL_SSL` with `AWS_MSK_IAM` mechanism (requires additional boto3 configuration).

---

## Redis

| Variable | Type | Default |
|----------|------|---------|
| `REDIS_URL` | string | `redis://localhost:6379/0` |
| `REDIS_TTL_SECONDS` | int | `3600` |

**`REDIS_URL`**
Standard Redis URL format. Supports: `redis://`, `rediss://` (TLS), `redis://:password@host:port/db`.

**`REDIS_TTL_SECONDS`**
Default TTL for cached values (NVD responses, genealogist metadata). Individual caches may override this. Does not affect Commander approval state (always 24-hour TTL).

---

## PostgreSQL / TimescaleDB

| Variable | Type | Default |
|----------|------|---------|
| `POSTGRES_DSN` | string | `postgresql://argos:argos@localhost:5432/argos` |

**`POSTGRES_DSN`**
asyncpg-compatible connection string. Do not use `postgresql+asyncpg://` (SQLAlchemy format) — asyncpg uses the plain `postgresql://` scheme.

For TimescaleDB Cloud, append `?sslmode=require` to the DSN.

The database schema is initialised automatically on first container start via `infra/postgres/init.sql`. On subsequent starts, all DDL uses `IF NOT EXISTS` — safe to re-run.

---

## Neo4j

| Variable | Type | Default |
|----------|------|---------|
| `NEO4J_URI` | string | `bolt://localhost:7687` |
| `NEO4J_USER` | string | `neo4j` |
| `NEO4J_PASSWORD` | SecretStr | `argos` |

**`NEO4J_URI`**
Use `bolt://` for unencrypted (local), `bolt+s://` for TLS (Neo4j AuraDB, production). The neo4j Python driver also accepts `neo4j://` (auto-routing) for clustered deployments.

**Neo4j AuraDB (production):**

```dotenv
NEO4J_URI=neo4j+s://xxxxxxxx.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=<aura-password>
```

---

## Qdrant

| Variable | Type | Default |
|----------|------|---------|
| `QDRANT_URL` | string | `http://localhost:6333` |
| `QDRANT_API_KEY` | SecretStr | — |

**`QDRANT_URL`**
REST endpoint for the Qdrant instance. The vector layer also uses the gRPC endpoint at port 6334 (auto-derived from the REST URL).

**`QDRANT_API_KEY`**
Required for Qdrant Cloud. Leave empty for local Docker Compose deployment.

The vector layer creates three collections on startup (`vulnerabilities`, `hardware_designs`, `fix_patterns`) if they do not exist. Collection creation is idempotent.

---

## Threat Intelligence

| Variable | Type | Default |
|----------|------|---------|
| `NVD_API_KEY` | SecretStr | — |
| `CISA_KEV_URL` | string | CISA CDN URL |

**`NVD_API_KEY`**
Increases the NVD API rate limit from 5 to 50 requests per 30 seconds. Free registration at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). Strongly recommended for production — without it, large CVE catch-up scans will be slow.

**`CISA_KEV_URL`**
URL of the CISA Known Exploited Vulnerabilities JSON feed. The default points to the official CISA CDN. Override only if your network cannot reach the public internet and you have a mirrored feed.

---

## Alert Channels

All alert channel variables are optional. ARGOS degrades gracefully — if a channel is not configured, Commander skips it.

### Slack

| Variable | Type | Description |
|----------|------|-------------|
| `SLACK_WEBHOOK_URL` | SecretStr | Incoming webhook URL from Slack App configuration |

Creates blocks-formatted messages with finding details, CVSS score, exploitation path, and Approve/Reject buttons. The button actions require a Slack App with Interactivity enabled, pointing back to your API server.

### PagerDuty

| Variable | Type | Description |
|----------|------|-------------|
| `PAGERDUTY_ROUTING_KEY` | SecretStr | Events API v2 integration key (32-character string) |

Triggers incidents only for Critical (CVSS ≥ 9.0) and CISA KEV findings. Severity mapping: `Critical → critical`, `High → error`, `Medium → warning`.

### Email (SMTP)

| Variable | Type | Default |
|----------|------|---------|
| `SMTP_HOST` | string | — |
| `SMTP_PORT` | int | `587` |
| `SMTP_USER` | string | — |
| `SMTP_PASS` | SecretStr | — |
| `ALERT_EMAIL_TO` | string | — |

Used by both Commander (security alerts) and Diplomat (disclosure documents). Uses STARTTLS on port 587. For Gmail, generate an App Password (not your account password).

**Example Gmail configuration:**
```dotenv
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=security-alerts@yourorg.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx    # App Password
ALERT_EMAIL_TO=security-team@yourorg.com
```

---

## Scanning Behaviour

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MAX_PARALLEL_WORKERS` | int | `8` | Kafka consumer coroutines running concurrently in the worker process |
| `MIN_RANKER_SCORE` | int | `3` | Sentinel skips files ranked below this (1–10) |
| `SANDBOX_TIMEOUT_SECONDS` | int | `30` | Maximum time for hardware tool processes (GHDL, binwalk, readelf) |
| `DELTA_SCAN_ENABLED` | bool | `true` | Scan only changed files on push; full scan on schedule/manual |
| `CVE_POLL_INTERVAL_HOURS` | int | `1` | How often Oracle polls NVD |

**`MIN_RANKER_SCORE`**
Sentinel assigns files a 1–10 relevance score before the Claude analysis layers. Files below `MIN_RANKER_SCORE` are skipped entirely (not even L1 checks run). Increase this value to reduce noise on large repos with many low-risk generated files. Decrease to `1` for maximum coverage.

**`DELTA_SCAN_ENABLED`**
When `true`, push webhook events carry only the changed file list and Sentinel analyses only those files. When `false`, every scan triggers a full repo scan. Delta scanning is recommended for repos > 10,000 files.

---

## Disclosure

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `DISCLOSURE_VENDOR_NOTIFY_DAY` | int | `1` | Day to send initial vendor notification |
| `DISCLOSURE_ESCALATION_DAY` | int | `45` | Day to send escalation if no response |
| `DISCLOSURE_PUBLIC_DAY` | int | `90` | Day to publish public advisory |

These match the standard 90-day coordinated disclosure timeline used by Google Project Zero and Anthropic Mythos. Adjust only if you have a standing agreement with a vendor to use a different timeline.

---

## API Server

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `API_HOST` | string | `0.0.0.0` | FastAPI bind address |
| `API_PORT` | int | `8000` | FastAPI port |
| `API_SECRET_KEY` | SecretStr | `change-me-in-production` | Bearer token for sensitive endpoints |

**`API_SECRET_KEY`**
Change this before any deployment. The default value is intentionally obvious as a reminder. The API server will log a warning at startup if the environment is `production` and this is set to the default.

---

## Environment

| Variable | Type | Default | Options |
|----------|------|---------|---------|
| `ENVIRONMENT` | string | `development` | `development` \| `staging` \| `production` |
| `LOG_LEVEL` | string | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |

**`ENVIRONMENT`**
Affects multiple platform behaviours:
- `development`: permissive CORS (`*`), verbose errors, API secret key warning suppressed
- `staging`: restricted CORS, verbose errors, API secret key warning active
- `production`: restricted CORS, minimal error detail in responses, all secrets validated at startup

**`LOG_LEVEL`**
Controls structlog output level. Use `DEBUG` during development to see full Claude prompt/response cycles and memory operation details. Use `INFO` in production to reduce volume. `WARNING` suppresses normal operation logs — only use when debugging specific issues.
