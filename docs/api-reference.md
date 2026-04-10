# ARGOS API Reference

Base URL: `http://localhost:8000` (development) | `https://argos.yourorg.com` (production)

All endpoints return JSON. Timestamps are ISO 8601 UTC strings. Errors follow RFC 7807 Problem Details format.

---

## Authentication

Sensitive endpoints (scan triggers, status mutations, agent retirement) require a Bearer token:

```http
Authorization: Bearer <API_SECRET_KEY>
```

Set `API_SECRET_KEY` in your `.env` file. Read-only list/get endpoints do not require authentication in the current version.

---

## Health

### `GET /`

Returns platform health and memory system status.

**Response 200**

```json
{
  "service": "ARGOS Security Platform",
  "version": "0.1.0",
  "environment": "development",
  "status": "healthy",
  "memory_stats": {
    "procedural": {
      "fix_patterns": 142,
      "false_positive_signals": 37,
      "confirmed_scan_patterns": 89
    },
    "episodic": {
      "total_scans": 1204,
      "total_findings": 483
    }
  }
}
```

---

## Scans

### `POST /api/v1/scans`

Trigger a manual scan. Publishes a `RepoScanEvent` to Kafka and returns immediately.

**Request body**

```json
{
  "repo": "myorg/backend-service",
  "branch": "main",
  "platform": "bitbucket",
  "priority": 8.0,
  "trigger": "manual",
  "changed_files": []
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repo` | string | Yes | `workspace/repo-slug` format |
| `branch` | string | No | Default: `main` |
| `platform` | string | No | `bitbucket` \| `github` \| `gitlab`. Default: `bitbucket` |
| `priority` | float | No | 0–10 priority score. Default: `5.0`. Navigator may override. |
| `trigger` | string | No | Human-readable trigger label (e.g. `"manual"`, `"cve_alert"`) |
| `changed_files` | array | No | List of relative file paths. Empty = full scan. |

**Response 202 Accepted**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "repo": "myorg/backend-service",
  "status": "queued",
  "message": "Scan queued. Check Kafka topic argos.scan.requested."
}
```

---

### `GET /api/v1/scans`

List recent scans from TimescaleDB episodic memory.

**Query parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo` | string | — | Filter by exact repo slug |
| `days` | integer | 30 | Look-back window in days |
| `limit` | integer | 50 | Maximum results |
| `offset` | integer | 0 | Pagination offset |

**Response 200**

```json
{
  "scans": [
    {
      "time": "2026-04-10T17:00:00Z",
      "scan_id": "550e8400-…",
      "repo": "myorg/backend-service",
      "agent": "navigator",
      "findings_count": 3,
      "duration_ms": 8420,
      "trigger": "push",
      "platform": "bitbucket"
    }
  ],
  "total": 1
}
```

---

### `GET /api/v1/scans/{scan_id}`

Get details for a specific scan.

**Response 200** — same schema as a single item from the list above.

**Response 404** — scan not found.

---

## Findings

### `GET /api/v1/findings/stats`

Aggregate finding counts. Must be called before `GET /api/v1/findings/{id}` in route order (declared first to avoid path capture).

**Query parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo` | string | — | Filter to a specific repo |

**Response 200**

```json
{
  "by_severity": {
    "Critical": 4,
    "High": 12,
    "Medium": 23,
    "Low": 8,
    "Info": 2
  },
  "by_vuln_class": {
    "sql_injection": 7,
    "xss": 5,
    "path_traversal": 3
  },
  "by_repo": {
    "myorg/backend-service": 9,
    "myorg/auth-service": 6
  },
  "total": 49
}
```

---

### `GET /api/v1/findings`

List findings from `triage_records`.

**Query parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `repo` | string | Filter by repo |
| `severity` | string | `Critical` \| `High` \| `Medium` \| `Low` \| `Info` |
| `status` | string | `open` \| `in_fix` \| `fixed` \| `disclosed` \| `false_positive` |
| `vuln_class` | string | Exact vuln class match |
| `limit` | integer | Default: 50 |
| `offset` | integer | Default: 0 |

**Response 200**

```json
{
  "findings": [
    {
      "finding_id": "abc123",
      "vuln_class": "sql_injection",
      "title": "SQL Injection via user-controlled query parameter",
      "repo": "myorg/backend-service",
      "file": "src/api/search.py",
      "severity": "Critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      "route": "sentinel",
      "status": "open",
      "discovery_ts": "2026-04-10T14:22:00Z",
      "disclosure_deadline": "2026-07-09T14:22:00Z",
      "exploitation_path": "Unauthenticated GET /search?q=... directly concatenated into SQL",
      "population_impact": "Affects all 3 repos depending on shared-db-utils v1.2.1",
      "affected_library": "",
      "commitment_hash": "sha3:e3b0c44298fc…",
      "blast_radius": 3,
      "cisa_kev": false,
      "cve_ids": [],
      "notes": ""
    }
  ],
  "total": 1
}
```

---

### `GET /api/v1/findings/{finding_id}`

Get a single finding.

**Response 200** — single finding object (same schema as list item).

**Response 404** — finding not found.

---

### `PATCH /api/v1/findings/{finding_id}`

Update a finding's status.

**Request body**

```json
{
  "status": "false_positive",
  "notes": "This eval() call is sandboxed with ast.literal_eval, not a real risk.",
  "pr_url": ""
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | Yes | New status: `open` \| `in_fix` \| `fixed` \| `disclosed` \| `false_positive` |
| `notes` | string | No | Analyst notes (appended to existing) |
| `pr_url` | string | No | PR URL if status is `in_fix` or `fixed` |

**Response 200**

```json
{
  "finding_id": "abc123",
  "status": "false_positive",
  "updated_at": "2026-04-10T18:00:00Z"
}
```

Setting status to `false_positive` automatically writes a false-positive signal to procedural memory with the `notes` text as the rejection reason.

---

## Agents

### `GET /api/v1/agents`

List all agents with their latest performance metrics.

**Response 200**

```json
{
  "agents": [
    {
      "agent_name": "sentinel",
      "precision": 0.94,
      "recall": 0.88,
      "fp_rate": 0.06,
      "fn_rate": 0.12,
      "scan_count": 214,
      "last_recorded": "2026-04-10T16:00:00Z",
      "supervised_mode": false
    }
  ]
}
```

---

### `GET /api/v1/agents/{agent_name}/stats`

Get detailed performance history for one agent.

**Response 200**

```json
{
  "agent": "sentinel",
  "stats": [
    {
      "precision": 0.94,
      "recall": 0.88,
      "fp_rate": 0.06,
      "fn_rate": 0.12,
      "scan_count": 214,
      "recorded_at": "2026-04-10T16:00:00Z"
    }
  ]
}
```

---

### `POST /api/v1/agents/{agent_name}/retire`

Retire an agent (requires Bearer token). Publishes `AgentRetiredEvent` to Kafka.

**Request body**

```json
{
  "reason": "Superseded by sentinel_v2 with higher precision",
  "final_precision": 0.61,
  "final_recall": 0.79
}
```

**Response 202 Accepted**

```json
{
  "agent": "old_sentinel",
  "status": "retiring",
  "message": "AgentRetiredEvent published. Navigator will stop routing to this agent."
}
```

---

## Repositories

### `GET /api/v1/repos`

List all known repositories from the Neo4j knowledge graph.

**Response 200**

```json
{
  "repos": [
    {
      "name": "myorg/backend-service",
      "platform": "bitbucket",
      "last_scanned": "2026-04-10T15:30:00Z",
      "dependency_count": 47,
      "active_findings": 3
    }
  ]
}
```

---

### `GET /api/v1/repos/{repo}`

Get repo details including dependency list and active findings.

**Path parameter:** `repo` is URL-encoded, e.g., `myorg%2Fbackend-service`.

**Response 200**

```json
{
  "name": "myorg/backend-service",
  "dependencies": [
    {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
    {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
  ],
  "hardware_assets": [],
  "active_findings": 3,
  "blast_radius_member_of": []
}
```

---

### `POST /api/v1/repos`

Register a new repository in the knowledge graph.

**Request body**

```json
{
  "name": "myorg/new-service",
  "platform": "bitbucket",
  "trigger_scan": true
}
```

If `trigger_scan` is true, also publishes a `RepoScanEvent` to Kafka.

**Response 201 Created**

```json
{
  "name": "myorg/new-service",
  "status": "registered"
}
```

---

## Bill of Materials

### `GET /api/v1/bom/{repo}`

Get the dependency bill of materials for a repo.

**Response 200**

```json
{
  "repo": "myorg/backend-service",
  "dependencies": [
    {
      "name": "express",
      "version": "4.18.2",
      "ecosystem": "npm",
      "last_seen": "2026-04-10T15:00:00Z"
    }
  ]
}
```

---

### `POST /api/v1/bom/{repo}`

Bulk-upsert dependency records (called by Cartographer after manifest parsing).

**Request body**

```json
{
  "dependencies": [
    {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
    {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}
  ]
}
```

**Response 200**

```json
{
  "upserted": 2
}
```

---

## Webhooks

### `POST /webhooks/bitbucket`

Bitbucket push/PR webhook receiver.

**Required headers:**

| Header | Description |
|--------|-------------|
| `X-Event-Key` | Bitbucket event type: `repo:push`, `pullrequest:fulfilled`, `pullrequest:created` |
| `X-Hub-Signature` | HMAC-SHA256 of the raw body using `BITBUCKET_WEBHOOK_SECRET` |

Events `repo:push` and `pullrequest:fulfilled` are queued to Kafka. Other event types return 200 and are ignored.

**Response 202 Accepted** — always returned quickly; Kafka publish is a background task.

---

### `POST /webhooks/github`

GitHub push/PR webhook receiver.

**Required headers:**

| Header | Description |
|--------|-------------|
| `X-GitHub-Event` | GitHub event type: `push`, `pull_request` |
| `X-Hub-Signature-256` | HMAC-SHA256 of the raw body using `GITHUB_WEBHOOK_SECRET` |

Branch deletion pushes (all-zero `after` SHA) are silently ignored.

**Response 202 Accepted**

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Finding not found: abc123"
}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request — invalid parameters |
| 401 | Missing or invalid Bearer token |
| 403 | Valid token but insufficient permissions, or webhook HMAC mismatch |
| 404 | Resource not found |
| 422 | Request body validation error (Pydantic) |
| 500 | Internal error — check worker logs |
| 503 | Memory backend unavailable — check docker compose ps |
