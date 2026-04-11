# ARGOS Architecture

This document describes the system design of the ARGOS security platform — how data flows from a Bitbucket webhook all the way to a fix PR, a CVSS correction, and a self-spawned new agent.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Event-Driven Core](#event-driven-core)
3. [Agent Tiers](#agent-tiers)
4. [Memory System](#memory-system)
5. [Data Flow Walkthroughs](#data-flow-walkthroughs)
6. [Self-Evolution Loop](#self-evolution-loop)
7. [Hardware Security Pipeline](#hardware-security-pipeline)
8. [Kafka Topic Reference](#kafka-topic-reference)

---

## System Overview

ARGOS is built on three architectural principles:

**1. Event-driven, not polling.** Every action in the platform is triggered by a Kafka event. No agent ever polls another agent. This gives the platform horizontal scalability — add more worker processes and Kafka partitions work.

**2. Memory-augmented agents.** Every agent reads learned knowledge before it runs and writes new knowledge after it succeeds. The platform improves automatically with each scan.

**3. Self-evolution.** The Breeder agent generates new specialized scanner agents from discovered vulnerability classes. The Benchmarker retires agents that underperform. ARGOS's agent population adapts over time.

### High-level topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Ingestion Layer                                  │
│  Bitbucket Webhook ──┐                                                  │
│  GitHub Webhook ─────┼──► FastAPI Webhook Handler ──► Kafka Producer   │
│  Manual API call ────┘                                                  │
│  NVD/CISA poller (Oracle) ──────────────────────────► Kafka Producer   │
└─────────────────────────────────────────────────────┬───────────────────┘
                                                      │
                                               Kafka Topics
                                                      │
┌─────────────────────────────────────────────────────▼───────────────────┐
│                        Radar Tier                                       │
│  Navigator ◄── argos.scan.requested    (routes to downstream agents)   │
│  Oracle    ◄── argos.cve.published     (correlates CVEs with assets)   │
│  Cartographer ◄── argos.pr.merged      (updates dependency graph)      │
│  Archaeologist ◄── argos.blast.radius  (traces vuln introduction)      │
│  Genealogist ── (called by Navigator for supply chain analysis)        │
└─────────────────────────────────────────────────────┬───────────────────┘
                                                      │
┌─────────────────────────────────────────────────────▼───────────────────┐
│              Analysis Tier (Software + Hardware)                        │
│  Sentinel   ── 10-layer code scanning                                  │
│  Architect  ── cross-service design flaws                              │
│  Auditor    ── SOC2 / PCI-DSS / HIPAA compliance                       │
│  Silicon    ── VHDL / Verilog hardware description                     │
│  PCB        ── KiCad schematics / PCB layout                          │
│  Necromancer ── firmware binary analysis                               │
└─────────────────────────────────────────────────────┬───────────────────┘
                                                      │
                                               argos.finding.created
                                                      │
┌─────────────────────────────────────────────────────▼───────────────────┐
│                        Action Tier                                      │
│  Commander  ── human-in-the-loop for Critical findings                 │
│  Alchemist  ── generates and opens fix PRs                             │
│  Reporter   ── stakeholder reports, SBOM, HBOM                        │
│  Diplomat   ── 90-day coordinated disclosure                           │
└─────────────────────────────────────────────────────┬───────────────────┘
                                                      │
┌─────────────────────────────────────────────────────▼───────────────────┐
│                     Intelligence + Evolution                            │
│  Prophet    ── predicts at-risk repos from historical trends           │
│  Hypothesis ── reads arXiv cs.CR papers → new vuln patterns           │
│  Breeder    ── spawns new agents from discovered vuln classes          │
│  Benchmarker ── evaluates precision/recall, retires weak agents        │
│  Adversary  ── red-teams all agents with adversarial test cases        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Event-Driven Core

### Kafka

All inter-agent communication passes through Kafka. This means:

- **Agents are decoupled.** Navigator does not call Sentinel directly. It publishes an event; Sentinel (and any future agent) consumes it.
- **Messages are durable.** If the worker process crashes mid-scan, Kafka retains unconsumed messages (7-day retention). Restart the worker and the scan continues.
- **Parallelism is free.** Multiple instances of the same agent can run simultaneously, each consuming a partition.

### The envelope

Every message on every topic uses the same base envelope:

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-04-10T17:00:00.000Z",
  "source": "argos",
  "schema_version": "1.0",
  "topic": "argos.scan.requested",
  "payload": { ... }
}
```

The `payload` structure is defined per topic by the Pydantic models in `argos/events.py`. The worker deserialises each message into the correct model automatically using `TOPIC_SCHEMAS`.

### Dead-letter queue

If a consumer fails to process a message after 3 retries (with exponential back-off), the message is forwarded to `{topic}.dlq` with the original payload, error message, and full traceback. The offset is then committed so the consumer does not get stuck.

Monitor DLQ topics in Kafka UI at http://localhost:8080.

---

## Agent Tiers

### Base class

Every agent inherits from `ArgosAgent` (`argos/agents/base.py`). The base class provides:

| Method | What it does |
|--------|-------------|
| `_call_claude(messages, system)` | Calls Claude Opus 4.6 with `thinking={"type": "adaptive"}`. Streams the response, returns the final message. Thread-safe for asyncio. |
| `_call_claude_agentic(messages, system, tools)` | Full tool-use loop — calls Claude, executes returned tool calls, loops up to 20 iterations. |
| `_priority_score(criticality, recency_hours, exposure)` | Computes `criticality × (1/recency_hours) × exposure`, clamped to [0, 10]. |
| `_record_performance(scan_id, precision, recall, fp_rate)` | Writes agent metrics to episodic memory. |
| `run(context)` | **Abstract.** Implement in every subclass. |

`AgentResult` is the uniform return type:

```python
@dataclass
class AgentResult:
    agent: str
    success: bool
    findings: list[dict]          # serialised Finding objects
    metadata: dict[str, Any]
    error: str | None
    duration_ms: int
    tokens_used: int
```

### Radar tier

| Agent | Trigger | Responsibility |
|-------|---------|---------------|
| Navigator | `argos.scan.requested` | Classifies changed files; Claude decides which downstream agents to activate; publishes activation events |
| Oracle | `argos.cve.published` + schedule | Fetches NVD/CISA KEV; correlates with org assets via Neo4j; produces `BlastRadiusEvent` |
| Cartographer | `argos.pr.merged` + manual | Parses manifests (pom.xml, package.json, go.mod, …); upserts dependency graph in Neo4j |
| Archaeologist | `argos.blast.radius` | Traces which commit introduced a vulnerability; detects regression patterns |
| Genealogist | Called by Navigator | Scores supply chain trust for each dependency (PyPI/npm/Maven/crates.io + OSV advisories) |

### Software tier

| Agent | What it scans |
|-------|-------------|
| Sentinel | Source code — 10-layer pipeline (infra detection → OS checks → language ID → framework fingerprint → vector memory lookup → Claude analysis → concurrent deep layers) |
| Architect | Service topology — broken auth boundaries, missing mTLS, over-privileged service accounts, admin API exposure |
| Auditor | Compliance mapping — maps triage_records to SOC2, PCI DSS 4.0, HIPAA, NIST 800-53, CIS Controls v8 |

### Hardware tier

| Agent | File types | Tools used |
|-------|-----------|-----------|
| Silicon | `.vhd`, `.vhdl`, `.v`, `.sv` | GHDL (simulation), Yosys (synthesis), regex pattern matching |
| PCB | `.kicad_pcb`, `.kicad_sch`, `.brd`, `.sch` | Pure-Python KiCad S-expression parser |
| Necromancer | `.bin`, `.hex`, `.elf`, `.img`, `.fw` | binwalk, strings, readelf, Ghidra headless |

Hardware findings use `layer_hit` values `H1_silicon`, `H2_pcb`, `H3_firmware` and asset types `AssetType.VHDL`, `AssetType.PCB`, `AssetType.FIRMWARE`.

### Action tier

| Agent | What it does |
|-------|-------------|
| Commander | Routes Critical findings (CVSS ≥ 9.0) to human approvers via Slack. Tracks decisions in Redis with 24h TTL. Auto-escalates on timeout. |
| Alchemist | Reads fix_patterns from procedural memory as few-shot examples. Generates code fixes via Claude. Opens PRs on Bitbucket/GitHub/GitLab. Writes successful patterns back to memory. |
| Reporter | Produces four report variants: Executive (business prose), Engineering (full Markdown with CVSS details), Auditor (formal evidence structure), Vendor (coordinated disclosure format). Also produces CycloneDX 1.5 SBOM/HBOM. |
| Diplomat | Runs every hour. Reads open `triage_records`. Sends D+1 vendor notification, D+45 escalation, D+90 public advisory. Writes each document to `disclosure_docs`. |

### Intelligence + Evolution tier

| Agent | Schedule | What it does |
|-------|----------|-------------|
| Prophet | Every 6 hours | Queries TimescaleDB trends; predicts at-risk repos; publishes elevated-priority scan events |
| Hypothesis | Daily | Fetches arXiv cs.CR papers; extracts new vuln classes; writes to confirmed_scan_patterns |
| Breeder | On-demand | Claude generates a complete ArgosAgent subclass; validates with ast.parse(); writes to disk; publishes AgentSpawnedEvent |
| Benchmarker | Weekly | Reads agent_performance_log; calculates precision/recall/F1; retires agents with precision < 0.70 over 20+ scans |
| Adversary | Weekly | Generates subtle + obvious adversarial test cases per agent; measures false-negative rate |

---

## Memory System

ARGOS uses five distinct memory stores, each optimised for a different access pattern.

### Redis — Working memory / cache

**What lives here:**
- NVD API response cache (1-hour TTL)
- CISA KEV list cache (2-hour TTL)
- Genealogist registry metadata cache (1-hour TTL)
- Commander pending-approval state (24-hour TTL)
- In-flight scan state

**Why Redis:** Sub-millisecond reads. All cache access is synchronous with the agent run; network latency matters.

### PostgreSQL + TimescaleDB — Episodic + Procedural memory

Two separate concern spaces share the same database:

**Episodic (TimescaleDB hypertables)** — time-indexed scan history:

| Table | Contents |
|-------|---------|
| `scans` | One row per completed scan: repo, agent, findings_count, duration_ms |
| `findings_timeline` | One row per finding state change: repo, finding_id, vuln_class, severity, status |
| `agent_metrics` | Arbitrary metric timeseries keyed by agent + metric_name |

TimescaleDB's `time_bucket()` makes trend queries efficient at any granularity without manual partitioning.

**Procedural (standard PostgreSQL)** — learned knowledge:

| Table | Contents |
|-------|---------|
| `fix_patterns` | Confirmed `(vulnerable_snippet → fix_snippet)` pairs with confidence counter |
| `false_positive_signals` | Known FP conditions keyed by `(vuln_class, file_pattern, signal)` |
| `cvss_corrections` | Analyst corrections to Claude-generated CVSS scores |
| `ranker_calibrations` | File-ranker misses — teaches Sentinel which files to prioritise |
| `confirmed_scan_patterns` | Patterns confirmed by sandbox, sandbox verdict, and source |
| `agent_performance_log` | Snapshots of precision/recall per agent over time |

**Triage records:**

| Table | Contents |
|-------|---------|
| `triage_records` | Master finding record: CVSS, commitment_hash, disclosure_deadline, blast_radius |
| `disclosure_docs` | Vendor notification, escalation, and public advisory documents |

### Neo4j — Knowledge graph

The graph models relationships that flat tables cannot express efficiently:

```
(Repo)-[:DEPENDS_ON]->(Library)-[:AFFECTED_BY]->(CVE)
(Repo)-[:CONTAINS]->(HardwareAsset)
(Repo)-[:HAS_FINDING]->(Finding)
(Library)-[:DEPENDS_ON]->(Library)   # transitive dependencies
```

Key queries:
- **Blast radius:** `MATCH (r:Repo)-[:DEPENDS_ON*1..5]->(l:Library {name: $lib, version: $ver}) RETURN r.name` — finds all repos transitively depending on a vulnerable library.
- **Asset context:** Returns the full subgraph for a repo in one traversal — all dependencies, hardware assets, and active findings.

### Qdrant — Semantic / vector memory

Three collections:

| Collection | Vector model | Use |
|-----------|-------------|-----|
| `vulnerabilities` | CodeBERT (768-dim, cosine) | Sentinel searches for semantically similar past vulnerabilities before calling Claude |
| `hardware_designs` | CodeBERT | Silicon and PCB search for similar hardware patterns |
| `fix_patterns` | CodeBERT | Alchemist searches for semantically similar past fixes as few-shot examples |

If CodeBERT is unavailable (no GPU, model not downloaded), the embedding layer falls back to a deterministic SHA-256 hash vector. This preserves all platform functionality except semantic similarity search.

---

## Data Flow Walkthroughs

### Walkthrough 1: Push event → vulnerability fix PR

```
1. Developer pushes to main branch
   └─► Bitbucket sends webhook to POST /webhooks/bitbucket

2. Webhook handler verifies HMAC-SHA256 signature
   └─► Publishes RepoScanEvent to argos.scan.requested

3. Navigator consumes event
   ├─► Classifies changed files (Python, config, no hardware)
   ├─► Calls Claude: "which agents should scan these files?"
   └─► Publishes activation events → Sentinel, Genealogist

4. Sentinel runs 10-layer pipeline on each changed file
   ├─► L1-L5: heuristic gates (fast, no Claude call)
   ├─► L6: Claude with few-shot fix_patterns from memory
   └─► Publishes FindingCreatedEvent for each finding

5. Commander receives Critical finding (CVSS 9.8)
   ├─► Sends Slack approval request
   └─► Waits up to 24h for human decision

6. Human approves (or timeout fires)
   └─► Commander publishes approval to argos.scan.requested

7. Alchemist receives the finding
   ├─► Queries fix_patterns: "any known fix for SQL injection in Python?"
   ├─► Fetches vulnerable file from Bitbucket
   ├─► Calls Claude with few-shot examples: "generate a fix"
   ├─► Creates branch → commits fix → opens PR
   └─► Writes (vulnerable_snippet, fix_snippet) to fix_patterns

8. Developer merges the PR
   └─► Bitbucket sends webhook → PRMergedEvent
       └─► Cartographer updates the knowledge graph
```

### Walkthrough 2: New CVE → blast radius assessment

```
1. Oracle polls NVD API every hour
   └─► Finds CVE-2026-XXXXX: critical RCE in lodash < 4.17.22

2. Oracle checks CISA KEV list
   └─► CVE is in KEV (actively exploited in the wild)

3. Oracle queries Neo4j for repos depending on affected lodash versions
   └─► Finds 7 repos with transitive lodash < 4.17.22 dependency

4. Oracle publishes BlastRadiusEvent:
   {cve_id: "CVE-2026-XXXXX", affected_repos: [...], priority: 9.8}

5. Archaeologist receives event
   └─► Queries git history of each affected repo to find introduction commit

6. Commander fires immediate alerts: Slack + PagerDuty

7. Prophet records this pattern in TimescaleDB
   └─► Next run: boosts priority for repos with lodash in manifest
```

---

## Self-Evolution Loop

The most distinctive feature of ARGOS is that its agent population changes over time.

### New agent creation (Breeder)

```
Hypothesis reads arXiv paper:
  "Novel JTAG Exfiltration via Undefined Instruction Traps in RISC-V"
  └─► Extracts: vuln_class="riscv_jtag_trap", patterns=[...], language="verilog"
  └─► Writes to confirmed_scan_patterns with source="hypothesis"

Breeder runs (triggered by Hypothesis event):
  └─► Fetches new vuln class from confirmed_scan_patterns
  └─► Calls Claude: "generate a complete ArgosAgent subclass that scans for riscv_jtag_trap"
  └─► Claude returns full Python source for RiscVJTAGAgent
  └─► ast.parse() validates syntax
  └─► Writes argos/agents/hardware/riscv_jtag.py to disk
  └─► Publishes AgentSpawnedEvent {supervised_mode: true}
```

New agents start in `supervised_mode=True`. All their findings are flagged for human review until the agent achieves >90% precision over 50 confirmed scans.

### Agent retirement (Benchmarker)

```
Benchmarker runs weekly:
  └─► Queries agent_performance_log for all agents, last 30 days
  └─► OldSentinel: precision=0.61 over 27 scans (below 0.70 threshold)
  └─► Publishes AgentRetiredEvent {reason: "poor_precision"}
  └─► Navigator removes OldSentinel from routing decisions
```

### Red-team stress testing (Adversary)

```
Adversary runs weekly against each agent:
  ├─► SUBTLE tests: obfuscated vulns the agent might miss
  │    Example: SQL injection hidden in a multi-line f-string
  └─► OBVIOUS tests: textbook vulns the agent must catch
       Example: eval(user_input) on line 1

Results → agent_performance_log false_negative_rate column
Benchmarker reads this on next cycle and adjusts pass/fail thresholds
```

---

## Hardware Security Pipeline

ARGOS is one of the few security platforms that analyzes hardware assets alongside software. The three hardware agents cover the full embedded hardware stack.

### Asset type detection

Navigator classifies files before routing:

| Extension | Detected as | Routed to |
|-----------|------------|-----------|
| `.vhd`, `.vhdl` | `AssetType.VHDL` | Silicon |
| `.v`, `.sv` | `AssetType.VERILOG` | Silicon |
| `.kicad_pcb`, `.kicad_sch` | `AssetType.PCB` | PCB |
| `.brd`, `.sch` | `AssetType.PCB` | PCB |
| `.bin`, `.hex`, `.elf`, `.img`, `.fw` | `AssetType.FIRMWARE` | Necromancer |

### Silicon agent (VHDL/Verilog)

**Phase 1 — Pattern pre-screening (no external tools):**
- Hardwired JTAG enable signals
- Non-constant-time comparison operations (timing side-channel)
- Unprotected memory-mapped I/O registers
- Trojan counter triggers
- Missing `others` clause in state machine (undefined state transition)
- Lock-bit bypass conditions
- Internal state exposure (`CWE-1189`, `CWE-1231`, `CWE-1234`)

**Phase 2 — Tool-assisted analysis (if installed):**
- GHDL elaboration pass for VHDL — catches structural errors Claude would miss
- Yosys synthesis + stat for Verilog — reveals unexpected combinational paths

**Phase 3 — Claude analysis** with the full hardware CWE taxonomy injected into the system prompt.

### PCB agent (KiCad)

**What it parses:**
- Component reference designators (J1, U3, TP7…)
- Net names (JTAG_TDI, SWD_CLK, UART_TX…)
- Footprint strings (DEBUG, JTAG, UART…)

**What it flags:**
- Populated debug connectors (JTAG, SWD, UART, I2C headers)
- Crypto storage chips (ATECC, W25Q, TPM) without write-protect net connections
- Exposed test points near crypto storage or key material
- Missing bulk bypass capacitors on power rails (glitch attack surface)

### Necromancer agent (Firmware binary)

**Five analysis phases:**
1. **binwalk** — signature + entropy scan; extracts embedded filesystems
2. **strings** — extracts all printable strings ≥ 6 characters
3. **Pattern matching** — checks strings for: hardcoded credentials, AWS keys, PEM headers, known-vulnerable library version strings (OpenSSL 1.0.x, zlib 1.x), telnetd presence, default credential pairs
4. **ELF hardening** (readelf) — checks PIE, stack canaries, NX bit, RELRO, RPATH
5. **Ghidra headless** — identifies calls to dangerous functions (system, popen, execve, strcpy, sprintf, gets) if Ghidra is installed and binary ≤ 32 MB

---

## Kafka Topic Reference

| Topic | Producer | Consumer | Schema |
|-------|---------|----------|--------|
| `argos.scan.requested` | Webhook handler, Oracle, Prophet | Navigator | `RepoScanEvent` |
| `argos.scan.completed` | Navigator (after routing) | Benchmarker | `ArgosEvent` |
| `argos.finding.created` | All analysis agents | Commander, Alchemist, Reporter | `FindingCreatedEvent` |
| `argos.finding.confirmed` | Commander (after approval) | Alchemist | `FindingConfirmedEvent` |
| `argos.finding.resolved` | Alchemist (after PR merge) | Reporter, Diplomat | `FindingResolvedEvent` |
| `argos.pr.merged` | Webhook handler | Cartographer | `PRMergedEvent` |
| `argos.cve.published` | Oracle | Navigator (re-routes as scan) | `CVEPublishedEvent` |
| `argos.blast.radius` | Oracle | Archaeologist, Commander | `BlastRadiusEvent` |
| `argos.agent.spawned` | Breeder | Navigator (adds to routing table) | `AgentSpawnedEvent` |
| `argos.agent.retired` | Benchmarker | Navigator (removes from routing) | `AgentRetiredEvent` |
| `argos.alert.required` | Commander | (external alert sinks) | `AlertRequiredEvent` |
| `{topic}.dlq` | Consumer retry logic | Human / ops monitoring | Raw envelope + error |
