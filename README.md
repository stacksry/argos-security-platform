# ARGOS — Adaptive Reconnaissance & Guard for Organizational Security

> A self-evolving, agentic AI security platform that thinks like an attacker and defends like a guardian.

---

## Overview

ARGOS is a self-evolving agentic AI security platform built on Anthropic's Claude models. It
deploys a coordinated fleet of 17+ specialized agents that continuously discover assets, analyse
software and hardware supply chains, hunt vulnerabilities, execute controlled remediations, and
improve their own strategies — all without human intervention in the critical path. ARGOS is
designed to operate across cloud-native, on-premise, and embedded-hardware environments,
correlating signals from every layer of the stack into a unified, queryable intelligence graph that
security teams can interrogate via a natural-language interface or integrate directly into existing
SIEM/SOAR workflows.

---

## Architecture — Agent Tiers

| Tier | Agent | Responsibility |
|------|-------|----------------|
| **Discovery** | AssetDiscoveryAgent | Network scanning, cloud inventory enumeration |
| **Discovery** | RepoHarvesterAgent | GitHub / GitLab / Bitbucket crawling, secret scanning |
| **Discovery** | SBOMAgent | CycloneDX SBOM generation for all discovered components |
| **Software** | VulnAnalysisAgent | CVE correlation, CVSS scoring, exploitability triage |
| **Software** | CodeAuditAgent | Static analysis, taint tracking, dangerous-pattern detection |
| **Software** | DependencyAgent | Transitive dependency graph construction and risk scoring |
| **Software** | ContainerAgent | Image layer scanning, base-image provenance verification |
| **Hardware** | FirmwareAgent | Firmware unpacking, entropy analysis, secret extraction |
| **Hardware** | HardwareAuditAgent | VHDL/Verilog design review, hardware backdoor detection |
| **Hardware** | ELFAnalysisAgent | ELF binary parsing, symbol table analysis, ROP gadget search |
| **Action** | PatchingAgent | Automated patch generation and PR submission |
| **Action** | RemediationAgent | Controlled exploit execution in sandboxed environments |
| **Action** | AlertingAgent | SIEM/SOAR integration, Slack / PagerDuty notifications |
| **Intelligence** | ThreatIntelAgent | CTI feed ingestion, IOC correlation, actor attribution |
| **Intelligence** | ReportingAgent | Executive and technical report generation |
| **Evolution** | StrategyAgent | Meta-reasoning over past findings; updates agent priorities |
| **Evolution** | SelfImprovementAgent | Generates new agent code, tests it, and hot-loads approved agents |

---

## Quick Start

### Prerequisites

- Docker >= 24 and Docker Compose V2
- Python 3.12+
- An Anthropic API key

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and adjust service credentials
```

### 2. Start infrastructure services

```bash
docker compose up -d
```

This starts Kafka, Redis, PostgreSQL/TimescaleDB, Neo4j, and Qdrant.

### 3. Start the ARGOS worker fleet

```bash
python -m argos.worker
```

### 4. Start the API server (optional)

```bash
uvicorn argos.api.server:app --host 0.0.0.0 --port 8000 --reload
```

The REST API and WebSocket streams will be available at `http://localhost:8000`.

---

## Environment Setup

Create a `.env` file at the project root (never commit this file):

```dotenv
# .env.example — copy to .env and fill in real values

# ── Anthropic ────────────────────────────────────────────────────
ANTHROPIC_API_KEY=sk-ant-...

# ── PostgreSQL / TimescaleDB ─────────────────────────────────────
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=argos
POSTGRES_USER=argos
POSTGRES_PASSWORD=changeme

# ── Redis ────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/0

# ── Neo4j ────────────────────────────────────────────────────────
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme

# ── Qdrant ───────────────────────────────────────────────────────
QDRANT_URL=http://localhost:6333

# ── Kafka ────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# ── Source control (optional) ────────────────────────────────────
GITHUB_TOKEN=ghp_...
GITLAB_TOKEN=glpat-...
BITBUCKET_TOKEN=...
```

---

## Kafka Topics

| Topic | Producer | Consumer | Description |
|-------|----------|----------|-------------|
| `argos.discovery.assets` | AssetDiscoveryAgent | VulnAnalysisAgent, SBOMAgent | Newly discovered assets |
| `argos.discovery.repos` | RepoHarvesterAgent | CodeAuditAgent, DependencyAgent | Repository metadata |
| `argos.sbom.generated` | SBOMAgent | VulnAnalysisAgent, DependencyAgent | CycloneDX SBOM payloads |
| `argos.vulns.found` | VulnAnalysisAgent | PatchingAgent, AlertingAgent, ReportingAgent | Vulnerability findings |
| `argos.hardware.findings` | FirmwareAgent, HardwareAuditAgent | ThreatIntelAgent, ReportingAgent | Hardware-layer findings |
| `argos.actions.patch` | PatchingAgent | RemediationAgent | Patch application instructions |
| `argos.intel.ioc` | ThreatIntelAgent | AlertingAgent, StrategyAgent | Indicators of compromise |
| `argos.evolution.feedback` | StrategyAgent | SelfImprovementAgent | Strategy update signals |
| `argos.reports.ready` | ReportingAgent | AlertingAgent | Completed report notifications |

---

## Memory System

ARGOS uses five complementary memory stores to give agents persistent, context-rich recall:

| Store | Technology | Purpose |
|-------|------------|---------|
| **Short-term / session cache** | Redis | Agent working memory, deduplication bloom filters, rate-limit counters |
| **Time-series events** | PostgreSQL + TimescaleDB | Immutable audit log, vulnerability timelines, metric retention |
| **Knowledge graph** | Neo4j | Asset relationships, dependency graphs, attack-path traversal |
| **Semantic search** | Qdrant | Embedding-based similarity search over code, findings, and threat intel |
| **Structured findings** | PostgreSQL (relational) | Normalised vulnerability records, SBOM data, agent task state |

Agents write to and read from these stores via a unified `MemoryRouter` abstraction, ensuring that
every insight is automatically indexed in all relevant stores without duplicating logic in each
agent.

---

## VS Code Copilot Integration (MCP)

ARGOS exposes an MCP (Model Context Protocol) server so that GitHub Copilot Chat and other
MCP-compatible clients can query the security knowledge graph directly from your editor.

### Setup

1. Ensure `.vscode/mcp.json` exists in the project root (it is already committed).
2. Start the MCP server manually to verify it works:

```bash
python -m argos.mcp.server
```

3. In VS Code, open the Command Palette and run **"MCP: List Servers"** — you should see
   `argos` listed and connected.
4. In Copilot Chat, you can now ask questions like:
   - *"What critical vulnerabilities were found in the last 24 hours?"*
   - *"Show me the attack path from the public API to the database."*
   - *"Which repositories contain hardcoded secrets?"*

The MCP server reads `ANTHROPIC_API_KEY` from your shell environment (passed through
`.vscode/mcp.json`).

---

## Hardware Security Capabilities

ARGOS extends beyond traditional software security to cover the full hardware supply chain:

- **Firmware analysis** — automated unpacking of UEFI, U-Boot, OpenWRT, and vendor firmware
  images; entropy heatmaps to locate encrypted blobs; string and secret extraction.
- **ELF binary analysis** — symbol table inspection, dangerous-function identification,
  ROP gadget enumeration, and function-level control-flow graph generation via `pyelftools`
  and `capstone`.
- **HDL design review** — static analysis of VHDL and Verilog source for timing side-channels,
  Trojan insertion points, and insecure cryptographic primitives using `PyVHDL`.
- **SBOM for silicon** — extension of CycloneDX SBOMs to include firmware components,
  third-party IP cores, and open-source HDL libraries.

Install the optional hardware extras to enable all capabilities:

```bash
pip install "argos-security-platform[hardware]"
# Also install system tools: binwalk, strings, objdump
```

---

## Self-Evolution

ARGOS is designed to improve itself over time through two dedicated agents:

**StrategyAgent** continuously monitors aggregate findings across all agents and updates a
priority-weight matrix that governs how the worker fleet allocates compute. If firmware
vulnerabilities are spiking, StrategyAgent raises the scheduling priority of FirmwareAgent and
HardwareAuditAgent automatically.

**SelfImprovementAgent** goes further: it uses Claude to draft new agent implementations in
response to newly discovered attack patterns, runs them in an isolated sandbox environment,
evaluates their output against a quality rubric, and — if they pass — hot-loads them into the
running worker fleet without a deployment cycle.

All generated code is committed to a dedicated `agents/generated/` branch for human review.
The hot-load mechanism is gated by a configurable confidence threshold and can be disabled
entirely via `ARGOS_SELF_IMPROVE=false` in `.env`.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Run the linter: `ruff check argos/`
4. Run tests: `pytest`
5. Open a pull request — all CI checks must pass before merge.

Please follow the existing code style (Ruff, 100-character line length) and include tests for any
new agent or capability.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Copyright (c) 2024 stacksry
