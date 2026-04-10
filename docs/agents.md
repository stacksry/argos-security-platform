# ARGOS Agent Reference

Detailed reference for all 17 ARGOS agents — inputs, outputs, memory interactions, and tuning guidance.

---

## Base Agent Contract

Every agent inherits from `ArgosAgent` (`argos/agents/base.py`).

**Constructor arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `memory` | `ArgosMemory` | Shared memory facade — injected by the worker |
| `producer` | `ArgosProducer` | Shared Kafka producer — injected by the worker |
| `settings` | `Settings` | Platform config — defaults to the singleton from `argos.config` |

**Uniform return type — `AgentResult`:**

```python
@dataclass
class AgentResult:
    agent: str           # agent class name
    success: bool        # False only on unhandled exception
    findings: list[dict] # serialised Finding objects
    metadata: dict       # agent-specific context (files scanned, patterns hit, etc.)
    error: str | None    # exception message if success=False
    duration_ms: int     # wall-clock run time
    tokens_used: int     # Claude output tokens consumed
```

**`Finding` model key fields:**

| Field | Type | Description |
|-------|------|-------------|
| `finding_id` | string | UUID-based identifier (auto-generated) |
| `repo` | string | `workspace/slug` format |
| `file` | string | Repo-relative file path |
| `line` | int | Line number of the vulnerable code |
| `vuln_class` | string | Short identifier, e.g. `sql_injection`, `jtag_exposed` |
| `title` | string | Human-readable one-line description |
| `severity` | Severity | `Critical` \| `High` \| `Medium` \| `Low` \| `Info` |
| `cvss_score` | float | CVSS v3.1 base score (0.0–10.0) |
| `cvss_vector` | string | Full CVSS vector string |
| `layer_hit` | string | Layer identifier: `L1`–`L6` (software), `H1`–`H3` (hardware) |
| `asset_type` | AssetType | `source_code` \| `firmware` \| `pcb` \| `vhdl` \| `verilog` |
| `cisa_kev` | bool | Whether the related CVE is in the CISA KEV catalogue |
| `blast_radius` | int | Number of other repos affected by the same vulnerability |
| `commitment_hash` | string | SHA-3 hash of `head_sha:file_path` — proof of prior discovery |

---

## Discovery Tier

### Navigator

**File:** `argos/agents/discovery/navigator.py`
**Kafka trigger:** `argos.scan.requested`
**Purpose:** The central router. Classifies changed files by asset type and calls Claude to decide which downstream agents to activate.

**Pipeline:**

1. Fetches the diff between `base_sha` and `head_sha` from Bitbucket/GitHub
2. Classifies each changed file into: `vhdl`, `kicad`, `firmware`, `code`, `iac`, `manifests`, `docs`, `other`
3. Calls Claude with the file classification and a compact routing policy system prompt
4. Parses Claude's JSON response: `{"agents": ["sentinel", "genealogist"], "reasoning": "..."}`
5. Falls back to deterministic rules if Claude is unavailable or returns malformed JSON
6. Publishes `RepoScanEvent` for each activated agent to `argos.scan.requested`

**Fallback routing rules:**

| File type | Agents activated |
|-----------|----------------|
| `.vhd`, `.vhdl` | silicon |
| `.v`, `.sv` | silicon |
| `.kicad_pcb`, `.kicad_sch` | pcb |
| `.bin`, `.hex`, `.elf`, `.fw` | necromancer |
| `.tf`, `.yaml`, `.yml` | sentinel |
| `.py`, `.js`, `.ts`, `.go`, `.java`, `.rb` | sentinel |
| `requirements.txt`, `package.json`, `pom.xml`, `Cargo.toml` | genealogist, cartographer |

**Tuning:** Adjust the routing policy in the Navigator's system prompt. The prompt is in `_build_routing_prompt()` and can be extended with org-specific rules without changing logic.

---

### Oracle

**File:** `argos/agents/discovery/oracle.py`
**Kafka trigger:** Schedule (every `CVE_POLL_INTERVAL_HOURS` hours) + `argos.cve.published`
**Purpose:** Fetches new CVEs from NVD and the CISA KEV list. Correlates them with org assets via the Neo4j dependency graph.

**Pipeline:**

1. Polls NVD CVE 2.0 API with date range filter (`lastModStartDate` = last poll timestamp)
2. Fetches CISA KEV list (cached 2 hours in Redis)
3. For each new CVE: queries Neo4j for `(Repo)-[:DEPENDS_ON*1..5]->(Library)` affected by the CVE
4. Calls Claude to synthesise urgency rating: `IMMEDIATE / HIGH / MEDIUM / LOW`
5. Publishes `CVEPublishedEvent` and `BlastRadiusEvent` for affected repos

**Rate limiting:**
- Without `NVD_API_KEY`: 5 requests per 30 seconds (0.7s sleep between calls)
- With `NVD_API_KEY`: 50 requests per 30 seconds (0.1s sleep)

**Memory reads:** Neo4j dependency graph
**Memory writes:** Redis CVE cache (1-hour TTL)

---

### Cartographer

**File:** `argos/agents/discovery/cartographer.py`
**Kafka trigger:** `argos.pr.merged` + manual scan
**Purpose:** Parses dependency manifests and builds/updates the Neo4j knowledge graph.

**Supported manifest formats:**

| Format | Parser | Notes |
|--------|--------|-------|
| `pom.xml` | ElementTree | Extracts `<groupId>:<artifactId>` + `<version>` |
| `package.json` | json | Reads `dependencies` + `devDependencies` |
| `go.mod` | regex | Extracts `require` block entries |
| `requirements.txt` | regex | Handles version specifiers (==, >=, ~=) |
| All others | Claude | Falls back to LLM parsing for Pipfile, Cargo.toml, build.gradle, etc. |

**Graph writes:**
- `MERGE (r:Repo {name: $repo})`
- `MERGE (l:Library {name: $name, version: $version})`
- `MERGE (r)-[:DEPENDS_ON {ecosystem: $eco, last_seen: $ts}]->(l)`

**Memory reads:** None
**Memory writes:** Neo4j dependency graph

---

### Archaeologist

**File:** `argos/agents/discovery/archaeologist.py`
**Kafka trigger:** `argos.blast.radius`
**Purpose:** Traces which commit introduced a vulnerability. Detects regression patterns (fix-then-revert).

**Pipeline:**

1. Fetches commit history for the vulnerable file (up to 100 commits)
2. For each commit, fetches the diff (truncated to 1500 chars to stay within context)
3. Calls Claude with commit history + diffs to reason about:
   - Which commit introduced the vulnerability
   - Whether it was intentional (backdoor) or accidental
   - Whether it regressed (was fixed then reintroduced)
4. Returns structured provenance: `{introduction_commit, was_regression, prior_fix_sha, was_intentional, confidence: HIGH|MEDIUM|LOW}`

**Public helpers (callable independently):**
- `find_introduction_commit(repo, file, vuln_description)` — returns the SHA of the introducing commit
- `detect_regression(repo, file, vuln_description)` — returns True if a prior fix was reverted

**Memory reads:** None (reads directly from SCM)
**Memory writes:** None (results appended to Finding metadata)

---

### Genealogist

**File:** `argos/agents/discovery/genealogist.py`
**Kafka trigger:** Called by Navigator for repos with manifest changes
**Purpose:** Scores supply chain trust for each dependency.

**Data sources (all fetched concurrently via `asyncio.gather`):**

| Registry | API endpoint | Data retrieved |
|----------|-------------|----------------|
| PyPI | `pypi.org/pypi/{name}/json` | Maintainers, release date, download stats, classifiers |
| npm | `registry.npmjs.org/{name}` | Maintainers, last publish, deprecated flag |
| Maven Central | `search.maven.org/solrsearch` | Group/artifact metadata |
| crates.io | `crates.io/api/v1/crates/{name}` | Owners, last updated, yanked flag |
| OSV | `api.osv.dev/v1/query` | Active advisory count for exact version |

**Trust score (0.0–1.0):**
Claude scores each dependency based on: maintainer count, last publish date, download volume, open advisory count, yanked/deprecated status, and suspicious metadata patterns. Flagged as: `none / abandoned / suspicious / compromised`.

**Fallback scoring (when Claude unavailable):**
- Active advisory > 0 → score ≤ 0.4
- Last published > 2 years ago → score penalty -0.2
- Yanked or deprecated → score 0.1

**Memory reads:** Redis (1-hour TTL per package)
**Memory writes:** None (results flow into Navigator's routing priority)

---

## Software Tier

### Sentinel

**File:** `argos/agents/software/sentinel.py`
**Purpose:** The primary source code scanner. 10-layer structured discovery pipeline.

**Layers:**

| Layer | Description | Claude? |
|-------|-------------|---------|
| L1 | Infrastructure file detection (Dockerfile, Kubernetes YAML, Terraform) | No |
| L2 | OS/base-image weakness checks (outdated base images, root user) | No |
| L3 | Language detection from file extension and shebangs | No |
| L4 | Framework fingerprinting (Django, Flask, Spring, Express…) | No |
| L5 | Qdrant vector search — semantically similar past vulnerabilities | No |
| L6 | Claude analysis with few-shot fix patterns from procedural memory | Yes |
| L7 | Dependency version range check against known CVEs (via Neo4j) | No |
| L8 | Authentication and authorisation pattern analysis | Yes |
| L9 | Cryptographic implementation review | Yes |
| L10 | Business logic vulnerability analysis | Yes |

L7–L10 run concurrently (`asyncio.gather`) and only on files that have findings from L6.

**Memory reads:** Qdrant (similar vulnerabilities), PostgreSQL (fix patterns, FP signals, confirmed patterns)
**Memory writes:** PostgreSQL (fix patterns after Alchemist confirms), Qdrant (new findings indexed)
**Min ranker score:** Files scored < `MIN_RANKER_SCORE` (default: 3) are skipped entirely.

---

### Architect

**File:** `argos/agents/software/architect.py`
**Purpose:** Analyzes cross-service architecture for design-level security flaws that no single-file scanner can detect.

**What it looks for:**
- Broken authentication boundaries (service A calls service B without auth)
- Admin APIs exposed to the internet (no network policy)
- Shared secrets across services (same DB credentials in 3 repos)
- Missing mTLS between internal services
- Over-privileged service accounts
- Missing network segmentation (all services in the same subnet)

**Input context:** Neo4j `get_asset_context()` subgraph — all dependencies, services, and hardware assets for an org prefix.

**Finding format:** `file = "[architecture] auth_boundaries"` (no line number — architecture findings are system-level).

**Memory reads:** Neo4j (asset context, cross-repo patterns)
**Memory writes:** None

---

### Auditor

**File:** `argos/agents/software/auditor.py`
**Purpose:** Maps existing findings to compliance framework controls. Identifies gaps.

**Supported frameworks:**

| Framework | Version | Key controls covered |
|-----------|---------|---------------------|
| SOC 2 Type II | 2022 | CC6-CC9 (Logical Access, System Operations) |
| PCI DSS | 4.0 | Requirements 6, 8, 10, 11 |
| HIPAA | 2024 | 164.312(a)-(e) Technical Safeguards |
| FIPS 140-2/3 | — | Cryptographic module requirements |
| NIST 800-53 | Rev 5 | AC, AU, IA, SA, SI control families |
| CIS Controls | v8 | Controls 4, 6, 8, 12, 16 |

**Outputs:**
- `generate_report(repo, framework)` — compliance gap report for a specific framework
- `generate_evidence_package(repo, framework)` — auditor-ready evidence with prose descriptions
- `detect_compliance_drift(repo)` — compares current findings against historical baseline

**Memory reads:** PostgreSQL (triage_records), TimescaleDB (scan history for drift detection)
**Memory writes:** None

---

## Hardware Tier

### Silicon

**File:** `argos/agents/hardware/silicon.py`
**Asset types:** `VHDL`, `VERILOG`
**Layer hit:** `H1_silicon`
**Purpose:** Analyzes hardware description language files for security vulnerabilities.

**Vulnerability classes detected:**

| CWE | Vuln class | Description |
|-----|-----------|-------------|
| CWE-1189 | `mmio_unprotected` | Unprotected memory-mapped I/O registers |
| CWE-1231 | `lock_bypass` | Register lock bit can be bypassed |
| CWE-1234 | `state_exposure` | Internal state exposed via debug interface |
| — | `jtag_hardwired` | JTAG enable signal tied to constant |
| — | `timing_side_channel` | Non-constant-time comparison in crypto path |
| — | `hardware_trojan` | Unexpected counter triggers in netlist |
| — | `fsm_undefined_state` | State machine missing `others` clause |

**External tools (graceful fallbacks if not installed):**
- `ghdl --elab-check` — VHDL elaboration validation
- `yosys -p "synth; stat"` — Verilog synthesis analysis

**Memory reads:** Qdrant (similar hardware designs)
**Memory writes:** Qdrant (new hardware findings indexed)

---

### PCB

**File:** `argos/agents/hardware/pcb.py`
**Asset type:** `PCB`
**Layer hit:** `H2_pcb`
**Purpose:** Analyzes PCB layout and schematic files for hardware security issues.

**Vulnerability classes detected:**

| Vuln class | Description |
|-----------|-------------|
| `jtag_exposed` | Populated JTAG/SWD debug connector found |
| `uart_exposed` | Populated UART header found |
| `crypto_storage_unprotected` | Crypto chip (ATECC, W25Q, TPM) without WP# net connection |
| `test_point_exposure` | Test points near crypto storage or key material |
| `missing_glitch_protection` | Insufficient bypass capacitors on power rails |

**KiCad parser:** Pure-Python S-expression reader — no external tools required. Handles KiCad v6/v7 `.kicad_pcb` and `.kicad_sch` formats. Eagle `.brd`/`.sch` format support is partial (falls back to Claude parsing).

**Component detection:** Matches component reference designators (`J*`, `P*`, `CN*`) against footprint strings containing: `JTAG`, `SWD`, `DEBUG`, `UART`, `CONSOLE`.

**Memory reads:** Qdrant (similar PCB designs)
**Memory writes:** Qdrant (new PCB findings indexed)

---

### Necromancer

**File:** `argos/agents/hardware/necromancer.py`
**Asset type:** `FIRMWARE`
**Layer hit:** `H3_firmware`
**Purpose:** Analyzes firmware binaries without source code.

**Five analysis phases:**

| Phase | Tool | Fallback |
|-------|------|---------|
| 1. File carving | binwalk | Skip if not installed |
| 2. String extraction | `strings -n 6` | Pure-Python printable byte extraction |
| 3. Credential/secret detection | Pattern matching | (no fallback needed — pure Python) |
| 4. ELF hardening | `readelf -W -l -d` | Skip if not installed |
| 5. Dangerous function calls | Ghidra headless | Skip if not installed, or binary > 32 MB |

**String patterns screened:**

| Pattern | Example match |
|---------|-------------|
| Hardcoded password | `password=admin123` |
| AWS access key | `AKIAIOSFODNN7EXAMPLE` |
| PEM private key | `-----BEGIN RSA PRIVATE KEY-----` |
| Vulnerable library version | `OpenSSL 1.0.2k`, `zlib 1.2.3` |
| Debug strings | `gdbserver`, `busybox`, `telnetd` |
| Default credentials | `admin:admin`, `root:toor` |
| Embedded URL with credentials | `ftp://user:pass@host` |

**ELF hardening checks:**

| Check | What it tests |
|-------|-------------|
| `no_aslr` | Binary not compiled as PIE (`-no-pie`) |
| `no_stack_canary` | `__stack_chk_fail` symbol absent |
| `executable_stack` | `GNU_STACK` segment has `E` (execute) flag |
| `no_relro` | `GNU_RELRO` segment absent |
| `rpath_injection` | `RPATH` or `RUNPATH` set to attacker-controllable path |

**Memory reads:** None
**Memory writes:** None (findings flow directly to Commander/Alchemist)

---

## Action Tier

### Commander

**File:** `argos/agents/action/commander.py`
**Kafka trigger:** `argos.finding.created` (Critical findings only)
**Purpose:** Human-in-the-loop gateway. Routes Critical findings for approval before automated fix.

**Thresholds:**
- CVSS ≥ 9.0 **or** `cisa_kev = true` → mandatory human approval
- CVSS 7.0–8.9 and `blast_radius >= 5` → recommended human review (still auto-approved if no response in 2 hours)
- All other findings → auto-approved, passed directly to Alchemist

**Approval flow:**

1. Commander publishes to all alert channels concurrently: Slack (with Approve/Reject buttons), email, PagerDuty
2. Pending approval stored in Redis with key `approval:{finding_id}`, TTL 24 hours
3. Analyst clicks Approve in Slack → your Slack app's action handler calls `PATCH /api/v1/findings/{id}` with `status: in_fix`
4. Commander polls Redis; on approval → publishes `FindingConfirmedEvent`; on 24h timeout → auto-escalates to PagerDuty

**Memory reads:** Redis (pending approval state)
**Memory writes:** Redis (approval state), TimescaleDB (decision logged to findings_timeline)

---

### Alchemist

**File:** `argos/agents/action/alchemist.py`
**Kafka trigger:** `argos.finding.confirmed`
**Purpose:** Generates code fixes and opens fix PRs.

**Fix generation pipeline:**

1. Reads fix_patterns from procedural memory for the finding's `vuln_class` and language
2. Injects patterns as few-shot examples into Claude's system prompt
3. Fetches the vulnerable file content from the SCM platform
4. Calls Claude: "Generate a minimal, correct fix that addresses exactly this vulnerability"
5. Creates a fix branch (`argos/fix-{finding_id}`)
6. Commits the fixed file
7. Opens a PR with: CVSS score, commitment hash, exploitation path, and proposed fix diff in the description
8. Writes `(vulnerable_snippet, fix_snippet)` to procedural memory on merge confirmation

**Platform support:** Bitbucket Cloud + Data Center, GitHub, GitLab (all via the `_PlatformClient` inner class).

**Hardware fix notes:** For hardware findings (VHDL/Verilog/PCB), Alchemist generates a structured JSON recommendation rather than a direct code commit (hardware changes require EDA tool validation outside ARGOS's scope).

**Memory reads:** PostgreSQL (fix_patterns as few-shot examples)
**Memory writes:** PostgreSQL (new fix_patterns on success), Qdrant (fix patterns indexed for similarity search)

---

### Reporter

**File:** `argos/agents/action/reporter.py`
**Purpose:** Generates stakeholder-specific security reports and bills of materials.

**Report variants:**

| Audience | Format | Contents |
|---------|--------|---------|
| Executive | Business prose, no code | Risk summary, business impact, remediation timeline, hygiene score trend |
| Engineering | Full Markdown with code blocks | All findings sorted by risk score, CVSS details, exploitation paths, fix suggestions |
| Auditor | Formal structure with evidence IDs | Control mapping, evidence citations, compliance gaps |
| Vendor | CVE-ready coordinated disclosure | Vulnerability description, reproduction steps, CVSS vector, commitment hash proof |

**SBOM/HBOM:**
- `generate_sbom(repo)` — CycloneDX 1.5 JSON, software components from Neo4j
- `generate_hbom(repo)` — CycloneDX 1.5 JSON, hardware components from Neo4j

**Hygiene score:** A 0–100 score combining: `(1 - fp_rate) × 40 + patch_velocity_score × 60`, Claude-refined with narrative context.

**Memory reads:** PostgreSQL (triage_records), Neo4j (dependencies for SBOM/HBOM), TimescaleDB (scan history for hygiene score)
**Memory writes:** None

---

## Intelligence Tier

### Prophet

**File:** `argos/agents/intelligence/prophet.py`
**Schedule:** Every 6 hours
**Purpose:** Predicts which repos are at elevated risk based on historical vulnerability trends.

**What it analyzes:**
- Repos with increasing finding rate over the last 30 days
- Files that historically had repeated vulnerabilities (recidivism)
- Dependency patterns that correlate with historical exploits
- Repos that haven't been scanned in > 7 days (staleness risk)

**Output:** Publishes `RepoScanEvent` at elevated priority (8.0–10.0) for at-risk repos. Writes high-risk file path patterns to `confirmed_scan_patterns` for Sentinel to use.

**Memory reads:** TimescaleDB (4 hypertables: scans, findings_timeline, agent_metrics)
**Memory writes:** PostgreSQL (confirmed_scan_patterns), Kafka (RepoScanEvent)

---

### Hypothesis

**File:** `argos/agents/intelligence/hypothesis.py`
**Schedule:** Daily at 03:00 UTC
**Purpose:** Reads security research papers from arXiv and extracts new vulnerability patterns.

**arXiv query:** `cs.CR` (Cryptography and Security) category, last 24 hours, filtered for security-relevant titles.

**Claude extraction per paper:**
- New vulnerability class name (snake_case identifier)
- Attack patterns / indicators (regex or code snippet)
- Affected technologies (language, framework, OS)
- Detection approach
- Whether this is a genuinely novel class (boolean)

**Output:** Writes patterns to `confirmed_scan_patterns` table with `source = "hypothesis:{arxiv_id}"`. Publishes `AgentSpawnedEvent` for novel classes — Breeder picks these up and generates a new scanner agent.

**Memory reads:** None
**Memory writes:** PostgreSQL (confirmed_scan_patterns), Kafka (AgentSpawnedEvent for novel classes)

---

### Diplomat

**File:** `argos/agents/intelligence/diplomat.py`
**Schedule:** Every hour
**Purpose:** Manages the full 90-day coordinated disclosure lifecycle.

**Disclosure timeline:**

| Day | Action | Claude generates |
|-----|--------|----------------|
| D+1 | Vendor notification | Professional email with CVSS, reproduction steps, 90-day timeline |
| D+45 | Escalation (if no response) | Formal escalation noting lack of response, shortened timeline |
| D+90 | Public disclosure | Full public advisory with all technical details |

**Email delivery:** SMTP via `smtplib` in a thread executor (async-safe). Configure with `SMTP_*` env vars.

**Finding eligibility:** Only findings with `status = "open"` and `severity in (Critical, High)` are eligible for the formal disclosure process.

**Memory reads:** PostgreSQL (triage_records, disclosure_docs)
**Memory writes:** PostgreSQL (disclosure_docs), SMTP (email delivery)

---

## Evolution Tier

### Breeder

**File:** `argos/agents/evolution/breeder.py`
**Kafka trigger:** `argos.agent.spawned` (from Hypothesis)
**Purpose:** Generates new specialized scanner agents from discovered vulnerability classes.

**Agent generation pipeline:**

1. Reads new vuln class from `confirmed_scan_patterns` (tagged `hypothesis:*` source)
2. Fetches known patterns for the class from procedural memory
3. Calls Claude with adaptive thinking: "Generate a complete Python ArgosAgent subclass that detects `{vuln_class}` in `{language}` files"
4. Claude returns full module source with: class definition, imports, `run()` implementation, regex patterns, system prompt
5. `ast.parse()` validates Python syntax — rejects malformed output
6. Writes to `argos/agents/software/` or `argos/agents/hardware/` based on Claude's recommendation
7. Logs to `agent_spawned_log` table (created on first run)
8. Publishes `AgentSpawnedEvent` with `supervised_mode=True`

**Promotion to autonomous mode:**
Breeder also runs a weekly promotion pass. Agents with `precision > 0.90` over `scan_count >= 50` are promoted. Promotion sets `supervised_mode=False` in the `agent_spawned_log` table and publishes an updated `AgentSpawnedEvent`.

**Memory reads:** PostgreSQL (confirmed_scan_patterns, fix_patterns)
**Memory writes:** Filesystem (new agent .py file), PostgreSQL (agent_spawned_log), Kafka (AgentSpawnedEvent)

---

### Benchmarker

**File:** `argos/agents/evolution/benchmarker.py`
**Schedule:** Weekly
**Purpose:** Evaluates all active agents and retires underperformers.

**Metrics computed per agent (30-day window):**
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 × (precision × recall) / (precision + recall)
- False positive rate = FP / (FP + TN)

**Retirement threshold:** Precision < 0.70 over ≥ 20 confirmed scans.

**Claude analysis:** Benchmarker calls Claude with the metric table and asks for: root cause of underperformance, suggested improvements, whether retirement is appropriate.

**Memory reads:** PostgreSQL (agent_performance_log, last 30 days)
**Memory writes:** PostgreSQL (new performance snapshot), Kafka (AgentRetiredEvent for retiring agents)

---

### Adversary

**File:** `argos/agents/evolution/adversary.py`
**Schedule:** Weekly
**Purpose:** Red-teams all active agents with adversarial test cases to measure false-negative rate.

**Two test case types per agent:**

| Type | Description | Example |
|------|-------------|---------|
| SUBTLE | Obfuscated, context-dependent vulnerabilities the agent might miss | SQL injection hidden in a multi-line f-string concatenation across 3 functions |
| OBVIOUS | Textbook vulnerabilities the agent must catch | `eval(request.args.get("code"))` on line 1 |

**Workflow:**
1. Claude generates 5 SUBTLE + 5 OBVIOUS test cases for each agent based on the agent's vuln_class specialisation
2. Runs each test case through the target agent
3. OBVIOUS misses → immediate false_negative_rate increment
4. SUBTLE misses → noted but weighted lower (0.5× penalty)
5. Writes results to `agent_performance_log` with `metric_name = "false_negative_rate"`

**Memory reads:** PostgreSQL (agent_spawned_log for active agent list)
**Memory writes:** PostgreSQL (agent_performance_log), Kafka (AgentPerformanceEvent)
