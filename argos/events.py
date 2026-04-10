"""
events.py — Pydantic event schemas flowing through Kafka.

Every message on every Kafka topic is one of these models.
Envelope fields (event_id, timestamp, source) are always present.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class Platform(StrEnum):
    BITBUCKET = "bitbucket"
    GITHUB = "github"
    GITLAB = "gitlab"

class EventType(StrEnum):
    PUSH = "push"
    PR_OPENED = "pr_opened"
    PR_MERGED = "pr_merged"
    CVE_PUBLISHED = "cve_published"
    SCHEDULED = "scheduled"
    MANUAL = "manual"

class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class FindingStatus(StrEnum):
    OPEN = "open"
    IN_FIX = "in_fix"
    FIXED = "fixed"
    DISCLOSED = "disclosed"
    FALSE_POSITIVE = "false_positive"

class AssetType(StrEnum):
    SOURCE_CODE = "source_code"
    FIRMWARE = "firmware"
    PCB = "pcb"
    VHDL = "vhdl"
    VERILOG = "verilog"
    CONTAINER = "container"
    IAC = "iac"
    BOM = "bom"


# ── Base envelope ─────────────────────────────────────────────────────────────

class ArgosEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "argos"
    schema_version: str = "1.0"


# ── Ingestion events ──────────────────────────────────────────────────────────

class CommitInfo(BaseModel):
    sha: str
    message: str
    author: str
    timestamp: datetime

class RepoScanEvent(ArgosEvent):
    """Published to argos.scan.requested when a repo needs scanning."""
    event_type: EventType
    platform: Platform
    repo: str                          # e.g. "org/backend-service"
    branch: str = "main"
    head_sha: str = ""
    base_sha: str = ""                 # for delta scanning
    changed_files: list[str] = []     # empty = full scan
    priority: float = 5.0             # 0-10, Navigator-assigned
    trigger: str = ""                  # who/what triggered this scan

class PRMergedEvent(ArgosEvent):
    """Published when a Glasswing/ARGOS fix PR is merged."""
    platform: Platform
    repo: str
    pr_id: str
    pr_url: str
    head_sha: str
    merged_files: list[str] = []
    finding_id: str = ""
    vuln_class: str = ""


# ── Finding events ────────────────────────────────────────────────────────────

class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:16])
    repo: str
    file: str
    line: int = 0
    vuln_class: str
    title: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    confidence: float = 0.0
    asset_type: AssetType = AssetType.SOURCE_CODE
    layer_hit: str = ""                # L1-L6 or H1-H4 (hardware layers)
    affected_library: str = ""
    exploitation_path: str = ""
    population_impact: str = ""
    cve_ids: list[str] = []
    cisa_kev: bool = False             # is this in CISA Known Exploited Vulnerabilities?
    blast_radius: int = 0              # how many repos affected
    discovery_ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    disclosure_deadline: datetime | None = None
    commitment_hash: str = ""          # SHA-3 proof of prior discovery
    status: FindingStatus = FindingStatus.OPEN
    agent: str = ""
    metadata: dict[str, Any] = {}

class FindingCreatedEvent(ArgosEvent):
    finding: Finding

class FindingConfirmedEvent(ArgosEvent):
    """Published by sandbox_agent after exploit confirmation."""
    finding: Finding
    sandbox_verdict: Literal["CONFIRMED_EXPLOITABLE", "NOT_REPRODUCIBLE", "SANDBOX_ERROR"]
    crash_indicator: str = ""
    poc_language: str = ""

class FindingResolvedEvent(ArgosEvent):
    finding_id: str
    repo: str
    resolution: FindingStatus
    pr_url: str = ""
    days_to_fix: int = 0


# ── CVE / threat intel events ─────────────────────────────────────────────────

class CVEPublishedEvent(ArgosEvent):
    cve_id: str
    cvss_score: float
    cvss_vector: str
    severity: Severity
    description: str
    affected_products: list[dict] = []  # [{vendor, product, version_range}]
    cisa_kev: bool = False
    published_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class BlastRadiusEvent(ArgosEvent):
    """Published by Oracle after correlating a CVE with org assets."""
    cve_id: str
    affected_repos: list[str]
    affected_library: str
    version_range: str
    priority: float


# ── Agent lifecycle events ────────────────────────────────────────────────────

class AgentSpawnedEvent(ArgosEvent):
    """Published by Breeder when a new agent type is created."""
    agent_name: str
    agent_version: str
    vuln_class: str
    supervised_mode: bool = True       # starts supervised, promoted after metrics pass
    spawned_by: str = "breeder"

class AgentRetiredEvent(ArgosEvent):
    agent_name: str
    reason: str                        # "poor_precision" | "superseded" | "manual"
    final_precision: float = 0.0
    final_recall: float = 0.0

class AgentPerformanceEvent(ArgosEvent):
    agent_name: str
    repo: str
    scan_id: str
    precision: float
    recall: float
    false_positive_rate: float
    duration_ms: int
    findings_count: int


# ── Alert events ──────────────────────────────────────────────────────────────

class AlertRequiredEvent(ArgosEvent):
    finding: Finding
    commitment_hash: str
    alert_channels: list[str] = ["slack", "email", "pagerduty"]
    message: str = ""


# ── Kafka topic → event model mapping ────────────────────────────────────────

TOPIC_SCHEMAS: dict[str, type[ArgosEvent]] = {
    "argos.scan.requested":    RepoScanEvent,
    "argos.scan.completed":    ArgosEvent,
    "argos.finding.created":   FindingCreatedEvent,
    "argos.finding.confirmed": FindingConfirmedEvent,
    "argos.finding.resolved":  FindingResolvedEvent,
    "argos.pr.merged":         PRMergedEvent,
    "argos.cve.published":     CVEPublishedEvent,
    "argos.blast.radius":      BlastRadiusEvent,
    "argos.agent.spawned":     AgentSpawnedEvent,
    "argos.agent.retired":     AgentRetiredEvent,
    "argos.alert.required":    AlertRequiredEvent,
}
