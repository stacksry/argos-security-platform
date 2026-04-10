"""
config.py — ARGOS platform configuration via environment variables.

All settings have sensible defaults for local development.
Production values come from environment / secrets manager.
"""

from functools import lru_cache
from typing import Literal
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Claude ───────────────────────────────────────────────────────────────
    anthropic_api_key: SecretStr = Field(..., description="Anthropic API key")
    claude_model: str = "claude-opus-4-6"

    # ── Bitbucket ────────────────────────────────────────────────────────────
    bitbucket_mode: Literal["cloud", "datacenter"] = "cloud"
    bitbucket_base_url: str = "https://api.bitbucket.org/2.0"
    bitbucket_token: SecretStr = Field(default=SecretStr(""), description="Bitbucket PAT")
    bitbucket_workspace: str = ""          # Cloud: workspace slug
    bitbucket_webhook_secret: SecretStr = Field(default=SecretStr(""))

    # ── GitHub (optional secondary source) ───────────────────────────────────
    github_token: SecretStr = Field(default=SecretStr(""))
    github_webhook_secret: SecretStr = Field(default=SecretStr(""))

    # ── Kafka ────────────────────────────────────────────────────────────────
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: str = ""
    kafka_sasl_username: str = ""
    kafka_sasl_password: SecretStr = Field(default=SecretStr(""))

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_ttl_seconds: int = 3600          # default cache TTL

    # ── PostgreSQL (procedural memory + TimescaleDB) ─────────────────────────
    postgres_dsn: str = "postgresql://argos:argos@localhost:5432/argos"

    # ── Neo4j (knowledge graph) ──────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = Field(default=SecretStr("argos"))

    # ── Qdrant (vector / semantic memory) ────────────────────────────────────
    qdrant_url: str = "http://localhost:6333"
    qdrant_api_key: SecretStr = Field(default=SecretStr(""))

    # ── NVD / Threat Intel ───────────────────────────────────────────────────
    nvd_api_key: SecretStr = Field(default=SecretStr(""), description="NVD 2.0 API key (optional, increases rate limit)")
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # ── Alert channels ───────────────────────────────────────────────────────
    slack_webhook_url: SecretStr = Field(default=SecretStr(""))
    pagerduty_routing_key: SecretStr = Field(default=SecretStr(""))
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: SecretStr = Field(default=SecretStr(""))
    alert_email_to: str = ""

    # ── Scanning behaviour ───────────────────────────────────────────────────
    max_parallel_workers: int = 8
    min_ranker_score: int = 3              # files below this skipped
    sandbox_timeout_seconds: int = 30
    delta_scan_enabled: bool = True        # only scan changed files on push
    cve_poll_interval_hours: int = 1       # how often Oracle polls NVD

    # ── Disclosure ───────────────────────────────────────────────────────────
    disclosure_vendor_notify_day: int = 1
    disclosure_escalation_day: int = 45
    disclosure_public_day: int = 90

    # ── API ──────────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: SecretStr = Field(default=SecretStr("change-me-in-production"))

    # ── Environment ──────────────────────────────────────────────────────────
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


# Convenience alias
settings = get_settings()
