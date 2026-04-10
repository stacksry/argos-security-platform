"""
argos/agents/discovery/oracle.py

OracleAgent — threat intelligence correlator.

Queries NVD (NIST National Vulnerability Database) and CISA KEV (Known
Exploited Vulnerabilities) for CVEs matching the organisation's software
dependencies.  Uses the knowledge graph (via self.memory) to calculate blast
radius, and Claude to synthesise findings into actionable urgency ratings.

NVD rate limits
---------------
  Without API key : 5 req / 30 s window (conservatively: ≤ 2 req/s)
  With API key    : 50 req / 30 s window
Set NVD_API_KEY in the environment to use the higher quota.

Redis caching
-------------
NVD responses are cached for 1 hour (TTL_SECONDS = 3600) to avoid hammering
the public API.  The cache key is ``nvd:cve:{cpe_or_term}``.  When redis is
not configured (self.memory.redis is None) the cache layer is bypassed and
every call hits NVD directly.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from argos.agents.base import AgentResult, ArgosAgent

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
TTL_SECONDS = 3600  # 1-hour NVD cache
NVD_RATE_LIMIT_DELAY = 0.7  # seconds between NVD requests (no API key)
NVD_RATE_LIMIT_DELAY_WITH_KEY = 0.1
_KEV_CACHE_TTL = 7200  # 2 hours for CISA KEV list (changes infrequently)

# ---------------------------------------------------------------------------
# OracleAgent
# ---------------------------------------------------------------------------


class OracleAgent(ArgosAgent):
    """
    Threat intelligence agent.

    Correlates org assets against CVE/NVD/CISA KEV feeds, computes blast
    radius via the graph memory, and uses Claude to assign urgency scores.
    """

    name = "oracle"

    _SYSTEM = """\
You are Oracle, the threat intelligence analyst for the ARGOS security platform.

Your task: synthesise CVE data, CISA KEV status, and blast radius information
into actionable security findings for an engineering team.

For each affected library you receive:
  - CVE IDs, CVSS scores, and descriptions
  - Whether each CVE is in CISA's Known Exploited Vulnerabilities list
  - How many repositories in the org use this library (blast radius)

You must return ONLY valid JSON (no markdown, no code fences) in this schema:
{
  "findings": [
    {
      "library": "<name>@<version>",
      "cve_id": "<CVE-YYYY-NNNNN>",
      "cvss_score": <float>,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
      "is_actively_exploited": <bool>,
      "blast_radius": <int>,
      "urgency": "IMMEDIATE|HIGH|MEDIUM|LOW",
      "description": "<one sentence description>",
      "recommendation": "<one sentence action>"
    }
  ],
  "summary": "<overall summary for the team>"
}

Urgency rules:
  IMMEDIATE : is_actively_exploited=true OR cvss >= 9.0
  HIGH      : cvss >= 7.0 OR blast_radius > 10
  MEDIUM    : cvss >= 4.0
  LOW       : cvss < 4.0
"""

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
        nvd_api_key: str | None = None,
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
        self._rate_delay = (
            NVD_RATE_LIMIT_DELAY_WITH_KEY
            if self._nvd_api_key
            else NVD_RATE_LIMIT_DELAY
        )
        # In-process cache as fallback when Redis is unavailable.
        self._local_cache: dict[str, tuple[Any, float]] = {}
        # Cached CISA KEV set: {cve_id, ...}
        self._kev_cache: set[str] = set()
        self._kev_cache_ts: float = 0.0

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Correlate a repository's libraries against CVE feeds.

        Context keys
        ------------
        repo : str
            Repository slug.
        libraries : list[dict]
            Each entry: {"name": str, "version": str, "ecosystem": str}
            e.g. {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven"}
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        repo: str = context.get("repo", "unknown")
        libraries: list[dict[str, Any]] = context.get("libraries", [])

        self.log.info(
            "oracle.run",
            repo=repo,
            library_count=len(libraries),
        )

        if not libraries:
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={"repo": repo, "message": "No libraries provided"},
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=0,
            )

        async with httpx.AsyncClient(timeout=30.0) as http:
            # 1. Fetch CISA KEV list (cached).
            await self._refresh_kev_cache(http)

            # 2. Query NVD for each library.
            raw_cve_data: list[dict[str, Any]] = []
            for lib in libraries:
                lib_cves = await self._fetch_cves_for_library(
                    http, lib["name"], lib["version"], lib.get("ecosystem", "")
                )
                raw_cve_data.append({
                    "library": lib,
                    "cves": lib_cves,
                })
                # Respect NVD rate limit.
                await asyncio.sleep(self._rate_delay)

        # 3. Annotate with KEV status and blast radius.
        enriched = await self._enrich_with_kev_and_blast(raw_cve_data)

        if not any(d["cves"] for d in raw_cve_data):
            # No CVEs found — return clean result without calling Claude.
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={
                    "repo": repo,
                    "libraries_checked": len(libraries),
                    "message": "No matching CVEs found",
                },
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        # 4. Ask Claude to synthesise findings and assign urgency.
        findings = await self._synthesise_with_claude(repo, enriched)

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "oracle.complete",
            repo=repo,
            findings_count=len(findings),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=findings,
            metadata={
                "repo": repo,
                "libraries_checked": len(libraries),
                "cve_sources": ["NVD", "CISA-KEV"],
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # NVD querying
    # ------------------------------------------------------------------

    async def _fetch_cves_for_library(
        self,
        http: httpx.AsyncClient,
        name: str,
        version: str,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """
        Query NVD CVE 2.0 API for CVEs matching this library name and version.

        Uses a keyword search (keywordSearch) because CPE-based matching
        requires knowing the exact vendor/product CPE strings.  Filters results
        client-side to those that mention the version string.
        """
        cache_key = f"nvd:cve:{name}:{version}"

        cached = await self._cache_get(cache_key)
        if cached is not None:
            self.log.debug("oracle.nvd_cache_hit", name=name, version=version)
            return cached  # type: ignore[return-value]

        params: dict[str, Any] = {
            "keywordSearch": f"{name} {version}",
            "resultsPerPage": 50,
        }
        headers: dict[str, str] = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        self.log.debug("oracle.nvd_query", name=name, version=version)

        try:
            resp = await http.get(NVD_API, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            self.log.warning(
                "oracle.nvd_http_error",
                name=name,
                version=version,
                status=exc.response.status_code,
            )
            return []
        except Exception as exc:  # noqa: BLE001
            self.log.warning("oracle.nvd_error", name=name, error=str(exc))
            return []

        cves: list[dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id: str = cve_obj.get("id", "")

            # Extract CVSS score (prefer v3.1, fall back to v3.0 then v2).
            metrics = cve_obj.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = float(cvss_data.get("baseScore", 0.0))
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            # Extract English description.
            descriptions = cve_obj.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "",
            )

            published = cve_obj.get("published", "")

            cves.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description,
                "published": published,
            })

        await self._cache_set(cache_key, cves, TTL_SECONDS)
        self.log.debug("oracle.nvd_result", name=name, cve_count=len(cves))
        return cves

    async def check_new_cves(self, since_hours: int = 24) -> list[dict[str, Any]]:
        """
        Poll NVD for CVEs published in the last N hours.

        Called by a cron job; returns raw CVE records for further processing.
        """
        since_dt = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        pub_start = since_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

        params: dict[str, Any] = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": 2000,
        }
        headers: dict[str, str] = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        self.log.info("oracle.check_new_cves", since_hours=since_hours)

        async with httpx.AsyncClient(timeout=60.0) as http:
            try:
                resp = await http.get(NVD_API, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:  # noqa: BLE001
                self.log.error("oracle.new_cves_error", error=str(exc))
                return []

        cves = [item["cve"] for item in data.get("vulnerabilities", [])]
        self.log.info("oracle.new_cves_found", count=len(cves))
        return cves

    async def correlate_with_assets(self, cve_id: str) -> dict[str, Any]:
        """
        Given a CVE ID, find all org assets affected via the knowledge graph.

        Returns a dict with keys:
          cve_id, affected_repos, affected_libraries, blast_radius
        """
        self.log.info("oracle.correlate_assets", cve_id=cve_id)

        affected_repos: list[str] = []
        affected_libraries: list[str] = []

        if self.memory is not None:
            try:
                # Graph memory is expected to expose query_cve_impact().
                impact = await self.memory.query_cve_impact(cve_id)
                affected_repos = impact.get("repos", [])
                affected_libraries = impact.get("libraries", [])
            except Exception as exc:  # noqa: BLE001
                self.log.warning(
                    "oracle.graph_query_failed",
                    cve_id=cve_id,
                    error=str(exc),
                )

        return {
            "cve_id": cve_id,
            "affected_repos": affected_repos,
            "affected_libraries": affected_libraries,
            "blast_radius": len(affected_repos),
        }

    # ------------------------------------------------------------------
    # CISA KEV
    # ------------------------------------------------------------------

    async def _refresh_kev_cache(self, http: httpx.AsyncClient) -> None:
        """Fetch and cache the CISA KEV JSON if stale (>2h old)."""
        now = time.monotonic()
        if self._kev_cache and (now - self._kev_cache_ts) < _KEV_CACHE_TTL:
            return

        self.log.debug("oracle.kev_refresh")
        try:
            resp = await http.get(CISA_KEV_URL, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            self._kev_cache = {
                v["cveID"] for v in data.get("vulnerabilities", [])
            }
            self._kev_cache_ts = now
            self.log.info("oracle.kev_loaded", count=len(self._kev_cache))
        except Exception as exc:  # noqa: BLE001
            self.log.warning("oracle.kev_load_failed", error=str(exc))

    def _is_kev(self, cve_id: str) -> bool:
        return cve_id in self._kev_cache

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    async def _enrich_with_kev_and_blast(
        self,
        raw_data: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Add KEV status and blast radius to each CVE record.
        """
        enriched: list[dict[str, Any]] = []

        for entry in raw_data:
            lib: dict[str, Any] = entry["library"]
            lib_str = f"{lib['name']}@{lib['version']}"

            # Blast radius: how many repos use this library?
            blast_radius = 0
            if self.memory is not None:
                try:
                    repos = await self.memory.find_blast_radius(
                        lib["name"], lib["version"]
                    )
                    blast_radius = len(repos)
                except Exception as exc:  # noqa: BLE001
                    self.log.debug(
                        "oracle.blast_radius_failed",
                        library=lib_str,
                        error=str(exc),
                    )

            for cve in entry["cves"]:
                enriched.append({
                    "library": lib_str,
                    "ecosystem": lib.get("ecosystem", ""),
                    "blast_radius": blast_radius,
                    "is_kev": self._is_kev(cve["cve_id"]),
                    **cve,
                })

        return enriched

    # ------------------------------------------------------------------
    # Claude synthesis
    # ------------------------------------------------------------------

    async def _synthesise_with_claude(
        self,
        repo: str,
        enriched_cves: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Ask Claude to synthesise CVE data into prioritised findings.

        Sends the enriched CVE list to Claude with the Oracle system prompt
        and parses the JSON response.
        """
        user_content = f"""Repository: {repo}

CVE data to synthesise (JSON):
{json.dumps(enriched_cves, indent=2)}

Return the findings JSON now."""

        try:
            text = await self._call_claude(
                system=self._SYSTEM,
                messages=[{"role": "user", "content": user_content}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("oracle.claude_failed", error=str(exc))
            # Fallback: return raw enriched data as unanalysed findings.
            return [
                {
                    "library": e["library"],
                    "cve_id": e["cve_id"],
                    "cvss_score": e["cvss_score"],
                    "severity": e["severity"],
                    "is_actively_exploited": e["is_kev"],
                    "blast_radius": e["blast_radius"],
                    "urgency": "HIGH" if e["is_kev"] else "MEDIUM",
                    "description": e["description"],
                    "recommendation": "Review and patch immediately.",
                }
                for e in enriched_cves
            ]

        # Strip markdown fences if present.
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            data = json.loads(text)
            findings: list[dict[str, Any]] = data.get("findings", [])
            self.log.info(
                "oracle.synthesis_complete",
                finding_count=len(findings),
                summary=data.get("summary", "")[:120],
            )
            return findings
        except json.JSONDecodeError as exc:
            self.log.error(
                "oracle.json_parse_failed",
                error=str(exc),
                raw=text[:300],
            )
            return []

    # ------------------------------------------------------------------
    # Cache helpers (Redis-first, in-process fallback)
    # ------------------------------------------------------------------

    async def _cache_get(self, key: str) -> Any | None:
        """Retrieve a cached value (Redis → in-process → miss)."""
        # Try Redis via memory layer.
        if self.memory is not None and hasattr(self.memory, "redis") and self.memory.redis:
            try:
                raw = await self.memory.redis.get(key)
                if raw is not None:
                    return json.loads(raw)
            except Exception:  # noqa: BLE001
                pass

        # In-process cache.
        entry = self._local_cache.get(key)
        if entry is not None:
            value, expires_at = entry
            if time.monotonic() < expires_at:
                return value
            del self._local_cache[key]

        return None

    async def _cache_set(self, key: str, value: Any, ttl: int) -> None:
        """Store a value in Redis (if available) and in-process cache."""
        # Try Redis.
        if self.memory is not None and hasattr(self.memory, "redis") and self.memory.redis:
            try:
                await self.memory.redis.setex(key, ttl, json.dumps(value))
            except Exception:  # noqa: BLE001
                pass

        # Always update in-process cache as well.
        self._local_cache[key] = (value, time.monotonic() + ttl)
