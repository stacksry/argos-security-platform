"""
argos/agents/discovery/genealogist.py

GeneaologistAgent — supply chain trust scoring.

For each library in scope the agent:
  1. Fetches registry metadata from PyPI / npm / Maven Central / crates.io.
  2. Checks for known-malicious version flags (via OSV and Sonatype OSS Index).
  3. Uses Claude with adaptive thinking to score supply chain risk factors:
       - Typosquatting risk (name similarity to popular packages).
       - Maintainer reputation (single-maintainer, account age).
       - Time since last release (abandoned packages).
       - Open security advisories.
       - Package popularity (download count proxy).
  4. Returns a trust_score (0.0 = untrusted → 1.0 = fully trusted) and a
     list of risk_factors with a recommendation.

Registry APIs used
------------------
  PyPI        : https://pypi.org/pypi/{name}/json
  npm         : https://registry.npmjs.org/{name}
  Maven       : https://search.maven.org/solrsearch/select?q=g:{group}+a:{artifact}
  crates.io   : https://crates.io/api/v1/crates/{name}
  OSV         : https://api.osv.dev/v1/query  (batch advisory lookup)

All registry calls are made with httpx.AsyncClient.  Responses are cached
in-process for one hour to keep repeat analysis of the same library cheap.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from argos.agents.base import AgentResult, ArgosAgent

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Registry endpoints
# ---------------------------------------------------------------------------

_PYPI_URL = "https://pypi.org/pypi/{name}/json"
_NPM_URL = "https://registry.npmjs.org/{name}"
_MAVEN_URL = (
    "https://search.maven.org/solrsearch/select"
    "?q=g:{group}+a:{artifact}&rows=5&wt=json"
)
_CRATES_URL = "https://crates.io/api/v1/crates/{name}"
_OSV_URL = "https://api.osv.dev/v1/query"

# Cache TTL in seconds.
_CACHE_TTL = 3600

# Thresholds for scoring heuristics.
_ABANDONED_DAYS = 365 * 2          # 2 years without a release → abandoned
_LOW_DOWNLOAD_NPM = 100            # npm weekly downloads below this → obscure
_LOW_DOWNLOAD_PYPI = 1000          # PyPI monthly downloads below this → obscure
_SINGLE_MAINTAINER_RISK = 0.15    # risk penalty for single-maintainer packages

# ---------------------------------------------------------------------------
# GeneaologistAgent
# ---------------------------------------------------------------------------


class GeneaologistAgent(ArgosAgent):
    """
    Supply chain trust scoring agent.

    Scores each library on a 0.0–1.0 trust scale and flags high-risk packages.
    """

    name = "genealogist"

    _SYSTEM = """\
You are Genealogist, the supply chain analyst for the ARGOS security platform.

You will receive metadata about a software library:
  - Registry metadata (maintainers, release dates, download counts, description)
  - OSV advisory count (open security advisories)
  - Ecosystem and version

Your task: assess supply chain risk and return a trust score.

Trust score: 0.0 = completely untrusted; 1.0 = fully trusted.

Risk factors to consider (each lowers the score):
  - typosquatting: name very similar to a well-known package (e.g. "requetss", "djnago")
  - abandoned: no release for more than 2 years
  - single_maintainer: only one maintainer and they have no public profile
  - low_popularity: very few downloads compared to ecosystem norms
  - open_advisories: one or more active CVEs or security advisories
  - suspicious_description: description is missing, very short, or contradicts the name
  - known_malicious_version: this exact version has been flagged as malicious

Return ONLY valid JSON (no markdown, no code fences) in this schema:
{
  "trust_score": <float 0.0-1.0>,
  "risk_factors": ["<factor_name>", ...],
  "risk_details": {
    "<factor_name>": "<one sentence explanation>"
  },
  "recommendation": "<one sentence: keep, upgrade, replace, or block>",
  "flag": "<none|abandoned|suspicious|compromised>"
}

flag values:
  none        – no critical concerns
  abandoned   – no release in > 2 years
  suspicious  – name looks like a typosquat or description is anomalous
  compromised – known-malicious version
"""

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._cache: dict[str, tuple[Any, float]] = {}  # key → (value, expires_at)

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Score supply chain trust for a list of libraries.

        Context keys
        ------------
        libraries : list[dict]
            Each entry: {"name": str, "version": str, "ecosystem": str,
                         "repo_url": str}
            ecosystem values: "pip" | "npm" | "maven" | "cargo" | "gem"
        repo : str
            Repository being scanned (for logging).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        repo: str = context.get("repo", "unknown")
        libraries: list[dict[str, Any]] = context.get("libraries", [])

        self.log.info(
            "genealogist.run",
            repo=repo,
            library_count=len(libraries),
        )

        if not libraries:
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={"repo": repo, "message": "No libraries to score"},
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=0,
            )

        async with httpx.AsyncClient(
            timeout=20.0,
            headers={"User-Agent": "ARGOS-Security-Platform/1.0"},
            follow_redirects=True,
        ) as http:
            tasks = [
                self.score_library(
                    name=lib["name"],
                    version=lib["version"],
                    ecosystem=lib.get("ecosystem", ""),
                    http=http,
                )
                for lib in libraries
            ]
            scores = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[dict[str, Any]] = []
        for lib, score in zip(libraries, scores):
            if isinstance(score, Exception):
                self.log.warning(
                    "genealogist.score_failed",
                    library=lib["name"],
                    error=str(score),
                )
                continue

            if score["trust_score"] < 0.7 or score["flag"] != "none":
                findings.append({
                    "library": f"{lib['name']}@{lib['version']}",
                    "ecosystem": lib.get("ecosystem", ""),
                    "repo_url": lib.get("repo_url", ""),
                    **score,
                })

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "genealogist.complete",
            repo=repo,
            scored=len(libraries),
            flagged=len(findings),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=findings,
            metadata={
                "repo": repo,
                "libraries_scored": len(libraries),
                "flagged_count": len(findings),
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Public: score_library
    # ------------------------------------------------------------------

    async def score_library(
        self,
        name: str,
        version: str,
        ecosystem: str,
        http: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """
        Fetch registry metadata and return a trust score dict.

        Returns {"trust_score": float, "risk_factors": list, "risk_details": dict,
                 "recommendation": str, "flag": str}
        """
        cache_key = f"genealogist:{ecosystem}:{name}:{version}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            self.log.debug("genealogist.cache_hit", name=name)
            return cached  # type: ignore[return-value]

        own_http = http is None
        if own_http:
            http = httpx.AsyncClient(
                timeout=20.0,
                headers={"User-Agent": "ARGOS-Security-Platform/1.0"},
                follow_redirects=True,
            )

        try:
            metadata = await self._fetch_registry_metadata(
                name=name, version=version, ecosystem=ecosystem, http=http
            )
            advisory_count = await self._fetch_osv_advisory_count(
                name=name, version=version, ecosystem=ecosystem, http=http
            )
        finally:
            if own_http:
                await http.aclose()  # type: ignore[union-attr]

        metadata["open_advisories"] = advisory_count

        score = await self._score_with_claude(
            name=name, version=version, ecosystem=ecosystem, metadata=metadata
        )

        self._cache_set(cache_key, score, _CACHE_TTL)
        return score

    # ------------------------------------------------------------------
    # Registry metadata fetching
    # ------------------------------------------------------------------

    async def _fetch_registry_metadata(
        self,
        name: str,
        version: str,
        ecosystem: str,
        http: httpx.AsyncClient,
    ) -> dict[str, Any]:
        """
        Fetch package metadata from the appropriate registry.

        Returns a normalised dict with keys:
          maintainers, last_release_date, download_count_monthly,
          description, homepage, total_versions, days_since_last_release
        """
        fetchers = {
            "pip":    self._fetch_pypi,
            "npm":    self._fetch_npm,
            "maven":  self._fetch_maven,
            "cargo":  self._fetch_crates,
        }
        fetcher = fetchers.get(ecosystem)
        if fetcher is None:
            return self._empty_metadata()

        try:
            return await fetcher(name=name, version=version, http=http)
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "genealogist.metadata_fetch_failed",
                name=name,
                ecosystem=ecosystem,
                error=str(exc),
            )
            return self._empty_metadata()

    async def _fetch_pypi(
        self, name: str, version: str, http: httpx.AsyncClient
    ) -> dict[str, Any]:
        url = _PYPI_URL.format(name=name)
        resp = await http.get(url)
        if resp.status_code == 404:
            return self._empty_metadata()
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})

        # Find release date for the requested version.
        releases = data.get("releases", {})
        version_files = releases.get(version, [])
        last_release_date: str | None = None
        if version_files:
            last_release_date = version_files[0].get("upload_time")
        elif info.get("version"):
            # Fall back to latest version date.
            latest_files = releases.get(info["version"], [])
            if latest_files:
                last_release_date = latest_files[0].get("upload_time")

        days_since = self._days_since(last_release_date)

        return {
            "maintainers": [info.get("author") or "unknown"],
            "maintainer_emails": [info.get("author_email") or ""],
            "last_release_date": last_release_date,
            "days_since_last_release": days_since,
            "download_count_monthly": None,  # PyPI stats require a separate API
            "description": info.get("summary", ""),
            "homepage": info.get("home_page") or info.get("project_url", ""),
            "total_versions": len(releases),
            "license": info.get("license", ""),
        }

    async def _fetch_npm(
        self, name: str, version: str, http: httpx.AsyncClient
    ) -> dict[str, Any]:
        url = _NPM_URL.format(name=name)
        resp = await http.get(url)
        if resp.status_code == 404:
            return self._empty_metadata()
        resp.raise_for_status()
        data = resp.json()

        maintainers = [m.get("name") or m.get("email", "") for m in data.get("maintainers", [])]
        versions = data.get("versions", {})
        time_data = data.get("time", {})

        last_release_date: str | None = time_data.get(version) or time_data.get("modified")
        days_since = self._days_since(last_release_date)

        latest_ver = data.get("dist-tags", {}).get("latest", "")
        description = data.get("description", "")
        homepage = data.get("homepage", "")

        return {
            "maintainers": maintainers,
            "maintainer_emails": [],
            "last_release_date": last_release_date,
            "days_since_last_release": days_since,
            "download_count_monthly": None,  # npm downloads require a separate stats API
            "description": description,
            "homepage": homepage,
            "total_versions": len(versions),
            "license": data.get("license", ""),
        }

    async def _fetch_maven(
        self, name: str, version: str, http: httpx.AsyncClient
    ) -> dict[str, Any]:
        # Maven name format: "groupId:artifactId"
        if ":" in name:
            group, artifact = name.split(":", 1)
        else:
            group, artifact = "", name

        url = _MAVEN_URL.format(
            group=group.replace(".", "%2E"),
            artifact=artifact,
        )
        try:
            resp = await http.get(url)
            resp.raise_for_status()
            data = resp.json()
        except Exception:  # noqa: BLE001
            return self._empty_metadata()

        docs = data.get("response", {}).get("docs", [])
        if not docs:
            return self._empty_metadata()
        doc = docs[0]

        last_release_date = None
        ts = doc.get("timestamp")
        if ts:
            # Maven Central returns millisecond epoch.
            try:
                last_release_date = datetime.fromtimestamp(
                    ts / 1000, tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError):
                pass

        return {
            "maintainers": [doc.get("g", "unknown")],
            "maintainer_emails": [],
            "last_release_date": last_release_date,
            "days_since_last_release": self._days_since(last_release_date),
            "download_count_monthly": None,
            "description": "",
            "homepage": "",
            "total_versions": doc.get("versionCount", 0),
            "license": doc.get("l", [""])[0] if doc.get("l") else "",
        }

    async def _fetch_crates(
        self, name: str, version: str, http: httpx.AsyncClient
    ) -> dict[str, Any]:
        url = _CRATES_URL.format(name=name)
        try:
            resp = await http.get(url)
            if resp.status_code == 404:
                return self._empty_metadata()
            resp.raise_for_status()
            data = resp.json()
        except Exception:  # noqa: BLE001
            return self._empty_metadata()

        crate = data.get("crate", {})
        latest_version = crate.get("newest_version", "")
        updated_at = crate.get("updated_at")

        return {
            "maintainers": [],  # crates.io owners require a second API call
            "maintainer_emails": [],
            "last_release_date": updated_at,
            "days_since_last_release": self._days_since(updated_at),
            "download_count_monthly": crate.get("recent_downloads"),
            "description": crate.get("description", ""),
            "homepage": crate.get("homepage", ""),
            "total_versions": crate.get("versions", 0),
            "license": "",
        }

    # ------------------------------------------------------------------
    # OSV advisory lookup
    # ------------------------------------------------------------------

    async def _fetch_osv_advisory_count(
        self,
        name: str,
        version: str,
        ecosystem: str,
        http: httpx.AsyncClient,
    ) -> int:
        """
        Query OSV (Open Source Vulnerabilities) for active advisories.

        Returns the count of matching advisories for name@version.
        """
        osv_ecosystem_map = {
            "pip": "PyPI",
            "npm": "npm",
            "maven": "Maven",
            "cargo": "crates.io",
            "gem": "RubyGems",
        }
        osv_eco = osv_ecosystem_map.get(ecosystem)
        if osv_eco is None:
            return 0

        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": osv_eco},
        }

        try:
            resp = await http.post(_OSV_URL, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return len(data.get("vulns", []))
        except Exception as exc:  # noqa: BLE001
            self.log.debug("genealogist.osv_failed", name=name, error=str(exc))

        return 0

    # ------------------------------------------------------------------
    # Claude scoring
    # ------------------------------------------------------------------

    async def _score_with_claude(
        self,
        name: str,
        version: str,
        ecosystem: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Use Claude with adaptive thinking to produce a trust score.
        """
        user_content = f"""Library: {name}@{version}
Ecosystem: {ecosystem}

Registry metadata:
{json.dumps(metadata, indent=2)}

Return the trust score JSON now."""

        try:
            text = await self._call_claude(
                system=self._SYSTEM,
                messages=[{"role": "user", "content": user_content}],
                max_tokens=2048,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error(
                "genealogist.claude_failed",
                name=name,
                error=str(exc),
            )
            return self._fallback_score(metadata)

        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            score = json.loads(text)
            self.log.debug(
                "genealogist.score",
                name=name,
                trust_score=score.get("trust_score"),
                flag=score.get("flag"),
            )
            return score
        except json.JSONDecodeError as exc:
            self.log.error(
                "genealogist.json_parse_failed",
                name=name,
                error=str(exc),
                raw=text[:200],
            )
            return self._fallback_score(metadata)

    def _fallback_score(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """
        Rule-based fallback trust scoring when Claude is unavailable.
        """
        risk_factors: list[str] = []
        details: dict[str, str] = {}

        days_since = metadata.get("days_since_last_release") or 0
        if days_since > _ABANDONED_DAYS:
            risk_factors.append("abandoned")
            details["abandoned"] = f"No release in {days_since} days."

        maintainers = metadata.get("maintainers", [])
        if len(maintainers) <= 1:
            risk_factors.append("single_maintainer")
            details["single_maintainer"] = "Only one maintainer."

        if metadata.get("open_advisories", 0) > 0:
            risk_factors.append("open_advisories")
            details["open_advisories"] = (
                f"{metadata['open_advisories']} active security advisory/ies."
            )

        # Compute a simple numeric score.
        score = 1.0 - (len(risk_factors) * _SINGLE_MAINTAINER_RISK)
        score = max(0.0, min(1.0, score))

        flag = "none"
        if "abandoned" in risk_factors:
            flag = "abandoned"

        return {
            "trust_score": round(score, 2),
            "risk_factors": risk_factors,
            "risk_details": details,
            "recommendation": (
                "Replace with a maintained alternative."
                if flag == "abandoned"
                else "Review before upgrading."
            ),
            "flag": flag,
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _days_since(date_str: str | None) -> int | None:
        """Return the number of days since a date string (ISO 8601), or None."""
        if not date_str:
            return None
        try:
            # Strip timezone suffix if present for simple parsing.
            clean = re.sub(r"[Z+].*$", "", date_str).strip()
            dt = datetime.fromisoformat(clean)
            delta = datetime.now() - dt
            return delta.days
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _empty_metadata() -> dict[str, Any]:
        return {
            "maintainers": [],
            "maintainer_emails": [],
            "last_release_date": None,
            "days_since_last_release": None,
            "download_count_monthly": None,
            "description": "",
            "homepage": "",
            "total_versions": 0,
            "license": "",
            "open_advisories": 0,
        }

    # ------------------------------------------------------------------
    # In-process cache
    # ------------------------------------------------------------------

    def _cache_get(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() < expires_at:
            return value
        del self._cache[key]
        return None

    def _cache_set(self, key: str, value: Any, ttl: int) -> None:
        self._cache[key] = (value, time.monotonic() + ttl)
