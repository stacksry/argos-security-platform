"""
argos/agents/radar/cartographer.py

CartographerAgent — org-wide asset knowledge graph builder and maintainer.

Builds and keeps current a Neo4j graph that represents:
  - Repository nodes
  - Library/dependency nodes (with ecosystem, name, version)
  - Hardware asset nodes (VHDL modules, KiCad schematics, firmware blobs)
  - DEPENDS_ON edges with semver and lockfile-resolved version info
  - USES_HARDWARE edges

On every push event the agent:
  1. Fetches manifest files (pom.xml, package.json, go.mod, etc.) from the SCM.
  2. Parses direct + transitive dependencies (using lockfiles when available).
  3. Upserts repo and dependency nodes in Neo4j.
  4. Detects hardware assets and upserts hardware nodes.
  5. Updates the last_seen timestamp on all touched nodes.

The graph model enables blast-radius queries:
  "Which repos use log4j-core 2.14.1?" → MATCH (r:Repo)-[:DEPENDS_ON*1..5]->(l:Library
  {name:'log4j-core', version:'2.14.1'}) RETURN r.name

Neo4j connection
----------------
The agent reads NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD from the environment
when memory.graph is not provided.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Manifest file names
# ---------------------------------------------------------------------------

MANIFEST_PARSERS: dict[str, str] = {
    "pom.xml":            "maven",
    "package.json":       "npm",
    "package-lock.json":  "npm",
    "yarn.lock":          "npm",
    "go.mod":             "go",
    "go.sum":             "go",
    "requirements.txt":   "pip",
    "pipfile.lock":       "pip",
    "pyproject.toml":     "pip",
    "cargo.toml":         "cargo",
    "cargo.lock":         "cargo",
    "gemfile":            "gem",
    "gemfile.lock":       "gem",
    "build.gradle":       "gradle",
}

# Hardware asset patterns.
_VHDL_EXTS = {".vhd", ".vhdl"}
_KICAD_EXTS = {".kicad_sch", ".kicad_pcb", ".sch"}
_FIRMWARE_EXTS = {".bin", ".hex", ".elf"}

# ---------------------------------------------------------------------------
# CartographerAgent
# ---------------------------------------------------------------------------


class CartographerAgent(ArgosAgent):
    """
    Asset knowledge graph builder.

    Integrates with Neo4j via self.memory.graph (an async Neo4j driver wrapper)
    and with the SCM via self.memory.scm_client (a BitbucketClient or similar).
    """

    name = "cartographer"

    _SYSTEM = """\
You are Cartographer, the asset mapping agent for the ARGOS security platform.

Your task: analyse repository manifest and lockfile contents and extract a
complete, accurate dependency list.

You will receive:
  - The manifest file name and its raw text content
  - The ecosystem (maven, npm, pip, go, cargo, gem, gradle)

You must return ONLY valid JSON (no markdown, no code fences) in this schema:
{
  "dependencies": [
    {
      "name": "<library name>",
      "version": "<exact resolved version or semver range>",
      "is_direct": <bool>,
      "scope": "<compile|test|dev|optional|runtime|provided|null>"
    }
  ]
}

Rules:
  - Include BOTH direct and transitive dependencies when a lockfile is provided.
  - Set is_direct=true only for deps declared in the primary manifest.
  - Use null for scope if the ecosystem does not have scopes.
  - Normalise version strings: strip leading "^", "~", "=", "v".
  - Do NOT include the project itself as a dependency.
"""

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Upsert graph nodes for a repository and its dependencies.

        Context keys
        ------------
        repo : str
            Repository slug.
        platform : str
            "bitbucket" | "github"
        event_type : str
            "push" | "pr_merged" | "scheduled"
        changed_files : list[str]
            Files changed in the triggering event (used to prioritise which
            manifests to fetch).  An empty list triggers a full manifest scan.
        ref : str
            Git ref / branch to fetch files from (default "HEAD").
        project_key : str
            Bitbucket DC project key (ignored on Cloud/GitHub).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        repo: str = context.get("repo", "unknown")
        platform: str = context.get("platform", "bitbucket")
        event_type: str = context.get("event_type", "push")
        changed_files: list[str] = context.get("changed_files", [])
        ref: str = context.get("ref", "HEAD")
        project_key: str = context.get("project_key", "")

        self.log.info(
            "cartographer.run",
            repo=repo,
            event_type=event_type,
            file_count=len(changed_files),
        )

        # Determine which manifests to fetch.
        manifest_paths = self._identify_manifests(changed_files)
        if not manifest_paths:
            # No manifest changes → still upsert the repo node and hardware nodes.
            manifest_paths = []

        scm = self._get_scm_client()

        # 1. Fetch and parse manifest files.
        all_dependencies: list[dict[str, Any]] = []
        fetched_manifests: list[str] = []

        for manifest_name in (manifest_paths or list(MANIFEST_PARSERS.keys())):
            content = await self._fetch_file(scm, repo, manifest_name, ref, project_key)
            if content is None:
                continue
            fetched_manifests.append(manifest_name)
            ecosystem = MANIFEST_PARSERS.get(
                PurePosixPath(manifest_name).name.lower(), "unknown"
            )

            deps = await self._parse_manifest(manifest_name, content, ecosystem)
            all_dependencies.extend(deps)

        # Deduplicate by (name, version).
        seen: set[tuple[str, str]] = set()
        unique_deps: list[dict[str, Any]] = []
        for dep in all_dependencies:
            key = (dep["name"], dep["version"])
            if key not in seen:
                seen.add(key)
                unique_deps.append(dep)

        # 2. Detect hardware assets.
        hardware_assets = self._detect_hardware_assets(changed_files)

        # 3. Upsert into Neo4j graph.
        upsert_errors: list[str] = []
        nodes_written = 0

        if self.memory is not None and hasattr(self.memory, "graph"):
            try:
                nodes_written = await self._upsert_graph(
                    repo=repo,
                    platform=platform,
                    dependencies=unique_deps,
                    hardware_assets=hardware_assets,
                )
            except Exception as exc:  # noqa: BLE001
                upsert_errors.append(str(exc))
                self.log.error("cartographer.graph_upsert_failed", error=str(exc))

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "cartographer.complete",
            repo=repo,
            deps=len(unique_deps),
            hardware=len(hardware_assets),
            nodes_written=nodes_written,
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=len(upsert_errors) == 0,
            findings=[],
            metadata={
                "repo": repo,
                "manifests_fetched": fetched_manifests,
                "dependency_count": len(unique_deps),
                "hardware_asset_count": len(hardware_assets),
                "nodes_written": nodes_written,
            },
            error="; ".join(upsert_errors),
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Bootstrap: map full org
    # ------------------------------------------------------------------

    async def map_full_org(self, org: str, platform: str) -> AgentResult:
        """
        Bootstrap: walk an entire org and build the graph from scratch.

        Lists all repositories in the org, then calls run() for each one.
        Intended to be called once during initial platform setup.
        Run via CLI or a one-off cron job, not during normal event processing.
        """
        self.log.info("cartographer.map_full_org", org=org, platform=platform)
        t0 = time.monotonic()

        scm = self._get_scm_client()
        if scm is None:
            return AgentResult(
                agent=self.name,
                success=False,
                error="No SCM client configured; cannot enumerate org repos.",
                duration_ms=0,
            )

        try:
            repos = await scm.list_repos()
        except Exception as exc:  # noqa: BLE001
            return AgentResult(
                agent=self.name,
                success=False,
                error=f"Failed to list repos: {exc}",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        total_findings = 0
        errors: list[str] = []

        # Process repos sequentially to avoid hammering Neo4j and the SCM API.
        for repo_obj in repos:
            repo_slug = repo_obj.get("slug") or repo_obj.get("name") or ""
            if not repo_slug:
                continue
            try:
                result = await self.run({
                    "repo": repo_slug,
                    "platform": platform,
                    "event_type": "scheduled",
                    "changed_files": [],
                })
                total_findings += result.metadata.get("dependency_count", 0)
                if not result.success:
                    errors.append(f"{repo_slug}: {result.error}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{repo_slug}: {exc}")

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "cartographer.org_map_complete",
            org=org,
            repos=len(repos),
            errors=len(errors),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=len(errors) == 0,
            findings=[],
            metadata={
                "org": org,
                "platform": platform,
                "repos_processed": len(repos),
                "total_dependencies": total_findings,
            },
            error="; ".join(errors[:5]),  # surface first 5 errors
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Graph query helpers
    # ------------------------------------------------------------------

    async def find_blast_radius(self, library: str, version: str) -> list[str]:
        """
        Return all repo slugs that depend on this library version.

        Uses graph memory; returns empty list if graph is unavailable.
        """
        if self.memory is None or not hasattr(self.memory, "graph"):
            return []

        cypher = (
            "MATCH (r:Repo)-[:DEPENDS_ON*1..5]->(l:Library "
            "{name: $name, version: $version}) "
            "RETURN DISTINCT r.slug AS slug"
        )
        try:
            records = await self.memory.graph.run(
                cypher, {"name": library, "version": version}
            )
            repos = [r["slug"] for r in records]
            self.log.info(
                "cartographer.blast_radius",
                library=library,
                version=version,
                count=len(repos),
            )
            return repos
        except Exception as exc:  # noqa: BLE001
            self.log.warning("cartographer.blast_radius_failed", error=str(exc))
            return []

    async def get_dependency_path(
        self, repo: str, target_library: str
    ) -> list[str]:
        """
        Return the dependency chain: repo → A → B → target_library.

        Uses Neo4j shortest-path query.  Returns empty list if no path found.
        """
        if self.memory is None or not hasattr(self.memory, "graph"):
            return []

        cypher = (
            "MATCH path = shortestPath("
            "(r:Repo {slug: $repo})-[:DEPENDS_ON*]->(l:Library {name: $target})"
            ") "
            "RETURN [n IN nodes(path) | coalesce(n.slug, n.name)] AS chain"
        )
        try:
            records = await self.memory.graph.run(
                cypher, {"repo": repo, "target": target_library}
            )
            if records:
                return records[0].get("chain", [])
            return []
        except Exception as exc:  # noqa: BLE001
            self.log.warning("cartographer.dep_path_failed", error=str(exc))
            return []

    # ------------------------------------------------------------------
    # Manifest identification
    # ------------------------------------------------------------------

    def _identify_manifests(self, changed_files: list[str]) -> list[str]:
        """Return the subset of changed_files that are known manifests."""
        result: list[str] = []
        for f in changed_files:
            name = PurePosixPath(f).name.lower()
            if name in MANIFEST_PARSERS:
                result.append(f)
        return result

    # ------------------------------------------------------------------
    # Hardware asset detection
    # ------------------------------------------------------------------

    def _detect_hardware_assets(
        self, changed_files: list[str]
    ) -> list[dict[str, Any]]:
        """Classify changed files into hardware asset records."""
        assets: list[dict[str, Any]] = []
        for f in changed_files:
            ext = PurePosixPath(f).suffix.lower()
            if ext in _VHDL_EXTS:
                assets.append({"path": f, "type": "vhdl_module"})
            elif ext in _KICAD_EXTS:
                assets.append({"path": f, "type": "kicad_design"})
            elif ext in _FIRMWARE_EXTS:
                assets.append({"path": f, "type": "firmware_blob"})
        return assets

    # ------------------------------------------------------------------
    # Manifest parsing (Claude-assisted)
    # ------------------------------------------------------------------

    async def _parse_manifest(
        self,
        filename: str,
        content: str,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """
        Parse manifest content into a dependency list.

        Tries a fast built-in parser first (to save tokens); falls back to
        Claude for complex or unfamiliar formats.
        """
        name = PurePosixPath(filename).name.lower()

        # Fast paths for common formats.
        if name == "pom.xml":
            deps = self._parse_pom(content)
            if deps is not None:
                return deps
        elif name == "package.json":
            deps = self._parse_package_json(content)
            if deps is not None:
                return deps
        elif name == "go.mod":
            deps = self._parse_go_mod(content)
            if deps is not None:
                return deps
        elif name == "requirements.txt":
            deps = self._parse_requirements_txt(content)
            if deps is not None:
                return deps

        # Fall back to Claude for everything else.
        return await self._parse_with_claude(filename, content, ecosystem)

    def _parse_pom(self, content: str) -> list[dict[str, Any]] | None:
        """Parse Maven pom.xml.  Returns None on parse error."""
        try:
            root = ET.fromstring(content)
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            deps: list[dict[str, Any]] = []
            for dep in root.findall(".//m:dependency", ns):
                group = dep.findtext("m:groupId", namespaces=ns) or ""
                artifact = dep.findtext("m:artifactId", namespaces=ns) or ""
                version = dep.findtext("m:version", namespaces=ns) or "UNKNOWN"
                scope = dep.findtext("m:scope", namespaces=ns)
                name = f"{group}:{artifact}" if group else artifact
                deps.append({
                    "name": name,
                    "version": version.lstrip("^~=v"),
                    "is_direct": True,
                    "scope": scope,
                })
            return deps
        except ET.ParseError:
            return None

    def _parse_package_json(self, content: str) -> list[dict[str, Any]] | None:
        """Parse npm package.json.  Returns None on parse error."""
        try:
            data = json.loads(content)
            deps: list[dict[str, Any]] = []
            for section, is_direct, scope in [
                ("dependencies", True, "runtime"),
                ("devDependencies", True, "dev"),
                ("peerDependencies", True, "peer"),
                ("optionalDependencies", True, "optional"),
            ]:
                for name, version in data.get(section, {}).items():
                    deps.append({
                        "name": name,
                        "version": str(version).lstrip("^~=v"),
                        "is_direct": is_direct,
                        "scope": scope,
                    })
            return deps
        except (json.JSONDecodeError, AttributeError):
            return None

    def _parse_go_mod(self, content: str) -> list[dict[str, Any]] | None:
        """Parse go.mod.  Returns None on unexpected format."""
        try:
            deps: list[dict[str, Any]] = []
            in_require_block = False
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("require ("):
                    in_require_block = True
                    continue
                if in_require_block and line == ")":
                    in_require_block = False
                    continue
                if in_require_block or line.startswith("require "):
                    # require github.com/some/pkg v1.2.3
                    parts = re.split(r"\s+", line.replace("require ", ""))
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1]
                        indirect = "// indirect" in line
                        deps.append({
                            "name": name,
                            "version": version.lstrip("v"),
                            "is_direct": not indirect,
                            "scope": None,
                        })
            return deps if deps else None
        except Exception:  # noqa: BLE001
            return None

    def _parse_requirements_txt(self, content: str) -> list[dict[str, Any]] | None:
        """Parse pip requirements.txt."""
        deps: list[dict[str, Any]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # e.g. "requests>=2.28.0" or "flask==2.3.0"
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[><=!~]+\s*([^\s;]+)", line)
            if match:
                name, version = match.group(1), match.group(2)
                deps.append({
                    "name": name,
                    "version": version.lstrip("v"),
                    "is_direct": True,
                    "scope": None,
                })
            else:
                # bare package name without version pin
                pkg = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if pkg:
                    deps.append({
                        "name": pkg.group(1),
                        "version": "ANY",
                        "is_direct": True,
                        "scope": None,
                    })
        return deps if deps else None

    async def _parse_with_claude(
        self,
        filename: str,
        content: str,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """
        Use Claude with adaptive thinking to parse an unfamiliar manifest.
        """
        # Truncate very large files (lockfiles can be huge).
        max_chars = 12_000
        truncated = len(content) > max_chars
        snippet = content[:max_chars]
        if truncated:
            snippet += "\n[... truncated ...]"

        user_content = f"""Manifest file: {filename}
Ecosystem: {ecosystem}
{"(Content truncated at 12,000 chars)" if truncated else ""}

--- BEGIN CONTENT ---
{snippet}
--- END CONTENT ---

Return the dependency JSON now."""

        try:
            text = await self._call_claude(
                system=self._SYSTEM,
                messages=[{"role": "user", "content": user_content}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error(
                "cartographer.claude_parse_failed",
                filename=filename,
                error=str(exc),
            )
            return []

        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            data = json.loads(text)
            deps: list[dict[str, Any]] = data.get("dependencies", [])
            self.log.debug(
                "cartographer.claude_parse_ok",
                filename=filename,
                count=len(deps),
            )
            return deps
        except json.JSONDecodeError as exc:
            self.log.error(
                "cartographer.json_parse_failed",
                filename=filename,
                error=str(exc),
                raw=text[:200],
            )
            return []

    # ------------------------------------------------------------------
    # Neo4j upsert
    # ------------------------------------------------------------------

    async def _upsert_graph(
        self,
        repo: str,
        platform: str,
        dependencies: list[dict[str, Any]],
        hardware_assets: list[dict[str, Any]],
    ) -> int:
        """
        Upsert repo, library, and hardware nodes + edges into Neo4j.

        Returns the number of nodes written.
        """
        from datetime import datetime, timezone

        graph = self.memory.graph  # type: ignore[union-attr]
        now_iso = datetime.now(timezone.utc).isoformat()
        nodes_written = 0

        # Upsert Repo node.
        await graph.run(
            "MERGE (r:Repo {slug: $slug}) "
            "SET r.platform = $platform, r.last_seen = $now",
            {"slug": repo, "platform": platform, "now": now_iso},
        )
        nodes_written += 1

        # Upsert Library nodes + DEPENDS_ON edges.
        for dep in dependencies:
            await graph.run(
                "MERGE (l:Library {name: $name, version: $version}) "
                "SET l.ecosystem = $ecosystem, l.last_seen = $now "
                "WITH l "
                "MATCH (r:Repo {slug: $repo}) "
                "MERGE (r)-[e:DEPENDS_ON]->(l) "
                "SET e.is_direct = $is_direct, e.scope = $scope, e.last_seen = $now",
                {
                    "name": dep["name"],
                    "version": dep["version"],
                    "ecosystem": dep.get("scope", ""),
                    "repo": repo,
                    "is_direct": dep.get("is_direct", True),
                    "scope": dep.get("scope"),
                    "now": now_iso,
                },
            )
            nodes_written += 1

        # Upsert Hardware nodes + USES_HARDWARE edges.
        for asset in hardware_assets:
            await graph.run(
                "MERGE (h:HardwareAsset {path: $path, repo: $repo}) "
                "SET h.type = $type, h.last_seen = $now "
                "WITH h "
                "MATCH (r:Repo {slug: $repo}) "
                "MERGE (r)-[:USES_HARDWARE]->(h)",
                {
                    "path": asset["path"],
                    "repo": repo,
                    "type": asset["type"],
                    "now": now_iso,
                },
            )
            nodes_written += 1

        return nodes_written

    # ------------------------------------------------------------------
    # SCM client helper
    # ------------------------------------------------------------------

    def _get_scm_client(self) -> Any | None:
        """Return the SCM client from memory, or None."""
        if self.memory is not None and hasattr(self.memory, "scm_client"):
            return self.memory.scm_client
        return None

    async def _fetch_file(
        self,
        scm: Any | None,
        repo: str,
        path: str,
        ref: str,
        project_key: str,
    ) -> str | None:
        """Fetch a file from the SCM.  Returns None on 404 or no SCM."""
        if scm is None:
            return None
        try:
            return await scm.get_file_content(
                repo=repo,
                path=path,
                ref=ref,
                project_key=project_key,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.debug(
                "cartographer.fetch_failed",
                repo=repo,
                path=path,
                error=str(exc),
            )
            return None
