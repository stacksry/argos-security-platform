"""
argos/memory/graph.py

Neo4j knowledge graph for ARGOS — the asset universe.

Models the full dependency and vulnerability graph:
  (Repo)-[:DEPENDS_ON]->(Library)-[:AFFECTED_BY]->(CVE)
  (Repo)-[:CONTAINS]->(HardwareAsset)
  (Repo)-[:HAS_FINDING]->(Finding)

All queries use parameterised Cypher (never string interpolation).
MERGE is used for all upserts to ensure idempotency.
"""

from __future__ import annotations

from typing import Any

import structlog
from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession

logger: structlog.BoundLogger = structlog.get_logger(__name__)


class GraphMemory:
    """
    Async Neo4j wrapper for ARGOS asset and vulnerability graph.

    Parameters
    ----------
    uri:
        Bolt URI, e.g. ``bolt://localhost:7687``.
    user:
        Neo4j username.
    password:
        Neo4j password.
    database:
        Target database (default ``neo4j``).
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "argos",
        database: str = "neo4j",
    ) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._database = database
        self._driver: AsyncDriver | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the async Neo4j driver."""
        self._driver = AsyncGraphDatabase.driver(
            self._uri, auth=(self._user, self._password)
        )
        logger.info("graph.connected", uri=self._uri, database=self._database)

    async def close(self) -> None:
        """Close the Neo4j driver and all open sessions."""
        if self._driver:
            await self._driver.close()
            logger.info("graph.disconnected")

    def _session(self) -> AsyncSession:
        if self._driver is None:
            raise RuntimeError("GraphMemory not connected — call connect() first.")
        return self._driver.session(database=self._database)

    # ------------------------------------------------------------------
    # Index / constraint bootstrap
    # ------------------------------------------------------------------

    async def init_schema(self) -> None:
        """
        Create uniqueness constraints and indexes used by ARGOS.

        Safe to call multiple times; Neo4j MERGE handles pre-existing objects.
        """
        constraints = [
            "CREATE CONSTRAINT repo_name IF NOT EXISTS FOR (r:Repo) REQUIRE r.name IS UNIQUE",
            "CREATE CONSTRAINT library_identity IF NOT EXISTS FOR (l:Library) REQUIRE (l.name, l.version) IS NODE KEY",
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
            "CREATE CONSTRAINT hardware_name IF NOT EXISTS FOR (h:HardwareAsset) REQUIRE h.name IS UNIQUE",
        ]
        async with self._session() as session:
            for stmt in constraints:
                await session.run(stmt)
        logger.info("graph.schema_initialized")

    # ------------------------------------------------------------------
    # Repo nodes
    # ------------------------------------------------------------------

    async def upsert_repo(
        self,
        name: str,
        url: str,
        language: str,
        team: str,
        metadata: dict[str, Any],
    ) -> None:
        """
        Insert or update a Repo node.

        Parameters
        ----------
        name:
            Canonical repo identifier, e.g. ``acme/payments-service``.
        url:
            Git remote URL.
        language:
            Primary language (``python``, ``c``, ``verilog``, …).
        team:
            Owning team slug.
        metadata:
            Arbitrary key/value pairs stored as node properties.
        """
        cypher = """
        MERGE (r:Repo {name: $name})
        SET r.url       = $url,
            r.language  = $language,
            r.team      = $team,
            r.metadata  = $metadata,
            r.updated_at = datetime()
        """
        async with self._session() as session:
            await session.run(
                cypher,
                name=name,
                url=url,
                language=language,
                team=team,
                metadata=str(metadata),
            )
        logger.debug("graph.repo_upserted", repo=name)

    # ------------------------------------------------------------------
    # Library nodes
    # ------------------------------------------------------------------

    async def upsert_library(
        self,
        name: str,
        version: str,
        ecosystem: str,
    ) -> None:
        """
        Insert or update a Library node.

        Parameters
        ----------
        name:
            Package name, e.g. ``requests``.
        version:
            Exact pinned version string, e.g. ``2.28.1``.
        ecosystem:
            Package ecosystem (``pypi``, ``npm``, ``maven``, ``cargo``, …).
        """
        cypher = """
        MERGE (l:Library {name: $name, version: $version})
        SET l.ecosystem  = $ecosystem,
            l.updated_at = datetime()
        """
        async with self._session() as session:
            await session.run(cypher, name=name, version=version, ecosystem=ecosystem)
        logger.debug("graph.library_upserted", library=name, version=version)

    # ------------------------------------------------------------------
    # Dependency edges
    # ------------------------------------------------------------------

    async def link_dependency(
        self,
        repo: str,
        library: str,
        version: str,
        dep_type: str = "direct",
    ) -> None:
        """
        Create a DEPENDS_ON edge from a Repo to a Library.

        Both nodes are MERGE'd so this is safe to call with or without a
        prior upsert_repo / upsert_library call.

        Parameters
        ----------
        repo:
            Repo name.
        library:
            Library name.
        version:
            Library version.
        dep_type:
            Relationship type: ``direct`` or ``transitive``.
        """
        cypher = """
        MERGE (r:Repo    {name: $repo})
        MERGE (l:Library {name: $library, version: $version})
        MERGE (r)-[d:DEPENDS_ON]->(l)
        SET d.dep_type   = $dep_type,
            d.updated_at = datetime()
        """
        async with self._session() as session:
            await session.run(
                cypher,
                repo=repo,
                library=library,
                version=version,
                dep_type=dep_type,
            )
        logger.debug(
            "graph.dependency_linked",
            repo=repo,
            library=library,
            version=version,
            dep_type=dep_type,
        )

    # ------------------------------------------------------------------
    # Hardware assets
    # ------------------------------------------------------------------

    async def upsert_hardware_asset(
        self,
        name: str,
        asset_type: str,
        repo: str,
    ) -> None:
        """
        Insert or update a HardwareAsset node and link it to a Repo.

        Parameters
        ----------
        name:
            Unique asset identifier, e.g. ``power-board-v3``.
        asset_type:
            One of ``PCB``, ``FPGA``, or ``firmware``.
        repo:
            Owning repo name.
        """
        cypher = """
        MERGE (h:HardwareAsset {name: $name})
        SET h.asset_type = $asset_type,
            h.updated_at = datetime()
        WITH h
        MERGE (r:Repo {name: $repo})
        MERGE (r)-[:CONTAINS]->(h)
        """
        async with self._session() as session:
            await session.run(cypher, name=name, asset_type=asset_type, repo=repo)
        logger.debug("graph.hardware_asset_upserted", name=name, asset_type=asset_type, repo=repo)

    # ------------------------------------------------------------------
    # CVE nodes
    # ------------------------------------------------------------------

    async def upsert_cve(
        self,
        cve_id: str,
        severity: float,
        affected_library: str,
        affected_versions: str,
    ) -> None:
        """
        Insert or update a CVE node and link it to the affected Library.

        Parameters
        ----------
        cve_id:
            CVE identifier, e.g. ``CVE-2023-12345``.
        severity:
            CVSS v3 base score (0.0–10.0).
        affected_library:
            Library name.
        affected_versions:
            Version range string, e.g. ``<2.29.0`` (stored as text for now).
        """
        cypher = """
        MERGE (c:CVE {cve_id: $cve_id})
        SET c.severity          = $severity,
            c.affected_versions = $affected_versions,
            c.updated_at        = datetime()
        WITH c
        MERGE (l:Library {name: $affected_library, version: $affected_versions})
        MERGE (l)-[:AFFECTED_BY]->(c)
        """
        async with self._session() as session:
            await session.run(
                cypher,
                cve_id=cve_id,
                severity=severity,
                affected_library=affected_library,
                affected_versions=affected_versions,
            )
        logger.debug("graph.cve_upserted", cve_id=cve_id, severity=severity)

    # ------------------------------------------------------------------
    # Finding nodes
    # ------------------------------------------------------------------

    async def mark_finding(
        self,
        repo: str,
        finding_id: str,
        severity: str,
        status: str,
    ) -> None:
        """
        Record a security finding on a Repo node.

        Parameters
        ----------
        repo:
            Repo name.
        finding_id:
            Unique finding identifier (UUID or deterministic hash).
        severity:
            ``critical``, ``high``, ``medium``, ``low``, or ``info``.
        status:
            ``open``, ``confirmed``, ``false_positive``, or ``resolved``.
        """
        cypher = """
        MERGE (r:Repo {name: $repo})
        MERGE (f:Finding {finding_id: $finding_id})
        SET f.severity   = $severity,
            f.status     = $status,
            f.updated_at = datetime()
        MERGE (r)-[:HAS_FINDING]->(f)
        """
        async with self._session() as session:
            await session.run(
                cypher,
                repo=repo,
                finding_id=finding_id,
                severity=severity,
                status=status,
            )
        logger.debug(
            "graph.finding_marked",
            repo=repo,
            finding_id=finding_id,
            severity=severity,
            status=status,
        )

    # ------------------------------------------------------------------
    # Blast radius
    # ------------------------------------------------------------------

    async def find_blast_radius(
        self,
        library: str,
        version_range: str,
    ) -> list[dict[str, Any]]:
        """
        Return all repos that depend on *library* within *version_range*.

        The version range is matched as an exact string for now; a richer
        semver comparator can be wired in as a Neo4j plugin or pre-filtered
        in Python before storing.

        Returns
        -------
        list[dict]
            Each entry: ``{"repo": str, "dep_type": str, "version": str}``.
        """
        cypher = """
        MATCH (r:Repo)-[d:DEPENDS_ON]->(l:Library {name: $library})
        WHERE l.version CONTAINS $version_range OR $version_range = '*'
        RETURN r.name AS repo, d.dep_type AS dep_type, l.version AS version
        ORDER BY r.name
        """
        async with self._session() as session:
            result = await session.run(
                cypher, library=library, version_range=version_range
            )
            records = await result.data()

        logger.info(
            "graph.blast_radius",
            library=library,
            version_range=version_range,
            affected_repos=len(records),
        )
        return records

    # ------------------------------------------------------------------
    # Cross-repo pattern search
    # ------------------------------------------------------------------

    async def find_cross_repo_pattern(
        self,
        pattern_signature: str,
    ) -> list[str]:
        """
        Return repo names that share a Finding with the given pattern signature.

        Useful for propagating a confirmed vulnerability detection to all repos
        that exhibit the same structural pattern.

        Parameters
        ----------
        pattern_signature:
            Opaque string that uniquely identifies a vulnerability pattern
            (typically the hash of a canonical AST subtree or regex).
        """
        cypher = """
        MATCH (r:Repo)-[:HAS_FINDING]->(f:Finding {pattern_signature: $sig})
        RETURN DISTINCT r.name AS repo
        ORDER BY r.name
        """
        async with self._session() as session:
            result = await session.run(cypher, sig=pattern_signature)
            records = await result.data()

        repos = [row["repo"] for row in records]
        logger.debug(
            "graph.cross_repo_pattern",
            pattern_signature=pattern_signature,
            repos_found=len(repos),
        )
        return repos

    # ------------------------------------------------------------------
    # Asset context
    # ------------------------------------------------------------------

    async def get_asset_context(self, repo: str) -> dict[str, Any]:
        """
        Return a summary subgraph for a repo: dependencies, CVEs, findings,
        hardware assets.

        Returns
        -------
        dict
            Keys: ``repo``, ``dependencies``, ``cves``, ``findings``,
            ``hardware_assets``.
        """
        cypher = """
        MATCH (r:Repo {name: $repo})
        OPTIONAL MATCH (r)-[d:DEPENDS_ON]->(l:Library)
        OPTIONAL MATCH (l)-[:AFFECTED_BY]->(c:CVE)
        OPTIONAL MATCH (r)-[:HAS_FINDING]->(f:Finding)
        OPTIONAL MATCH (r)-[:CONTAINS]->(h:HardwareAsset)
        RETURN
          r.name        AS repo,
          collect(DISTINCT {
            library:  l.name,
            version:  l.version,
            dep_type: d.dep_type
          })            AS dependencies,
          collect(DISTINCT {
            cve_id:   c.cve_id,
            severity: c.severity
          })            AS cves,
          collect(DISTINCT {
            finding_id: f.finding_id,
            severity:   f.severity,
            status:     f.status
          })            AS findings,
          collect(DISTINCT {
            name:       h.name,
            asset_type: h.asset_type
          })            AS hardware_assets
        """
        async with self._session() as session:
            result = await session.run(cypher, repo=repo)
            records = await result.data()

        if not records:
            logger.warning("graph.asset_context_not_found", repo=repo)
            return {"repo": repo, "dependencies": [], "cves": [], "findings": [], "hardware_assets": []}

        ctx = records[0]
        # Filter out None-only dicts produced when optional matches miss.
        for key in ("dependencies", "cves", "findings", "hardware_assets"):
            ctx[key] = [item for item in ctx.get(key, []) if any(v is not None for v in item.values())]

        logger.debug("graph.asset_context_fetched", repo=repo)
        return ctx
