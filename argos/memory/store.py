"""
argos/memory/store.py

Unified memory facade for ARGOS agents.

Agents import ArgosMemory and call its methods — they never talk to the
individual backends (Qdrant, Neo4j, TimescaleDB, PostgreSQL) directly.

Memory model
------------
  semantic   – vector similarity search (Qdrant via VectorMemory)
  episodic   – time-series scan history (TimescaleDB via EpisodicMemory)
  procedural – structured learned knowledge (PostgreSQL via ProceduralMemory)
  graph      – asset / dependency relationships (Neo4j via GraphMemory)

Typical agent usage::

    memory = await ArgosMemory.create()

    # Retrieve context before analysis
    examples = await memory.get_fix_examples("sql_injection", "python")
    fp_signals = await memory.get_false_positive_signals("sql_injection")

    # ... run analysis ...

    # Write back what was learned
    await memory.record_fix_pattern("sql_injection", "python", vuln, fix, repo)
    await memory.record_scan(repo, scan_id, findings_count, duration_ms)
    await memory.index_vulnerability(finding_id, snippet, metadata)
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from argos.memory.episodic import EpisodicMemory
from argos.memory.graph import GraphMemory
from argos.memory.procedural import ProceduralMemory
from argos.memory.vector import VectorMemory

logger: structlog.BoundLogger = structlog.get_logger(__name__)


class ArgosMemory:
    """
    Unified memory facade.

    Agents call this — they do not interact with individual backends.

    Parameters
    ----------
    vector:
        Pre-constructed :class:`~argos.memory.vector.VectorMemory` instance.
    episodic:
        Pre-constructed :class:`~argos.memory.episodic.EpisodicMemory` instance.
    procedural:
        Pre-constructed :class:`~argos.memory.procedural.ProceduralMemory` instance.
    graph:
        Pre-constructed :class:`~argos.memory.graph.GraphMemory` instance.
    """

    def __init__(
        self,
        vector: VectorMemory,
        episodic: EpisodicMemory,
        procedural: ProceduralMemory,
        graph: GraphMemory,
    ) -> None:
        self._vector = vector
        self._episodic = episodic
        self._procedural = procedural
        self._graph = graph

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        *,
        qdrant_host: str = "localhost",
        qdrant_port: int = 6333,
        qdrant_api_key: str | None = None,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "argos",
        neo4j_database: str = "neo4j",
        pg_dsn: str = "postgresql://argos:argos@localhost:5432/argos",
    ) -> "ArgosMemory":
        """
        Convenience factory: construct all backends, connect, and initialise
        their schemas in one call.

        Returns a fully initialised :class:`ArgosMemory` instance.
        """
        vector = VectorMemory(
            host=qdrant_host,
            port=qdrant_port,
            api_key=qdrant_api_key,
        )
        await vector.connect()
        await vector.init_collections()

        episodic = EpisodicMemory(dsn=pg_dsn)
        await episodic.connect()
        await episodic.init_schema()

        procedural = ProceduralMemory(dsn=pg_dsn)
        await procedural.connect()
        await procedural.init_schema()

        graph = GraphMemory(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            database=neo4j_database,
        )
        await graph.connect()
        await graph.init_schema()

        logger.info("argos_memory.ready")
        return cls(vector=vector, episodic=episodic, procedural=procedural, graph=graph)

    async def close(self) -> None:
        """Close all backend connections gracefully."""
        await self._vector.close()
        await self._episodic.close()
        await self._procedural.close()
        await self._graph.close()
        logger.info("argos_memory.closed")

    # ==================================================================
    # Semantic memory  (Qdrant)
    # ==================================================================

    async def search_similar_vulnerability(
        self,
        code_snippet: str,
        language: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Find stored vulnerability findings that are semantically similar to
        *code_snippet*.

        Parameters
        ----------
        code_snippet:
            Source code fragment to use as the query.
        language:
            Programming language of the snippet — used as a collection filter.
        limit:
            Maximum number of results.

        Returns
        -------
        list[dict]
            Each entry: ``{"id": str, "score": float, "payload": dict}``.
        """
        results = await self._vector.search(
            collection="vulnerabilities",
            query_text=code_snippet,
            filter={"language": language},
            limit=limit,
        )
        logger.debug(
            "store.search_similar_vulnerability",
            language=language,
            hits=len(results),
        )
        return results

    async def index_vulnerability(
        self,
        finding_id: str,
        code_snippet: str,
        metadata: dict[str, Any],
    ) -> None:
        """
        Embed and store a vulnerability finding in the vector index.

        Parameters
        ----------
        finding_id:
            Stable finding identifier.
        code_snippet:
            The vulnerable code fragment to embed.
        metadata:
            Arbitrary key/value pairs (``language``, ``vuln_class``,
            ``severity``, ``repo``, etc.) stored as Qdrant payload.
        """
        vector = await self._vector.embed_code(code_snippet)
        await self._vector.upsert(
            collection="vulnerabilities",
            id=finding_id,
            vector=vector,
            payload={**metadata, "finding_id": finding_id},
        )
        logger.debug("store.index_vulnerability", finding_id=finding_id)

    async def search_similar_hardware(
        self,
        design_snippet: str,
        design_type: str,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Find stored hardware designs similar to *design_snippet*.

        Parameters
        ----------
        design_snippet:
            HDL / schematic text fragment to embed.
        design_type:
            Design kind: ``PCB``, ``FPGA``, ``firmware``, etc. Used as filter.
        limit:
            Maximum number of results.

        Returns
        -------
        list[dict]
            Each entry: ``{"id": str, "score": float, "payload": dict}``.
        """
        results = await self._vector.search(
            collection="hardware_designs",
            query_text=design_snippet,
            filter={"design_type": design_type},
            limit=limit,
        )
        logger.debug(
            "store.search_similar_hardware",
            design_type=design_type,
            hits=len(results),
        )
        return results

    # ==================================================================
    # Episodic memory  (TimescaleDB)
    # ==================================================================

    async def record_scan(
        self,
        repo: str,
        scan_id: str,
        findings_count: int,
        duration_ms: int,
        agent: str = "argos",
        trigger: str = "manual",
    ) -> None:
        """
        Append a scan event to the episodic time-series store.

        Parameters
        ----------
        repo:
            Repository name.
        scan_id:
            Unique scan run identifier.
        findings_count:
            Number of findings produced by the scan.
        duration_ms:
            Wall-clock duration in milliseconds.
        agent:
            Agent slug that performed the scan.
        trigger:
            What triggered the scan (``manual``, ``push``, ``schedule``, …).
        """
        await self._episodic.record_scan(
            repo=repo,
            scan_id=scan_id,
            agent=agent,
            findings=findings_count,
            duration_ms=duration_ms,
            trigger=trigger,
        )
        logger.debug("store.record_scan", repo=repo, scan_id=scan_id)

    async def get_scan_history(
        self,
        repo: str,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Return the findings trend for a repo over the last *days* days.

        Parameters
        ----------
        repo:
            Repository name.
        days:
            Look-back window in days.

        Returns
        -------
        list[dict]
            Sorted ascending by day; each entry has ``day``, ``agent``,
            ``findings`` keys.
        """
        return await self._episodic.get_vulnerability_trend(repo=repo, days=days)

    async def record_finding_resolution(
        self,
        finding_id: str,
        resolution: str,
        days_to_fix: int,
        repo: str = "",
        vuln_class: str = "",
        severity: str = "medium",
        agent: str = "argos",
    ) -> None:
        """
        Record that a finding has been resolved (or closed as a false positive).

        Appends two events to the findings_timeline hypertable: the original
        ``open`` event (if not already present) and the ``resolved`` /
        ``false_positive`` event. Also stores ``days_to_fix`` as an agent metric.

        Parameters
        ----------
        finding_id:
            Finding identifier.
        resolution:
            ``resolved`` or ``false_positive``.
        days_to_fix:
            Calendar days elapsed between discovery and resolution.
        repo:
            Originating repository.
        vuln_class:
            Vulnerability class.
        severity:
            Severity string.
        agent:
            Agent that resolved the finding.
        """
        await self._episodic.record_finding_event(
            repo=repo,
            finding_id=finding_id,
            vuln_class=vuln_class,
            severity=severity,
            status=resolution,
            agent=agent,
        )
        if days_to_fix >= 0:
            await self._episodic.record_metric(
                repo=repo,
                metric_name="days_to_fix",
                value=float(days_to_fix),
                agent=agent,
            )
        logger.debug(
            "store.finding_resolved",
            finding_id=finding_id,
            resolution=resolution,
            days_to_fix=days_to_fix,
        )

    # ==================================================================
    # Procedural memory  (PostgreSQL)
    # ==================================================================

    async def get_fix_examples(
        self,
        vuln_class: str,
        language: str,
        limit: int = 3,
    ) -> str:
        """
        Return LLM-ready fix examples for a vulnerability class.

        Returns a Markdown-formatted string ready to inject into an agent
        prompt as few-shot context.

        Parameters
        ----------
        vuln_class:
            Vulnerability category.
        language:
            Programming language.
        limit:
            Maximum number of examples to return.
        """
        return await self._procedural.get_fix_examples(
            vuln_class=vuln_class, language=language, limit=limit
        )

    async def record_fix_pattern(
        self,
        vuln_class: str,
        language: str,
        vulnerable: str,
        fix: str,
        repo: str = "",
        confidence: int = 1,
    ) -> None:
        """
        Store a vulnerable → fix code pair for self-learning.

        Parameters
        ----------
        vuln_class:
            Vulnerability category.
        language:
            Programming language of the snippets.
        vulnerable:
            Insecure code fragment.
        fix:
            Corrected replacement.
        repo:
            Source repository (provenance).
        confidence:
            Initial confidence weight.
        """
        await self._procedural.record_fix_pattern(
            vuln_class=vuln_class,
            language=language,
            vulnerable=vulnerable,
            fix=fix,
            repo=repo,
            confidence=confidence,
        )
        # Also index the fix pattern in the vector store for similarity search.
        pattern_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{vuln_class}:{language}:{vulnerable}"))
        vector = await self._vector.embed_code(vulnerable)
        await self._vector.upsert(
            collection="fix_patterns",
            id=pattern_id,
            vector=vector,
            payload={
                "vuln_class": vuln_class,
                "language": language,
                "fix_snippet": fix,
                "repo": repo,
            },
        )
        logger.debug(
            "store.fix_pattern_recorded",
            vuln_class=vuln_class,
            language=language,
        )

    async def get_false_positive_signals(self, vuln_class: str) -> str:
        """
        Return LLM-ready false positive suppression signals.

        Returns a Markdown-formatted string for prompt injection.
        """
        return await self._procedural.get_false_positive_signals(vuln_class=vuln_class)

    async def record_false_positive(
        self,
        vuln_class: str,
        file_pattern: str,
        reason: str,
        signal: str,
    ) -> None:
        """
        Record a false positive suppression signal.

        Parameters
        ----------
        vuln_class:
            Vulnerability class.
        file_pattern:
            Glob / regex matching the file context where this is a FP.
        reason:
            Why this is a false positive.
        signal:
            Machine-readable trigger to suppress future findings.
        """
        await self._procedural.record_false_positive(
            vuln_class=vuln_class,
            file_pattern=file_pattern,
            reason=reason,
            signal=signal,
        )

    async def get_cvss_calibrations(self, vuln_class: str) -> str:
        """
        Return LLM-ready CVSS calibration context for a vuln class.

        Returns a Markdown string with historical score corrections and the
        average systematic delta.
        """
        return await self._procedural.get_cvss_calibrations(vuln_class=vuln_class)

    async def record_cvss_correction(
        self,
        vuln_class: str,
        original: float,
        corrected: float,
        reason: str,
    ) -> None:
        """
        Record a CVSS score correction for calibration.

        Parameters
        ----------
        vuln_class:
            Vulnerability class.
        original:
            Score initially assigned.
        corrected:
            Analyst-validated score.
        reason:
            Explanation of the discrepancy.
        """
        await self._procedural.record_cvss_correction(
            vuln_class=vuln_class,
            original=original,
            corrected=corrected,
            reason=reason,
        )

    async def get_ranker_calibrations(self) -> str:
        """
        Return LLM-ready file-ranker calibration lessons.

        Returns a Markdown-formatted string listing past ranker misses and
        the lessons extracted from them.
        """
        return await self._procedural.get_ranker_calibrations()

    async def record_ranker_miss(
        self,
        file_pattern: str,
        extension: str,
        ranked: int,
        actual: str,
        lesson: str,
    ) -> None:
        """
        Record a file ranker mis-prioritisation for calibration.

        Parameters
        ----------
        file_pattern:
            Glob / regex matching the affected file.
        extension:
            File extension.
        ranked:
            Score the ranker assigned.
        actual:
            True severity discovered post-triage.
        lesson:
            Free-text calibration lesson.
        """
        await self._procedural.record_ranker_miss(
            file_pattern=file_pattern,
            extension=extension,
            ranked=ranked,
            actual=actual,
            lesson=lesson,
        )

    async def record_confirmed_pattern(
        self,
        vuln_class: str,
        pattern: str,
        language: str,
        confirmed_by: str = "agent",
    ) -> None:
        """
        Store or reinforce a confirmed vulnerability detection pattern.

        Parameters
        ----------
        vuln_class:
            Vulnerability class this pattern detects.
        pattern:
            Regex or AST pattern string.
        language:
            Target language.
        confirmed_by:
            Agent or analyst that confirmed the pattern.
        """
        await self._procedural.record_confirmed_pattern(
            vuln_class=vuln_class,
            pattern=pattern,
            language=language,
            confirmed_by=confirmed_by,
        )

    async def get_confirmed_patterns(self, vuln_class: str) -> list[str]:
        """
        Return confirmed detection pattern strings for a vuln class.

        Sorted by confirmation frequency descending.

        Returns
        -------
        list[str]
            Pattern strings.
        """
        return await self._procedural.get_confirmed_patterns(vuln_class=vuln_class)

    async def memory_stats(self) -> dict[str, Any]:
        """
        Return row counts across all procedural memory tables.

        Useful for monitoring dashboards and health checks.

        Returns
        -------
        dict
            Table-name → row count.
        """
        return await self._procedural.memory_stats()

    # ==================================================================
    # Graph memory  (Neo4j)
    # ==================================================================

    async def upsert_repo(self, repo: str, metadata: dict[str, Any]) -> None:
        """
        Insert or update a repository node in the knowledge graph.

        Parameters
        ----------
        repo:
            Canonical repo identifier (e.g. ``acme/payments-service``).
        metadata:
            Dict with optional keys: ``url``, ``language``, ``team``.
            Unknown keys are stored as a serialised ``metadata`` property.
        """
        await self._graph.upsert_repo(
            name=repo,
            url=metadata.get("url", ""),
            language=metadata.get("language", ""),
            team=metadata.get("team", ""),
            metadata={k: v for k, v in metadata.items() if k not in ("url", "language", "team")},
        )
        logger.debug("store.upsert_repo", repo=repo)

    async def upsert_dependency(
        self,
        repo: str,
        library: str,
        version: str,
        ecosystem: str,
    ) -> None:
        """
        Record a dependency edge in the knowledge graph.

        Upserts both the Library node and the DEPENDS_ON relationship from
        the Repo node.

        Parameters
        ----------
        repo:
            Repository name.
        library:
            Package name.
        version:
            Exact pinned version.
        ecosystem:
            Package ecosystem (``pypi``, ``npm``, ``maven``, ``cargo``, …).
        """
        await self._graph.upsert_library(name=library, version=version, ecosystem=ecosystem)
        await self._graph.link_dependency(repo=repo, library=library, version=version)
        logger.debug(
            "store.upsert_dependency",
            repo=repo,
            library=library,
            version=version,
        )

    async def find_blast_radius(
        self,
        library: str,
        version: str,
    ) -> list[str]:
        """
        Return all repository names that depend on a given library version.

        Used to assess the impact of a newly published CVE.

        Parameters
        ----------
        library:
            Library / package name.
        version:
            Exact version string or range marker. Pass ``*`` to match all versions.

        Returns
        -------
        list[str]
            Sorted list of repository names.
        """
        records = await self._graph.find_blast_radius(
            library=library, version_range=version
        )
        repos = sorted({r["repo"] for r in records})
        logger.info(
            "store.blast_radius",
            library=library,
            version=version,
            affected_repos=len(repos),
        )
        return repos

    async def upsert_hardware_component(
        self,
        repo: str,
        component: str,
        part_number: str,
    ) -> None:
        """
        Record a hardware component in the knowledge graph.

        Creates a HardwareAsset node labelled by *component* (the human-readable
        name) with ``part_number`` stored as a property, linked to *repo*.

        Parameters
        ----------
        repo:
            Owning repository.
        component:
            Human-readable component name, e.g. ``power-board-v3``.
        part_number:
            Manufacturer part number, e.g. ``STM32F4-DISC1``.
        """
        await self._graph.upsert_hardware_asset(
            name=component,
            asset_type=part_number,  # stored in asset_type field as part number tag
            repo=repo,
        )
        logger.debug(
            "store.upsert_hardware_component",
            repo=repo,
            component=component,
            part_number=part_number,
        )
