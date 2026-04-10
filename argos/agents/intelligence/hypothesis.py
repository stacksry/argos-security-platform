"""
argos/agents/intelligence/hypothesis.py

HypothesisAgent — Security research reader.

Monitors arXiv (cs.CR category) and security research feeds for papers
describing new vulnerability classes, attack techniques, exploit primitives,
and zero-day patterns. Uses Claude to extract structured intelligence and
persists new patterns to ProceduralMemory's confirmed_scan_patterns table.
Optionally triggers the Breeder to create specialised scanner agents.

Schedule: daily (orchestrated externally via APScheduler / cron).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.config import settings
from argos.events import AgentSpawnedEvent

logger: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# arXiv query constants
# ---------------------------------------------------------------------------

_ARXIV_API_BASE = "http://export.arxiv.org/api/query"
_ARXIV_SEARCH_TERMS = [
    "vulnerability",
    "exploit",
    "zero-day",
    "memory corruption",
    "supply chain attack",
    "side channel",
    "fuzzing",
    "CVE",
]
_ARXIV_CATEGORY = "cs.CR"
_MAX_PAPERS_PER_RUN = 25
_ARXIV_NAMESPACE = "{http://www.w3.org/2005/Atom}"


class HypothesisAgent(ArgosAgent):
    """
    Research paper reader that extracts new vulnerability intelligence from
    arXiv cs.CR papers and persists learnings to ProceduralMemory.

    For each qualifying paper, Claude extracts:
      - New vulnerability classes described
      - Attack patterns and primitives
      - Affected technologies / languages
      - PoC code indicators
      - Recommended detection patterns

    Patterns are written to ``confirmed_scan_patterns`` via
    ``memory.record_confirmed_pattern()``. If a truly novel vuln class is
    identified, an ``AgentSpawnedEvent`` request is published so the Breeder
    can create a dedicated scanner agent.
    """

    name: str = "hypothesis"

    def __init__(self, memory: Any | None = None, producer: Any | None = None) -> None:
        super().__init__(memory=memory, producer=producer)

    # -----------------------------------------------------------------------
    # Main entrypoint
    # -----------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute one Hypothesis cycle.

        Context keys (all optional):
            max_papers   (int):  override for max papers to process (default 25)
            trigger_breeder (bool): whether to publish AgentSpawnedEvent for novel classes
        """
        self._total_tokens = 0
        t0 = time.monotonic()

        max_papers: int = int(context.get("max_papers", _MAX_PAPERS_PER_RUN))
        trigger_breeder: bool = bool(context.get("trigger_breeder", True))

        self.log.info("hypothesis.cycle_start", max_papers=max_papers)

        try:
            # 1. Fetch papers from arXiv
            papers = await self._fetch_arxiv_papers(max_results=max_papers)
            self.log.info("hypothesis.papers_fetched", count=len(papers))

            if not papers:
                return AgentResult(
                    agent=self.name,
                    success=True,
                    findings=[],
                    metadata={"papers_processed": 0},
                    duration_ms=int((time.monotonic() - t0) * 1000),
                    tokens_used=self._total_tokens,
                )

            # 2. Use Claude to extract intelligence from each paper (batched)
            all_findings: list[dict[str, Any]] = []
            novel_classes: list[dict[str, Any]] = []

            for paper in papers:
                extraction = await self._extract_intelligence(paper)
                if not extraction:
                    continue

                # 3. Persist confirmed patterns to ProceduralMemory
                if self.memory:
                    for pattern_info in extraction.get("detection_patterns", []):
                        vuln_class = pattern_info.get("vuln_class", "unknown")
                        pattern = pattern_info.get("pattern", "")
                        language = pattern_info.get("language", "any")
                        if vuln_class and pattern:
                            await self.memory.record_confirmed_pattern(
                                vuln_class=vuln_class,
                                pattern=pattern,
                                language=language,
                                confirmed_by=f"{self.name}:arxiv:{paper.get('arxiv_id', '')}",
                            )
                            self.log.debug(
                                "hypothesis.pattern_stored",
                                vuln_class=vuln_class,
                                language=language,
                            )

                # Track novel classes for Breeder
                for nc in extraction.get("novel_vuln_classes", []):
                    nc["source_paper"] = paper.get("arxiv_id", "")
                    nc["source_title"] = paper.get("title", "")
                    novel_classes.append(nc)

                all_findings.append(
                    {
                        "finding_id": str(uuid.uuid4())[:16],
                        "severity": "Info",
                        "description": (
                            f"Hypothesis: paper '{paper.get('title', '')[:80]}' "
                            f"identified {len(extraction.get('detection_patterns', []))} patterns"
                        ),
                        "arxiv_id": paper.get("arxiv_id", ""),
                        "vuln_classes": extraction.get("vuln_classes_found", []),
                        "affected_technologies": extraction.get("affected_technologies", []),
                    }
                )

            # 4. Optionally trigger Breeder for novel classes
            if trigger_breeder and novel_classes and self.producer:
                for nc in novel_classes[:3]:  # cap at 3 new agents per cycle
                    vuln_class = nc.get("name", "unknown_vuln_class")
                    event = AgentSpawnedEvent(
                        agent_name=f"scanner_{vuln_class.lower().replace(' ', '_')}",
                        agent_version="0.1.0",
                        vuln_class=vuln_class,
                        supervised_mode=True,
                        spawned_by=self.name,
                    )
                    await self.producer.publish("argos.agent.spawned", event)
                    self.log.info(
                        "hypothesis.breeder_triggered",
                        vuln_class=vuln_class,
                        source=nc.get("source_paper", ""),
                    )

            self.log.info(
                "hypothesis.cycle_complete",
                papers_processed=len(papers),
                findings=len(all_findings),
                novel_classes=len(novel_classes),
                tokens=self._total_tokens,
            )
            return AgentResult(
                agent=self.name,
                success=True,
                findings=all_findings,
                metadata={
                    "papers_processed": len(papers),
                    "novel_classes_found": novel_classes,
                },
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        except Exception as exc:  # noqa: BLE001
            self.log.exception("hypothesis.cycle_failed", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

    # -----------------------------------------------------------------------
    # arXiv fetching
    # -----------------------------------------------------------------------

    async def _fetch_arxiv_papers(self, max_results: int = 25) -> list[dict[str, Any]]:
        """
        Query arXiv API for recent cs.CR papers matching security keywords.

        Returns a list of dicts with keys: arxiv_id, title, abstract, authors,
        published, categories.
        """
        search_query = (
            f"cat:{_ARXIV_CATEGORY} AND ("
            + " OR ".join(f'ti:"{term}"' for term in _ARXIV_SEARCH_TERMS[:4])
            + ")"
        )
        params = urlencode(
            {
                "search_query": search_query,
                "sortBy": "submittedDate",
                "sortOrder": "descending",
                "max_results": max_results,
            }
        )
        url = f"{_ARXIV_API_BASE}?{params}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return _parse_arxiv_atom(resp.text)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("hypothesis.arxiv_fetch_failed", error=str(exc))
            return []

    # -----------------------------------------------------------------------
    # Claude extraction
    # -----------------------------------------------------------------------

    async def _extract_intelligence(
        self, paper: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Use Claude to extract structured security intelligence from a paper.

        Returns dict with keys:
            vuln_classes_found       list[str]
            novel_vuln_classes       list[{name, description, affected_techs}]
            attack_patterns          list[str]
            affected_technologies    list[str]
            poc_indicators           list[str]
            detection_patterns       list[{vuln_class, pattern, language}]
        """
        system = (
            "You are Hypothesis, a security research analyst agent inside the ARGOS "
            "platform. You read academic security papers and extract actionable "
            "vulnerability intelligence. Be precise and conservative — only flag "
            "genuinely novel vuln classes. Return ONLY valid JSON."
        )

        title = paper.get("title", "")
        abstract = paper.get("abstract", "")[:3000]  # truncate very long abstracts

        prompt = (
            f"Analyse this security research paper and extract vulnerability intelligence.\n\n"
            f"Title: {title}\n"
            f"Abstract: {abstract}\n\n"
            "Return a JSON object with this exact shape:\n"
            "{\n"
            '  "vuln_classes_found": ["<class>", ...],\n'
            '  "novel_vuln_classes": [\n'
            '    {"name": "<name>", "description": "<desc>", "affected_techs": ["..."]}\n'
            "  ],\n"
            '  "attack_patterns": ["<pattern>", ...],\n'
            '  "affected_technologies": ["<tech>", ...],\n'
            '  "poc_indicators": ["<indicator>", ...],\n'
            '  "detection_patterns": [\n'
            '    {"vuln_class": "<class>", "pattern": "<regex or AST pattern>", "language": "<lang or any>"}\n'
            "  ]\n"
            "}\n"
            "If no security-relevant content is found, return an empty object {}. "
            "Only flag novel_vuln_classes if the paper describes a vulnerability class "
            "not previously named in CVE/CWE databases."
        )

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2048,
            )
            result = _parse_json_response(raw)
            if not result:
                return None
            return result
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "hypothesis.extraction_failed",
                arxiv_id=paper.get("arxiv_id", ""),
                error=str(exc),
            )
            return None


# ---------------------------------------------------------------------------
# arXiv Atom XML parser
# ---------------------------------------------------------------------------

def _parse_arxiv_atom(xml_text: str) -> list[dict[str, Any]]:
    """Parse arXiv Atom feed XML into a list of paper dicts."""
    papers: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("hypothesis.arxiv_xml_parse_failed", error=str(exc))
        return papers

    ns = _ARXIV_NAMESPACE
    for entry in root.findall(f"{ns}entry"):
        arxiv_id_el = entry.find(f"{ns}id")
        title_el = entry.find(f"{ns}title")
        summary_el = entry.find(f"{ns}summary")
        published_el = entry.find(f"{ns}published")

        arxiv_id = (arxiv_id_el.text or "").strip().split("/")[-1] if arxiv_id_el is not None else ""
        title = (title_el.text or "").strip() if title_el is not None else ""
        abstract = (summary_el.text or "").strip() if summary_el is not None else ""
        published = (published_el.text or "").strip() if published_el is not None else ""

        authors = [
            (a.find(f"{ns}name").text or "").strip()
            for a in entry.findall(f"{ns}author")
            if a.find(f"{ns}name") is not None
        ]

        categories = [
            t.get("term", "")
            for t in entry.findall(f"{ns}category")
        ]

        if arxiv_id and title:
            papers.append(
                {
                    "arxiv_id": arxiv_id,
                    "title": title,
                    "abstract": abstract,
                    "authors": authors,
                    "published": published,
                    "categories": categories,
                }
            )
    return papers


def _parse_json_response(text: str, fallback: Any = None) -> Any:
    """Extract and parse the first JSON object from a Claude text response."""
    import re
    text = text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
        if match:
            text = match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("hypothesis.json_parse_failed", snippet=text[:200])
        return fallback if fallback is not None else {}
