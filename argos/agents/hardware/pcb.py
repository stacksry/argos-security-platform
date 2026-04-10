"""
argos/agents/hardware/pcb.py

PCBAgent — PCB and schematic security analyzer.

Scans KiCad PCB layouts (.kicad_pcb), KiCad schematics (.kicad_sch), Eagle
board files (.brd), and Eagle/OrCAD schematic files (.sch) for hardware
security vulnerabilities that manifest at the board level.

Analysis pipeline
-----------------
1. **KiCad netlist / file parsing**
   KiCad files are text-based S-expression (or XML for older formats) and can
   be parsed without running KiCad.  The parser extracts:
   - Component references (U?, J?, TP?) with their footprints and values
   - Net names (GND, VCC, JTAG_TDI, SWDIO, UART_TX, etc.)
   - Test point locations
   This structured information is passed to both the pattern screener and
   Claude as structured context.

2. **Pattern-based pre-screening**
   Regex and keyword matching on component references, footprint names, and net
   names to quickly flag obvious issues (exposed JTAG headers, unprotected
   crypto key pins, etc.).

3. **Claude analysis** (adaptive thinking)
   Claude receives the parsed component list, net inventory, and raw file
   snippets and reasons about board-level security architecture.

Vulnerability classes detected
-------------------------------
- Exposed JTAG/SWD/UART/I2C debug headers (populated connectors in production)
- Unprotected cryptographic key storage pins (external SPI flash without WP#)
- Hardware backdoors via unpopulated-but-wired test points
- Power supply tampering vulnerabilities (no UVLO, glitch filter absent)
- Electromagnetic side-channel exposure (unshielded crypto ICs, long key signal traces)
- Missing write-protect / hold signals on secure NVM components
- Unlocked JTAG fuse signals routed to accessible pads
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.events import AssetType, Finding, Severity

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: File extensions handled by this agent.
PCB_EXTENSIONS: frozenset[str] = frozenset(
    {".kicad_pcb", ".kicad_sch", ".brd", ".sch"}
)

#: Net name fragments indicating debug/programming interfaces.
_DEBUG_NET_KEYWORDS: list[str] = [
    "jtag", "tck", "tms", "tdi", "tdo", "trst",
    "swdio", "swdclk", "swd_",
    "uart_tx", "uart_rx", "dbg_tx", "dbg_rx",
    "console", "serial_",
]

#: Component reference prefixes that may be debug connectors.
_DEBUG_REF_PREFIXES: list[str] = ["J", "CN", "P", "HDR", "CONN"]

#: Footprint / value keywords that flag debug headers.
_DEBUG_FOOTPRINT_KEYWORDS: list[str] = [
    "jtag", "swd", "debug", "prog", "isp", "uart", "serial",
    "openocd", "arm_debug", "cortex_debug",
]

#: Crypto / key storage component keywords.
_CRYPTO_STORAGE_KEYWORDS: list[str] = [
    "atecc", "ds28", "se050", "ataes132", "atsha",  # secure elements
    "w25q", "mx25", "s25fl", "is25",                # SPI NOR flash (often key store)
    "m24", "at24", "24lc",                          # I2C EEPROM
    "tpm",                                           # TPM chips
]

#: Signals that should accompany crypto storage but may be missing.
_CRYPTO_PROTECT_SIGNALS: list[str] = [
    "wp_n", "wp#", "hold_n", "hold#", "wc_n",
    "protect", "write_protect",
]

# ---------------------------------------------------------------------------
# KiCad text-format component extraction
# ---------------------------------------------------------------------------


def _extract_kicad_components(content: str) -> list[dict[str, str]]:
    """
    Extract component records from KiCad S-expression PCB/schematic files.

    Returns a list of dicts with keys: ref, value, footprint.
    Handles both .kicad_pcb and .kicad_sch text formats (v5/v6/v7).
    """
    components: list[dict[str, str]] = []

    # Modern KiCad (v6+) footprint/symbol blocks
    # (footprint "..." (at ...) ... (property "Reference" "U1") ...)
    ref_pattern = re.compile(
        r'\(property\s+"Reference"\s+"([^"]+)"', re.IGNORECASE
    )
    val_pattern = re.compile(
        r'\(property\s+"Value"\s+"([^"]+)"', re.IGNORECASE
    )
    fp_pattern = re.compile(
        r'\(property\s+"Footprint"\s+"([^"]+)"', re.IGNORECASE
    )

    # Split on top-level footprint/symbol blocks
    block_re = re.compile(r'\((?:footprint|symbol)\s+"[^"]*"', re.IGNORECASE)
    positions = [m.start() for m in block_re.finditer(content)]
    positions.append(len(content))

    for i, start in enumerate(positions[:-1]):
        block = content[start:positions[i + 1]]
        ref_m = ref_pattern.search(block)
        val_m = val_pattern.search(block)
        fp_m = fp_pattern.search(block)
        if ref_m:
            components.append(
                {
                    "ref": ref_m.group(1),
                    "value": val_m.group(1) if val_m else "",
                    "footprint": fp_m.group(1) if fp_m else "",
                }
            )

    # Fallback: older KiCad / Eagle style
    if not components:
        for m in re.finditer(
            r'(?:reference|ref)\s+"([A-Z]+\d+)"', content, re.IGNORECASE
        ):
            components.append({"ref": m.group(1), "value": "", "footprint": ""})

    return components


def _extract_net_names(content: str) -> list[str]:
    """Extract net names from KiCad or Eagle board/schematic content."""
    nets: set[str] = set()

    # KiCad: (net 1 "JTAG_TCK") or (net_name "SWD_CLK")
    for m in re.finditer(
        r'\(net(?:_name)?\s+\d*\s*"([^"]+)"', content, re.IGNORECASE
    ):
        nets.add(m.group(1))

    # Eagle: <net name="JTAG_TDI" ...>
    for m in re.finditer(r'<net\s+name="([^"]+)"', content, re.IGNORECASE):
        nets.add(m.group(1))

    return sorted(nets)


def _extract_test_points(components: list[dict[str, str]]) -> list[str]:
    """Return component references that look like test points."""
    return [
        c["ref"]
        for c in components
        if c["ref"].upper().startswith("TP")
        or "testpoint" in c["footprint"].lower()
        or "test_point" in c["footprint"].lower()
    ]


# ---------------------------------------------------------------------------
# Pattern screener
# ---------------------------------------------------------------------------


def _screen_pcb(
    file_path: str,
    content: str,
    components: list[dict[str, str]],
    nets: list[str],
    test_points: list[str],
) -> list[dict[str, Any]]:
    """Produce a list of pattern-hit dicts for known PCB security issues."""
    hits: list[dict[str, Any]] = []

    # -- Debug headers (JTAG / SWD / UART) ----------------------------------
    debug_nets = [
        n for n in nets
        if any(kw in n.lower() for kw in _DEBUG_NET_KEYWORDS)
    ]
    debug_connectors = [
        c for c in components
        if (
            any(c["ref"].upper().startswith(pfx) for pfx in _DEBUG_REF_PREFIXES)
            and any(kw in (c["value"] + c["footprint"]).lower() for kw in _DEBUG_FOOTPRINT_KEYWORDS)
        )
    ]

    if debug_nets:
        hits.append(
            {
                "vuln_class": "exposed_debug_interface",
                "severity": Severity.CRITICAL,
                "title": "Debug interface nets present on PCB",
                "description": (
                    f"The following nets indicate active debug interfaces: "
                    f"{', '.join(debug_nets[:8])}.  If these traces reach populated "
                    "headers or accessible pads an attacker can attach a debugger."
                ),
                "confidence": 0.85,
                "matched": debug_nets[:8],
            }
        )

    if debug_connectors:
        refs = [c["ref"] for c in debug_connectors]
        hits.append(
            {
                "vuln_class": "populated_debug_header",
                "severity": Severity.HIGH,
                "title": "Populated debug connector detected",
                "description": (
                    f"Components {', '.join(refs)} appear to be JTAG/SWD/UART "
                    "headers.  Production boards should either omit these "
                    "footprints or fuse-disable the debug interface."
                ),
                "confidence": 0.80,
                "matched": refs,
            }
        )

    # -- Crypto storage without write-protect --------------------------------
    crypto_comps = [
        c for c in components
        if any(kw in (c["value"] + c["footprint"]).lower() for kw in _CRYPTO_STORAGE_KEYWORDS)
    ]
    protect_nets = [
        n for n in nets
        if any(kw in n.lower() for kw in _CRYPTO_PROTECT_SIGNALS)
    ]

    if crypto_comps and not protect_nets:
        refs = [c["ref"] for c in crypto_comps]
        hits.append(
            {
                "vuln_class": "unprotected_crypto_storage",
                "severity": Severity.HIGH,
                "title": "Crypto/key-storage component without write-protect net",
                "description": (
                    f"Components {', '.join(refs)} appear to store cryptographic "
                    "material but no write-protect or hold signal was found in "
                    "the netlist.  An attacker with physical access can overwrite "
                    "key material."
                ),
                "confidence": 0.70,
                "matched": refs,
            }
        )

    # -- Exposed test points near debug / power rails -----------------------
    if test_points:
        suspicious_tp = test_points[:10]
        hits.append(
            {
                "vuln_class": "exposed_test_points",
                "severity": Severity.MEDIUM,
                "title": "Test points present — verify they don't expose sensitive signals",
                "description": (
                    f"Test points {', '.join(suspicious_tp)} are present.  If any "
                    "are connected to debug, power, or key-bus nets they provide "
                    "physical attack surface."
                ),
                "confidence": 0.60,
                "matched": suspicious_tp,
            }
        )

    # -- Power glitching surface: no bulk capacitor on VCC ------------------
    vcc_nets = [n for n in nets if re.match(r"^v[cd]{2}|^vcc|^vdd|^3v3|^1v8", n, re.IGNORECASE)]
    bulk_cap = [
        c for c in components
        if c["ref"].upper().startswith("C")
        and any(v in c["value"].lower() for v in ["100u", "47u", "10u", "220u", "470u"])
    ]
    if vcc_nets and not bulk_cap:
        hits.append(
            {
                "vuln_class": "power_glitch_surface",
                "severity": Severity.MEDIUM,
                "title": "No bulk capacitor detected on power rail — glitching risk",
                "description": (
                    "No large bulk bypass capacitors (≥10 µF) were found in the "
                    "schematic.  Without sufficient power filtering an attacker "
                    "can perform voltage-fault injection to bypass secure boot "
                    "or crypto operations."
                ),
                "confidence": 0.55,
                "matched": [],
            }
        )

    # Tag file info into each hit
    for h in hits:
        h["file"] = file_path
        h["line"] = 0

    return hits


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------


def _severity_from_str(s: str) -> Severity:
    try:
        return Severity(s.capitalize() if s else "Medium")
    except ValueError:
        return Severity.MEDIUM


# ---------------------------------------------------------------------------
# PCBAgent
# ---------------------------------------------------------------------------


class PCBAgent(ArgosAgent):
    """
    PCB and schematic security analyzer.

    Parameters
    ----------
    memory:
        ArgosMemory instance (graph + vector + episodic).  Optional.
    producer:
        Kafka producer for publishing FindingCreatedEvents.  Optional.
    """

    name = "pcb"

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Scan PCB and schematic files for hardware security vulnerabilities.

        Context keys
        ------------
        files : dict[str, str]
            Mapping of ``{file_path: file_content}`` for all PCB/schematic
            files to be analyzed.
        repo : str
            Repository or project identifier (used in Finding.repo).
        memory_context : str
            Optional free-text prior-knowledge blurb from the Navigator.
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        files: dict[str, str] = context.get("files", {})
        repo: str = context.get("repo", "unknown")
        memory_context: str = context.get("memory_context", "")

        # Filter to PCB/schematic files
        pcb_files = {
            path: content
            for path, content in files.items()
            if Path(path).suffix.lower() in PCB_EXTENSIONS
        }

        self.log.info(
            "pcb.scan_start",
            repo=repo,
            file_count=len(pcb_files),
        )

        if not pcb_files:
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={"repo": repo, "reason": "no_pcb_files"},
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        try:
            findings = await self._analyze(
                pcb_files=pcb_files,
                repo=repo,
                memory_context=memory_context,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.exception("pcb.pipeline_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "pcb.scan_complete",
            repo=repo,
            findings=len(findings),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[f.model_dump() for f in findings],
            metadata={
                "repo": repo,
                "files_scanned": len(pcb_files),
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def _analyze(
        self,
        pcb_files: dict[str, str],
        repo: str,
        memory_context: str,
    ) -> list[Finding]:
        """Parse PCB files, screen patterns, then call Claude."""
        all_pattern_hits: list[dict[str, Any]] = []
        parsed_summary: list[dict[str, Any]] = []

        for file_path, content in pcb_files.items():
            components = _extract_kicad_components(content)
            nets = _extract_net_names(content)
            test_points = _extract_test_points(components)

            parsed_summary.append(
                {
                    "file": file_path,
                    "component_count": len(components),
                    "net_count": len(nets),
                    "test_point_count": len(test_points),
                    "components_sample": components[:30],
                    "nets_sample": nets[:50],
                    "test_points": test_points[:20],
                }
            )

            hits = _screen_pcb(file_path, content, components, nets, test_points)
            all_pattern_hits.extend(hits)

        self.log.debug("pcb.pattern_hits", count=len(all_pattern_hits))

        # Claude analysis using parsed structure + pattern hits
        claude_findings = await self._claude_analysis(
            pcb_files=pcb_files,
            repo=repo,
            parsed_summary=parsed_summary,
            pattern_hits=all_pattern_hits,
            memory_context=memory_context,
        )

        findings: list[Finding] = list(claude_findings)

        # Promote pattern hits not covered by Claude
        claude_keys = {(f.file, f.vuln_class) for f in findings}
        for hit in all_pattern_hits:
            if (hit["file"], hit["vuln_class"]) not in claude_keys:
                findings.append(self._hit_to_finding(hit, repo))

        return findings

    # ------------------------------------------------------------------
    # Claude analysis
    # ------------------------------------------------------------------

    async def _claude_analysis(
        self,
        pcb_files: dict[str, str],
        repo: str,
        parsed_summary: list[dict[str, Any]],
        pattern_hits: list[dict[str, Any]],
        memory_context: str,
    ) -> list[Finding]:
        """Send parsed PCB data to Claude and parse the JSON findings."""
        file_block = self._build_file_block(pcb_files)
        summary_block = json.dumps(parsed_summary, indent=2)[:4000]
        hits_block = self._build_hits_block(pattern_hits)

        system = """\
You are a hardware security engineer specializing in PCB and schematic security reviews.

Analyze the provided PCB layouts, schematics, and parsed component/net data for security vulnerabilities.

Vulnerability classes to detect:
1. EXPOSED DEBUG HEADERS — populated JTAG/SWD/UART/I2C/SPI connectors reachable without disassembly
2. UNPROTECTED CRYPTO KEY STORAGE — SPI flash, EEPROM, or secure element without WP#/HOLD# signals
3. HARDWARE BACKDOORS — test points wired to sensitive signals; unpopulated pads on security-critical lines
4. POWER SUPPLY TAMPERING — missing bulk capacitors, no UVLO circuit, glitch-susceptible regulators
5. EM SIDE-CHANNEL EXPOSURE — unshielded crypto IC placement, long unguarded key signal traces
6. PRODUCTION DEBUG STRAP — pull-up/down resistors that enable debug in production boot mode
7. INSECURE BOOT MODE SELECTION — MODE/BOOT pins accessible via pads or headers

Scoring guidance:
- Severity CRITICAL: Direct physical access yields root/code execution or key extraction
- Severity HIGH: Physical access with modest effort yields privileged access
- Severity MEDIUM: Requires sustained physical access or specialist equipment
- Severity LOW: Theoretical risk requiring unlikely preconditions

Return ONLY valid JSON (no markdown fences):
{
  "findings": [
    {
      "file": "<path>",
      "line": 0,
      "title": "<short title>",
      "vuln_class": "<class from list above>",
      "severity": "Critical|High|Medium|Low",
      "confidence": <float 0.0-1.0>,
      "cvss_score": <float>,
      "description": "<2-4 sentence technical description>",
      "exploitation_path": "<physical attack steps>"
    }
  ]
}
Return {"findings": []} if no vulnerabilities found."""

        user_parts = [f"Repository: {repo}"]
        if memory_context:
            user_parts.append(f"\nPrior analysis context:\n{memory_context}")
        user_parts.append(f"\nParsed component and net summary:\n{summary_block}")
        if hits_block:
            user_parts.append(f"\nPre-screened pattern alerts:\n{hits_block}")
        user_parts.append(f"\nRaw PCB/schematic file excerpts:{file_block}")
        user_parts.append("\nReturn the JSON findings now.")

        raw = ""
        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": "\n".join(user_parts)}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("pcb.claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_file_block(
        self, pcb_files: dict[str, str], max_files: int = 5, max_chars: int = 3000
    ) -> str:
        block = ""
        for path, content in list(pcb_files.items())[:max_files]:
            snippet = content[:max_chars] if len(content) > max_chars else content
            block += f"\n\n### File: {path}\n```\n{snippet}\n```"
        return block

    def _build_hits_block(self, hits: list[dict[str, Any]]) -> str:
        if not hits:
            return ""
        lines = []
        for h in hits:
            sev = h["severity"].value if isinstance(h["severity"], Severity) else h["severity"]
            lines.append(
                f"  [{sev}] {h['file']} — {h['title']}\n"
                f"    {h['description'][:200]}"
            )
        return "\n".join(lines)

    def _parse_findings(self, raw: str, repo: str) -> list[Finding]:
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.log.warning("pcb.json_parse_error", error=str(exc))
            return []

        results: list[Finding] = []
        for item in data.get("findings", []):
            try:
                finding = Finding(
                    finding_id=str(uuid.uuid4())[:16],
                    repo=repo,
                    file=item.get("file", "unknown"),
                    line=int(item.get("line", 0)),
                    vuln_class=item.get("vuln_class", "pcb_security"),
                    title=item.get("title", "PCB Security Finding"),
                    severity=_severity_from_str(item.get("severity", "Medium")),
                    cvss_score=float(item.get("cvss_score", 0.0)),
                    confidence=float(item.get("confidence", 0.5)),
                    asset_type=AssetType.PCB,
                    layer_hit="H2_pcb",
                    exploitation_path=item.get("exploitation_path", ""),
                    agent=self.name,
                    metadata={"description": item.get("description", "")},
                )
                results.append(finding)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("pcb.finding_parse_error", error=str(exc), item=item)

        self.log.info("pcb.claude_findings", count=len(results))
        return results

    def _hit_to_finding(self, hit: dict[str, Any], repo: str) -> Finding:
        sev = hit["severity"] if isinstance(hit["severity"], Severity) else _severity_from_str(str(hit["severity"]))
        return Finding(
            finding_id=str(uuid.uuid4())[:16],
            repo=repo,
            file=hit["file"],
            line=hit.get("line", 0),
            vuln_class=hit["vuln_class"],
            title=hit["title"],
            severity=sev,
            confidence=hit.get("confidence", 0.60),
            asset_type=AssetType.PCB,
            layer_hit="H2_pcb_pattern",
            exploitation_path="",
            agent=self.name,
            metadata={
                "description": hit["description"],
                "matched": hit.get("matched", []),
            },
        )
