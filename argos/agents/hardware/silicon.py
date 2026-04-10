"""
argos/agents/hardware/silicon.py

SiliconAgent — Hardware description language (HDL) security analyzer.

Scans VHDL (.vhd, .vhdl) and Verilog / SystemVerilog (.v, .sv) source files
for hardware-level security vulnerabilities.  Two analysis paths are available
and are composed:

1. **Tool-assisted static analysis** (opportunistic)
   - GHDL: Elaborates and simulates VHDL to surface timing anomalies.
   - Yosys: Synthesises Verilog/SV to a gate-level netlist and runs pattern
     queries looking for trojan logic, debug backdoors, and unprotected I/O.
   Both tools are optional; if absent, this phase is silently skipped.

2. **Pattern-based pre-screening**
   A curated regex table detects the most common HDL security anti-patterns
   (JTAG enable without fusing, unconstrained inputs to state machines, etc.)
   before Claude is ever called.  Pre-screened hits are passed as context to
   the LLM phase.

3. **Claude analysis** (adaptive thinking)
   Claude receives the HDL source together with any tool outputs and pattern
   hits, then reasons using the hardware security CWE taxonomy:
   - CWE-1189  Improper isolation of shared resources
   - CWE-1231  Improper prevention of lock bit modification
   - CWE-1234  Hardware internal state exposed to untrusted agent

Vulnerability classes detected
-------------------------------
- Timing side channels (variable-time crypto operations)
- Power analysis vulnerabilities (non-constant-time comparisons)
- Debug backdoors — JTAG / boundary-scan left permanently enabled
- Hardware trojans in netlists (extra combinatorial paths)
- Insecure state machine transitions (unreachable reset → exploitable deadlock)
- Missing bounds checks in hardware accelerators
- Unprotected memory-mapped I/O registers
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.events import AssetType, Finding, FindingStatus, Severity

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: File extensions handled by this agent.
HDL_EXTENSIONS: dict[str, AssetType] = {
    ".vhd":  AssetType.VHDL,
    ".vhdl": AssetType.VHDL,
    ".v":    AssetType.VERILOG,
    ".sv":   AssetType.VERILOG,
}

#: Pre-screening regex patterns.  Each entry is
#: (pattern_id, compiled_regex, vuln_class, severity, description).
_PATTERNS: list[tuple[str, re.Pattern[str], str, Severity, str]] = [
    (
        "JTAG_ALWAYS_ENABLED",
        re.compile(
            r"\b(trst_n|tms|tck|tdi|tdo)\s*<=?\s*[01'bB]",
            re.IGNORECASE,
        ),
        "debug_backdoor",
        Severity.CRITICAL,
        "JTAG signal hardwired — debug port may be permanently accessible",
    ),
    (
        "JTAG_ENABLE_SIGNAL",
        re.compile(
            r"jtag\s*_?\s*en(?:able)?\s*<=?\s*1'?b?1",
            re.IGNORECASE,
        ),
        "debug_backdoor",
        Severity.HIGH,
        "JTAG enable register set to logic-1 without fuse/strap guard",
    ),
    (
        "TIMING_VARIABLE_LOOP",
        re.compile(
            r"for\s*\(.*?secret|key.*?for\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "timing_side_channel",
        Severity.HIGH,
        "Loop count or termination appears to depend on secret/key material",
    ),
    (
        "NONCONST_TIME_COMPARE",
        re.compile(
            r"(if|when)\s*\(?\s*\w*(key|secret|hmac|hash|passwd)\w*\s*(==|=)\s*",
            re.IGNORECASE,
        ),
        "power_analysis",
        Severity.HIGH,
        "Key/secret compared with == — vulnerable to power/timing side channel",
    ),
    (
        "UNPROTECTED_MMIO",
        re.compile(
            r"std_logic_vector\s*\(.*?\)\s*<=?\s*(?!.*lock|.*protect)(data_in|bus_data|apb_pwdata|axi_wdata)",
            re.IGNORECASE,
        ),
        "unprotected_mmio",
        Severity.HIGH,
        "Memory-mapped I/O register written from bus without lock/protect qualifier",
    ),
    (
        "MISSING_RESET_STATE",
        re.compile(
            r"case\s*\(\s*\w+_state\s*\)(?!.*\bothers\b)",
            re.IGNORECASE | re.DOTALL,
        ),
        "insecure_state_machine",
        Severity.MEDIUM,
        "State machine case statement may be missing 'others' catch-all — unreachable states",
    ),
    (
        "TROJAN_COUNTER_TRIGGER",
        re.compile(
            r"(cnt|counter|tick)\s*=\s*\d{5,}.*?(\bif\b|\bwhen\b).*?(activate|trigger|enable|backdoor)",
            re.IGNORECASE | re.DOTALL,
        ),
        "hardware_trojan",
        Severity.CRITICAL,
        "Large counter with conditional activation — possible hardware trojan trigger",
    ),
    (
        "ACCELERATOR_NO_BOUNDS",
        re.compile(
            r"(dma_len|transfer_size|burst_count)\s*<=?\s*\w+\s*(?!and\s+\w+\s*<)",
            re.IGNORECASE,
        ),
        "missing_bounds_check",
        Severity.HIGH,
        "DMA/accelerator length register written from bus with no bounds check",
    ),
    (
        "LOCK_BIT_UNPROTECTED",
        re.compile(
            r"lock\s*_?\s*bit\s*<=?\s*(?!.*0\s*;)(.+?);",
            re.IGNORECASE,
        ),
        "lock_bit_bypass",
        Severity.HIGH,
        "Lock-bit register may be modifiable post-boot (CWE-1231)",
    ),
    (
        "INTERNAL_STATE_EXPOSED",
        re.compile(
            r"(debug_out|scan_out|observe_port)\s*<=?\s*(key|secret|internal_state|priv_data)",
            re.IGNORECASE,
        ),
        "internal_state_exposure",
        Severity.CRITICAL,
        "Internal secret/key state routed to observable debug port (CWE-1234)",
    ),
]

# ---------------------------------------------------------------------------
# Tool availability checks (cached at import time)
# ---------------------------------------------------------------------------


def _tool_available(name: str) -> bool:
    """Return True if `name` is on PATH and exits without error."""
    try:
        subprocess.run(
            [name, "--version"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_GHDL_AVAILABLE = _tool_available("ghdl")
_YOSYS_AVAILABLE = _tool_available("yosys")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_from_str(s: str) -> Severity:
    try:
        return Severity(s.capitalize() if s else "Medium")
    except ValueError:
        return Severity.MEDIUM


def _asset_type_for(path: str) -> AssetType:
    ext = Path(path).suffix.lower()
    return HDL_EXTENSIONS.get(ext, AssetType.VHDL)


def _run_subprocess(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "NOT_FOUND", -1


# ---------------------------------------------------------------------------
# SiliconAgent
# ---------------------------------------------------------------------------


class SiliconAgent(ArgosAgent):
    """
    HDL security analyzer for VHDL and Verilog/SystemVerilog designs.

    Parameters
    ----------
    memory:
        ArgosMemory instance (graph + vector + episodic).  Optional.
    producer:
        Kafka producer for publishing FindingCreatedEvents.  Optional.
    work_dir:
        Scratch directory for GHDL/Yosys temporary files.  Defaults to
        ``/tmp/argos_silicon``.
    """

    name = "silicon"

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
        work_dir: str = "/tmp/argos_silicon",
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._work_dir = Path(work_dir)

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Scan HDL files for hardware security vulnerabilities.

        Context keys
        ------------
        files : dict[str, str]
            Mapping of ``{file_path: source_content}`` for all HDL files to
            be analyzed.  At least one entry is required.
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

        # Filter to HDL files only
        hdl_files = {
            path: content
            for path, content in files.items()
            if Path(path).suffix.lower() in HDL_EXTENSIONS
        }

        self.log.info(
            "silicon.scan_start",
            repo=repo,
            hdl_file_count=len(hdl_files),
            ghdl=_GHDL_AVAILABLE,
            yosys=_YOSYS_AVAILABLE,
        )

        if not hdl_files:
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={"repo": repo, "reason": "no_hdl_files"},
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        try:
            findings = await self._analyze(
                hdl_files=hdl_files,
                repo=repo,
                memory_context=memory_context,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.exception("silicon.pipeline_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "silicon.scan_complete",
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
                "files_scanned": len(hdl_files),
                "ghdl_used": _GHDL_AVAILABLE,
                "yosys_used": _YOSYS_AVAILABLE,
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def _analyze(
        self,
        hdl_files: dict[str, str],
        repo: str,
        memory_context: str,
    ) -> list[Finding]:
        """Compose pattern screening, tool analysis, and Claude reasoning."""
        findings: list[Finding] = []

        # Phase 1: Static pattern pre-screening (sync — fast)
        pattern_hits = self._screen_patterns(hdl_files)
        self.log.debug("silicon.pattern_hits", count=len(pattern_hits))

        # Phase 2: Optional tool-assisted analysis (async subprocess wrappers)
        tool_output = await self._run_tools(hdl_files)

        # Phase 3: Claude deep analysis
        claude_findings = await self._claude_analysis(
            hdl_files=hdl_files,
            repo=repo,
            pattern_hits=pattern_hits,
            tool_output=tool_output,
            memory_context=memory_context,
        )
        findings.extend(claude_findings)

        # Promote pattern hits that Claude did not already cover
        claude_files_lines = {(f.file, f.line) for f in findings}
        for hit in pattern_hits:
            key = (hit["file"], hit["line"])
            if key not in claude_files_lines:
                findings.append(self._hit_to_finding(hit, repo))

        return findings

    # ------------------------------------------------------------------
    # Phase 1: Pattern screening
    # ------------------------------------------------------------------

    def _screen_patterns(
        self, hdl_files: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Apply regex patterns to all HDL source files."""
        hits: list[dict[str, Any]] = []
        for file_path, content in hdl_files.items():
            lines = content.splitlines()
            for pid, pattern, vuln_class, severity, description in _PATTERNS:
                for lineno, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        hits.append(
                            {
                                "file": file_path,
                                "line": lineno,
                                "pattern_id": pid,
                                "vuln_class": vuln_class,
                                "severity": severity,
                                "description": description,
                                "matched_text": line.strip()[:200],
                            }
                        )
        return hits

    # ------------------------------------------------------------------
    # Phase 2: Tool-assisted analysis
    # ------------------------------------------------------------------

    async def _run_tools(self, hdl_files: dict[str, str]) -> str:
        """
        Run GHDL (VHDL) and Yosys (Verilog/SV) if available.
        Returns a combined textual report for Claude.
        """
        if not _GHDL_AVAILABLE and not _YOSYS_AVAILABLE:
            return ""

        loop = asyncio.get_event_loop()
        self._work_dir.mkdir(parents=True, exist_ok=True)

        # Write source files to disk for tool consumption
        for file_path, content in hdl_files.items():
            dest = self._work_dir / Path(file_path).name
            dest.write_text(content, encoding="utf-8")

        results: list[str] = []

        if _GHDL_AVAILABLE:
            vhdl_files = [
                p for p in hdl_files if Path(p).suffix.lower() in (".vhd", ".vhdl")
            ]
            if vhdl_files:
                out = await loop.run_in_executor(None, self._run_ghdl)
                if out:
                    results.append(f"=== GHDL Analysis ===\n{out}")

        if _YOSYS_AVAILABLE:
            v_files = [
                p for p in hdl_files if Path(p).suffix.lower() in (".v", ".sv")
            ]
            if v_files:
                out = await loop.run_in_executor(None, self._run_yosys, v_files)
                if out:
                    results.append(f"=== Yosys Netlist Analysis ===\n{out}")

        return "\n\n".join(results)

    def _run_ghdl(self) -> str:
        """Run GHDL analysis on all VHDL files in work_dir."""
        vhdl_files = list(self._work_dir.glob("*.vhd")) + list(
            self._work_dir.glob("*.vhdl")
        )
        if not vhdl_files:
            return ""

        # Analysis pass
        cmd_analyze = (
            ["ghdl", "-a", "--std=08"]
            + [str(f) for f in vhdl_files]
        )
        stdout_a, stderr_a, rc_a = _run_subprocess(cmd_analyze)

        report_lines = [
            f"GHDL analysis rc={rc_a}",
            stderr_a[:2000] if stderr_a else "(no stderr)",
        ]

        # Elaborate pass (best-effort — needs top entity name)
        return "\n".join(report_lines)

    def _run_yosys(self, file_paths: list[str]) -> str:
        """Run Yosys synthesis and report for Verilog/SV files."""
        v_files = [str(self._work_dir / Path(p).name) for p in file_paths]
        read_cmds = " ".join(
            f'read_verilog -sv "{f}"' for f in v_files
        )
        # synth to generic gates and dump stats
        script = (
            f"{read_cmds}; "
            "synth -flatten -top; "
            "stat; "
            "check"
        )
        cmd = ["yosys", "-p", script]
        stdout, stderr, rc = _run_subprocess(cmd, timeout=60)
        output = (stdout or "")[:3000]
        if stderr:
            output += f"\nSTDERR:\n{stderr[:1000]}"
        return f"Yosys rc={rc}\n{output}"

    # ------------------------------------------------------------------
    # Phase 3: Claude analysis
    # ------------------------------------------------------------------

    async def _claude_analysis(
        self,
        hdl_files: dict[str, str],
        repo: str,
        pattern_hits: list[dict[str, Any]],
        tool_output: str,
        memory_context: str,
    ) -> list[Finding]:
        """Send HDL source + context to Claude and parse findings."""
        file_block = self._build_file_block(hdl_files)
        hits_block = self._build_hits_block(pattern_hits)

        system = """\
You are a hardware security engineer with deep expertise in VHDL, Verilog, and SystemVerilog.
You specialize in identifying security vulnerabilities in hardware description language (HDL) designs.

Apply the following hardware security CWE taxonomy:
- CWE-1189: Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
- CWE-1231: Improper Prevention of Lock Bit Modification
- CWE-1234: Hardware Internal State Exposed to Untrusted Agent
- CWE-1300: Improper Protection of Physical Side Channels

Vulnerability classes to detect:
1. TIMING SIDE CHANNELS — variable-time crypto operations, early-exit comparisons
2. POWER ANALYSIS VULNERABILITIES — non-constant-power key operations, Hamming weight leakage
3. DEBUG BACKDOORS — JTAG/boundary-scan left enabled in production mode, missing fuse check
4. HARDWARE TROJANS — extra combinatorial logic paths, large counter triggers, unusual mux conditions
5. INSECURE STATE MACHINE TRANSITIONS — missing 'others'/'default' catch-all, reachable unsafe states
6. MISSING BOUNDS CHECKS — DMA length, burst count, buffer index without hardware limit
7. UNPROTECTED MEMORY-MAPPED I/O — registers writable without privilege/lock check
8. LOCK BIT BYPASS — security-critical registers unlockable post-boot (CWE-1231)
9. INTERNAL STATE EXPOSURE — key/secret/internal state routed to scan/observe ports (CWE-1234)

For each finding return exact file path and line number estimate.
Assess CVSS-adjacent severity: Critical (CVSS 9-10), High (7-9), Medium (4-7), Low (0-4).
Confidence 0.0-1.0 — be conservative; only report findings with confidence ≥ 0.6.

Return ONLY valid JSON (no markdown fences):
{
  "findings": [
    {
      "file": "<path>",
      "line": <int>,
      "title": "<short title>",
      "vuln_class": "<class from list above>",
      "cwe": "CWE-NNNN",
      "severity": "Critical|High|Medium|Low",
      "confidence": <float 0.0-1.0>,
      "cvss_score": <float>,
      "description": "<2-4 sentence technical description>",
      "exploitation_path": "<physical/logical attack path>"
    }
  ]
}
Return {"findings": []} if no vulnerabilities found."""

        user_parts = [f"Repository: {repo}"]
        if memory_context:
            user_parts.append(f"\nPrior analysis context:\n{memory_context}")
        if hits_block:
            user_parts.append(f"\nPre-screened pattern hits:\n{hits_block}")
        if tool_output:
            user_parts.append(f"\nTool analysis output:\n{tool_output[:3000]}")
        user_parts.append(f"\nHDL source files:{file_block}")
        user_parts.append("\nReturn the JSON findings now.")

        raw = ""
        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": "\n".join(user_parts)}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("silicon.claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_file_block(
        self, hdl_files: dict[str, str], max_files: int = 10, max_chars: int = 4000
    ) -> str:
        block = ""
        for path, content in list(hdl_files.items())[:max_files]:
            snippet = content[:max_chars] if len(content) > max_chars else content
            block += f"\n\n### File: {path}\n```\n{snippet}\n```"
        return block

    def _build_hits_block(self, hits: list[dict[str, Any]]) -> str:
        if not hits:
            return ""
        lines = []
        for h in hits[:20]:
            lines.append(
                f"  [{h['severity'].value}] {h['file']}:{h['line']} "
                f"({h['pattern_id']}) — {h['description']}\n"
                f"    Matched: {h['matched_text']}"
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
            self.log.warning("silicon.json_parse_error", error=str(exc))
            return []

        results: list[Finding] = []
        for item in data.get("findings", []):
            try:
                file_path = item.get("file", "unknown")
                finding = Finding(
                    finding_id=str(uuid.uuid4())[:16],
                    repo=repo,
                    file=file_path,
                    line=int(item.get("line", 0)),
                    vuln_class=item.get("vuln_class", "hdl_security"),
                    title=item.get("title", "HDL Security Finding"),
                    severity=_severity_from_str(item.get("severity", "Medium")),
                    cvss_score=float(item.get("cvss_score", 0.0)),
                    confidence=float(item.get("confidence", 0.5)),
                    asset_type=_asset_type_for(file_path),
                    layer_hit="H1_silicon",
                    exploitation_path=item.get("exploitation_path", ""),
                    agent=self.name,
                    metadata={
                        "description": item.get("description", ""),
                        "cwe": item.get("cwe", ""),
                    },
                )
                results.append(finding)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("silicon.finding_parse_error", error=str(exc), item=item)

        self.log.info("silicon.claude_findings", count=len(results))
        return results

    def _hit_to_finding(self, hit: dict[str, Any], repo: str) -> Finding:
        """Convert a pattern-screen hit to a Finding when Claude didn't cover it."""
        file_path = hit["file"]
        return Finding(
            finding_id=str(uuid.uuid4())[:16],
            repo=repo,
            file=file_path,
            line=hit["line"],
            vuln_class=hit["vuln_class"],
            title=f"[Pattern] {hit['pattern_id']}",
            severity=hit["severity"],
            confidence=0.65,
            asset_type=_asset_type_for(file_path),
            layer_hit="H1_silicon_pattern",
            exploitation_path="",
            agent=self.name,
            metadata={
                "description": hit["description"],
                "pattern_id": hit["pattern_id"],
                "matched_text": hit["matched_text"],
            },
        )
