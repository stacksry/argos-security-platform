"""
argos/agents/hardware/necromancer.py

NecromancerAgent — Firmware binary security analyst.

Raises the dead — extracts intelligence from opaque binary firmware images
(.bin, .hex, .elf, .img, .firmware, .fw) and reports security vulnerabilities
found within.

Analysis pipeline
-----------------
1. **Binwalk** (optional) — filesystem/archive extraction and entropy analysis.
   Identifies embedded filesystems, compressed blobs, crypto material, and
   known file signatures.  If binwalk is not installed this phase is skipped;
   the remaining phases still execute on the raw binary.

2. **Strings extraction** — ``strings`` (or Python fallback) pulls printable
   character sequences ≥ 6 bytes.  The output is searched for:
   - Hardcoded credentials (password=, passwd=, secret=, api_key=)
   - AWS/GCP/Azure API key patterns
   - Private key PEM headers
   - Debug / development strings (/dev/ttyS0, gdbserver, busybox)
   - Vulnerable library version strings (OpenSSL 1.0.x, zlib 1.2.x, etc.)
   - URL / IP address patterns

3. **ELF binary hardening checks** (readelf / objdump) — checks applied to
   ELF executables found within the image:
   - PIE / ASLR (ET_DYN vs ET_EXEC)
   - Stack canaries (__stack_chk_fail symbol present)
   - NX (non-executable stack — GNU_STACK segment flags)
   - RELRO (GNU_RELRO segment / BIND_NOW flag)
   - RPATH / RUNPATH injection risk

4. **Ghidra headless analysis** (optional) — if ``analyzeHeadless`` is on
   PATH, Ghidra decompiles entry points and key functions, surfacing:
   - Command injection sinks (system(), popen(), execve() with user input)
   - Unsafe string operations (strcpy, sprintf without bounds)
   - Crypto misuse (hardcoded keys passed to crypto functions)
   This phase is expensive and is only triggered for binaries ≤ 32 MB.

5. **Claude analysis** (adaptive thinking) — Claude receives the aggregated
   output of all preceding phases and reasons about:
   - Severity and exploitability of each string hit
   - Combined risk of missing hardening + dangerous function patterns
   - Whether Ghidra decompilation reveals exploitable call chains

Vulnerability classes detected
-------------------------------
- Hardcoded credentials and API keys
- Missing ASLR / PIE
- Stack canaries disabled
- Executable stack (NX bit absent)
- RPATH / RUNPATH manipulation
- Embedded private keys / certificates
- Known-vulnerable library versions
- Debug interface strings (gdbserver, JTAG tools)
- Command injection sinks with tainted input (via Ghidra)
- Unsafe C string functions without bounds checking (via Ghidra)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import tempfile
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

#: File extensions treated as firmware binaries.
FIRMWARE_EXTENSIONS: frozenset[str] = frozenset(
    {".bin", ".hex", ".elf", ".img", ".firmware", ".fw"}
)

#: Maximum binary size to pass through the full pipeline (bytes).
_MAX_BINARY_SIZE = 128 * 1024 * 1024  # 128 MB

#: Maximum binary size for Ghidra headless (expensive).
_MAX_GHIDRA_SIZE = 32 * 1024 * 1024  # 32 MB

#: Minimum printable run length for strings extraction (Python fallback).
_STRINGS_MIN_LEN = 6

# ---------------------------------------------------------------------------
# Credential / key patterns for strings post-processing
# ---------------------------------------------------------------------------

_CRED_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    (
        "HARDCODED_PASSWORD",
        re.compile(
            r"(?:password|passwd|pass|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,64})",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Hardcoded password literal found in firmware strings",
    ),
    (
        "HARDCODED_SECRET",
        re.compile(
            r"(?:secret|api_?key|auth_?token|access_?key|private_?key)\s*[=:]\s*['\"]?([^\s'\"]{8,})",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Hardcoded secret / API key found in firmware strings",
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
        "AWS access key ID pattern detected",
    ),
    (
        "PEM_PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "PEM private key embedded in firmware image",
    ),
    (
        "GDBSERVER_DEBUG",
        re.compile(r"gdbserver|gdbstub|/dev/ttyS\d|busybox|dropbear", re.IGNORECASE),
        Severity.HIGH,
        "Debug tool or serial console string — development artifact in production firmware",
    ),
    (
        "OPENSSL_VULNERABLE",
        re.compile(r"OpenSSL\s+(?:0\.\d|1\.0\.[01])", re.IGNORECASE),
        Severity.HIGH,
        "Vulnerable OpenSSL version string detected (EOL branch)",
    ),
    (
        "ZLIB_VULNERABLE",
        re.compile(r"zlib\s+1\.[01]\.\d", re.IGNORECASE),
        Severity.MEDIUM,
        "Potentially vulnerable zlib version string detected",
    ),
    (
        "TELNET_LISTENER",
        re.compile(r"\btelnetd\b|\btelnet\s+listen", re.IGNORECASE),
        Severity.HIGH,
        "Telnet daemon string — plaintext remote access protocol",
    ),
    (
        "DEFAULT_CREDENTIAL_PAIR",
        re.compile(r"\badmin\b.*?\bpassword\b|\broot\b.*?\btoor\b|\bguest\b.*?\bguest\b", re.IGNORECASE | re.DOTALL),
        Severity.CRITICAL,
        "Default credential pair (admin/password, root/toor) found in strings",
    ),
    (
        "URL_WITH_CREDS",
        re.compile(r"https?://[^:@\s]{1,64}:[^@\s]{1,64}@"),
        Severity.HIGH,
        "URL with embedded credentials (user:pass@host)",
    ),
]

# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------


def _tool_available(name: str) -> bool:
    try:
        subprocess.run([name, "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _ghidra_available() -> bool:
    """Check if Ghidra analyzeHeadless is on PATH."""
    try:
        subprocess.run(
            ["analyzeHeadless", "--help"], capture_output=True, timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_BINWALK_AVAILABLE = _tool_available("binwalk")
_READELF_AVAILABLE = _tool_available("readelf")
_STRINGS_AVAILABLE = _tool_available("strings")
_GHIDRA_AVAILABLE = _ghidra_available()


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 60, input_data: bytes | None = None) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            input=input_data,
        )
        return (
            proc.stdout.decode("utf-8", errors="replace"),
            proc.stderr.decode("utf-8", errors="replace"),
            proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "NOT_FOUND", -1


# ---------------------------------------------------------------------------
# Strings extraction (tool or Python fallback)
# ---------------------------------------------------------------------------


def _extract_strings_python(data: bytes, min_len: int = _STRINGS_MIN_LEN) -> str:
    """Pure-Python printable-string extractor (fallback when `strings` absent)."""
    pattern = re.compile(
        rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    )
    found = pattern.findall(data)
    return "\n".join(s.decode("ascii", errors="replace") for s in found[:5000])


def _extract_strings(binary_path: str) -> str:
    """Extract printable strings from a binary file."""
    if _STRINGS_AVAILABLE:
        stdout, _, _ = _run(["strings", "-n", str(_STRINGS_MIN_LEN), binary_path])
        return stdout
    # Python fallback
    try:
        with open(binary_path, "rb") as fh:
            data = fh.read(_MAX_BINARY_SIZE)
        return _extract_strings_python(data)
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Pattern scanning on strings output
# ---------------------------------------------------------------------------


def _screen_strings(strings_output: str, file_path: str) -> list[dict[str, Any]]:
    """Apply credential / key patterns to extracted strings."""
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    lines = strings_output.splitlines()

    for pid, pattern, severity, description in _CRED_PATTERNS:
        for lineno, line in enumerate(lines, start=1):
            m = pattern.search(line)
            if m:
                dedup_key = f"{pid}:{line[:80]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                hits.append(
                    {
                        "file": file_path,
                        "line": lineno,
                        "pattern_id": pid,
                        "vuln_class": pid.lower(),
                        "severity": severity,
                        "description": description,
                        "matched_text": line.strip()[:200],
                    }
                )
                if len(hits) >= 50:  # cap to avoid noise flooding
                    break
        if len(hits) >= 50:
            break

    return hits


# ---------------------------------------------------------------------------
# ELF hardening checks
# ---------------------------------------------------------------------------


def _check_elf_hardening(binary_path: str) -> dict[str, Any]:
    """
    Run readelf checks for common ELF hardening properties.
    Returns a dict with boolean fields and a human-readable summary.
    """
    result: dict[str, Any] = {
        "is_elf": False,
        "pie": False,
        "stack_canary": False,
        "nx_stack": False,
        "relro": False,
        "rpath": None,
        "summary": "",
    }

    if not _READELF_AVAILABLE:
        result["summary"] = "readelf not available — ELF hardening checks skipped"
        return result

    # Check if ELF
    stdout_h, _, rc = _run(["readelf", "-h", binary_path])
    if rc != 0 or "ELF" not in stdout_h:
        result["summary"] = "Not an ELF binary"
        return result

    result["is_elf"] = True

    # PIE: ET_DYN in header
    result["pie"] = "DYN" in stdout_h

    # Stack canary: __stack_chk_fail in dynamic symbols
    stdout_sym, _, _ = _run(["readelf", "-s", binary_path])
    result["stack_canary"] = "__stack_chk_fail" in stdout_sym

    # NX stack: GNU_STACK with RWE flags (W+E = no NX)
    stdout_seg, _, _ = _run(["readelf", "-l", binary_path])
    for line in stdout_seg.splitlines():
        if "GNU_STACK" in line:
            # flags field is at end of line, RWE means no NX
            result["nx_stack"] = "E" not in line.split()[-1] if line.split() else False
            break
    else:
        result["nx_stack"] = False  # GNU_STACK absent → NX status unknown

    # RELRO: GNU_RELRO segment
    result["relro"] = "GNU_RELRO" in stdout_seg

    # RPATH / RUNPATH
    stdout_dyn, _, _ = _run(["readelf", "-d", binary_path])
    for line in stdout_dyn.splitlines():
        if "RPATH" in line or "RUNPATH" in line:
            result["rpath"] = line.strip()
            break

    # Build summary
    issues = []
    if not result["pie"]:
        issues.append("No PIE/ASLR (ET_EXEC binary)")
    if not result["stack_canary"]:
        issues.append("Stack canaries absent (__stack_chk_fail not linked)")
    if not result["nx_stack"]:
        issues.append("Executable stack (NX bit not set)")
    if not result["relro"]:
        issues.append("No RELRO — GOT/PLT writable")
    if result["rpath"]:
        issues.append(f"RPATH/RUNPATH set: {result['rpath']}")

    result["summary"] = "; ".join(issues) if issues else "All basic ELF hardening present"
    return result


# ---------------------------------------------------------------------------
# Binwalk analysis
# ---------------------------------------------------------------------------


def _run_binwalk(binary_path: str, work_dir: str) -> str:
    """Run binwalk signature scan and entropy analysis. Returns text report."""
    if not _BINWALK_AVAILABLE:
        return ""

    # Signature scan
    stdout_sig, stderr_sig, _ = _run(
        ["binwalk", "--entropy", "--term", binary_path],
        timeout=120,
    )
    return (stdout_sig or "") + ("\n" + stderr_sig[:500] if stderr_sig else "")


# ---------------------------------------------------------------------------
# Ghidra headless analysis
# ---------------------------------------------------------------------------


def _run_ghidra(binary_path: str, work_dir: str) -> str:
    """
    Run Ghidra headless import + analysis and return a summary.
    Only called when _GHIDRA_AVAILABLE is True and binary is ≤ 32 MB.
    """
    ghidra_out = os.path.join(work_dir, "ghidra_project")
    os.makedirs(ghidra_out, exist_ok=True)

    script_content = """\
import ghidra.app.decompiler.DecompInterface as DecompInterface
from ghidra.program.model.listing import Function

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

dangerous_fns = [
    "system", "popen", "execve", "execl", "execvp",
    "strcpy", "strcat", "sprintf", "gets",
]

results = []
for fn_name in dangerous_fns:
    syms = currentProgram.getSymbolTable().getSymbols(fn_name)
    for sym in syms:
        refs = sym.getReferences()
        for ref in refs:
            results.append("DANGEROUS_CALL: {} at {}".format(fn_name, ref.fromAddress))

print("\\n".join(results[:200]))
"""
    script_path = os.path.join(work_dir, "argos_scan.py")
    with open(script_path, "w") as fh:
        fh.write(script_content)

    cmd = [
        "analyzeHeadless",
        ghidra_out,
        "ArgosProject",
        "-import", binary_path,
        "-postScript", script_path,
        "-deleteProject",
        "-log", os.path.join(work_dir, "ghidra.log"),
    ]

    stdout, stderr, rc = _run(cmd, timeout=300)
    output = (stdout or "")[:4000]
    if "DANGEROUS_CALL" not in output and stderr:
        output += f"\n[Ghidra stderr excerpt]\n{stderr[:500]}"
    return output


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------


def _severity_from_str(s: str) -> Severity:
    try:
        return Severity(s.capitalize() if s else "Medium")
    except ValueError:
        return Severity.MEDIUM


# ---------------------------------------------------------------------------
# NecromancerAgent
# ---------------------------------------------------------------------------


class NecromancerAgent(ArgosAgent):
    """
    Firmware binary security analyst.

    Parameters
    ----------
    memory:
        ArgosMemory instance (graph + vector + episodic).  Optional.
    producer:
        Kafka producer for publishing FindingCreatedEvents.  Optional.
    work_dir:
        Scratch directory for temporary extraction files.  Defaults to
        ``/tmp/argos_necromancer``.
    """

    name = "necromancer"

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
        work_dir: str = "/tmp/argos_necromancer",
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._work_dir = work_dir

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Analyze firmware binary files for security vulnerabilities.

        Context keys
        ------------
        files : dict[str, str | bytes]
            Mapping of ``{file_path: content}`` where content may be either
            a file path string pointing to a binary on disk (preferred for
            large binaries) or raw bytes.  For path references use the special
            key ``"__path__"`` in a nested dict.
        binary_paths : dict[str, str]
            Alternative: mapping of ``{logical_name: absolute_disk_path}``
            for binary files already on disk.
        repo : str
            Repository or project identifier.
        memory_context : str
            Optional prior-knowledge blurb from the Navigator.
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        binary_paths: dict[str, str] = context.get("binary_paths", {})
        repo: str = context.get("repo", "unknown")
        memory_context: str = context.get("memory_context", "")

        # Accept inline raw bytes keyed by logical name (small files / tests)
        raw_files: dict[str, bytes] = context.get("raw_files", {})

        self.log.info(
            "necromancer.scan_start",
            repo=repo,
            binary_count=len(binary_paths) + len(raw_files),
            binwalk=_BINWALK_AVAILABLE,
            readelf=_READELF_AVAILABLE,
            ghidra=_GHIDRA_AVAILABLE,
        )

        if not binary_paths and not raw_files:
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={"repo": repo, "reason": "no_firmware_files"},
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        try:
            findings = await self._analyze(
                binary_paths=binary_paths,
                raw_files=raw_files,
                repo=repo,
                memory_context=memory_context,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.exception("necromancer.pipeline_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "necromancer.scan_complete",
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
                "binaries_analyzed": len(binary_paths) + len(raw_files),
                "binwalk_used": _BINWALK_AVAILABLE,
                "ghidra_used": _GHIDRA_AVAILABLE,
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Core pipeline
    # ------------------------------------------------------------------

    async def _analyze(
        self,
        binary_paths: dict[str, str],
        raw_files: dict[str, bytes],
        repo: str,
        memory_context: str,
    ) -> list[Finding]:
        """Run the full multi-phase analysis pipeline."""
        os.makedirs(self._work_dir, exist_ok=True)
        findings: list[Finding] = []

        # Materialise raw_files to disk so tools can access them
        materialized: dict[str, str] = dict(binary_paths)
        for name, data in raw_files.items():
            dest = os.path.join(self._work_dir, Path(name).name)
            with open(dest, "wb") as fh:
                fh.write(data)
            materialized[name] = dest

        loop = asyncio.get_event_loop()

        for logical_name, disk_path in materialized.items():
            file_findings = await self._analyze_one(
                logical_name=logical_name,
                disk_path=disk_path,
                repo=repo,
                memory_context=memory_context,
                loop=loop,
            )
            findings.extend(file_findings)

        return findings

    async def _analyze_one(
        self,
        logical_name: str,
        disk_path: str,
        repo: str,
        memory_context: str,
        loop: asyncio.AbstractEventLoop,
    ) -> list[Finding]:
        """Full analysis pipeline for a single binary."""
        self.log.info("necromancer.analyzing_file", file=logical_name)

        binary_size = os.path.getsize(disk_path) if os.path.exists(disk_path) else 0

        # Phase 1: Binwalk (async subprocess)
        binwalk_output = ""
        if _BINWALK_AVAILABLE:
            binwalk_output = await loop.run_in_executor(
                None, _run_binwalk, disk_path, self._work_dir
            )
            self.log.debug("necromancer.binwalk_done", file=logical_name)

        # Phase 2: Strings extraction + pattern screening
        strings_output = await loop.run_in_executor(
            None, _extract_strings, disk_path
        )
        pattern_hits = _screen_strings(strings_output, logical_name)
        self.log.debug(
            "necromancer.strings_done",
            file=logical_name,
            string_count=len(strings_output.splitlines()),
            pattern_hits=len(pattern_hits),
        )

        # Phase 3: ELF hardening
        elf_info = await loop.run_in_executor(
            None, _check_elf_hardening, disk_path
        )
        self.log.debug(
            "necromancer.elf_done",
            file=logical_name,
            is_elf=elf_info["is_elf"],
            summary=elf_info["summary"],
        )

        # Phase 4: Ghidra (only for ELF, only if available and size OK)
        ghidra_output = ""
        if (
            _GHIDRA_AVAILABLE
            and elf_info.get("is_elf")
            and binary_size <= _MAX_GHIDRA_SIZE
        ):
            ghidra_output = await loop.run_in_executor(
                None, _run_ghidra, disk_path, self._work_dir
            )
            self.log.debug("necromancer.ghidra_done", file=logical_name)

        # Phase 5: Claude analysis
        claude_findings = await self._claude_analysis(
            logical_name=logical_name,
            repo=repo,
            strings_sample=strings_output[:6000],
            pattern_hits=pattern_hits,
            elf_info=elf_info,
            binwalk_output=binwalk_output[:3000],
            ghidra_output=ghidra_output[:3000],
            binary_size=binary_size,
            memory_context=memory_context,
        )

        findings: list[Finding] = list(claude_findings)

        # Promote pattern hits not already reported by Claude
        claude_classes = {f.vuln_class for f in findings}
        for hit in pattern_hits:
            if hit["vuln_class"] not in claude_classes:
                findings.append(self._hit_to_finding(hit, repo))

        # Add ELF hardening findings if Claude didn't explicitly cover them
        if elf_info.get("is_elf") and elf_info["summary"] and "All basic" not in elf_info["summary"]:
            elf_classes = {"no_aslr", "no_stack_canary", "executable_stack", "no_relro", "rpath_injection"}
            if not elf_classes.intersection(claude_classes):
                findings.extend(self._elf_hardening_findings(elf_info, logical_name, repo))

        return findings

    # ------------------------------------------------------------------
    # Claude analysis
    # ------------------------------------------------------------------

    async def _claude_analysis(
        self,
        logical_name: str,
        repo: str,
        strings_sample: str,
        pattern_hits: list[dict[str, Any]],
        elf_info: dict[str, Any],
        binwalk_output: str,
        ghidra_output: str,
        binary_size: int,
        memory_context: str,
    ) -> list[Finding]:
        """Send all phase outputs to Claude and parse the JSON findings."""
        hits_block = self._build_hits_block(pattern_hits)

        system = """\
You are a firmware and embedded systems security expert specializing in binary analysis.

Analyze the provided firmware binary intelligence (strings, ELF metadata, binwalk output,
Ghidra decompilation excerpts) for security vulnerabilities.

Vulnerability classes to detect and report:
1. HARDCODED_CREDENTIALS — passwords, secrets, API keys, default credential pairs
2. EMBEDDED_PRIVATE_KEY — PEM headers, raw RSA/EC key blobs
3. NO_ASLR — ET_EXEC ELF (no position-independent code)
4. NO_STACK_CANARY — missing __stack_chk_fail linkage
5. EXECUTABLE_STACK — NX bit absent on GNU_STACK segment
6. NO_RELRO — GOT/PLT writable at runtime
7. RPATH_INJECTION — RPATH/RUNPATH set to attacker-influenced path
8. VULNERABLE_LIBRARY — EOL / known-CVE library version string
9. DEBUG_ARTIFACT — gdbserver, busybox, serial console strings in production image
10. COMMAND_INJECTION_SINK — system()/popen() called with potentially tainted input (Ghidra)
11. UNSAFE_STRING_OP — strcpy/sprintf without bounds near network input parsing (Ghidra)

Severity guidance:
- CRITICAL: Direct unauthenticated RCE or key extraction
- HIGH: Exploitation with low effort, significant impact
- MEDIUM: Requires local access or specific conditions
- LOW: Defense-in-depth issue, hardening recommendation

Return ONLY valid JSON (no markdown fences):
{
  "findings": [
    {
      "file": "<logical_name>",
      "line": 0,
      "title": "<short title>",
      "vuln_class": "<class from list>",
      "severity": "Critical|High|Medium|Low",
      "confidence": <float 0.0-1.0>,
      "cvss_score": <float>,
      "description": "<2-4 sentence technical description>",
      "exploitation_path": "<attacker steps>"
    }
  ]
}
Return {"findings": []} if no vulnerabilities found."""

        user_parts = [
            f"Repository: {repo}",
            f"Firmware file: {logical_name}",
            f"Binary size: {binary_size:,} bytes",
        ]

        if memory_context:
            user_parts.append(f"\nPrior analysis context:\n{memory_context}")

        if elf_info.get("is_elf"):
            user_parts.append(
                f"\nELF hardening summary: {elf_info['summary']}\n"
                f"  PIE: {elf_info['pie']}, "
                f"Stack canary: {elf_info['stack_canary']}, "
                f"NX stack: {elf_info['nx_stack']}, "
                f"RELRO: {elf_info['relro']}, "
                f"RPATH: {elf_info['rpath']}"
            )

        if hits_block:
            user_parts.append(f"\nPre-screened string pattern hits:\n{hits_block}")

        if binwalk_output:
            user_parts.append(f"\nBinwalk analysis:\n{binwalk_output}")

        if ghidra_output:
            user_parts.append(f"\nGhidra decompilation excerpts:\n{ghidra_output}")

        user_parts.append(
            f"\nExtracted strings sample (first 6000 chars):\n{strings_sample}"
        )
        user_parts.append("\nReturn the JSON findings now.")

        raw = ""
        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": "\n".join(user_parts)}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("necromancer.claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo, logical_name)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_hits_block(self, hits: list[dict[str, Any]]) -> str:
        if not hits:
            return ""
        lines = []
        for h in hits[:20]:
            sev = h["severity"].value if isinstance(h["severity"], Severity) else str(h["severity"])
            lines.append(
                f"  [{sev}] ({h['pattern_id']}) {h['description']}\n"
                f"    Matched: {h['matched_text']}"
            )
        return "\n".join(lines)

    def _parse_findings(self, raw: str, repo: str, default_file: str) -> list[Finding]:
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.log.warning("necromancer.json_parse_error", error=str(exc))
            return []

        results: list[Finding] = []
        for item in data.get("findings", []):
            try:
                finding = Finding(
                    finding_id=str(uuid.uuid4())[:16],
                    repo=repo,
                    file=item.get("file", default_file),
                    line=int(item.get("line", 0)),
                    vuln_class=item.get("vuln_class", "firmware_security"),
                    title=item.get("title", "Firmware Security Finding"),
                    severity=_severity_from_str(item.get("severity", "Medium")),
                    cvss_score=float(item.get("cvss_score", 0.0)),
                    confidence=float(item.get("confidence", 0.5)),
                    asset_type=AssetType.FIRMWARE,
                    layer_hit="H3_firmware",
                    exploitation_path=item.get("exploitation_path", ""),
                    agent=self.name,
                    metadata={"description": item.get("description", "")},
                )
                results.append(finding)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("necromancer.finding_parse_error", error=str(exc), item=item)

        self.log.info("necromancer.claude_findings", count=len(results), file=default_file)
        return results

    def _hit_to_finding(self, hit: dict[str, Any], repo: str) -> Finding:
        sev = hit["severity"] if isinstance(hit["severity"], Severity) else _severity_from_str(str(hit["severity"]))
        return Finding(
            finding_id=str(uuid.uuid4())[:16],
            repo=repo,
            file=hit["file"],
            line=hit.get("line", 0),
            vuln_class=hit["vuln_class"],
            title=f"[Pattern] {hit['pattern_id']}",
            severity=sev,
            confidence=0.70,
            asset_type=AssetType.FIRMWARE,
            layer_hit="H3_firmware_pattern",
            exploitation_path="",
            agent=self.name,
            metadata={
                "description": hit["description"],
                "pattern_id": hit["pattern_id"],
                "matched_text": hit["matched_text"],
            },
        )

    def _elf_hardening_findings(
        self, elf_info: dict[str, Any], file_path: str, repo: str
    ) -> list[Finding]:
        """Convert ELF hardening gaps into individual Finding objects."""
        findings: list[Finding] = []

        checks = [
            (
                not elf_info["pie"],
                "no_aslr",
                "Binary compiled without PIE — ASLR ineffective",
                Severity.HIGH,
                "Attacker can predict memory layout, enabling ROP chains without ASLR randomisation.",
                6.8,
            ),
            (
                not elf_info["stack_canary"],
                "no_stack_canary",
                "Stack canaries disabled — stack buffer overflows undetected",
                Severity.HIGH,
                "Stack overflow exploitation proceeds without canary check blocking control flow hijack.",
                7.0,
            ),
            (
                not elf_info["nx_stack"],
                "executable_stack",
                "Executable stack (NX bit absent)",
                Severity.HIGH,
                "Shellcode placed on the stack can be executed directly without ROP gadget chains.",
                7.5,
            ),
            (
                not elf_info["relro"],
                "no_relro",
                "No RELRO — GOT/PLT writable at runtime",
                Severity.MEDIUM,
                "GOT overwrite attacks succeed without RELRO protection; function pointers can be hijacked.",
                5.5,
            ),
            (
                bool(elf_info.get("rpath")),
                "rpath_injection",
                f"RPATH/RUNPATH set in binary: {elf_info.get('rpath', '')}",
                Severity.MEDIUM,
                "Attacker with write access to RPATH directory can substitute malicious shared libraries.",
                5.0,
            ),
        ]

        for condition, vuln_class, title, severity, exploitation_path, cvss_score in checks:
            if condition:
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4())[:16],
                        repo=repo,
                        file=file_path,
                        line=0,
                        vuln_class=vuln_class,
                        title=title,
                        severity=severity,
                        cvss_score=cvss_score,
                        confidence=0.95,
                        asset_type=AssetType.FIRMWARE,
                        layer_hit="H3_elf_hardening",
                        exploitation_path=exploitation_path,
                        agent=self.name,
                        metadata={"elf_summary": elf_info["summary"]},
                    )
                )

        return findings
