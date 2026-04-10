"""
argos/agents/software/sentinel.py

SentinelAgent — 10-layer structured vulnerability discovery for source code,
infrastructure-as-code, and container configurations.

Extends the conceptual 6-layer Glasswing model with four additional deep-
analysis layers (data flow, auth/authz, cryptographic correctness, and business
logic).  Layers gate sequentially: a repo that fails to match L1-L5 heuristics
is ruled out before any Claude call is made.  L6-L10 use Claude with adaptive
thinking for deep code reasoning.

Layer map
---------
L1  infrastructure   Dockerfiles, CI/CD YAML, Terraform, Kubernetes manifests
L2  os               Base image names, OS package managers, known-bad base tags
L3  language         Runtime/build files, language detection
L4  framework        Spring, Django, Express, Rails, FastAPI, etc.
L5  library_versions Dependency files vs affected version ranges
L6  code_patterns    Vulnerable code patterns (memory-confirmed) — Claude
L7  data_flow        Untrusted input → dangerous sink tracing — Claude
L8  auth_authz       Authentication and authorization gaps — Claude
L9  crypto           Cryptographic correctness — Claude
L10 business_logic   Logic bugs, TOCTOU, race conditions — Claude
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

import httpx
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.events import Finding, FindingStatus, Severity

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Layer names (ordered — index + 1 == layer number)
# ---------------------------------------------------------------------------

LAYERS: list[str] = [
    "L1_infrastructure",
    "L2_os",
    "L3_language",
    "L4_framework",
    "L5_library_versions",
    "L6_code_patterns",
    "L7_data_flow",
    "L8_auth_authz",
    "L9_crypto",
    "L10_business_logic",
]

# ---------------------------------------------------------------------------
# Heuristic pattern tables (L1-L5 — no Claude needed)
# ---------------------------------------------------------------------------

_INFRA_FILENAMES: set[str] = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "jenkinsfile", ".travis.yml", ".github", ".gitlab-ci.yml",
    "azure-pipelines.yml", "buildkite.yml", "circle.yml",
    "main.tf", "variables.tf", "outputs.tf", "provider.tf",
    "kustomization.yaml", "helm", "chart.yaml",
}

_INFRA_EXTENSIONS: set[str] = {".tf", ".tfvars"}

_OS_PACKAGE_FILES: set[str] = {
    "apt.txt", "yum.txt", "alpine-packages.txt", "apk.txt",
    "requirements.system", "packages.txt",
}

_OS_BASE_IMAGE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"FROM\s+(\S+)", re.IGNORECASE),
]

_KNOWN_VULNERABLE_BASE_TAGS: list[str] = [
    "latest", ":old", ":deprecated", "ubuntu:14.04", "ubuntu:16.04",
    "debian:stretch", "debian:buster", "centos:6", "centos:7",
    "python:2.", "node:10.", "node:12.", "openjdk:8", "openjdk:11",
]

_LANGUAGE_RUNTIME_FILES: dict[str, list[str]] = {
    "java":       ["pom.xml", "build.gradle", "settings.gradle", ".java-version"],
    "python":     ["requirements.txt", "pipfile", "pyproject.toml", "setup.py", "setup.cfg"],
    "javascript": ["package.json", "package-lock.json", "yarn.lock"],
    "typescript": ["package.json", "tsconfig.json"],
    "go":         ["go.mod", "go.sum"],
    "ruby":       ["gemfile", "gemfile.lock", ".ruby-version"],
    "rust":       ["cargo.toml", "cargo.lock"],
    "php":        ["composer.json", "composer.lock"],
    "dotnet":     [".csproj", ".fsproj", ".vbproj", "packages.config"],
}

_FRAMEWORK_SIGNALS: dict[str, list[str]] = {
    "spring":      ["spring-boot", "spring-security", "spring-framework"],
    "django":      ["django", "djangorestframework"],
    "express":     ["express", "koa", "fastify", "hapi"],
    "rails":       ["rails", "actionpack", "activerecord"],
    "fastapi":     ["fastapi", "uvicorn"],
    "laravel":     ["laravel/framework"],
    "gin":         ["gin-gonic/gin"],
    "actix":       ["actix-web"],
    "flask":       ["flask", "werkzeug"],
    "struts":      ["struts2-core", "struts2"],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _file_basename(path: str) -> str:
    return PurePosixPath(path).name.lower()


def _file_extension(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def _is_infra_file(path: str) -> bool:
    name = _file_basename(path)
    ext = _file_extension(path)
    if ext in _INFRA_EXTENSIONS:
        return True
    for token in _INFRA_FILENAMES:
        if token in name:
            return True
    return False


def _detect_language(file_names: list[str]) -> str:
    """Return the most likely primary language from a list of file names."""
    lower = [n.lower() for n in file_names]
    for lang, signals in _LANGUAGE_RUNTIME_FILES.items():
        if any(s in lower for s in signals):
            return lang
    # Extension fallback
    ext_map = {
        ".java": "java", ".py": "python", ".js": "javascript",
        ".ts": "typescript", ".go": "go", ".rb": "ruby",
        ".rs": "rust", ".php": "php", ".cs": "dotnet",
    }
    for name in lower:
        ext = PurePosixPath(name).suffix
        if ext in ext_map:
            return ext_map[ext]
    return "unknown"


def _detect_frameworks(manifest_content: str) -> list[str]:
    """Detect frameworks from manifest/lockfile text."""
    detected: list[str] = []
    lower = manifest_content.lower()
    for fw, signals in _FRAMEWORK_SIGNALS.items():
        if any(s in lower for s in signals):
            detected.append(fw)
    return detected


def _severity_from_confidence(confidence: float) -> Severity:
    if confidence >= 0.9:
        return Severity.CRITICAL
    if confidence >= 0.75:
        return Severity.HIGH
    if confidence >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# SentinelAgent
# ---------------------------------------------------------------------------


class SentinelAgent(ArgosAgent):
    """
    10-layer structured vulnerability scanner.

    Parameters
    ----------
    memory:
        ArgosMemory (graph + vector + episodic).  When present, L6 augments
        patterns from vector memory and writes successful patterns back.
    producer:
        Kafka producer for publishing FindingCreatedEvents.
    platform_token:
        Optional personal access token for fetching raw file content from
        the VCS platform (Bitbucket/GitHub/GitLab).
    platform_base_url:
        Base URL for the VCS API (e.g. ``https://api.bitbucket.org/2.0``).
    """

    name = "sentinel"

    LAYERS = LAYERS  # expose for introspection

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
        platform_token: str = "",
        platform_base_url: str = "https://api.bitbucket.org/2.0",
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._platform_token = platform_token
        self._platform_base_url = platform_base_url.rstrip("/")

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Execute the 10-layer scan pipeline.

        Context keys
        ------------
        repo : str
            Repository slug, e.g. ``acme/payments-service``.
        changed_files : list[str]
            File paths to scan (empty = full repo scan signal).
        vuln_class : str
            Target vulnerability class (e.g. ``sql_injection``, ``ssrf``).
            Used to focus L6 pattern matching.
        platform : str
            ``bitbucket`` | ``github`` | ``gitlab``.
        memory_context : str
            Pre-fetched memory blurb from the Navigator (free-form text with
            confirmed patterns, prior findings, etc.).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        repo: str = context.get("repo", "")
        changed_files: list[str] = context.get("changed_files", [])
        vuln_class: str = context.get("vuln_class", "")
        platform: str = context.get("platform", "bitbucket")
        memory_context: str = context.get("memory_context", "")

        self.log.info(
            "sentinel.scan_start",
            repo=repo,
            files=len(changed_files),
            vuln_class=vuln_class,
        )

        try:
            findings = await self._run_layers(
                repo=repo,
                changed_files=changed_files,
                vuln_class=vuln_class,
                platform=platform,
                memory_context=memory_context,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.exception("sentinel.pipeline_error", error=str(exc))
            return AgentResult(
                agent=self.name,
                success=False,
                error=str(exc),
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=self._total_tokens,
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "sentinel.scan_complete",
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
                "vuln_class": vuln_class,
                "platform": platform,
                "files_scanned": len(changed_files),
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    async def _run_layers(
        self,
        repo: str,
        changed_files: list[str],
        vuln_class: str,
        platform: str,
        memory_context: str,
    ) -> list[Finding]:
        """
        Execute layers L1-L10 in order, gating on each result.

        L1-L5: heuristic checks (no Claude).
        L6-L10: Claude with adaptive thinking on surviving files only.
        """
        findings: list[Finding] = []

        # ---- L1: Infrastructure -------------------------------------------
        infra_files = [f for f in changed_files if _is_infra_file(f)]
        all_names = [_file_basename(f) for f in changed_files]
        l1_pass = bool(infra_files) or bool(changed_files)
        self.log.debug("sentinel.L1", infra_files=len(infra_files), pass_=l1_pass)
        if not l1_pass:
            return []

        # ---- L2: OS / base-image check ------------------------------------
        dockerfile_files = [f for f in changed_files if "dockerfile" in _file_basename(f)]
        l2_suspicious: list[str] = []
        raw_dockerfiles: dict[str, str] = {}
        for df in dockerfile_files:
            content = await self._fetch_file(repo, df, platform)
            raw_dockerfiles[df] = content
            for tag in _KNOWN_VULNERABLE_BASE_TAGS:
                if tag.lower() in content.lower():
                    l2_suspicious.append(df)
                    break

        self.log.debug("sentinel.L2", suspicious_dockerfiles=len(l2_suspicious))

        # ---- L3: Language detection ----------------------------------------
        primary_language = _detect_language(all_names)
        self.log.debug("sentinel.L3", language=primary_language)

        # ---- L4: Framework detection --------------------------------------
        manifest_files = [
            f for f in changed_files
            if _file_basename(f) in {
                "pom.xml", "package.json", "requirements.txt",
                "go.mod", "gemfile", "cargo.toml", "composer.json",
            }
        ]
        detected_frameworks: list[str] = []
        raw_manifests: dict[str, str] = {}
        for mf in manifest_files[:5]:  # cap to avoid excessive API calls
            content = await self._fetch_file(repo, mf, platform)
            raw_manifests[mf] = content
            detected_frameworks.extend(_detect_frameworks(content))
        detected_frameworks = list(set(detected_frameworks))
        self.log.debug("sentinel.L4", frameworks=detected_frameworks)

        # ---- L5: Library version matching ---------------------------------
        # Ask vector memory for known-vulnerable version ranges if available.
        vulnerable_libs: list[dict[str, Any]] = []
        if self.memory is not None and hasattr(self.memory, "vector"):
            try:
                hits = await self.memory.vector.search(
                    collection="vulnerabilities",
                    query_text=f"{vuln_class} {primary_language} {' '.join(detected_frameworks)}",
                    limit=10,
                )
                for hit in hits:
                    if hit["score"] > 0.75:
                        vulnerable_libs.append(hit["payload"])
            except Exception as exc:  # noqa: BLE001
                self.log.warning("sentinel.L5_memory_error", error=str(exc))

        self.log.debug("sentinel.L5", vulnerable_lib_matches=len(vulnerable_libs))

        # Gate: if no code or infra files at all, stop here.
        code_exts = {".java", ".py", ".js", ".ts", ".go", ".rb", ".rs", ".php", ".cs", ".cpp", ".c"}
        code_files = [f for f in changed_files if _file_extension(f) in code_exts]
        surviving_files = list(set(code_files + infra_files + dockerfile_files + manifest_files))
        if not surviving_files:
            self.log.info("sentinel.gated_out", layer="L5", reason="no code or infra files")
            return []

        # Fetch code content for deep layers (cap at 20 files for cost control)
        files_for_deep_analysis = surviving_files[:20]
        file_contents: dict[str, str] = {}
        fetch_tasks = [
            self._fetch_file(repo, f, platform)
            for f in files_for_deep_analysis
            if f not in raw_dockerfiles and f not in raw_manifests
        ]
        fetched = await asyncio.gather(*fetch_tasks, return_exceptions=True)
        for path, result in zip(
            [f for f in files_for_deep_analysis if f not in raw_dockerfiles and f not in raw_manifests],
            fetched,
        ):
            if isinstance(result, str):
                file_contents[path] = result
            else:
                self.log.warning("sentinel.fetch_error", file=path, error=str(result))

        file_contents.update(raw_dockerfiles)
        file_contents.update(raw_manifests)

        # Build memory-confirmed patterns for L6
        memory_patterns = await self._fetch_memory_patterns(vuln_class, primary_language)

        # ---- L6: Code pattern matching (Claude) ---------------------------
        l6_findings = await self._layer_code_patterns(
            repo=repo,
            file_contents=file_contents,
            vuln_class=vuln_class,
            language=primary_language,
            frameworks=detected_frameworks,
            memory_patterns=memory_patterns,
            memory_context=memory_context,
        )
        findings.extend(l6_findings)

        # Gate L7-L10 on files that triggered L6 hits
        confirmed_files = {f.file for f in l6_findings}
        # Also include all code files for auth / crypto / logic review
        deep_files = {
            path: content
            for path, content in file_contents.items()
            if path in confirmed_files or _file_extension(path) in code_exts
        }

        if not deep_files:
            self.log.info("sentinel.gated_out", layer="L6", reason="no confirmed-vulnerable files")
            return findings

        # ---- L7-L10: Deep analysis in parallel (Claude) -------------------
        l7_task = self._layer_data_flow(repo, deep_files, vuln_class, primary_language, memory_context)
        l8_task = self._layer_auth_authz(repo, deep_files, primary_language, detected_frameworks, memory_context)
        l9_task = self._layer_crypto(repo, deep_files, primary_language, memory_context)
        l10_task = self._layer_business_logic(repo, deep_files, primary_language, memory_context)

        deep_results = await asyncio.gather(l7_task, l8_task, l9_task, l10_task, return_exceptions=True)
        for result in deep_results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                self.log.warning("sentinel.deep_layer_error", error=str(result))

        # Write successful L6 patterns back to memory
        if l6_findings and self.memory is not None:
            await self._persist_patterns(l6_findings, vuln_class, primary_language)

        return findings

    # ------------------------------------------------------------------
    # L6: Code patterns (Claude + memory-confirmed patterns)
    # ------------------------------------------------------------------

    async def _layer_code_patterns(
        self,
        repo: str,
        file_contents: dict[str, str],
        vuln_class: str,
        language: str,
        frameworks: list[str],
        memory_patterns: list[dict[str, Any]],
        memory_context: str,
    ) -> list[Finding]:
        """L6: Identify vulnerable code patterns using memory-confirmed examples."""
        if not file_contents:
            return []

        patterns_block = ""
        if memory_patterns:
            examples = "\n".join(
                f"Pattern {i+1} (confidence={p.get('confidence', '?')}):\n{p.get('pattern', '')}"
                for i, p in enumerate(memory_patterns[:5])
            )
            patterns_block = f"\n\nMemory-confirmed patterns for {vuln_class} in {language}:\n{examples}"

        # Build a compact file listing (truncate large files)
        file_block = ""
        for path, content in list(file_contents.items())[:15]:
            snippet = content[:3000] if len(content) > 3000 else content
            file_block += f"\n\n### File: {path}\n```\n{snippet}\n```"

        system = f"""\
You are a senior application security engineer specializing in {vuln_class} vulnerabilities.
Your task: identify concrete instances of {vuln_class} vulnerability patterns in the provided code.

Rules:
- Only report findings where you are confident a real vulnerability exists.
- Focus on: {vuln_class} in language={language}, frameworks={frameworks}.
- Do NOT report false positives or theoretical issues without concrete evidence in the code.
- For each finding, provide the exact file, line number estimate, a confidence score (0.0-1.0),
  and a brief exploitation_path explaining how an attacker would reach the vulnerable code.
{patterns_block}

Return ONLY valid JSON (no markdown fences) in this schema:
{{
  "findings": [
    {{
      "file": "<path>",
      "line": <int>,
      "title": "<short title>",
      "description": "<2-3 sentences>",
      "confidence": <float 0.0-1.0>,
      "exploitation_path": "<attacker steps>",
      "severity": "Critical|High|Medium|Low"
    }}
  ]
}}
Return {{"findings": []}} if no vulnerabilities found."""

        user_msg = f"Repository: {repo}\nVulnerability class: {vuln_class}\n"
        if memory_context:
            user_msg += f"\nPrior memory context:\n{memory_context}\n"
        user_msg += f"\nFiles to analyze:{file_block}\n\nReturn the JSON findings now."

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("sentinel.L6_claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo, "L6_code_patterns", vuln_class)

    # ------------------------------------------------------------------
    # L7: Data flow tracing (Claude)
    # ------------------------------------------------------------------

    async def _layer_data_flow(
        self,
        repo: str,
        file_contents: dict[str, str],
        vuln_class: str,
        language: str,
        memory_context: str,
    ) -> list[Finding]:
        """L7: Trace untrusted input to dangerous sinks."""
        file_block = self._build_file_block(file_contents, max_files=10, max_chars=2500)

        system = f"""\
You are an expert in taint analysis and data flow security for {language} code.

Task: Identify paths where untrusted user input (HTTP request parameters, headers, body,
environment variables, file uploads) flows into dangerous sinks without adequate sanitization.

Dangerous sinks include (but are not limited to):
- SQL query execution
- OS command execution (subprocess, exec, eval)
- File system write/read with user-controlled paths
- Deserialization of untrusted data
- Server-side template rendering with user data
- XML/HTML rendering (XSS, XXE)
- LDAP/SSRF/SMTP injection sinks
- Cryptographic key derivation from user input

For each data flow path found, identify:
1. The source (where untrusted data enters)
2. The transformations applied (or lack thereof)
3. The sink (where the data is used dangerously)
4. Whether any sanitization/validation is present (and if it's bypassable)

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "file": "<path>",
      "line": <int>,
      "title": "<short title>",
      "description": "<source → transforms → sink description>",
      "confidence": <float 0.0-1.0>,
      "exploitation_path": "<attacker-controlled input to exploitation>",
      "severity": "Critical|High|Medium|Low"
    }}
  ]
}}"""

        user_msg = f"Repository: {repo}\nVulnerability focus: {vuln_class}\n"
        if memory_context:
            user_msg += f"\nMemory context:\n{memory_context}\n"
        user_msg += f"\nFiles:{file_block}\n\nReturn JSON now."

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("sentinel.L7_claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo, "L7_data_flow", vuln_class)

    # ------------------------------------------------------------------
    # L8: Auth / authz gaps (Claude)
    # ------------------------------------------------------------------

    async def _layer_auth_authz(
        self,
        repo: str,
        file_contents: dict[str, str],
        language: str,
        frameworks: list[str],
        memory_context: str,
    ) -> list[Finding]:
        """L8: Identify authentication and authorization gaps."""
        file_block = self._build_file_block(file_contents, max_files=10, max_chars=2500)

        system = f"""\
You are an application security expert specializing in authentication and authorization vulnerabilities
in {language} services using frameworks: {frameworks}.

Analyze the code for:
- Missing authentication on sensitive endpoints
- Broken object-level authorization (BOLA/IDOR) — accessing resources by ID without ownership check
- Privilege escalation paths (user → admin, low privilege → high)
- JWT/session token validation issues (algorithm confusion, none algorithm, missing expiry check)
- Missing rate limiting on auth endpoints
- Insecure "remember me" / persistent session tokens
- OAuth2/OIDC misconfigurations (open redirects, state parameter missing)
- API endpoints callable without token (anonymous access to private resources)
- Role/permission checks that can be bypassed
- Horizontal privilege escalation (user A accessing user B's data)

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "file": "<path>",
      "line": <int>,
      "title": "<short title>",
      "description": "<detailed description>",
      "confidence": <float 0.0-1.0>,
      "exploitation_path": "<step-by-step attacker path>",
      "severity": "Critical|High|Medium|Low"
    }}
  ]
}}"""

        user_msg = f"Repository: {repo}\n"
        if memory_context:
            user_msg += f"\nMemory context:\n{memory_context}\n"
        user_msg += f"\nFiles:{file_block}\n\nReturn JSON now."

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("sentinel.L8_claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo, "L8_auth_authz", "auth_authz")

    # ------------------------------------------------------------------
    # L9: Cryptographic correctness (Claude)
    # ------------------------------------------------------------------

    async def _layer_crypto(
        self,
        repo: str,
        file_contents: dict[str, str],
        language: str,
        memory_context: str,
    ) -> list[Finding]:
        """L9: Identify cryptographic weaknesses."""
        # Only scan files that mention crypto-related terms to reduce noise
        crypto_keywords = {
            "encrypt", "decrypt", "hash", "hmac", "aes", "rsa", "sha", "md5",
            "ssl", "tls", "certificate", "signature", "random", "key", "secret",
            "pbkdf", "bcrypt", "cipher", "jwt", "token",
        }
        crypto_files = {
            path: content
            for path, content in file_contents.items()
            if any(kw in content.lower() for kw in crypto_keywords)
        }

        if not crypto_files:
            return []

        file_block = self._build_file_block(crypto_files, max_files=8, max_chars=3000)

        system = f"""\
You are a cryptography security expert reviewing {language} code for cryptographic weaknesses.

Analyze for:
- Use of broken algorithms: MD5, SHA-1, DES, 3DES, RC4 for security purposes
- Weak RSA key sizes (< 2048 bits) or EC curve choices
- Hard-coded cryptographic keys, IV, or salts
- ECB mode encryption (lacks semantic security)
- Non-random or predictable IVs/nonces
- Password storage with reversible encryption (should use bcrypt/argon2/scrypt)
- Predictable random number generation (math.random, rand() for security)
- Missing HMAC authentication on encrypted data (encrypt-then-MAC violations)
- Incorrect padding schemes (PKCS#1 v1.5 for encryption)
- TLS misconfiguration (accepting expired certs, disabling hostname verification, weak ciphersuites)
- JWT with symmetric secret that is too short or hard-coded
- Timing side channels in comparison operations (using == instead of constant-time compare)

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "file": "<path>",
      "line": <int>,
      "title": "<short title>",
      "description": "<what is wrong and why it matters>",
      "confidence": <float 0.0-1.0>,
      "exploitation_path": "<how an attacker exploits this>",
      "severity": "Critical|High|Medium|Low"
    }}
  ]
}}"""

        user_msg = f"Repository: {repo}\n"
        if memory_context:
            user_msg += f"\nMemory context:\n{memory_context}\n"
        user_msg += f"\nFiles:{file_block}\n\nReturn JSON now."

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("sentinel.L9_claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo, "L9_crypto", "crypto_weakness")

    # ------------------------------------------------------------------
    # L10: Business logic (Claude)
    # ------------------------------------------------------------------

    async def _layer_business_logic(
        self,
        repo: str,
        file_contents: dict[str, str],
        language: str,
        memory_context: str,
    ) -> list[Finding]:
        """L10: Identify logic bugs, TOCTOU races, and application-layer flaws."""
        file_block = self._build_file_block(file_contents, max_files=10, max_chars=2500)

        system = f"""\
You are a senior security engineer specializing in application business logic vulnerabilities in {language}.

Analyze for:
- TOCTOU (time-of-check-to-time-of-use) race conditions on files, database records, or shared state
- Price / quantity manipulation in e-commerce flows (negative values, integer overflow)
- Workflow bypass — skipping required steps (e.g. jumping to checkout without completing payment)
- Unlimited resource consumption (missing pagination limits, unbounded loops on user input)
- Mass assignment vulnerabilities (accepting all fields from request body)
- Insecure direct object reference via predictable IDs (sequential integers)
- Negative number / boundary conditions in financial calculations
- Double-spend patterns in payment flows
- State machine violations (transitioning to invalid states)
- Asymmetric resource exhaustion (cheap request causes expensive server work)
- Logic errors in permission inheritance (parent grants permission to children without check)

Return ONLY valid JSON:
{{
  "findings": [
    {{
      "file": "<path>",
      "line": <int>,
      "title": "<short title>",
      "description": "<concrete description of the logic flaw>",
      "confidence": <float 0.0-1.0>,
      "exploitation_path": "<how an attacker exploits this>",
      "severity": "Critical|High|Medium|Low"
    }}
  ]
}}"""

        user_msg = f"Repository: {repo}\n"
        if memory_context:
            user_msg += f"\nMemory context:\n{memory_context}\n"
        user_msg += f"\nFiles:{file_block}\n\nReturn JSON now."

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("sentinel.L10_claude_error", error=str(exc))
            return []

        return self._parse_findings(raw, repo, "L10_business_logic", "business_logic")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_file_block(
        self, file_contents: dict[str, str], max_files: int = 10, max_chars: int = 2500
    ) -> str:
        block = ""
        for path, content in list(file_contents.items())[:max_files]:
            snippet = content[:max_chars] if len(content) > max_chars else content
            block += f"\n\n### File: {path}\n```\n{snippet}\n```"
        return block

    def _parse_findings(
        self,
        raw: str,
        repo: str,
        layer_hit: str,
        vuln_class: str,
    ) -> list[Finding]:
        """Parse Claude's JSON response into a list of Finding objects."""
        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.log.warning("sentinel.json_parse_error", layer=layer_hit, error=str(exc))
            return []

        results: list[Finding] = []
        for item in data.get("findings", []):
            try:
                confidence = float(item.get("confidence", 0.5))
                sev_str = item.get("severity", "Medium")
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = _severity_from_confidence(confidence)

                finding = Finding(
                    finding_id=str(uuid.uuid4())[:16],
                    repo=repo,
                    file=item.get("file", "unknown"),
                    line=int(item.get("line", 0)),
                    vuln_class=vuln_class,
                    title=item.get("title", f"{layer_hit} finding"),
                    severity=severity,
                    confidence=confidence,
                    layer_hit=layer_hit,
                    exploitation_path=item.get("exploitation_path", ""),
                    agent=self.name,
                    metadata={"description": item.get("description", "")},
                )
                results.append(finding)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("sentinel.finding_parse_error", error=str(exc), item=item)

        self.log.info("sentinel.layer_complete", layer=layer_hit, findings=len(results))
        return results

    async def _fetch_memory_patterns(
        self, vuln_class: str, language: str
    ) -> list[dict[str, Any]]:
        """Fetch confirmed vulnerability patterns from vector memory."""
        if self.memory is None or not hasattr(self.memory, "vector"):
            return []
        try:
            hits = await self.memory.vector.search(
                collection="vulnerabilities",
                query_text=f"{vuln_class} {language} confirmed pattern",
                filter={"vuln_class": vuln_class},
                limit=5,
            )
            return [h["payload"] for h in hits if h["score"] > 0.70]
        except Exception as exc:  # noqa: BLE001
            self.log.warning("sentinel.memory_fetch_error", error=str(exc))
            return []

    async def _persist_patterns(
        self, findings: list[Finding], vuln_class: str, language: str
    ) -> None:
        """Write confirmed L6 patterns back to vector memory."""
        if self.memory is None or not hasattr(self.memory, "vector"):
            return
        for finding in findings:
            if finding.confidence < 0.8:
                continue
            pattern_text = f"{vuln_class} {language} {finding.file}\n{finding.exploitation_path}"
            try:
                vector = await self.memory.vector.embed_code(pattern_text)
                await self.memory.vector.upsert(
                    collection="vulnerabilities",
                    id=finding.finding_id,
                    vector=vector,
                    payload={
                        "vuln_class": vuln_class,
                        "language": language,
                        "pattern": finding.exploitation_path,
                        "confidence": finding.confidence,
                        "layer": finding.layer_hit,
                        "ts": datetime.now(timezone.utc).isoformat(),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                self.log.warning("sentinel.memory_persist_error", error=str(exc))

    async def _fetch_file(self, repo: str, path: str, platform: str) -> str:
        """Fetch raw file content from the VCS platform API."""
        if not self._platform_token:
            return f"# [sentinel] No platform token configured — cannot fetch {path}"

        headers = {"Authorization": f"Bearer {self._platform_token}"}
        url = self._build_raw_url(repo, path, platform)

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                return resp.text
        except Exception as exc:  # noqa: BLE001
            self.log.warning("sentinel.fetch_file_error", file=path, error=str(exc))
            return f"# [sentinel] Failed to fetch {path}: {exc}"

    def _build_raw_url(self, repo: str, path: str, platform: str) -> str:
        """Build the raw-file URL for the given platform."""
        if platform == "github":
            owner, name = repo.split("/", 1) if "/" in repo else (repo, repo)
            return f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{path}"
        if platform == "gitlab":
            encoded_repo = repo.replace("/", "%2F")
            encoded_path = path.replace("/", "%2F")
            return f"https://gitlab.com/api/v4/projects/{encoded_repo}/repository/files/{encoded_path}/raw?ref=HEAD"
        # Default: Bitbucket Cloud
        return f"{self._platform_base_url}/repositories/{repo}/src/HEAD/{path}"
