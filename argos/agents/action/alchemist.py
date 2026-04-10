"""
argos/agents/action/alchemist.py

AlchemistAgent — multi-language, multi-platform automated fix generator.

Evolved from the conceptual Glasswing fixer_agent.  For each confirmed
finding, Alchemist:

1. Reads vector memory for proven fix patterns for this vuln_class + language.
2. Fetches the vulnerable file from the VCS platform.
3. Asks Claude (adaptive thinking) to produce a minimal, targeted fix,
   injecting memory patterns as few-shot examples.
4. Creates a branch, writes the fix, opens a PR.
5. Writes the successful fix pattern back to memory.

Hardware mode:  when asset_type is firmware or PCB, delegates to
generate_fix_for_hardware() which produces a design-change recommendation
(no auto-PR for hardware).

Supported languages:
    java, python, javascript, typescript, go, ruby, rust, c, cpp, php
"""

from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from argos.agents.base import AgentResult, ArgosAgent
from argos.events import AssetType, Finding

log = structlog.get_logger(__name__)

SUPPORTED_LANGUAGES: list[str] = [
    "java", "python", "javascript", "typescript",
    "go", "ruby", "rust", "c", "cpp", "php",
]

# ---------------------------------------------------------------------------
# Language → file-extension map (for creating fix file names)
# ---------------------------------------------------------------------------

_LANG_EXT: dict[str, str] = {
    "java": ".java",
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "ruby": ".rb",
    "rust": ".rs",
    "c": ".c",
    "cpp": ".cpp",
    "php": ".php",
}

# ---------------------------------------------------------------------------
# Platform API helpers
# ---------------------------------------------------------------------------


class _PlatformClient:
    """Thin async HTTP wrapper for Bitbucket/GitHub/GitLab operations."""

    def __init__(self, platform: str, token: str, base_url: str) -> None:
        self.platform = platform
        self.token = token
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def get_file(self, repo: str, path: str) -> str:
        """Fetch raw file content."""
        url = self._raw_url(repo, path)
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, headers=self._headers)
            resp.raise_for_status()
            return resp.text

    async def create_branch(self, repo: str, branch: str, from_ref: str = "HEAD") -> bool:
        """Create a branch. Returns True on success."""
        if self.platform == "github":
            # GitHub: get SHA of from_ref first, then create branch
            owner, name = repo.split("/", 1)
            async with httpx.AsyncClient(timeout=20.0) as client:
                ref_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{name}/git/ref/heads/{from_ref}",
                    headers={**self._headers, "Accept": "application/vnd.github+json"},
                )
                sha = ref_resp.json().get("object", {}).get("sha", "")
                branch_resp = await client.post(
                    f"https://api.github.com/repos/{owner}/{name}/git/refs",
                    headers={**self._headers, "Accept": "application/vnd.github+json"},
                    json={"ref": f"refs/heads/{branch}", "sha": sha},
                )
                return branch_resp.is_success

        if self.platform == "bitbucket":
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{self.base_url}/repositories/{repo}/refs/branches",
                    headers=self._headers,
                    json={"name": branch, "target": {"hash": from_ref}},
                )
                return resp.is_success

        if self.platform == "gitlab":
            project = repo.replace("/", "%2F")
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{self.base_url}/projects/{project}/repository/branches",
                    headers=self._headers,
                    json={"branch": branch, "ref": from_ref},
                )
                return resp.is_success

        return False

    async def update_file(self, repo: str, path: str, content: str, branch: str, message: str) -> bool:
        """Commit updated file content on a branch. Returns True on success."""
        import base64

        encoded = base64.b64encode(content.encode()).decode()

        if self.platform == "github":
            owner, name = repo.split("/", 1)
            async with httpx.AsyncClient(timeout=20.0) as client:
                # Get current file SHA (required by GitHub API)
                get_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{name}/contents/{path}",
                    headers={**self._headers, "Accept": "application/vnd.github+json"},
                    params={"ref": branch},
                )
                file_sha = get_resp.json().get("sha", "")
                put_resp = await client.put(
                    f"https://api.github.com/repos/{owner}/{name}/contents/{path}",
                    headers={**self._headers, "Accept": "application/vnd.github+json"},
                    json={
                        "message": message,
                        "content": encoded,
                        "branch": branch,
                        "sha": file_sha,
                    },
                )
                return put_resp.is_success

        if self.platform == "bitbucket":
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{self.base_url}/repositories/{repo}/src",
                    headers={"Authorization": f"Bearer {self.token}"},
                    data={path: content, "message": message, "branch": branch},
                )
                return resp.is_success

        if self.platform == "gitlab":
            project = repo.replace("/", "%2F")
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.put(
                    f"{self.base_url}/projects/{project}/repository/files/{path.replace('/', '%2F')}",
                    headers=self._headers,
                    json={
                        "branch": branch,
                        "content": content,
                        "commit_message": message,
                        "encoding": "text",
                    },
                )
                return resp.is_success

        return False

    async def open_pr(
        self, repo: str, branch: str, base: str, title: str, description: str
    ) -> str:
        """Open a pull request. Returns the PR URL."""
        if self.platform == "github":
            owner, name = repo.split("/", 1)
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"https://api.github.com/repos/{owner}/{name}/pulls",
                    headers={**self._headers, "Accept": "application/vnd.github+json"},
                    json={"title": title, "body": description, "head": branch, "base": base},
                )
                return resp.json().get("html_url", "")

        if self.platform == "bitbucket":
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{self.base_url}/repositories/{repo}/pullrequests",
                    headers=self._headers,
                    json={
                        "title": title,
                        "description": description,
                        "source": {"branch": {"name": branch}},
                        "destination": {"branch": {"name": base}},
                    },
                )
                return resp.json().get("links", {}).get("html", {}).get("href", "")

        if self.platform == "gitlab":
            project = repo.replace("/", "%2F")
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{self.base_url}/projects/{project}/merge_requests",
                    headers=self._headers,
                    json={
                        "title": title,
                        "description": description,
                        "source_branch": branch,
                        "target_branch": base,
                    },
                )
                return resp.json().get("web_url", "")

        return ""

    def _raw_url(self, repo: str, path: str) -> str:
        if self.platform == "github":
            owner, name = repo.split("/", 1)
            return f"https://raw.githubusercontent.com/{owner}/{name}/HEAD/{path}"
        if self.platform == "gitlab":
            encoded_repo = repo.replace("/", "%2F")
            encoded_path = path.replace("/", "%2F")
            return f"{self.base_url}/projects/{encoded_repo}/repository/files/{encoded_path}/raw?ref=HEAD"
        return f"{self.base_url}/repositories/{repo}/src/HEAD/{path}"


# ---------------------------------------------------------------------------
# AlchemistAgent
# ---------------------------------------------------------------------------


class AlchemistAgent(ArgosAgent):
    """
    Multi-language automated fix generator.

    Parameters
    ----------
    memory:
        ArgosMemory for reading/writing fix patterns.
    producer:
        Kafka producer.
    platform_token:
        VCS personal access token.
    platform_base_url:
        VCS API base URL.
    default_base_branch:
        Default base branch for PRs (default: ``main``).
    """

    name = "alchemist"
    SUPPORTED_LANGUAGES = SUPPORTED_LANGUAGES

    def __init__(
        self,
        memory: Any | None = None,
        producer: Any | None = None,
        platform_token: str = "",
        platform_base_url: str = "https://api.bitbucket.org/2.0",
        default_base_branch: str = "main",
    ) -> None:
        super().__init__(memory=memory, producer=producer)
        self._platform_token = platform_token
        self._platform_base_url = platform_base_url
        self._default_base_branch = default_base_branch

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Generate and apply a fix for a confirmed finding.

        Context keys
        ------------
        finding : dict | Finding
            The confirmed Finding to fix.
        platform : str
            VCS platform: ``bitbucket`` | ``github`` | ``gitlab``.
        memory_context : str
            Pre-fetched memory blurb with known good fix patterns.
        base_branch : str
            Base branch to branch off (default: ``main``).
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        finding_raw = context.get("finding", {})
        platform: str = context.get("platform", "bitbucket")
        memory_context: str = context.get("memory_context", "")
        base_branch: str = context.get("base_branch", self._default_base_branch)

        try:
            finding = Finding(**finding_raw) if isinstance(finding_raw, dict) else finding_raw
        except Exception as exc:  # noqa: BLE001
            return AgentResult(
                agent=self.name,
                success=False,
                error=f"Invalid finding: {exc}",
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=0,
            )

        self.log.info(
            "alchemist.fix_start",
            finding_id=finding.finding_id,
            repo=finding.repo,
            vuln_class=finding.vuln_class,
            file=finding.file,
        )

        try:
            # Hardware assets get a different path
            if finding.asset_type in (AssetType.PCB, AssetType.FIRMWARE, AssetType.VHDL, AssetType.VERILOG):
                result_data = await self.generate_fix_for_hardware(finding)
            else:
                result_data = await self.apply_fix(finding, platform, memory_context, base_branch)
        except Exception as exc:  # noqa: BLE001
            self.log.exception("alchemist.fix_error", finding_id=finding.finding_id, error=str(exc))
            result_data = {"success": False, "error": str(exc)}

        duration_ms = int((time.monotonic() - t0) * 1000)
        success = result_data.get("success", False)

        self.log.info(
            "alchemist.fix_complete",
            finding_id=finding.finding_id,
            success=success,
            pr_url=result_data.get("pr_url", ""),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=success,
            findings=[finding.model_dump()],
            metadata={**result_data, "finding_id": finding.finding_id},
            error=result_data.get("error", "") if not success else "",
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # apply_fix()
    # ------------------------------------------------------------------

    async def apply_fix(
        self,
        finding: Finding,
        platform: str,
        memory_context: str = "",
        base_branch: str = "main",
    ) -> dict[str, Any]:
        """
        End-to-end fix workflow for a software finding.

        Steps:
        1. Read memory for proven fix patterns.
        2. Fetch the vulnerable file.
        3. Generate fix via Claude.
        4. Create branch, update file, open PR.
        5. Write fix pattern to memory on success.

        Returns dict with keys: success, pr_url, branch, vulnerable_snippet, fix_snippet, error.
        """
        if not self._platform_token:
            return {
                "success": False,
                "error": "No platform token configured — cannot apply fix.",
                "pr_url": "",
                "branch": "",
                "vulnerable_snippet": "",
                "fix_snippet": "",
            }

        client = _PlatformClient(platform, self._platform_token, self._platform_base_url)

        # 1. Read memory for proven fix patterns
        fix_patterns = await self._fetch_fix_patterns(finding.vuln_class, finding.file)

        # 2. Fetch the vulnerable file
        try:
            file_content = await client.get_file(finding.repo, finding.file)
        except Exception as exc:  # noqa: BLE001
            self.log.error("alchemist.fetch_file_error", file=finding.file, error=str(exc))
            return {
                "success": False,
                "error": f"Failed to fetch {finding.file}: {exc}",
                "pr_url": "", "branch": "", "vulnerable_snippet": "", "fix_snippet": "",
            }

        # 3. Generate fix via Claude
        fix_result = await self._generate_fix(finding, file_content, fix_patterns, memory_context)
        if not fix_result.get("success"):
            return {
                "success": False,
                "error": fix_result.get("error", "Fix generation failed"),
                "pr_url": "", "branch": "",
                "vulnerable_snippet": fix_result.get("vulnerable_snippet", ""),
                "fix_snippet": "",
            }

        fixed_content: str = fix_result["fixed_content"]
        vulnerable_snippet: str = fix_result.get("vulnerable_snippet", "")
        fix_snippet: str = fix_result.get("fix_snippet", "")

        # 4. Create branch, update file, open PR
        branch = f"argos/fix-{finding.vuln_class.replace('_', '-')}-{finding.finding_id[:8]}"
        branch_ok = await client.create_branch(finding.repo, branch, from_ref=base_branch)
        if not branch_ok:
            self.log.warning("alchemist.branch_create_warning", branch=branch)

        commit_msg = (
            f"fix({finding.vuln_class}): remediate {finding.title}\n\n"
            f"Finding: {finding.finding_id}\n"
            f"Severity: {finding.severity.value}\n"
            f"Auto-generated by ARGOS AlchemistAgent"
        )
        update_ok = await client.update_file(
            repo=finding.repo,
            path=finding.file,
            content=fixed_content,
            branch=branch,
            message=commit_msg,
        )
        if not update_ok:
            return {
                "success": False,
                "error": "Failed to commit fix to branch",
                "pr_url": "", "branch": branch,
                "vulnerable_snippet": vulnerable_snippet,
                "fix_snippet": fix_snippet,
            }

        pr_desc = (
            f"## ARGOS Security Fix\n\n"
            f"**Finding ID:** `{finding.finding_id}`\n"
            f"**Vulnerability:** {finding.title}\n"
            f"**Severity:** {finding.severity.value}\n"
            f"**Class:** {finding.vuln_class}\n"
            f"**File:** `{finding.file}` (line {finding.line})\n\n"
            f"### Vulnerable Code\n```\n{vulnerable_snippet}\n```\n\n"
            f"### Fixed Code\n```\n{fix_snippet}\n```\n\n"
            f"### Exploitation Path\n{finding.exploitation_path}\n\n"
            f"---\n*Auto-generated by ARGOS AlchemistAgent. Review before merging.*"
        )
        pr_title = f"[ARGOS] {finding.severity.value}: {finding.title} ({finding.vuln_class})"

        pr_url = await client.open_pr(
            repo=finding.repo,
            branch=branch,
            base=base_branch,
            title=pr_title,
            description=pr_desc,
        )

        # 5. Write fix pattern to memory on success
        if pr_url:
            await self._persist_fix_pattern(finding, vulnerable_snippet, fix_snippet)

        return {
            "success": bool(pr_url),
            "pr_url": pr_url,
            "branch": branch,
            "vulnerable_snippet": vulnerable_snippet,
            "fix_snippet": fix_snippet,
            "error": "" if pr_url else "PR creation returned empty URL",
        }

    # ------------------------------------------------------------------
    # generate_fix_for_hardware()
    # ------------------------------------------------------------------

    async def generate_fix_for_hardware(self, finding: Finding) -> dict[str, Any]:
        """
        Generate a design-change recommendation for hardware findings.

        Hardware findings (PCB, firmware, VHDL) cannot be auto-patched via PR.
        Instead, Claude produces a structured design change recommendation with
        a risk assessment and mitigation checklist.

        Returns dict: success, recommendation, risk_assessment, checklist, error.
        """
        self.log.info(
            "alchemist.hardware_fix",
            finding_id=finding.finding_id,
            asset_type=finding.asset_type.value,
        )

        system = """\
You are a hardware security engineer specializing in embedded systems, PCB design, and FPGA security.

Given a hardware security finding, produce a structured design-change recommendation that:
1. Describes the exact design flaw
2. Provides a concrete mitigation (component change, layout change, firmware patch, etc.)
3. Lists a verification checklist (how to confirm the fix is effective)
4. Assesses residual risk after the fix

Return ONLY valid JSON:
{
  "recommendation": "<detailed design change description>",
  "risk_assessment": {
    "pre_fix_risk": "Critical|High|Medium|Low",
    "post_fix_risk": "High|Medium|Low|Info",
    "residual_concerns": "<what risk remains after the fix>"
  },
  "checklist": [
    "<verification step 1>",
    "<verification step 2>"
  ],
  "estimated_effort": "hours|days|weeks",
  "requires_pcb_respin": true|false
}"""

        user_msg = (
            f"Hardware finding:\n"
            f"- Asset type: {finding.asset_type.value}\n"
            f"- File / schematic: {finding.file}\n"
            f"- Vulnerability class: {finding.vuln_class}\n"
            f"- Title: {finding.title}\n"
            f"- Severity: {finding.severity.value}\n"
            f"- Exploitation path: {finding.exploitation_path}\n"
            f"- Description: {finding.metadata.get('description', '')}\n\n"
            f"Generate the hardware design-change recommendation now."
        )

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=4096,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("alchemist.hardware_claude_error", error=str(exc))
            return {"success": False, "error": str(exc)}

        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            data = json.loads(raw)
            return {
                "success": True,
                "recommendation": data.get("recommendation", ""),
                "risk_assessment": data.get("risk_assessment", {}),
                "checklist": data.get("checklist", []),
                "estimated_effort": data.get("estimated_effort", "unknown"),
                "requires_pcb_respin": data.get("requires_pcb_respin", False),
                "error": "",
            }
        except json.JSONDecodeError as exc:
            self.log.warning("alchemist.hardware_json_error", error=str(exc))
            return {"success": True, "recommendation": raw, "error": ""}

    # ------------------------------------------------------------------
    # Fix generation (Claude)
    # ------------------------------------------------------------------

    async def _generate_fix(
        self,
        finding: Finding,
        file_content: str,
        fix_patterns: list[dict[str, Any]],
        memory_context: str,
    ) -> dict[str, Any]:
        """Ask Claude to produce a minimal, targeted fix for the finding."""
        language = self._detect_language(finding.file)

        few_shot = ""
        if fix_patterns:
            examples = "\n\n".join(
                f"Example {i+1} ({p.get('vuln_class', '')}):\n"
                f"BEFORE:\n```\n{p.get('vulnerable_snippet', '')}\n```\n"
                f"AFTER:\n```\n{p.get('fix_snippet', '')}\n```\n"
                f"Rationale: {p.get('rationale', '')}"
                for i, p in enumerate(fix_patterns[:3])
            )
            few_shot = f"\n\nProven fix patterns from memory:\n{few_shot}\n{examples}"

        # Truncate large files — focus on the area around the vulnerable line
        focused_content = self._extract_focus_window(file_content, finding.line, window=80)

        system = f"""\
You are a senior {language} security engineer. Your task: produce a minimal, targeted fix for a
confirmed {finding.vuln_class} vulnerability. Do NOT refactor unrelated code.
Do NOT change business logic. Fix ONLY the security issue.
{few_shot}

Return ONLY valid JSON:
{{
  "vulnerable_snippet": "<exact vulnerable lines from the file>",
  "fix_snippet": "<replacement lines>",
  "fixed_content": "<complete fixed file content>",
  "rationale": "<1-2 sentence explanation of what the fix does and why>",
  "confidence": <float 0.0-1.0>
}}"""

        user_msg = (
            f"Repository: {finding.repo}\n"
            f"File: {finding.file}\n"
            f"Language: {language}\n"
            f"Vulnerability: {finding.title} ({finding.vuln_class})\n"
            f"Severity: {finding.severity.value}\n"
            f"Line: {finding.line}\n"
            f"Exploitation path: {finding.exploitation_path}\n"
        )
        if memory_context:
            user_msg += f"\nMemory context:\n{memory_context}\n"

        user_msg += f"\nFile content (around line {finding.line}):\n```{language}\n{focused_content}\n```\n\nReturn the JSON fix now."

        try:
            raw = await self._call_claude(
                system=system,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=8192,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("alchemist.claude_fix_error", error=str(exc))
            return {"success": False, "error": str(exc)}

        raw = raw.strip()
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            data = json.loads(raw)
            fixed_content = data.get("fixed_content", "")
            if not fixed_content:
                # Fallback: apply the snippet replacement to the full file
                vulnerable = data.get("vulnerable_snippet", "")
                fix = data.get("fix_snippet", "")
                fixed_content = file_content.replace(vulnerable, fix, 1) if vulnerable else file_content

            return {
                "success": True,
                "fixed_content": fixed_content,
                "vulnerable_snippet": data.get("vulnerable_snippet", ""),
                "fix_snippet": data.get("fix_snippet", ""),
                "rationale": data.get("rationale", ""),
                "confidence": float(data.get("confidence", 0.8)),
                "error": "",
            }
        except json.JSONDecodeError as exc:
            self.log.warning("alchemist.fix_json_error", error=str(exc))
            return {"success": False, "error": f"Fix JSON parse error: {exc}"}

    # ------------------------------------------------------------------
    # Memory helpers
    # ------------------------------------------------------------------

    async def _fetch_fix_patterns(
        self, vuln_class: str, file_path: str
    ) -> list[dict[str, Any]]:
        """Fetch proven fix patterns from vector memory."""
        if self.memory is None or not hasattr(self.memory, "vector"):
            return []
        language = self._detect_language(file_path)
        try:
            hits = await self.memory.vector.search(
                collection="fix_patterns",
                query_text=f"{vuln_class} {language} fix pattern",
                filter={"vuln_class": vuln_class},
                limit=5,
            )
            return [h["payload"] for h in hits if h["score"] > 0.72]
        except Exception as exc:  # noqa: BLE001
            self.log.warning("alchemist.memory_fetch_error", error=str(exc))
            return []

    async def _persist_fix_pattern(
        self, finding: Finding, vulnerable_snippet: str, fix_snippet: str
    ) -> None:
        """Write a successful fix pattern to vector memory."""
        if self.memory is None or not hasattr(self.memory, "vector"):
            return
        language = self._detect_language(finding.file)
        pattern_text = f"{finding.vuln_class} {language}\n{vulnerable_snippet}\n---\n{fix_snippet}"
        try:
            vector = await self.memory.vector.embed_code(pattern_text)
            await self.memory.vector.upsert(
                collection="fix_patterns",
                id=f"fix-{finding.finding_id}",
                vector=vector,
                payload={
                    "vuln_class": finding.vuln_class,
                    "language": language,
                    "vulnerable_snippet": vulnerable_snippet[:500],
                    "fix_snippet": fix_snippet[:500],
                    "rationale": f"Auto-confirmed fix for {finding.title}",
                    "finding_id": finding.finding_id,
                    "ts": datetime.now(timezone.utc).isoformat(),
                },
            )
            self.log.debug("alchemist.pattern_persisted", finding_id=finding.finding_id)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("alchemist.memory_persist_error", error=str(exc))

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """Infer language from file extension."""
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        ext_map = {
            "java": "java", "py": "python", "js": "javascript", "ts": "typescript",
            "go": "go", "rb": "ruby", "rs": "rust", "c": "c", "cpp": "cpp",
            "cc": "cpp", "cxx": "cpp", "php": "php", "cs": "csharp",
        }
        return ext_map.get(ext, "unknown")

    @staticmethod
    def _extract_focus_window(content: str, line: int, window: int = 80) -> str:
        """Extract `window` lines centred on `line` from file content."""
        lines = content.splitlines()
        if line <= 0 or not lines:
            return content[:8000] if len(content) > 8000 else content
        start = max(0, line - window // 2)
        end = min(len(lines), line + window // 2)
        return "\n".join(lines[start:end])
