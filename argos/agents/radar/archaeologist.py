"""
argos/agents/radar/archaeologist.py

ArchaeologistAgent — git history analysis for confirmed security findings.

Given a confirmed finding (vulnerable pattern in a specific file), the agent:
  1. Fetches the git log for that file (last 100 commits via SCM API).
  2. Uses Claude with adaptive thinking to identify:
       - When the vulnerable pattern was introduced.
       - Who introduced it and whether it looks intentional.
       - Whether a previous fix was applied and then reverted (regression).
  3. Returns structured provenance data: introduction commit, date, author,
     regression flag, and the SHA of any prior fix.

This information is used downstream by:
  - ProphetAgent  : to assess systemic patterns of vulnerability re-introduction.
  - AlchemistAgent: to target the right commit/PR when generating a fix.
  - Security team : for incident response and responsible disclosure.

SCM integration
---------------
The agent fetches git log via self.memory.scm_client.  When no SCM client is
available it returns an empty result with a warning rather than failing hard.
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

from argos.agents.base import AgentResult, ArgosAgent

log = structlog.get_logger(__name__)

# Maximum number of commits to fetch per file.
MAX_COMMITS = 100

# ---------------------------------------------------------------------------
# ArchaeologistAgent
# ---------------------------------------------------------------------------


class ArchaeologistAgent(ArgosAgent):
    """
    Git history provenance agent.

    Determines the origin of a confirmed vulnerability: which commit introduced
    it, who authored it, and whether it is a regression of a previously fixed
    issue.
    """

    name = "archaeologist"

    _SYSTEM = """\
You are Archaeologist, the git history forensics agent for the ARGOS security platform.

You will receive:
  1. A file path and a vulnerable pattern description (the thing we're hunting for).
  2. The git log for that file: a JSON list of commits, each with keys:
       sha, author_name, author_email, date, message, diff (unified diff of the commit).

Your task:
  A. Find the commit where the vulnerable pattern was FIRST introduced (not removed).
  B. Assess whether the introduction looks INTENTIONAL (deliberate backdoor) or
     ACCIDENTAL (oversight, copy-paste, dependency update).
  C. Determine whether a PRIOR FIX was applied and then REVERTED (regression).
     A regression is when a commit removes the pattern, and a later commit re-adds it.

Return ONLY valid JSON (no markdown, no code fences) in this schema:
{
  "introduction_commit": "<sha or null>",
  "introduction_date":   "<ISO 8601 date string or null>",
  "author_name":         "<string or null>",
  "author_email":        "<string or null>",
  "was_intentional":     <bool or null>,
  "intentionality_reasoning": "<one sentence>",
  "was_regression":      <bool>,
  "prior_fix_sha":       "<sha of the commit that previously fixed it, or null>",
  "regression_reasoning": "<one sentence explaining why it is/isn't a regression>",
  "confidence":          "HIGH|MEDIUM|LOW"
}

Notes:
  - Set introduction_commit to null if you cannot identify it from the provided diffs.
  - was_intentional may be null when there is insufficient evidence either way.
  - confidence reflects how much evidence exists in the diffs (HIGH = clear diff
    shows the exact pattern; LOW = pattern not visible in diffs, only circumstantial).
"""

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, context: dict[str, Any]) -> AgentResult:
        """
        Analyse the git history of a file to find the origin of a vulnerability.

        Context keys
        ------------
        repo : str
            Repository slug.
        file : str
            File path within the repository.
        platform : str
            "bitbucket" | "github"
        finding_id : str
            Unique ID of the confirmed finding (for cross-referencing).
        vulnerable_pattern : str
            Human-readable description of the vulnerability to hunt for.
            E.g. "SQL query built via string concatenation using user input"
        project_key : str
            Bitbucket DC project key (ignored on Cloud/GitHub).
        ref : str
            Git ref / branch (default "HEAD").
        """
        t0 = time.monotonic()
        self._total_tokens = 0

        repo: str = context.get("repo", "unknown")
        file_path: str = context.get("file", "")
        platform: str = context.get("platform", "bitbucket")
        finding_id: str = context.get("finding_id", "")
        vulnerable_pattern: str = context.get("vulnerable_pattern", "")
        project_key: str = context.get("project_key", "")
        ref: str = context.get("ref", "HEAD")

        self.log.info(
            "archaeologist.run",
            repo=repo,
            file=file_path,
            finding_id=finding_id,
        )

        if not file_path:
            return AgentResult(
                agent=self.name,
                success=False,
                error="No file path provided in context.",
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        # 1. Fetch git log for the file.
        commits = await self._fetch_commit_log(
            repo=repo,
            file_path=file_path,
            project_key=project_key,
            ref=ref,
            max_commits=MAX_COMMITS,
        )

        if not commits:
            self.log.warning(
                "archaeologist.no_commits",
                repo=repo,
                file=file_path,
            )
            return AgentResult(
                agent=self.name,
                success=True,
                findings=[],
                metadata={
                    "repo": repo,
                    "file": file_path,
                    "finding_id": finding_id,
                    "message": "No commits found for file; cannot determine provenance.",
                },
                duration_ms=int((time.monotonic() - t0) * 1000),
                tokens_used=0,
            )

        # 2. Ask Claude to analyse the history.
        provenance = await self._analyse_history(
            repo=repo,
            file_path=file_path,
            vulnerable_pattern=vulnerable_pattern,
            commits=commits,
        )

        # 3. Build the finding record.
        finding: dict[str, Any] = {
            "finding_id": finding_id,
            "repo": repo,
            "file": file_path,
            "platform": platform,
            "vulnerable_pattern": vulnerable_pattern,
            **provenance,
        }

        duration_ms = int((time.monotonic() - t0) * 1000)
        self.log.info(
            "archaeologist.complete",
            repo=repo,
            file=file_path,
            introduction_commit=provenance.get("introduction_commit"),
            was_regression=provenance.get("was_regression"),
            duration_ms=duration_ms,
        )

        return AgentResult(
            agent=self.name,
            success=True,
            findings=[finding],
            metadata={
                "repo": repo,
                "file": file_path,
                "commits_analysed": len(commits),
            },
            duration_ms=duration_ms,
            tokens_used=self._total_tokens,
        )

    # ------------------------------------------------------------------
    # Public helpers (callable independently)
    # ------------------------------------------------------------------

    async def find_introduction_commit(
        self,
        repo: str,
        file: str,
        pattern: str,
        project_key: str = "",
        ref: str = "HEAD",
    ) -> dict[str, Any]:
        """
        Return provenance data for when a pattern was introduced in a file.

        Returns a dict with keys matching the Claude schema above, or an empty
        dict if the analysis could not be completed.
        """
        commits = await self._fetch_commit_log(
            repo=repo,
            file_path=file,
            project_key=project_key,
            ref=ref,
            max_commits=MAX_COMMITS,
        )
        if not commits:
            return {}
        return await self._analyse_history(
            repo=repo,
            file_path=file,
            vulnerable_pattern=pattern,
            commits=commits,
        )

    async def detect_regression(
        self,
        repo: str,
        file: str,
        pattern: str,
        project_key: str = "",
        ref: str = "HEAD",
    ) -> bool:
        """
        Return True if the pattern was previously fixed then re-introduced.
        """
        provenance = await self.find_introduction_commit(
            repo=repo, file=file, pattern=pattern, project_key=project_key, ref=ref
        )
        return bool(provenance.get("was_regression", False))

    # ------------------------------------------------------------------
    # Git log fetching
    # ------------------------------------------------------------------

    async def _fetch_commit_log(
        self,
        repo: str,
        file_path: str,
        project_key: str,
        ref: str,
        max_commits: int,
    ) -> list[dict[str, Any]]:
        """
        Fetch the commit log for a specific file via the SCM API.

        Returns a list of commit dicts with keys:
          sha, author_name, author_email, date, message, diff
        """
        scm = self._get_scm_client()
        if scm is None:
            self.log.warning("archaeologist.no_scm_client")
            return []

        try:
            # Attempt to use a file-specific log endpoint.
            # BitbucketClient and GithubClient are expected to expose
            # get_file_commits(repo, path, ref, limit) returning a list of
            # commit dicts.  Fall back gracefully if the method doesn't exist.
            if hasattr(scm, "get_file_commits"):
                raw_commits = await scm.get_file_commits(
                    repo=repo,
                    path=file_path,
                    ref=ref,
                    limit=max_commits,
                    project_key=project_key,
                )
            else:
                self.log.warning(
                    "archaeologist.scm_no_file_commits",
                    scm_type=type(scm).__name__,
                )
                return []
        except Exception as exc:  # noqa: BLE001
            self.log.warning(
                "archaeologist.commit_log_fetch_failed",
                repo=repo,
                file=file_path,
                error=str(exc),
            )
            return []

        # Normalise into a flat structure suitable for Claude.
        commits: list[dict[str, Any]] = []
        for c in raw_commits[:max_commits]:
            commits.append({
                "sha":          c.get("hash") or c.get("sha") or c.get("id", ""),
                "author_name":  (
                    c.get("author", {}).get("user", {}).get("displayName")
                    or c.get("commit", {}).get("author", {}).get("name", "")
                    or c.get("author_name", "")
                ),
                "author_email": (
                    c.get("author", {}).get("user", {}).get("emailAddress")
                    or c.get("commit", {}).get("author", {}).get("email", "")
                    or c.get("author_email", "")
                ),
                "date":    (
                    c.get("authorTimestamp")
                    or c.get("commit", {}).get("author", {}).get("date", "")
                    or c.get("date", "")
                ),
                "message": c.get("message", ""),
                "diff":    c.get("diff", ""),  # may be empty; SCM client should populate
            })

        self.log.debug(
            "archaeologist.commits_fetched",
            repo=repo,
            file=file_path,
            count=len(commits),
        )
        return commits

    # ------------------------------------------------------------------
    # Claude analysis
    # ------------------------------------------------------------------

    async def _analyse_history(
        self,
        repo: str,
        file_path: str,
        vulnerable_pattern: str,
        commits: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Ask Claude with adaptive thinking to analyse the commit history.

        Returns the parsed provenance dict, or a minimal fallback on error.
        """
        # Keep the prompt manageable: truncate each diff to 1,500 chars.
        summarised_commits: list[dict[str, Any]] = []
        for c in commits:
            diff_snippet = c.get("diff", "")
            if len(diff_snippet) > 1500:
                diff_snippet = diff_snippet[:1500] + "\n[diff truncated]"
            summarised_commits.append({
                "sha": c["sha"],
                "author_name": c["author_name"],
                "author_email": c["author_email"],
                "date": c["date"],
                "message": c["message"],
                "diff": diff_snippet,
            })

        user_content = f"""Repository: {repo}
File: {file_path}
Vulnerable pattern: {vulnerable_pattern}

Git log (most recent first, up to {MAX_COMMITS} commits):
{json.dumps(summarised_commits, indent=2)}

Return the provenance JSON now."""

        try:
            text = await self._call_claude(
                system=self._SYSTEM,
                messages=[{"role": "user", "content": user_content}],
                max_tokens=4096,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.error("archaeologist.claude_failed", error=str(exc))
            return self._empty_provenance(reason="Claude call failed")

        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            provenance = json.loads(text)
            self.log.debug(
                "archaeologist.provenance_parsed",
                introduction_commit=provenance.get("introduction_commit"),
                was_regression=provenance.get("was_regression"),
                confidence=provenance.get("confidence"),
            )
            return provenance
        except json.JSONDecodeError as exc:
            self.log.error(
                "archaeologist.json_parse_failed",
                error=str(exc),
                raw=text[:300],
            )
            return self._empty_provenance(reason="JSON parse failed")

    @staticmethod
    def _empty_provenance(reason: str = "") -> dict[str, Any]:
        return {
            "introduction_commit": None,
            "introduction_date": None,
            "author_name": None,
            "author_email": None,
            "was_intentional": None,
            "intentionality_reasoning": reason,
            "was_regression": False,
            "prior_fix_sha": None,
            "regression_reasoning": reason,
            "confidence": "LOW",
        }

    # ------------------------------------------------------------------
    # SCM helper
    # ------------------------------------------------------------------

    def _get_scm_client(self) -> Any | None:
        if self.memory is not None and hasattr(self.memory, "scm_client"):
            return self.memory.scm_client
        return None
