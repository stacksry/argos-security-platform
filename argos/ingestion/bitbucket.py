"""
argos/ingestion/bitbucket.py

Async Bitbucket client supporting both Cloud (REST v2.0) and Data Center (REST v1.0).

Cloud auth   : Bearer token via Authorization header.
DC auth      : Personal access token via Authorization header (same Bearer scheme).

URL patterns:
  Cloud  : https://api.bitbucket.org/2.0/repositories/{workspace}/{repo}/...
  DC     : https://{host}/rest/api/1.0/projects/{project}/repos/{repo}/...
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_CLOUD_MODE = "cloud"
_DC_MODE = "datacenter"

_RATE_LIMIT_STATUS = 429
_MAX_RETRIES = 5
_BACKOFF_BASE = 1.5  # seconds


@dataclass
class BitbucketConfig:
    """
    Configuration for the Bitbucket client.

    Args:
        mode: "cloud" or "datacenter"
        base_url: Root URL for the API.
                  Cloud example    : "https://api.bitbucket.org/2.0"
                  DC example       : "https://bitbucket.mycompany.com"
        token: Bearer / personal-access token.
        workspace: Bitbucket Cloud workspace slug (ignored in DC mode).
    """

    mode: str  # "cloud" | "datacenter"
    base_url: str
    token: str
    workspace: str = ""

    def __post_init__(self) -> None:
        if self.mode not in (_CLOUD_MODE, _DC_MODE):
            raise ValueError(f"mode must be 'cloud' or 'datacenter', got: {self.mode!r}")
        if self.mode == _CLOUD_MODE and not self.workspace:
            raise ValueError("workspace is required for cloud mode")
        # Strip trailing slash so URL joins are consistent.
        self.base_url = self.base_url.rstrip("/")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_cloud(cfg: BitbucketConfig) -> bool:
    return cfg.mode == _CLOUD_MODE


def _repo_base_url(cfg: BitbucketConfig, repo: str, project_key: str = "") -> str:
    """Return the base URL for a specific repository."""
    if _is_cloud(cfg):
        return f"{cfg.base_url}/repositories/{cfg.workspace}/{repo}"
    # In DC, project_key is mandatory; fall back to a placeholder if callers omit it.
    proj = project_key or "UNKNOWN"
    return f"{cfg.base_url}/rest/api/1.0/projects/{proj}/repos/{repo}"


def _repos_list_url(cfg: BitbucketConfig, project_key: str = "") -> str:
    """Return the URL used to enumerate repositories."""
    if _is_cloud(cfg):
        return f"{cfg.base_url}/repositories/{cfg.workspace}"
    proj = project_key or ""
    if proj:
        return f"{cfg.base_url}/rest/api/1.0/projects/{proj}/repos"
    return f"{cfg.base_url}/rest/api/1.0/repos"


def _projects_url(cfg: BitbucketConfig) -> str:
    if _is_cloud(cfg):
        return f"{cfg.base_url}/workspaces/{cfg.workspace}/projects"
    return f"{cfg.base_url}/rest/api/1.0/projects"


# ---------------------------------------------------------------------------
# BitbucketClient
# ---------------------------------------------------------------------------


class BitbucketClient:
    """
    Async client for Bitbucket Cloud (REST v2.0) and Data Center (REST v1.0).

    Usage::

        cfg = BitbucketConfig(mode="cloud", base_url="https://api.bitbucket.org/2.0",
                              token="...", workspace="myworkspace")
        async with BitbucketClient(cfg) as client:
            repos = await client.list_repos()

    The client handles 429 rate-limit responses with exponential back-off and
    supports async context-manager usage so the underlying ``httpx.AsyncClient``
    is cleanly closed.
    """

    def __init__(self, config: BitbucketConfig, timeout: float = 30.0) -> None:
        self._cfg = config
        self._timeout = timeout
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "BitbucketClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Internal HTTP layer
    # ------------------------------------------------------------------

    async def _ensure_client(self) -> None:
        if self._http is None:
            headers = {
                "Authorization": f"Bearer {self._cfg.token}",
                "Accept": "application/json",
            }
            self._http = httpx.AsyncClient(
                headers=headers,
                timeout=self._timeout,
                follow_redirects=True,
            )

    async def _get(
        self,
        url: str,
        params: dict | None = None,
        accept_bytes: bool = False,
    ) -> httpx.Response:
        """GET with retry / exponential back-off on 429."""
        await self._ensure_client()
        assert self._http is not None

        for attempt in range(1, _MAX_RETRIES + 1):
            log.debug("bitbucket.get", url=url, params=params, attempt=attempt)
            resp = await self._http.get(url, params=params)

            if resp.status_code == _RATE_LIMIT_STATUS:
                retry_after = float(resp.headers.get("Retry-After", _BACKOFF_BASE ** attempt))
                log.warning(
                    "bitbucket.rate_limited",
                    url=url,
                    retry_after=retry_after,
                    attempt=attempt,
                )
                await asyncio.sleep(retry_after)
                continue

            resp.raise_for_status()
            return resp

        raise RuntimeError(f"Exceeded {_MAX_RETRIES} retries for GET {url}")

    async def _post(self, url: str, json: dict) -> httpx.Response:
        """POST with retry / exponential back-off on 429."""
        await self._ensure_client()
        assert self._http is not None

        for attempt in range(1, _MAX_RETRIES + 1):
            log.debug("bitbucket.post", url=url, attempt=attempt)
            resp = await self._http.post(url, json=json)

            if resp.status_code == _RATE_LIMIT_STATUS:
                retry_after = float(resp.headers.get("Retry-After", _BACKOFF_BASE ** attempt))
                log.warning(
                    "bitbucket.rate_limited",
                    url=url,
                    retry_after=retry_after,
                    attempt=attempt,
                )
                await asyncio.sleep(retry_after)
                continue

            resp.raise_for_status()
            return resp

        raise RuntimeError(f"Exceeded {_MAX_RETRIES} retries for POST {url}")

    # ------------------------------------------------------------------
    # Pagination helpers
    # ------------------------------------------------------------------

    async def _paginate_cloud(self, url: str, params: dict | None = None) -> list[dict]:
        """
        Follow Bitbucket Cloud cursor-based pagination (``next`` field).
        Returns a flat list of all ``values`` items.
        """
        params = dict(params or {})
        results: list[dict] = []
        next_url: str | None = url

        while next_url:
            resp = await self._get(next_url, params=params if next_url == url else None)
            body = resp.json()
            results.extend(body.get("values", []))
            next_url = body.get("next")  # None when exhausted

        return results

    async def _paginate_dc(self, url: str, params: dict | None = None) -> list[dict]:
        """
        Follow Bitbucket DC page-based pagination (``isLastPage`` / ``nextPageStart``).
        Returns a flat list of all ``values`` items.
        """
        params = dict(params or {})
        results: list[dict] = []
        start = 0

        while True:
            params["start"] = start
            resp = await self._get(url, params=params)
            body = resp.json()
            results.extend(body.get("values", []))

            if body.get("isLastPage", True):
                break
            start = body.get("nextPageStart", start + len(body.get("values", [])))

        return results

    async def _paginate(self, url: str, params: dict | None = None) -> list[dict]:
        if _is_cloud(self._cfg):
            return await self._paginate_cloud(url, params)
        return await self._paginate_dc(url, params)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def list_projects(self) -> list[dict]:
        """
        List all projects/workspaces visible to the authenticated user.

        Cloud  : returns workspace projects.
        DC     : returns all projects.
        """
        url = _projects_url(self._cfg)
        log.info("bitbucket.list_projects", url=url)
        return await self._paginate(url)

    async def list_repos(self, project_key: str = "") -> list[dict]:
        """
        List repositories.

        Args:
            project_key: DC project key (e.g. "INFRA"). Ignored in Cloud mode.
                         When omitted in DC mode all accessible repos are returned.

        Returns:
            List of repository dicts as returned by the API.
        """
        url = _repos_list_url(self._cfg, project_key)
        log.info("bitbucket.list_repos", url=url, project_key=project_key)
        return await self._paginate(url)

    async def get_file_content(
        self,
        repo: str,
        path: str,
        ref: str = "HEAD",
        project_key: str = "",
    ) -> str | None:
        """
        Fetch the decoded text content of a file at a given ref.

        Returns None if the file does not exist (404).
        """
        try:
            raw = await self.get_raw_file(repo, path, ref=ref, project_key=project_key)
            if raw is None:
                return None
            return raw.decode("utf-8", errors="replace")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                log.warning(
                    "bitbucket.file_not_found",
                    repo=repo,
                    path=path,
                    ref=ref,
                )
                return None
            raise

    async def get_raw_file(
        self,
        repo: str,
        path: str,
        ref: str = "HEAD",
        project_key: str = "",
    ) -> bytes | None:
        """
        Fetch the raw bytes of a file at a given ref.

        Returns None if the file does not exist (404).
        """
        base = _repo_base_url(self._cfg, repo, project_key)

        if _is_cloud(self._cfg):
            # Cloud: GET /repositories/{workspace}/{repo}/src/{ref}/{path}
            url = f"{base}/src/{ref}/{path}"
            params: dict = {}
        else:
            # DC: GET /rest/api/1.0/projects/{proj}/repos/{repo}/raw/{path}?at={ref}
            url = f"{base}/raw/{path}"
            params = {"at": ref}

        log.info("bitbucket.get_raw_file", repo=repo, path=path, ref=ref)
        try:
            resp = await self._get(url, params=params, accept_bytes=True)
            return resp.content
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def get_diff(
        self,
        repo: str,
        from_sha: str,
        to_sha: str,
        project_key: str = "",
    ) -> list[str]:
        """
        Return the list of file paths changed between two commits.

        Cloud  : uses /diff/{from_sha}..{to_sha} with ``path`` extraction.
        DC     : uses /compare/changes?from={from_sha}&to={to_sha}.
        """
        base = _repo_base_url(self._cfg, repo, project_key)

        if _is_cloud(self._cfg):
            url = f"{base}/diff/{from_sha}..{to_sha}"
            resp = await self._get(url, params={"binary": "false"})
            # Cloud returns unified diff text; extract ``--- a/`` / ``+++ b/`` paths.
            changed: list[str] = []
            for line in resp.text.splitlines():
                if line.startswith("+++ b/"):
                    changed.append(line[6:])
            return list(dict.fromkeys(changed))  # deduplicate while preserving order

        else:
            # DC compare/changes endpoint returns structured JSON.
            url = f"{base}/compare/changes"
            items = await self._paginate_dc(url, params={"from": from_sha, "to": to_sha})
            return [item["path"]["toString"] for item in items if "path" in item]

    async def get_commit(
        self,
        repo: str,
        sha: str,
        project_key: str = "",
    ) -> dict:
        """Fetch metadata for a single commit."""
        base = _repo_base_url(self._cfg, repo, project_key)

        if _is_cloud(self._cfg):
            url = f"{base}/commit/{sha}"
        else:
            url = f"{base}/commits/{sha}"

        log.info("bitbucket.get_commit", repo=repo, sha=sha)
        resp = await self._get(url)
        return resp.json()

    async def create_pull_request(
        self,
        repo: str,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str = "main",
        project_key: str = "",
        reviewers: list[str] | None = None,
    ) -> dict:
        """
        Open a pull request.

        Args:
            repo: Repository slug.
            title: PR title.
            description: PR body / description.
            source_branch: Branch with changes.
            target_branch: Target (destination) branch. Defaults to "main".
            project_key: DC project key (ignored in Cloud).
            reviewers: Optional list of reviewer account IDs / usernames.

        Returns:
            The API response dict representing the created PR.
        """
        base = _repo_base_url(self._cfg, repo, project_key)

        if _is_cloud(self._cfg):
            url = f"{base}/pullrequests"
            payload: dict = {
                "title": title,
                "description": description,
                "source": {"branch": {"name": source_branch}},
                "destination": {"branch": {"name": target_branch}},
            }
            if reviewers:
                payload["reviewers"] = [{"account_id": r} for r in reviewers]
        else:
            url = f"{base}/pull-requests"
            payload = {
                "title": title,
                "description": description,
                "fromRef": {"id": f"refs/heads/{source_branch}"},
                "toRef": {"id": f"refs/heads/{target_branch}"},
            }
            if reviewers:
                payload["reviewers"] = [{"user": {"name": r}} for r in reviewers]

        log.info(
            "bitbucket.create_pr",
            repo=repo,
            source=source_branch,
            target=target_branch,
        )
        resp = await self._post(url, json=payload)
        return resp.json()

    async def search_code(
        self,
        repo: str,
        query: str,
        project_key: str = "",
    ) -> list[dict]:
        """
        Search for code within a repository.

        Cloud: Uses Bitbucket's code-search API (searches default branch only).
        DC:    Uses Bitbucket DC's code-search endpoint (default branch, no regex).

        Returns a list of match dicts as returned by the API.
        """
        log.info("bitbucket.search_code", repo=repo, query=query)

        if _is_cloud(self._cfg):
            # Cloud code-search is workspace-scoped; filter by repository.
            url = f"{self._cfg.base_url}/workspaces/{self._cfg.workspace}/search/code"
            params: dict = {
                "search_query": query,
                "repository": repo,
            }
            results = await self._paginate_cloud(url, params=params)
            return results
        else:
            # DC code-search endpoint.
            base = _repo_base_url(self._cfg, repo, project_key)
            url = f"{self._cfg.base_url}/rest/search/1.0/search"
            params = {
                "query": query,
                "scope.type": "REPOSITORY",
                "scope.project.key": project_key,
                "scope.repository.slug": repo,
            }
            results = await self._paginate_dc(url, params=params)
            return results
