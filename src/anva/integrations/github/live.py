"""GitHub REST implementation used only by the dedicated provider worker."""

from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPResponse
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt

from anva.integrations.github.client import (
    AmbiguousGitHubWriteError,
    GitHubClientError,
    GitHubRateLimitError,
    GitHubWriteResult,
    PullRequestSnapshot,
    RepositoryReference,
)

API_VERSION = "2022-11-28"
USER_AGENT = "Anva-GitHub-App/0.1"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 1_200_000
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MIN_TOKEN_LIFETIME_SECONDS = 30
MAX_TOKEN_LIFETIME_SECONDS = 65 * 60
FULL_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
INSTALLATION_TOKEN_PATTERN = re.compile(r"ghs_[A-Za-z0-9_]{20,251}")


@dataclass(frozen=True, slots=True)
class GitHubAppCredentials:
    """File-backed App key and public configuration for one worker process."""

    app_id: int
    app_slug: str
    private_key_path: Path
    api_base_url: str = "https://api.github.com"
    timeout_seconds: int = 15


class _RejectRedirects(HTTPRedirectHandler):
    """Fail every redirect so a bearer credential is never replayed to another hop."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None


def _open_url(request: Request, *, timeout: int) -> HTTPResponse:
    """Open one exact-origin request without following same- or cross-origin redirects."""
    opener = build_opener(_RejectRedirects())
    return cast(HTTPResponse, opener.open(request, timeout=timeout))


class LiveGitHubClient:
    """Short-lived installation-token client with bounded, validated requests."""

    def __init__(self, *, credentials: GitHubAppCredentials, installation_id: int) -> None:
        if credentials.app_id < 1 or installation_id < 1:
            raise ValueError("GitHub App and installation IDs must be positive")
        if not re.fullmatch(r"[A-Za-z0-9-]{1,100}", credentials.app_slug):
            raise ValueError("GitHub App slug is invalid")
        if credentials.api_base_url.rstrip("/") != "https://api.github.com":
            raise ValueError("Only the public GitHub API origin is supported")
        self._credentials = credentials
        self._installation_id = installation_id

    def get_pull_request(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> PullRequestSnapshot:
        payload = self._json_request(
            method="GET",
            path=f"{self._repo_path(repository)}/pulls/{pull_request_number}",
            repository=repository,
        )
        head = _object(payload, "head")
        base = _object(payload, "base")
        head_repo = _object(head, "repo")
        base_repo = _object(base, "repo")
        return PullRequestSnapshot(
            external_id=_positive_int(payload, "id"),
            number=_positive_int(payload, "number"),
            base_commit=_commit(base, "sha"),
            head_commit=_commit(head, "sha"),
            title=_bounded_string(payload, "title", 1_000),
            description=_optional_bounded_string(payload, "body", 50_000),
            target_branch=_bounded_string(base, "ref", 300),
            is_draft=_boolean(payload, "draft"),
            state=_bounded_string(payload, "state", 16).upper(),
            merged=bool(payload.get("merged", False)),
            head_repository_id=_positive_int(head_repo, "id"),
            head_ref=_bounded_string(head, "ref", 300),
            is_fork=_positive_int(head_repo, "id") != _positive_int(base_repo, "id"),
        )

    def get_pull_request_diff(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> str:
        raw = self._request(
            method="GET",
            path=f"{self._repo_path(repository)}/pulls/{pull_request_number}",
            repository=repository,
            accept="application/vnd.github.v3.diff",
            max_bytes=MAX_DIFF_BYTES,
        )
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise GitHubClientError("github_diff_encoding_invalid", transient=False) from None

    def upsert_check(
        self,
        *,
        repository: RepositoryReference,
        head_commit: str,
        check_name: str,
        payload: dict[str, object],
        external_id: str,
        idempotency_key: str,
    ) -> GitHubWriteResult:
        del idempotency_key
        check_id = external_id or self._find_check(
            repository=repository,
            head_commit=head_commit,
            check_name=check_name,
        )
        request_payload = {
            "name": check_name,
            "head_sha": head_commit,
            **payload,
        }
        method = "PATCH" if check_id else "POST"
        suffix = f"/check-runs/{check_id}" if check_id else "/check-runs"
        result = self._json_request(
            method=method,
            path=f"{self._repo_path(repository)}{suffix}",
            repository=repository,
            payload=request_payload,
            accept="application/vnd.github+json",
            ambiguous_write=True,
        )
        return GitHubWriteResult(
            external_id=str(_positive_int(result, "id")),
            external_url=_optional_bounded_string(result, "html_url", 2_000),
        )

    def upsert_comment(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
        marker_prefix: str,
        body: str,
        external_id: str,
        idempotency_key: str,
    ) -> GitHubWriteResult:
        del idempotency_key
        comment_id = external_id or self._find_comment(
            repository=repository,
            pull_request_number=pull_request_number,
            marker_prefix=marker_prefix,
        )
        method = "PATCH" if comment_id else "POST"
        suffix = (
            f"/issues/comments/{comment_id}"
            if comment_id
            else f"/issues/{pull_request_number}/comments"
        )
        result = self._json_request(
            method=method,
            path=f"{self._repo_path(repository)}{suffix}",
            repository=repository,
            payload={"body": body},
            ambiguous_write=True,
        )
        return GitHubWriteResult(
            external_id=str(_positive_int(result, "id")),
            external_url=_optional_bounded_string(result, "html_url", 2_000),
        )

    def _find_check(
        self,
        *,
        repository: RepositoryReference,
        head_commit: str,
        check_name: str,
    ) -> str:
        query = urlencode({"check_name": check_name, "per_page": 100})
        result = self._json_request(
            method="GET",
            path=f"{self._repo_path(repository)}/commits/{head_commit}/check-runs?{query}",
            repository=repository,
        )
        rows = result.get("check_runs")
        if not isinstance(rows, list) or len(rows) > 100:
            raise GitHubClientError("github_check_list_invalid", transient=False)
        matches: list[int] = []
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            app = raw.get("app")
            if (
                raw.get("name") == check_name
                and isinstance(app, dict)
                and app.get("id") == self._credentials.app_id
            ):
                matches.append(_positive_int(cast(dict[str, object], raw), "id"))
        if len(matches) > 1:
            raise GitHubClientError("github_check_identity_ambiguous", transient=False)
        return str(matches[0]) if matches else ""

    def _find_comment(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
        marker_prefix: str,
    ) -> str:
        result = self._json_request(
            method="GET",
            path=(
                f"{self._repo_path(repository)}/issues/{pull_request_number}/comments?per_page=100"
            ),
            repository=repository,
            expect_array=True,
        )
        rows = cast(list[object], result["items"])
        bot_login = f"{self._credentials.app_slug}[bot]"
        matches: list[int] = []
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            user = raw.get("user")
            body = raw.get("body")
            if (
                isinstance(user, dict)
                and user.get("login") == bot_login
                and isinstance(body, str)
                and body.startswith(marker_prefix)
            ):
                matches.append(_positive_int(cast(dict[str, object], raw), "id"))
        if len(matches) > 1:
            raise GitHubClientError("github_comment_identity_ambiguous", transient=False)
        return str(matches[0]) if matches else ""

    def _repo_path(self, repository: RepositoryReference) -> str:
        if repository.external_id < 1 or not FULL_NAME_PATTERN.fullmatch(repository.full_name):
            raise GitHubClientError("github_repository_binding_invalid", transient=False)
        owner, name = repository.full_name.split("/", 1)
        return f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"

    def _json_request(
        self,
        *,
        method: str,
        path: str,
        repository: RepositoryReference,
        payload: dict[str, object] | None = None,
        accept: str = "application/vnd.github+json",
        ambiguous_write: bool = False,
        expect_array: bool = False,
    ) -> dict[str, object]:
        raw = self._request(
            method=method,
            path=path,
            repository=repository,
            payload=payload,
            accept=accept,
            max_bytes=MAX_RESPONSE_BYTES,
            ambiguous_write=ambiguous_write,
        )
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            raise GitHubClientError("github_response_invalid", transient=False) from None
        if expect_array:
            if not isinstance(parsed, list) or len(parsed) > 100:
                raise GitHubClientError("github_response_invalid", transient=False)
            return {"items": parsed}
        if not isinstance(parsed, dict):
            raise GitHubClientError("github_response_invalid", transient=False)
        return cast(dict[str, object], parsed)

    def _request(
        self,
        *,
        method: str,
        path: str,
        repository: RepositoryReference,
        accept: str,
        max_bytes: int,
        payload: dict[str, object] | None = None,
        ambiguous_write: bool = False,
    ) -> bytes:
        token = self._installation_token(repository.external_id)
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = Request(  # noqa: S310 - origin and path are validated constants/bindings
            f"{self._credentials.api_base_url.rstrip('/')}{path}",
            data=body,
            method=method,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with _open_url(request, timeout=self._credentials.timeout_seconds) as response:
                raw = response.read(max_bytes + 1)
        except HTTPError as error:
            self._raise_http(error)
        except (TimeoutError, URLError):
            if ambiguous_write and method in {"POST", "PATCH"}:
                raise AmbiguousGitHubWriteError() from None
            raise GitHubClientError("github_network_unavailable", transient=True) from None
        if len(raw) > max_bytes:
            raise GitHubClientError("github_response_too_large", transient=False)
        return raw

    def _installation_token(self, repository_id: int) -> str:
        now = int(time.time())
        private_key = _read_private_key(self._credentials.private_key_path)
        app_jwt = jwt.encode(
            {"iat": now - 30, "exp": now + 540, "iss": str(self._credentials.app_id)},
            private_key,
            algorithm="RS256",
        )
        payload = json.dumps(
            {
                "repository_ids": [repository_id],
                "permissions": {
                    "actions": "read",
                    "checks": "write",
                    "contents": "read",
                    "issues": "write",
                    "pull_requests": "read",
                },
            },
            separators=(",", ":"),
        ).encode()
        request = Request(  # noqa: S310 - fixed GitHub API origin
            (
                f"{self._credentials.api_base_url.rstrip('/')}/app/installations/"
                f"{self._installation_id}/access_tokens"
            ),
            data=payload,
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {app_jwt}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with _open_url(request, timeout=self._credentials.timeout_seconds) as response:
                raw = response.read(64 * 1024 + 1)
        except HTTPError as error:
            self._raise_http(error)
        except (TimeoutError, URLError):
            raise GitHubClientError("github_token_unavailable", transient=True) from None
        if len(raw) > 64 * 1024:
            raise GitHubClientError("github_token_response_too_large", transient=False)
        try:
            response_payload = json.loads(raw)
        except json.JSONDecodeError:
            raise GitHubClientError("github_token_response_invalid", transient=False) from None
        if not isinstance(response_payload, dict):
            raise GitHubClientError("github_token_response_invalid", transient=False)
        token = response_payload.get("token")
        expires_at = response_payload.get("expires_at")
        if (
            not isinstance(token, str)
            or INSTALLATION_TOKEN_PATTERN.fullmatch(token) is None
            or not isinstance(expires_at, str)
        ):
            raise GitHubClientError("github_token_response_invalid", transient=False)
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise GitHubClientError("github_token_response_invalid", transient=False) from None
        if expiry.tzinfo is None:
            raise GitHubClientError("github_token_response_invalid", transient=False)
        lifetime_seconds = (expiry - datetime.now(UTC)).total_seconds()
        if not MIN_TOKEN_LIFETIME_SECONDS <= lifetime_seconds <= MAX_TOKEN_LIFETIME_SECONDS:
            raise GitHubClientError("github_token_response_invalid", transient=False)
        return token

    def _raise_http(self, error: HTTPError) -> None:
        request_id = str(error.headers.get("X-GitHub-Request-Id", ""))[:100]
        retry_after = error.headers.get("Retry-After")
        remaining = error.headers.get("X-RateLimit-Remaining")
        reset = error.headers.get("X-RateLimit-Reset")
        if error.code == 429 or (
            error.code == 403 and (retry_after is not None or remaining == "0")
        ):
            seconds = 60
            if retry_after is not None and retry_after.isdigit():
                seconds = int(retry_after)
            elif reset is not None and reset.isdigit():
                seconds = max(1, int(reset) - int(time.time()))
            raise GitHubRateLimitError(
                retry_after_seconds=seconds,
                request_id=request_id,
            ) from None
        if error.code >= 500:
            raise GitHubClientError(
                "github_server_error",
                transient=True,
                request_id=request_id,
            ) from None
        raise GitHubClientError(
            f"github_http_{error.code}",
            transient=False,
            request_id=request_id,
        ) from None


def _read_private_key(path: Path) -> str:
    """Read one bounded regular key without following a replacement symlink."""
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 1
            or metadata.st_size > MAX_PRIVATE_KEY_BYTES
        ):
            raise OSError("GitHub App private key file is invalid")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_PRIVATE_KEY_BYTES + 1)
    except OSError:
        raise GitHubClientError("github_private_key_unavailable", transient=False) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > MAX_PRIVATE_KEY_BYTES:
        raise GitHubClientError("github_private_key_unavailable", transient=False)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise GitHubClientError("github_private_key_unavailable", transient=False) from None


def _object(payload: dict[str, object], name: str) -> dict[str, object]:
    value = payload.get(name)
    if not isinstance(value, dict):
        raise GitHubClientError("github_response_invalid", transient=False)
    return cast(dict[str, object], value)


def _positive_int(payload: dict[str, object], name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise GitHubClientError("github_response_invalid", transient=False)
    return value


def _bounded_string(payload: dict[str, object], name: str, maximum: int) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise GitHubClientError("github_response_invalid", transient=False)
    return value


def _optional_bounded_string(payload: dict[str, object], name: str, maximum: int) -> str:
    value = payload.get(name)
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > maximum:
        raise GitHubClientError("github_response_invalid", transient=False)
    return value


def _boolean(payload: dict[str, object], name: str) -> bool:
    value = payload.get(name)
    if not isinstance(value, bool):
        raise GitHubClientError("github_response_invalid", transient=False)
    return value


def _commit(payload: dict[str, object], name: str) -> str:
    value = _bounded_string(payload, name, 40)
    if re.fullmatch(r"[a-f0-9]{40}", value) is None:
        raise GitHubClientError("github_response_invalid", transient=False)
    return value
