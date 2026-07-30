"""Typed GitHub client boundary and deterministic, credential-free fake."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class RepositoryReference:
    """Validated provider repository identity passed only by a stored binding."""

    external_id: int
    full_name: str


@dataclass(frozen=True, slots=True)
class PullRequestSnapshot:
    """Current provider truth needed by the provider-neutral assurance service."""

    external_id: int
    number: int
    base_commit: str
    head_commit: str
    title: str
    description: str
    target_branch: str
    is_draft: bool
    state: str
    merged: bool
    head_repository_id: int
    head_ref: str
    is_fork: bool


@dataclass(frozen=True, slots=True)
class GitHubWriteResult:
    """Safe external identity returned after an idempotent write."""

    external_id: str
    external_url: str
    request_id: str = ""


class GitHubClientError(RuntimeError):
    """Safe provider failure without response bodies or credentials."""

    def __init__(
        self,
        code: str,
        *,
        transient: bool,
        retry_after_seconds: int | None = None,
        request_id: str = "",
    ) -> None:
        super().__init__(code)
        self.code = code
        self.transient = transient
        self.retry_after_seconds = retry_after_seconds
        self.request_id = request_id[:100]


class GitHubRateLimitError(GitHubClientError):
    """Provider instructed the worker to retry after a bounded delay."""

    def __init__(
        self,
        *,
        retry_after_seconds: int,
        request_id: str = "",
    ) -> None:
        super().__init__(
            "github_rate_limited",
            transient=True,
            retry_after_seconds=max(1, min(retry_after_seconds, 3_600)),
            request_id=request_id,
        )


class AmbiguousGitHubWriteError(GitHubClientError):
    """The provider may have committed the write before the response was lost."""

    def __init__(self, *, request_id: str = "") -> None:
        super().__init__(
            "github_ambiguous_write",
            transient=True,
            retry_after_seconds=1,
            request_id=request_id,
        )


class GitHubClient(Protocol):
    """Only operations used by the GitHub adapter; no credentials cross this API."""

    def get_pull_request(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> PullRequestSnapshot: ...

    def get_pull_request_diff(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> str: ...

    def upsert_check(
        self,
        *,
        repository: RepositoryReference,
        head_commit: str,
        check_name: str,
        payload: dict[str, object],
        external_id: str,
        idempotency_key: str,
    ) -> GitHubWriteResult: ...

    def upsert_comment(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
        marker_prefix: str,
        body: str,
        external_id: str,
        idempotency_key: str,
    ) -> GitHubWriteResult: ...


@dataclass(slots=True)
class _FakeFailure:
    error: GitHubClientError
    after_write: bool = False


@dataclass(slots=True)
class _FakeComment:
    external_id: str
    body: str
    authored_by_app: bool


@dataclass(slots=True)
class FakeGitHubClient:
    """Deterministic contract fake with retries and ambiguous-write adoption."""

    pull_requests: dict[tuple[int, int], PullRequestSnapshot] = field(default_factory=dict)
    diffs: dict[tuple[int, int], str] = field(default_factory=dict)
    calls: list[dict[str, object]] = field(default_factory=list)
    credential_mint_calls: int = 0
    _failures: dict[str, deque[_FakeFailure]] = field(
        default_factory=lambda: defaultdict(deque),
        repr=False,
    )
    _checks: dict[tuple[int, str, str], GitHubWriteResult] = field(
        default_factory=dict,
        repr=False,
    )
    _comments: dict[tuple[int, int], list[_FakeComment]] = field(
        default_factory=lambda: defaultdict(list),
        repr=False,
    )
    _next_external_id: int = 1

    def add_pull_request(
        self,
        *,
        repository: RepositoryReference,
        snapshot: PullRequestSnapshot,
        unified_diff: str,
    ) -> None:
        self.pull_requests[(repository.external_id, snapshot.number)] = snapshot
        self.diffs[(repository.external_id, snapshot.number)] = unified_diff

    def add_human_comment(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
        body: str,
    ) -> str:
        external_id = self._new_id()
        self._comments[(repository.external_id, pull_request_number)].append(
            _FakeComment(external_id, body, False)
        )
        return external_id

    def queue_failure(
        self,
        operation: str,
        error: GitHubClientError,
        *,
        after_write: bool = False,
    ) -> None:
        self._failures[operation].append(_FakeFailure(error, after_write))

    def get_pull_request(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> PullRequestSnapshot:
        self._raise_before("get_pull_request")
        self.calls.append(
            {
                "operation": "get_pull_request",
                "repository_id": repository.external_id,
                "pull_request_number": pull_request_number,
            }
        )
        try:
            return self.pull_requests[(repository.external_id, pull_request_number)]
        except KeyError:
            raise GitHubClientError("github_pull_request_not_found", transient=False) from None

    def get_pull_request_diff(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> str:
        self._raise_before("get_pull_request_diff")
        self.calls.append(
            {
                "operation": "get_pull_request_diff",
                "repository_id": repository.external_id,
                "pull_request_number": pull_request_number,
            }
        )
        try:
            return self.diffs[(repository.external_id, pull_request_number)]
        except KeyError:
            raise GitHubClientError("github_diff_not_found", transient=False) from None

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
        failure = self._pop_failure("upsert_check")
        if failure is not None and not failure.after_write:
            raise failure.error
        key = (repository.external_id, head_commit, check_name)
        current = self._checks.get(key)
        if external_id:
            if current is None or current.external_id != external_id:
                raise GitHubClientError("github_check_not_found", transient=False)
            result = current
        elif current is not None:
            result = current
        else:
            result = GitHubWriteResult(
                external_id=self._new_id(),
                external_url=f"https://github.invalid/checks/{self._next_external_id - 1}",
            )
        self._checks[key] = result
        self.calls.append(
            {
                "operation": "upsert_check",
                "repository_id": repository.external_id,
                "head_commit": head_commit,
                "check_name": check_name,
                "payload": payload,
                "external_id": result.external_id,
                "idempotency_key": idempotency_key,
            }
        )
        if failure is not None:
            raise failure.error
        return result

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
        failure = self._pop_failure("upsert_comment")
        if failure is not None and not failure.after_write:
            raise failure.error
        comments = self._comments[(repository.external_id, pull_request_number)]
        current = next(
            (
                comment
                for comment in comments
                if comment.authored_by_app
                and (
                    (external_id and comment.external_id == external_id)
                    or (not external_id and comment.body.startswith(marker_prefix))
                )
            ),
            None,
        )
        if current is None:
            if external_id:
                raise GitHubClientError("github_comment_not_found", transient=False)
            current = _FakeComment(self._new_id(), body, True)
            comments.append(current)
        else:
            current.body = body
        result = GitHubWriteResult(
            external_id=current.external_id,
            external_url=f"https://github.invalid/comments/{current.external_id}",
        )
        self.calls.append(
            {
                "operation": "upsert_comment",
                "repository_id": repository.external_id,
                "pull_request_number": pull_request_number,
                "marker_prefix": marker_prefix,
                "body": body,
                "external_id": current.external_id,
                "idempotency_key": idempotency_key,
            }
        )
        if failure is not None:
            raise failure.error
        return result

    @property
    def checks(self) -> tuple[GitHubWriteResult, ...]:
        return tuple(self._checks.values())

    def app_comments(
        self,
        *,
        repository: RepositoryReference,
        pull_request_number: int,
    ) -> tuple[str, ...]:
        return tuple(
            comment.body
            for comment in self._comments[(repository.external_id, pull_request_number)]
            if comment.authored_by_app
        )

    def _new_id(self) -> str:
        external_id = str(self._next_external_id)
        self._next_external_id += 1
        return external_id

    def _pop_failure(self, operation: str) -> _FakeFailure | None:
        queue = self._failures[operation]
        return queue.popleft() if queue else None

    def _raise_before(self, operation: str) -> None:
        failure = self._pop_failure(operation)
        if failure is not None:
            raise failure.error
