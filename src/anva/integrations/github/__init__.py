"""Least-privilege GitHub App boundary."""

from anva.integrations.github.client import (
    AmbiguousGitHubWriteError,
    FakeGitHubClient,
    GitHubClient,
    GitHubClientError,
    GitHubRateLimitError,
    GitHubWriteResult,
    PullRequestSnapshot,
    RepositoryReference,
)

__all__ = [
    "AmbiguousGitHubWriteError",
    "FakeGitHubClient",
    "GitHubClient",
    "GitHubClientError",
    "GitHubRateLimitError",
    "GitHubWriteResult",
    "PullRequestSnapshot",
    "RepositoryReference",
]
