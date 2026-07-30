"""Worker-only construction of live GitHub clients from isolated settings."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings

from anva.integrations.github.client import GitHubClient
from anva.integrations.github.live import GitHubAppCredentials, LiveGitHubClient


def live_client_for_installation(installation_id: int) -> GitHubClient:
    """Build a client that mints only short-lived, repository-selected tokens."""
    if not settings.ANVA_GITHUB_ENABLED:
        raise RuntimeError("GitHub integration is disabled")
    key_path = Path(str(settings.ANVA_GITHUB_APP_PRIVATE_KEY_FILE))
    if not key_path.is_absolute() or not key_path.is_file() or key_path.is_symlink():
        raise RuntimeError("GitHub App private key file is unavailable")
    credentials = GitHubAppCredentials(
        app_id=int(settings.ANVA_GITHUB_APP_ID),
        app_slug=str(settings.ANVA_GITHUB_APP_SLUG),
        private_key_path=key_path,
    )
    return LiveGitHubClient(
        credentials=credentials,
        installation_id=installation_id,
    )
