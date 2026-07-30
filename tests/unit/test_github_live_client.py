"""Unit contract for the credential-bearing public GitHub client."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest
from pytest_django.fixtures import SettingsWrapper

from anva.integrations.github.client import (
    AmbiguousGitHubWriteError,
    GitHubClientError,
    GitHubRateLimitError,
    RepositoryReference,
)
from anva.integrations.github.factory import live_client_for_installation
from anva.integrations.github.live import (
    MAX_DIFF_BYTES,
    MAX_RESPONSE_BYTES,
    GitHubAppCredentials,
    LiveGitHubClient,
)

VALID_INSTALLATION_TOKEN = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"  # noqa: S105


def _client(key_path: Path) -> LiveGitHubClient:
    return LiveGitHubClient(
        credentials=GitHubAppCredentials(
            app_id=12345,
            app_slug="anva-example",
            private_key_path=key_path,
        ),
        installation_id=67890,
    )


def _response(payload: bytes) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = payload
    return response


@contextmanager
def _http_server(
    handler: type[BaseHTTPRequestHandler],
) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.mark.unit
def test_installation_token_is_short_lived_repository_scoped_and_not_persisted(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {
            "token": VALID_INSTALLATION_TOKEN,
            "expires_at": (datetime.now(UTC) + timedelta(minutes=55)).isoformat(),
        }
    ).encode()
    client = _client(key_path)

    with (
        patch("anva.integrations.github.live.jwt.encode", return_value="app-jwt") as encode,
        patch("anva.integrations.github.live._open_url", return_value=response) as open_url,
    ):
        token = client._installation_token(24680)

    assert token == VALID_INSTALLATION_TOKEN
    encode.assert_called_once()
    claims = encode.call_args.args[0]
    assert claims["exp"] - claims["iat"] == 570
    request = open_url.call_args.args[0]
    assert request.full_url == ("https://api.github.com/app/installations/67890/access_tokens")
    assert request.get_header("Authorization") == "Bearer app-jwt"
    assert json.loads(request.data) == {
        "repository_ids": [24680],
        "permissions": {
            "actions": "read",
            "checks": "write",
            "contents": "read",
            "issues": "write",
            "pull_requests": "read",
        },
    }
    assert token not in repr(vars(client))


@pytest.mark.unit
def test_installation_token_rejects_malformed_expiry_with_safe_error(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {
            "token": VALID_INSTALLATION_TOKEN,
            "expires_at": "not-a-date",
        }
    ).encode()
    client = _client(key_path)

    with (
        patch("anva.integrations.github.live.jwt.encode", return_value="app-jwt"),
        patch("anva.integrations.github.live._open_url", return_value=response),
        pytest.raises(GitHubClientError, match="github_token_response_invalid"),
    ):
        client._installation_token(24680)


@pytest.mark.unit
def test_installation_token_rejects_oversized_private_key_before_signing(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_bytes(b"x" * (64 * 1024 + 1))
    client = _client(key_path)

    with (
        patch("anva.integrations.github.live.jwt.encode") as encode,
        pytest.raises(GitHubClientError, match="github_private_key_unavailable"),
    ):
        client._installation_token(24680)

    encode.assert_not_called()


@pytest.mark.unit
def test_comment_adoption_requires_exact_app_bot_and_marker(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    client = _client(key_path)
    repository = RepositoryReference(24680, "anva/example")
    marker = "<!-- anva:pr=internal report=assurance"
    provider_result = {
        "items": [
            {
                "id": 1,
                "body": f"{marker} commit={'a' * 40} -->",
                "user": {"login": "human-reviewer"},
            },
            {
                "id": 2,
                "body": "<!-- unrelated -->",
                "user": {"login": "anva-example[bot]"},
            },
            {
                "id": 3,
                "body": f"{marker} commit={'a' * 40} -->",
                "user": {"login": "anva-example[bot]"},
            },
        ]
    }

    with patch.object(client, "_json_request", return_value=provider_result):
        assert (
            client._find_comment(
                repository=repository,
                pull_request_number=17,
                marker_prefix=marker,
            )
            == "3"
        )


@pytest.mark.unit
def test_check_adoption_requires_same_app_name_and_exact_head_query(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    client = _client(key_path)
    repository = RepositoryReference(24680, "anva/example")
    provider_result = {
        "total_count": 3,
        "check_runs": [
            {"id": 1, "name": "Anva / Assurance", "app": {"id": 999}},
            {"id": 2, "name": "Other", "app": {"id": 12345}},
            {"id": 3, "name": "Anva / Assurance", "app": {"id": 12345}},
        ],
    }

    with patch.object(client, "_json_request", return_value=provider_result) as request:
        assert (
            client._find_check(
                repository=repository,
                head_commit="a" * 40,
                check_name="Anva / Assurance",
            )
            == "3"
        )

    assert "/commits/" + ("a" * 40) + "/check-runs?" in request.call_args.kwargs["path"]


@pytest.mark.unit
@pytest.mark.parametrize(
    "full_name",
    [
        "missing-owner",
        "../owner/repository",
        "owner/repository/extra",
        "owner%2Frepository",
    ],
)
def test_repository_binding_cannot_control_origin_or_path(
    full_name: str,
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    client = _client(key_path)

    with pytest.raises(GitHubClientError, match="github_repository_binding_invalid"):
        client._repo_path(RepositoryReference(24680, full_name))


@pytest.mark.unit
def test_live_client_rejects_configurable_non_public_github_origin(tmp_path: Path) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")

    with pytest.raises(ValueError, match="public GitHub"):
        LiveGitHubClient(
            credentials=GitHubAppCredentials(
                app_id=12345,
                app_slug="anva-example",
                private_key_path=key_path,
                api_base_url="https://attacker.example",
            ),
            installation_id=67890,
        )


@pytest.mark.unit
def test_live_client_factory_rejects_symlinked_private_key(
    tmp_path: Path,
    settings: SettingsWrapper,
) -> None:
    target = tmp_path / "github-app.pem"
    target.write_text("synthetic-private-key")
    linked = tmp_path / "linked.pem"
    linked.symlink_to(target)
    settings.ANVA_GITHUB_ENABLED = True
    settings.ANVA_GITHUB_APP_ID = 12345
    settings.ANVA_GITHUB_APP_SLUG = "anva-example"
    settings.ANVA_GITHUB_APP_PRIVATE_KEY_FILE = str(linked)

    with pytest.raises(RuntimeError, match="unavailable"):
        live_client_for_installation(67890)


@pytest.mark.unit
def test_live_client_maps_bounded_pull_request_provider_truth(tmp_path: Path) -> None:
    client = _client(tmp_path / "github-app.pem")
    repository = RepositoryReference(24680, "anva/example")
    provider_payload: dict[str, object] = {
        "id": 123,
        "number": 17,
        "title": "Keep the exact head",
        "body": None,
        "draft": False,
        "state": "open",
        "merged": False,
        "head": {
            "sha": "a" * 40,
            "ref": "feature",
            "repo": {"id": 999},
        },
        "base": {
            "sha": "b" * 40,
            "ref": "main",
            "repo": {"id": 24680},
        },
    }

    with patch.object(client, "_json_request", return_value=provider_payload) as request:
        snapshot = client.get_pull_request(
            repository=repository,
            pull_request_number=17,
        )

    assert snapshot.external_id == 123
    assert snapshot.head_commit == "a" * 40
    assert snapshot.base_commit == "b" * 40
    assert snapshot.description == ""
    assert snapshot.is_fork is True
    assert request.call_args.kwargs["path"] == "/repos/anva/example/pulls/17"


@pytest.mark.unit
def test_live_client_decodes_only_utf8_pull_request_diffs(tmp_path: Path) -> None:
    client = _client(tmp_path / "github-app.pem")
    repository = RepositoryReference(24680, "anva/example")

    with patch.object(client, "_request", return_value=b"diff --git a/a b/a") as request:
        assert (
            client.get_pull_request_diff(
                repository=repository,
                pull_request_number=17,
            )
            == "diff --git a/a b/a"
        )

    assert request.call_args.kwargs["max_bytes"] == MAX_DIFF_BYTES
    with (
        patch.object(client, "_request", return_value=b"\xff"),
        pytest.raises(GitHubClientError, match="github_diff_encoding_invalid"),
    ):
        client.get_pull_request_diff(repository=repository, pull_request_number=17)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("external_id", "adopted_id", "expected_method", "expected_suffix"),
    [
        ("55", "", "PATCH", "/check-runs/55"),
        ("", "", "POST", "/check-runs"),
    ],
)
def test_live_client_updates_or_creates_exact_head_check(
    external_id: str,
    adopted_id: str,
    expected_method: str,
    expected_suffix: str,
    tmp_path: Path,
) -> None:
    client = _client(tmp_path / "github-app.pem")
    repository = RepositoryReference(24680, "anva/example")
    with (
        patch.object(client, "_find_check", return_value=adopted_id) as find,
        patch.object(
            client,
            "_json_request",
            return_value={"id": 77, "html_url": "https://github.com/anva/example/runs/77"},
        ) as request,
    ):
        result = client.upsert_check(
            repository=repository,
            head_commit="a" * 40,
            check_name="Anva / Assurance",
            payload={"status": "completed"},
            external_id=external_id,
            idempotency_key="intent",
        )

    assert result.external_id == "77"
    assert request.call_args.kwargs["method"] == expected_method
    assert request.call_args.kwargs["path"].endswith(expected_suffix)
    assert request.call_args.kwargs["ambiguous_write"] is True
    if external_id:
        find.assert_not_called()
    else:
        find.assert_called_once()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("external_id", "adopted_id", "expected_method", "expected_suffix"),
    [
        ("88", "", "PATCH", "/issues/comments/88"),
        ("", "", "POST", "/issues/17/comments"),
    ],
)
def test_live_client_updates_or_creates_marker_comment(
    external_id: str,
    adopted_id: str,
    expected_method: str,
    expected_suffix: str,
    tmp_path: Path,
) -> None:
    client = _client(tmp_path / "github-app.pem")
    repository = RepositoryReference(24680, "anva/example")
    with (
        patch.object(client, "_find_comment", return_value=adopted_id) as find,
        patch.object(client, "_json_request", return_value={"id": 91}) as request,
    ):
        result = client.upsert_comment(
            repository=repository,
            pull_request_number=17,
            marker_prefix="<!-- anva:",
            body="<!-- anva: --> report",
            external_id=external_id,
            idempotency_key="intent",
        )

    assert result.external_id == "91"
    assert result.external_url == ""
    assert request.call_args.kwargs["method"] == expected_method
    assert request.call_args.kwargs["path"].endswith(expected_suffix)
    if external_id:
        find.assert_not_called()
    else:
        find.assert_called_once()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expect_array"),
    [
        (b"not-json", False),
        (b"[]", False),
        (b"{}", True),
        (json.dumps([{}] * 101).encode(), True),
    ],
)
def test_live_client_rejects_malformed_or_unbounded_json_responses(
    raw: bytes,
    expect_array: bool,
    tmp_path: Path,
) -> None:
    client = _client(tmp_path / "github-app.pem")
    with (
        patch.object(client, "_request", return_value=raw),
        pytest.raises(GitHubClientError, match="github_response_invalid"),
    ):
        client._json_request(
            method="GET",
            path="/repos/anva/example",
            repository=RepositoryReference(24680, "anva/example"),
            expect_array=expect_array,
        )


@pytest.mark.unit
def test_live_client_bounds_response_and_classifies_uncertain_writes(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path / "github-app.pem")
    repository = RepositoryReference(24680, "anva/example")

    with (
        patch.object(client, "_installation_token", return_value="short-lived-token"),
        patch(
            "anva.integrations.github.live._open_url",
            return_value=_response(b"x" * (MAX_RESPONSE_BYTES + 1)),
        ),
        pytest.raises(GitHubClientError, match="github_response_too_large"),
    ):
        client._request(
            method="GET",
            path="/repos/anva/example/check-runs",
            repository=repository,
            accept="application/json",
            max_bytes=MAX_RESPONSE_BYTES,
        )

    with (
        patch.object(client, "_installation_token", return_value="short-lived-token"),
        patch(
            "anva.integrations.github.live._open_url",
            side_effect=URLError("unavailable"),
        ),
        pytest.raises(GitHubClientError, match="github_network_unavailable"),
    ):
        client._request(
            method="GET",
            path="/repos/anva/example/check-runs",
            repository=repository,
            accept="application/json",
            max_bytes=MAX_RESPONSE_BYTES,
        )

    with (
        patch.object(client, "_installation_token", return_value="short-lived-token"),
        patch(
            "anva.integrations.github.live._open_url",
            side_effect=TimeoutError(),
        ),
        pytest.raises(AmbiguousGitHubWriteError),
    ):
        client._request(
            method="POST",
            path="/repos/anva/example/check-runs",
            repository=repository,
            accept="application/json",
            max_bytes=MAX_RESPONSE_BYTES,
            payload={"status": "completed"},
            ambiguous_write=True,
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    "raw",
    [
        b"x" * (64 * 1024 + 1),
        b"not-json",
        b"[]",
        b"{}",
        json.dumps(
            {
                "token": VALID_INSTALLATION_TOKEN,
                "expires_at": "2000-01-01T00:00:00Z",
            }
        ).encode(),
        json.dumps(
            {
                "token": VALID_INSTALLATION_TOKEN,
                "expires_at": "2099-01-01T00:00:00Z",
            }
        ).encode(),
        json.dumps(
            {
                "token": VALID_INSTALLATION_TOKEN,
                "expires_at": "2099-01-01T00:00:00",
            }
        ).encode(),
    ],
)
def test_installation_token_rejects_unsafe_provider_responses(
    raw: bytes,
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    client = _client(key_path)
    with (
        patch("anva.integrations.github.live.jwt.encode", return_value="app-jwt"),
        patch("anva.integrations.github.live._open_url", return_value=_response(raw)),
        pytest.raises(GitHubClientError, match="github_token_response_(too_large|invalid)"),
    ):
        client._installation_token(24680)


@pytest.mark.unit
def test_installation_token_rejects_unsafe_token_syntax(tmp_path: Path) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    client = _client(key_path)
    raw = json.dumps(
        {
            "token": "not-a-github-token with spaces",
            "expires_at": (datetime.now(UTC) + timedelta(minutes=55)).isoformat(),
        }
    ).encode()
    with (
        patch("anva.integrations.github.live.jwt.encode", return_value="app-jwt"),
        patch("anva.integrations.github.live._open_url", return_value=_response(raw)),
        pytest.raises(GitHubClientError, match="github_token_response_invalid"),
    ):
        client._installation_token(24680)


@pytest.mark.unit
def test_installation_token_network_failure_is_transient(tmp_path: Path) -> None:
    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    client = _client(key_path)
    with (
        patch("anva.integrations.github.live.jwt.encode", return_value="app-jwt"),
        patch("anva.integrations.github.live._open_url", side_effect=TimeoutError()),
        pytest.raises(GitHubClientError, match="github_token_unavailable") as raised,
    ):
        client._installation_token(24680)

    assert raised.value.transient is True


@pytest.mark.unit
@pytest.mark.parametrize(
    ("status", "headers", "error_type", "error_code", "transient"),
    [
        (429, {"Retry-After": "7"}, GitHubRateLimitError, "github_rate_limited", True),
        (
            503,
            {"X-GitHub-Request-Id": "request-123"},
            GitHubClientError,
            "github_server_error",
            True,
        ),
        (
            404,
            {"X-GitHub-Request-Id": "request-456"},
            GitHubClientError,
            "github_http_404",
            False,
        ),
    ],
)
def test_live_client_classifies_http_failures_without_response_bodies(
    status: int,
    headers: dict[str, str],
    error_type: type[GitHubClientError],
    error_code: str,
    transient: bool,
    tmp_path: Path,
) -> None:
    client = _client(tmp_path / "github-app.pem")
    message = Message()
    for name, value in headers.items():
        message[name] = value
    error = HTTPError("https://api.github.com/fixed", status, "failure", message, None)

    with pytest.raises(error_type) as raised:
        client._raise_http(error)

    assert raised.value.code == error_code
    assert raised.value.transient is transient
    if isinstance(raised.value, GitHubRateLimitError):
        assert raised.value.retry_after_seconds == 7


@pytest.mark.unit
def test_live_client_factory_enforces_enabled_absolute_key_and_builds_client(
    tmp_path: Path,
    settings: SettingsWrapper,
) -> None:
    settings.ANVA_GITHUB_ENABLED = False
    with pytest.raises(RuntimeError, match="disabled"):
        live_client_for_installation(67890)

    key_path = tmp_path / "github-app.pem"
    key_path.write_text("synthetic-private-key")
    settings.ANVA_GITHUB_ENABLED = True
    settings.ANVA_GITHUB_APP_ID = 12345
    settings.ANVA_GITHUB_APP_SLUG = "anva-example"
    settings.ANVA_GITHUB_APP_PRIVATE_KEY_FILE = str(key_path)
    client = live_client_for_installation(67890)

    assert isinstance(client, LiveGitHubClient)


@pytest.mark.unit
def test_live_client_never_forwards_bearer_across_origin_redirect(
    tmp_path: Path,
) -> None:
    attacker_authorization: list[str | None] = []

    class AttackerHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            attacker_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format_string: str, *args: object) -> None:
            del format_string, args

    with _http_server(AttackerHandler) as attacker:
        attacker_url = f"http://127.0.0.1:{attacker.server_address[1]}/collect"

        class OriginHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", attacker_url)
                self.end_headers()

            def log_message(self, format_string: str, *args: object) -> None:
                del format_string, args

        with _http_server(OriginHandler) as origin:
            client = _client(tmp_path / "github-app.pem")
            client._credentials = GitHubAppCredentials(
                app_id=12345,
                app_slug="anva-example",
                private_key_path=tmp_path / "github-app.pem",
                api_base_url=f"http://127.0.0.1:{origin.server_address[1]}",
            )
            with (
                patch.object(
                    client,
                    "_installation_token",
                    return_value=VALID_INSTALLATION_TOKEN,
                ),
                pytest.raises(GitHubClientError, match="github_http_302"),
            ):
                client._request(
                    method="GET",
                    path="/redirect",
                    repository=RepositoryReference(24680, "anva/example"),
                    accept="application/json",
                    max_bytes=MAX_RESPONSE_BYTES,
                )

    assert attacker_authorization == []


@pytest.mark.unit
def test_live_client_deliberately_rejects_same_origin_redirects(tmp_path: Path) -> None:
    redirected_authorization: list[str | None] = []

    class SameOriginHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "/final")
                self.end_headers()
                return
            redirected_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format_string: str, *args: object) -> None:
            del format_string, args

    with _http_server(SameOriginHandler) as origin:
        client = _client(tmp_path / "github-app.pem")
        client._credentials = GitHubAppCredentials(
            app_id=12345,
            app_slug="anva-example",
            private_key_path=tmp_path / "github-app.pem",
            api_base_url=f"http://127.0.0.1:{origin.server_address[1]}",
        )
        with (
            patch.object(
                client,
                "_installation_token",
                return_value=VALID_INSTALLATION_TOKEN,
            ),
            pytest.raises(GitHubClientError, match="github_http_307"),
        ):
            client._request(
                method="GET",
                path="/redirect",
                repository=RepositoryReference(24680, "anva/example"),
                accept="application/json",
                max_bytes=MAX_RESPONSE_BYTES,
            )

    assert redirected_authorization == []
