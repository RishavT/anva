"""Security boundaries for provider code and process credentials."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import cast

import pytest
import yaml


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.add(node.module)
    return modules


@pytest.mark.unit
def test_core_services_do_not_import_github_or_network_clients() -> None:
    forbidden = {
        "http.client",
        "requests",
        "httpx",
        "socket",
        "urllib.request",
    }
    violations: list[str] = []
    for path in sorted(Path("src/anva/core/services").glob("*.py")):
        for module in _imports(path):
            if module in forbidden or module.startswith("anva.integrations.github"):
                violations.append(f"{path}:{module}")

    assert violations == []


@pytest.mark.unit
def test_compose_isolates_webhook_and_private_key_credentials_by_process() -> None:
    compose = cast(
        dict[str, object],
        yaml.safe_load(Path("compose.yaml").read_text()),
    )
    services = cast(dict[str, dict[str, object]], compose["services"])

    def environment(service: str) -> dict[str, object]:
        return cast(dict[str, object], services[service].get("environment", {}))

    api = environment("api")
    github_worker = environment("github-worker")
    assert "ANVA_GITHUB_WEBHOOK_SECRETS" in api
    assert "ANVA_GITHUB_APP_PRIVATE_KEY_FILE" not in api
    assert "ANVA_GITHUB_WEBHOOK_SECRETS" not in github_worker
    assert github_worker["ANVA_GITHUB_APP_PRIVATE_KEY_FILE"] == (
        "/run/secrets/github_app_private_key"
    )
    assert services["github-worker"]["profiles"] == ["github"]
    assert services["github-worker"]["secrets"] == ["github_app_private_key"]

    for service in ("worker", "mcp", "cli"):
        provider_variables = {
            name for name in environment(service) if name.startswith("ANVA_GITHUB_")
        }
        assert provider_variables == set()


@pytest.mark.unit
@pytest.mark.parametrize(
    "token",
    [
        "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    ],
)
def test_github_token_families_are_redacted(token: str) -> None:
    from anva.core.logging import redact_text

    rendered = redact_text(f"provider token={token}")
    assert token not in rendered
    assert "[REDACTED]" in rendered
