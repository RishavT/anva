"""Contracts for the reviewed GitHub App boundary."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.generate import openapi_document
from anva.contracts.validation import validate_payload


@pytest.mark.contract
def test_github_publication_schema_has_a_valid_canonical_example() -> None:
    schema = SCHEMAS["github-publication"]
    example = EXAMPLES["github-publication"]

    validate_payload("github-publication", example)
    assert schema["additionalProperties"] is False
    assert str(example["head_commit"]) in str(example["rendered_payload"])
    assert example["state"] == "PENDING"
    assert "token" not in str(example).lower()
    assert "authorization" not in str(example).lower()
    assert "private_key" not in str(example).lower()


@pytest.mark.contract
def test_github_openapi_surfaces_are_closed_and_webhook_is_unauthenticated() -> None:
    paths = cast(dict[str, object], openapi_document()["paths"])
    binding = cast(
        dict[str, object],
        cast(dict[str, object], paths["/repositories/{repository_id}/github-binding"])["post"],
    )
    revoke = cast(
        dict[str, object],
        cast(
            dict[str, object],
            paths["/repositories/{repository_id}/github-binding/revoke"],
        )["post"],
    )
    webhook = cast(
        dict[str, object],
        cast(dict[str, object], paths["/webhooks/github"])["post"],
    )

    binding_schema = cast(
        dict[str, object],
        cast(
            dict[str, object],
            cast(dict[str, object], binding["requestBody"])["content"],
        )["application/json"],
    )["schema"]
    revoke_schema = cast(
        dict[str, object],
        cast(
            dict[str, object],
            cast(dict[str, object], revoke["requestBody"])["content"],
        )["application/json"],
    )["schema"]
    assert cast(dict[str, object], binding_schema)["additionalProperties"] is False
    assert cast(dict[str, object], revoke_schema)["additionalProperties"] is False
    assert webhook["security"] == []
    assert webhook["servers"] == [{"url": "/"}]
    assert {"202", "400", "401", "409", "413", "503"} <= cast(
        dict[str, object], webhook["responses"]
    ).keys()


@pytest.mark.contract
def test_checked_in_github_manifest_matches_reviewed_permissions_and_events() -> None:
    manifest = yaml.safe_load(Path("deploy/github/app-manifest.yaml").read_text())

    assert manifest["public"] is False
    assert "setup_url" not in manifest
    assert "redirect_url" not in manifest
    assert manifest.get("request_oauth_on_install", False) is False
    assert manifest["hook_attributes"]["active"] is True
    assert manifest["default_permissions"] == {
        "actions": "read",
        "checks": "write",
        "contents": "read",
        "issues": "write",
        "metadata": "read",
        "pull_requests": "read",
    }
    assert set(manifest["default_events"]) == {
        "check_run",
        "check_suite",
        "installation",
        "installation_repositories",
        "pull_request",
        "repository",
        "workflow_run",
    }
    assert "administration" not in manifest["default_permissions"]
    assert "members" not in manifest["default_permissions"]
