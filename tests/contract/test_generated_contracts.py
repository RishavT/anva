"""Contract tests for deterministic OpenAPI, MCP, schemas, and examples."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from anva.contracts.catalog import SCHEMAS
from anva.contracts.generate import (
    check_artifacts,
    mcp_document,
    openapi_document,
    rendered_artifacts,
    validate_catalog,
)
from anva.mcp.contracts import TOOL_BY_NAME


def _mcp_request_schema(document: dict[str, object]) -> dict[str, object]:
    paths = cast(dict[str, object], document["paths"])
    operation = cast(
        dict[str, object],
        cast(dict[str, object], paths["/mcp/tools/{tool_name}"])["post"],
    )
    request_body = cast(dict[str, object], operation["requestBody"])
    content = cast(dict[str, object], request_body["content"])
    media_type = cast(dict[str, object], content["application/json"])
    return cast(dict[str, object], media_type["schema"])


@pytest.mark.contract
def test_contract_catalog_and_checked_in_generation_are_current() -> None:
    validate_catalog()
    first = rendered_artifacts()
    second = rendered_artifacts()

    assert first == second
    assert len(first) == 24
    check_artifacts(first)


@pytest.mark.contract
def test_openapi_and_mcp_share_the_canonical_schemas() -> None:
    openapi = openapi_document()
    mcp = mcp_document()
    components = cast(dict[str, object], openapi["components"])
    tools = cast(list[dict[str, object]], mcp["tools"])

    assert openapi["openapi"] == "3.1.0"
    schemas = cast(dict[str, object], components["schemas"])
    assert {name: schemas[name] for name in SCHEMAS} == SCHEMAS
    assert components["securitySchemes"] == {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "AnvaRepositoryToken",
        },
        "browserSession": {
            "type": "apiKey",
            "in": "cookie",
            "name": "sessionid",
            "description": (
                "Recently authenticated human browser session; unsafe requests also "
                "require Django's X-CSRFToken header."
            ),
        },
    }
    assert mcp["contract_version"] == "1"
    assert [tool["name"] for tool in tools] == [
        "anva.resolve_repository",
        "anva.resolve_work_item",
        "anva.get_context_packet",
        "anva.search",
        "anva.get_entity",
        "anva.get_relationships",
        "anva.get_repository_profile",
        "anva.get_policy_bundle",
        "anva.get_requirements",
        "anva.explain_assertion",
        "anva.get_source_excerpt",
        "anva.propose_correction",
        "anva.propose_relationship",
        "anva.propose_decision",
        "anva.submit_work_summary",
        "anva.submit_preflight_summary",
    ]


@pytest.mark.contract
def test_openapi_mcp_request_schema_resolves_recursive_bounded_payloads() -> None:
    payload: dict[str, object] = {
        "contract_version": "1",
        "repository_id": "00000000-0000-4000-8000-000000000009",
        "access_scope_id": "00000000-0000-4000-8000-000000000010",
        "summary": "Correct recursively nested knowledge.",
        "source_references": [
            {
                "kind": "ASSERTION",
                "id": "00000000-0000-4000-8000-000000000011",
            }
        ],
        "idempotency_key": "recursive-openapi-proposal",
        "assertion_id": "00000000-0000-4000-8000-000000000011",
        "correction": {
            "nested": [
                {
                    "deeper": {
                        "value": "bounded",
                    }
                }
            ]
        },
    }
    generated_schema = _mcp_request_schema(openapi_document())
    checked_document = cast(
        dict[str, object],
        json.loads(Path("contracts/openapi/v1/openapi.json").read_text()),
    )
    checked_schema = _mcp_request_schema(checked_document)

    Draft202012Validator.check_schema(generated_schema)
    Draft202012Validator(generated_schema).validate(payload)
    Draft202012Validator(checked_schema).validate(payload)
    Draft202012Validator(TOOL_BY_NAME["anva.propose_correction"]["input_schema"]).validate(payload)
    assert checked_schema == generated_schema

    oversized = {
        **payload,
        "correction": {
            "nested": {f"key_{index}": index for index in range(101)},
        },
    }
    with pytest.raises(ValidationError):
        Draft202012Validator(generated_schema).validate(oversized)


@pytest.mark.contract
def test_external_contracts_never_expose_legacy_brain_sources() -> None:
    rendered = json.dumps(
        {
            "schemas": SCHEMAS,
            "openapi": openapi_document(),
            "mcp": mcp_document(),
        }
    )

    assert "brain_sources" not in rendered
    assert "anva_sources" in rendered


@pytest.mark.contract
def test_openapi_exposes_versioned_tenancy_and_authorization_boundaries() -> None:
    paths = cast(dict[str, object], openapi_document()["paths"])

    assert {
        "/bootstrap",
        "/organizations/{organization_id}",
        "/organizations/{organization_id}/retention-runs",
        "/organizations/{organization_id}/decommission",
        "/organizations/{organization_id}/members",
        "/organizations/{organization_id}/members/{resource_id}",
        "/repositories/{repository_id}/tokens",
        "/repositories/{repository_id}/github-binding",
        "/repositories/{repository_id}/github-binding/revoke",
        "/webhooks/github",
        "/tokens/{resource_id}/rotate",
        "/tokens/{resource_id}",
        "/search",
        "/query",
        "/context-packets",
        "/context-packets/{resource_id}",
        "/entities/{resource_id}/relationships",
        "/entities/{resource_id}/history",
        "/entities/{resource_id}/sources",
        "/assertions/{resource_id}/explanation",
        "/canvas/assertions/{resource_id}",
        "/mcp/context",
        "/mcp/diagnostics",
        "/mcp/tools/{tool_name}",
        "/artifacts/{resource_id}",
        "/work-items",
        "/work-items/import",
        "/work-items/{resource_id}",
        "/work-item-revisions/{resource_id}/approvals",
        "/work-item-revisions/{resource_id}/evidence-map",
        "/work-approvals/{resource_id}/revoke",
        "/policies",
        "/policies/import",
        "/policies/simulate",
        "/policies/{resource_id}",
        "/knowledge/assertions/{resource_id}/review",
        "/assurance-runs/{resource_id}/transition",
        "/repositories/{repository_id}/pull-requests/{pull_request_number}/manual-diff",
        "/pull-request-revisions/{resource_id}/assurance-runs",
        "/repositories/{repository_id}/evaluator-tasks/claim",
        "/evaluator-tasks/{resource_id}/submit",
        "/assurance-runs/{resource_id}",
        "/assurance-runs/{resource_id}/findings",
        "/assurance-runs/{resource_id}/report",
        "/assurance-runs/{resource_id}/post-merge-proposals",
        "/findings/{resource_id}/dismiss",
        "/policies/{resource_id}/override",
        "/repositories/{repository_id}/pull-requests/{pull_request_number}/evidence",
        "/evidence-manifests/{resource_id}",
        "/policy-overrides/{resource_id}/revoke",
        "/source-connections/filesystem",
        "/source-connections/{resource_id}",
        "/source-connections/{resource_id}/sync",
        "/source-connections/{resource_id}/resync",
        "/source-connections/{resource_id}/sync-runs",
        "/source-connections/{resource_id}/revoke",
    } <= paths.keys()
    bootstrap = cast(dict[str, object], paths["/bootstrap"])
    bootstrap_post = cast(dict[str, object], bootstrap["post"])
    assert bootstrap_post["security"] == []

    decommission = cast(dict[str, object], paths["/organizations/{organization_id}/decommission"])
    decommission_post = cast(dict[str, object], decommission["post"])
    decommission_responses = cast(dict[str, object], decommission_post["responses"])
    assert decommission_responses["403"] == {
        "description": "CSRF validation failed before domain dispatch."
    }

    for path in (
        "/work-item-revisions/{resource_id}/approvals",
        "/work-approvals/{resource_id}/revoke",
        "/work-item-revisions/{resource_id}/evidence-map",
        "/policies/simulate",
        "/policies/{resource_id}/override",
        "/policy-overrides/{resource_id}/revoke",
        "/repositories/{repository_id}/pull-requests/{pull_request_number}/manual-diff",
        "/pull-request-revisions/{resource_id}/assurance-runs",
        "/repositories/{repository_id}/evaluator-tasks/claim",
        "/evaluator-tasks/{resource_id}/submit",
        "/assurance-runs/{resource_id}/post-merge-proposals",
        "/repositories/{repository_id}/github-binding",
        "/repositories/{repository_id}/github-binding/revoke",
    ):
        operation = cast(dict[str, object], cast(dict[str, object], paths[path])["post"])
        body = cast(dict[str, object], operation["requestBody"])
        schema = cast(
            dict[str, object],
            cast(
                dict[str, object],
                cast(dict[str, object], body["content"])["application/json"],
            )["schema"],
        )
        assert schema["additionalProperties"] is False

    evaluator_result = SCHEMAS["evaluator-result"]
    properties = cast(dict[str, object], evaluator_result["properties"])
    assert "readiness" not in properties
    assert "outcome" not in properties

    simulation = cast(
        dict[str, object],
        cast(dict[str, object], paths["/policies/simulate"])["post"],
    )
    assert {"200", "201"} <= cast(dict[str, object], simulation["responses"]).keys()
    assert all(
        parameter.get("name") != "Idempotency-Key"
        for parameter in cast(list[dict[str, object]], simulation["parameters"])
    )
