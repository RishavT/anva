"""Public, standalone acceptance-case and operation contract coverage."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from anva.acceptance.case import acceptance_case
from anva.contracts import ContractValidationError, validate_payload
from anva.contracts.acceptance import (
    ACCEPTANCE_HTTP_OPERATION_IDS,
    CREATED_OR_REPLAYED_OPERATION_IDS,
    HTTP_OPERATION_EXAMPLES,
    validate_acceptance_http_response,
)
from anva.contracts.bootstrap_scope import acceptance_bootstrap_scope_payload
from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.generate import openapi_document, rendered_artifacts
from anva.core.services.evidence_uploads import inspect_evidence_upload
from anva.mcp.contracts import validate_tool_output

PRIVATE_FIELD_NAMES = ("private_oracle_payload", "private", "oracle")


def _operation(document: dict[str, object], operation_id: str) -> dict[str, object]:
    paths = cast(dict[str, object], document["paths"])
    for value in paths.values():
        path_item = cast(dict[str, object], value)
        for method in ("get", "post", "put", "patch", "delete"):
            candidate = path_item.get(method)
            if isinstance(candidate, dict) and candidate.get("operationId") == operation_id:
                return cast(dict[str, object], candidate)
    raise AssertionError(f"OpenAPI operation not found: {operation_id}")


def _unsafe_schema_paths(
    value: object,
    path: tuple[str | int, ...] = (),
) -> list[tuple[str | int, ...]]:
    if value is True:
        return [path]
    if not isinstance(value, dict):
        return []
    schema_type = value.get("type")
    allows_object = schema_type == "object" or (
        isinstance(schema_type, list) and "object" in schema_type
    )
    allows_array = schema_type == "array" or (
        isinstance(schema_type, list) and "array" in schema_type
    )
    found = (
        [path]
        if not value
        or (
            (allows_object or "properties" in value)
            and value.get("additionalProperties") is not False
        )
        or (allows_array and "items" not in value)
        else []
    )
    nested = list(found)
    for keyword in (
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
    ):
        children = value.get(keyword)
        if isinstance(children, dict):
            for key, child in children.items():
                nested.extend(_unsafe_schema_paths(child, (*path, keyword, key)))
    for keyword in (
        "additionalProperties",
        "unevaluatedProperties",
        "items",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
        "contentSchema",
        "unevaluatedItems",
    ):
        if keyword in value:
            nested.extend(_unsafe_schema_paths(value[keyword], (*path, keyword)))
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        children = value.get(keyword)
        if isinstance(children, list):
            for index, child in enumerate(children):
                nested.extend(_unsafe_schema_paths(child, (*path, keyword, index)))
    return nested


def _payload_object_paths(
    value: object,
    path: tuple[str | int, ...] = (),
) -> list[tuple[str | int, ...]]:
    if isinstance(value, list):
        return [
            nested
            for index, item in enumerate(value)
            for nested in _payload_object_paths(item, (*path, index))
        ]
    if not isinstance(value, dict):
        return []
    return [
        path,
        *(
            nested
            for key, item in value.items()
            for nested in _payload_object_paths(item, (*path, key))
        ),
    ]


def _payload_at_path(
    payload: dict[str, object],
    path: tuple[str | int, ...],
) -> dict[str, object]:
    value: object = payload
    for part in path:
        if isinstance(part, str):
            value = cast(dict[str, object], value)[part]
        else:
            value = cast(list[object], value)[part]
    return cast(dict[str, object], value)


def _assert_private_fields_rejected(
    schema: dict[str, object],
    example: dict[str, object],
    identity: tuple[object, ...],
) -> int:
    validator = Draft202012Validator(schema)
    validator.validate(example)
    checked = 0
    for path in _payload_object_paths(example):
        for field_name in PRIVATE_FIELD_NAMES:
            injected = deepcopy(example)
            _payload_at_path(injected, path)[field_name] = {"verdict": "must remain private"}
            assert not validator.is_valid(injected), (*identity, path, field_name)
            checked += 1
    return checked


def _mcp_input_examples() -> dict[str, dict[str, object]]:
    repository_id = "00000000-0000-4000-8000-000000000004"
    scope_id = "00000000-0000-4000-8000-000000000006"
    entity_id = "00000000-0000-4000-8000-000000000020"
    work_item_id = "00000000-0000-4000-8000-000000000021"
    root: dict[str, object] = {
        "contract_version": "1",
        "repository_id": repository_id,
    }
    proposal: dict[str, object] = {
        **root,
        "access_scope_id": scope_id,
        "summary": "Public review-only proposal.",
        "source_references": [{"kind": "ENTITY", "id": entity_id}],
        "idempotency_key": "public-proposal-example",
    }
    return {
        "anva.resolve_repository": root,
        "anva.resolve_work_item": {**root, "external_key": "ANVA-35"},
        "anva.get_context_packet": {
            **root,
            "task": "Review the public contract.",
            "phase": "ASSURANCE",
        },
        "anva.search": {**root, "query": "public contract"},
        "anva.get_entity": {**root, "entity_id": entity_id},
        "anva.get_relationships": {**root, "entity_id": entity_id},
        "anva.get_repository_profile": root,
        "anva.get_policy_bundle": root,
        "anva.get_requirements": {**root, "work_item_id": work_item_id},
        "anva.explain_assertion": {**root, "assertion_id": entity_id},
        "anva.get_source_excerpt": {**root, "chunk_id": entity_id},
        "anva.propose_correction": {
            **proposal,
            "assertion_id": entity_id,
            "correction": {"value": "Corrected public value."},
        },
        "anva.propose_relationship": {
            **proposal,
            "source_entity_id": entity_id,
            "target_entity_id": "00000000-0000-4000-8000-000000000022",
            "relationship_type": "DEPENDS_ON",
            "rationale": "Public source-backed relationship.",
        },
        "anva.propose_decision": {
            **proposal,
            "work_item_id": work_item_id,
            "title": "Use the closed public contract",
            "outcome": "Accepted for human review.",
            "rationale": "Prevents undocumented payload fields.",
        },
        "anva.submit_work_summary": {
            **proposal,
            "work_item_id": work_item_id,
            "summary_data": {"status": "complete"},
        },
        "anva.submit_preflight_summary": {
            **proposal,
            "work_item_id": work_item_id,
            "commit_sha": "a" * 40,
            "checks": [{"name": "contract-tests", "passed": True}],
            "limitations": ["Human review is still required."],
        },
    }


@pytest.mark.contract
def test_acceptance_case_is_closed_public_only_and_has_two_distinct_valid_cases() -> None:
    schema = SCHEMAS["acceptance-case"]
    first = EXAMPLES["acceptance-case"]
    second = deepcopy(first)
    second["case_id"] = "tst-009.scn-lantern"
    organization = cast(dict[str, object], second["organization"])
    organization.update(
        {
            "slug": "anva-tst-009-lantern",
            "name": "TST-009 Lantern Organization",
            "bootstrap_scope": acceptance_bootstrap_scope_payload(
                admin_email="operator@lantern.invalid",
                admin_display_name="TST-009 Lantern initiator",
                repository_external_id="github:synthetic/lantern",
                repository_name="lantern",
                initiator_name="TST-009 Lantern acceptance runner",
                reviewer_name="TST-009 Lantern independent reviewer",
                access_scope_name="TST-009 Lantern acceptance scope",
            ),
        }
    )
    change = cast(dict[str, object], second["change"])
    change.update(
        {
            "pull_request_number": 41,
            "base_commit": "1" * 40,
            "head_commit": "2" * 40,
            "affected_paths": ["src/lantern.py"],
        }
    )
    evidence = cast(dict[str, object], second["evidence"])
    evidence["scenario"] = "tst-009.scn-lantern"
    second_evidence = (
        json.dumps(
            {
                "checks": [{"name": "TESTS_PASS", "status": "PASSED"}],
                "head_sha": "2" * 40,
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    evidence["content_base64"] = base64.b64encode(second_evidence).decode()

    validator = Draft202012Validator(schema)
    validator.validate(first)
    validator.validate(second)
    for case in (first, second):
        accepted = acceptance_case(case)
        inspected = inspect_evidence_upload(
            io.BytesIO(accepted.evidence_bytes),
            content_length=len(accepted.evidence_bytes),
            expected_size=len(accepted.evidence_bytes),
            expected_sha256=hashlib.sha256(accepted.evidence_bytes).hexdigest(),
            commit_sha=cast(str, cast(dict[str, object], case["change"])["head_commit"]),
        )
        assert inspected.archive_summary["check_count"] == 1
    assert first != second

    invalid = deepcopy(first)
    invalid["expected_readiness"] = "BLOCKED"
    with pytest.raises(ValidationError):
        validator.validate(invalid)
    nested_invalid = deepcopy(first)
    cast(dict[str, object], nested_invalid["assurance"])["oracle"] = {"answer": "BLOCKED"}
    with pytest.raises(ValidationError):
        validator.validate(nested_invalid)


@pytest.mark.contract
def test_acceptance_openapi_has_strict_success_schemas_and_canonical_examples() -> None:
    document = openapi_document()
    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    standalone = {operation["operation_id"]: operation for operation in bundle["http_operations"]}
    assert len(ACCEPTANCE_HTTP_OPERATION_IDS) == 19
    for operation_id in ACCEPTANCE_HTTP_OPERATION_IDS:
        operation = _operation(document, operation_id)
        request_body = operation.get("requestBody")
        if isinstance(request_body, dict):
            content = cast(dict[str, object], request_body["content"])
            media = cast(dict[str, object], next(iter(content.values())))
            assert "schema" in media
            assert "example" in media
            standalone_request = cast(dict[str, object], standalone[operation_id]["request"])
            standalone_media = cast(
                dict[str, object],
                next(iter(cast(dict[str, object], standalone_request["content"]).values())),
            )
            assert media["example"] == standalone_media["example"]
            Draft202012Validator(cast(dict[str, object], standalone_media["schema"])).validate(
                standalone_media["example"]
            )
        responses = cast(dict[str, object], operation["responses"])
        successes = [status for status in responses if status.startswith("2")]
        assert successes
        for status in successes:
            response = cast(dict[str, object], responses[status])
            content = cast(dict[str, object], response.get("content", {}))
            assert "application/json" in content, f"{operation_id} {status}"
            media = cast(dict[str, object], content["application/json"])
            assert "schema" in media, f"{operation_id} {status}"
            assert "example" in media, f"{operation_id} {status}"
            schema = cast(dict[str, object], media["schema"])
            assert schema
            standalone_response = cast(dict[str, object], standalone[operation_id]["responses"])[
                status
            ]
            standalone_response_content = cast(
                dict[str, object],
                cast(dict[str, object], standalone_response)["content"],
            )
            standalone_response_media = cast(
                dict[str, object],
                standalone_response_content["application/json"],
            )
            assert media["example"] == standalone_response_media["example"]
            standalone_schema = cast(dict[str, object], standalone_response_media["schema"])
            Draft202012Validator.check_schema(standalone_schema)
            Draft202012Validator(standalone_schema).validate(standalone_response_media["example"])


@pytest.mark.contract
def test_standalone_request_and_success_schemas_are_recursively_closed() -> None:
    artifacts = rendered_artifacts()
    bundle = json.loads(artifacts[Path("acceptance/v1/operations.json")])
    checked_objects = 0
    for operation in bundle["http_operations"]:
        request = operation["request"]
        if request is not None:
            for media in request["content"].values():
                schema = media["schema"]
                assert _unsafe_schema_paths(schema) == [], (
                    operation["operation_id"],
                    "request",
                    _unsafe_schema_paths(schema),
                )
                example = media["example"]
                Draft202012Validator(schema).validate(example)
                if isinstance(example, dict):
                    checked_objects += _assert_private_fields_rejected(
                        schema,
                        example,
                        (operation["operation_id"], "request"),
                    )
        for status, response in operation["responses"].items():
            if not status.startswith("2"):
                continue
            media = response["content"]["application/json"]
            schema = media["schema"]
            assert _unsafe_schema_paths(schema) == [], (
                operation["operation_id"],
                status,
                _unsafe_schema_paths(schema),
            )
            example = media["example"]
            checked_objects += _assert_private_fields_rejected(
                schema,
                example,
                (
                    operation["operation_id"],
                    status,
                ),
            )

    mcp_bundle_operations = cast(list[dict[str, object]], bundle["mcp_operations"])
    for operation in mcp_bundle_operations:
        schema = cast(dict[str, object], operation["input_schema"])
        example = cast(dict[str, object], operation["input_example"])
        assert _unsafe_schema_paths(schema) == [], (
            operation["tool"],
            _unsafe_schema_paths(schema),
        )
        checked_objects += _assert_private_fields_rejected(
            schema,
            example,
            (operation["tool"], "acceptance-input"),
        )

    mcp_document = json.loads(artifacts[Path("mcp/v1/tools.json")])
    tools = cast(list[dict[str, object]], mcp_document["tools"])
    input_examples = _mcp_input_examples()
    assert {cast(str, tool["name"]) for tool in tools} == set(input_examples)

    openapi = json.loads(artifacts[Path("openapi/v1/openapi.json")])
    mcp_parity_operation = _operation(openapi, "callMcpParityTool")
    request_body = cast(dict[str, object], mcp_parity_operation["requestBody"])
    content = cast(dict[str, object], request_body["content"])
    parity_media = cast(dict[str, object], content["application/json"])
    parity_schema = cast(dict[str, object], parity_media["schema"])
    assert _unsafe_schema_paths(parity_schema) == []

    for tool in tools:
        tool_name = cast(str, tool["name"])
        schema = cast(dict[str, object], tool["inputSchema"])
        assert _unsafe_schema_paths(schema) == [], (
            tool_name,
            _unsafe_schema_paths(schema),
        )
        checked_objects += _assert_private_fields_rejected(
            schema,
            input_examples[tool_name],
            (tool_name, "input"),
        )
    assert checked_objects >= len(ACCEPTANCE_HTTP_OPERATION_IDS)


@pytest.mark.contract
def test_work_item_import_canonical_summary_is_runtime_valid_and_closed() -> None:
    payload = deepcopy(HTTP_OPERATION_EXAMPLES["importWorkItemRevision"]["request"])
    validate_payload("work-item-import", payload)

    summaries = cast(list[dict[str, object]], cast(dict[str, object], payload)["summaries"])
    structured_data = cast(dict[str, object], summaries[0]["structured_data"])
    assert structured_data == {"text": "Context only; never evidence."}
    structured_data["private_oracle_payload"] = {"verdict": "BLOCKED"}
    with pytest.raises(ContractValidationError, match="structured_data"):
        validate_payload("work-item-import", payload)


@pytest.mark.contract
def test_runtime_validators_bind_every_acceptance_http_and_mcp_operation() -> None:
    assert set(HTTP_OPERATION_EXAMPLES) == set(ACCEPTANCE_HTTP_OPERATION_IDS)
    for operation_id, examples in HTTP_OPERATION_EXAMPLES.items():
        for raw_status, payload in examples.items():
            if raw_status == "request":
                continue
            validate_acceptance_http_response(
                operation_id,
                int(raw_status),
                cast(dict[str, object], payload),
            )

    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    mcp_operations = cast(list[dict[str, object]], bundle["mcp_operations"])
    assert {operation["tool"] for operation in mcp_operations} == {
        "anva.search",
        "anva.get_context_packet",
    }
    for operation in mcp_operations:
        validate_tool_output(
            cast(str, operation["tool"]),
            cast(dict[str, object], operation["output_example"]),
        )


@pytest.mark.contract
def test_all_create_or_replay_status_contracts_are_mutually_exclusive() -> None:
    dual_status_operations = {
        operation_id
        for operation_id, examples in HTTP_OPERATION_EXAMPLES.items()
        if {"200", "201"}.issubset(examples)
    }
    assert dual_status_operations == {
        *CREATED_OR_REPLAYED_OPERATION_IDS,
        "createEvidenceUploadAuthorization",
    }
    assert len(dual_status_operations) == 9

    for operation_id in sorted(dual_status_operations):
        examples = HTTP_OPERATION_EXAMPLES[operation_id]
        fresh = cast(dict[str, object], examples["201"])
        replay = cast(dict[str, object], examples["200"])
        validate_acceptance_http_response(operation_id, 201, fresh)
        validate_acceptance_http_response(operation_id, 200, replay)
        with pytest.raises(ValueError, match="Acceptance response contract failed"):
            validate_acceptance_http_response(operation_id, 200, fresh)
        with pytest.raises(ValueError, match="Acceptance response contract failed"):
            validate_acceptance_http_response(operation_id, 201, replay)

    upload_examples = HTTP_OPERATION_EXAMPLES["createEvidenceUploadAuthorization"]
    fresh_upload = cast(dict[str, object], deepcopy(upload_examples["201"]))
    replay_upload = cast(dict[str, object], deepcopy(upload_examples["200"]))
    assert isinstance(fresh_upload["upload_token"], str)
    assert replay_upload["upload_token"] is None
    replay_upload["upload_token"] = fresh_upload["upload_token"]
    with pytest.raises(ValueError, match="Acceptance response contract failed"):
        validate_acceptance_http_response("createEvidenceUploadAuthorization", 200, replay_upload)


@pytest.mark.contract
def test_published_create_or_replay_status_schemas_differ() -> None:
    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    operations = {operation["operation_id"]: operation for operation in bundle["http_operations"]}
    for operation_id, operation in operations.items():
        responses = cast(dict[str, object], operation["responses"])
        if not {"200", "201"}.issubset(responses):
            continue
        response_200 = cast(dict[str, object], responses["200"])
        response_201 = cast(dict[str, object], responses["201"])
        schema_200 = cast(
            dict[str, object],
            cast(dict[str, object], response_200["content"])["application/json"],
        )["schema"]
        schema_201 = cast(
            dict[str, object],
            cast(dict[str, object], response_201["content"])["application/json"],
        )["schema"]
        assert schema_200 != schema_201, operation_id


@pytest.mark.contract
def test_exact_claim_selector_is_all_or_nothing_and_response_is_identity_bound() -> None:
    operation = _operation(openapi_document(), "claimManualEvaluatorTask")
    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    standalone = next(
        value
        for value in bundle["http_operations"]
        if value["operation_id"] == "claimManualEvaluatorTask"
    )
    body = cast(dict[str, object], operation["requestBody"])
    content = cast(dict[str, object], body["content"])
    media = cast(dict[str, object], content["application/json"])
    schema = cast(dict[str, object], media["schema"])
    example = cast(dict[str, object], media["example"])
    Draft202012Validator(schema).validate(example)

    incomplete = deepcopy(example)
    incomplete.pop("head_commit")
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(incomplete)

    response = cast(dict[str, object], standalone["responses"])["200"]
    response_content = cast(dict[str, object], cast(dict[str, object], response)["content"])
    response_media = cast(dict[str, object], response_content["application/json"])
    response_schema = cast(dict[str, object], response_media["schema"])
    response_example = cast(dict[str, object], response_media["example"])
    Draft202012Validator(response_schema).validate(response_example)
    rendered = json.dumps(response_example, sort_keys=True)
    for field in (
        "task_id",
        "assurance_run_id",
        "request_id",
        "input_hash",
        "head_commit",
        "claimed_by",
        "claim_token",
        "replayed",
    ):
        assert field in rendered


@pytest.mark.contract
def test_standalone_bundle_validates_without_importing_anva(tmp_path: Path) -> None:
    artifacts = rendered_artifacts()
    bundle_path = tmp_path / "operations.json"
    bundle_path.write_bytes(artifacts[Path("acceptance/v1/operations.json")])
    script = r"""
import json
import sys
from jsonschema import Draft202012Validator

bundle = json.loads(open(sys.argv[1], encoding="utf-8").read())
for operation in bundle["http_operations"]:
    request = operation["request"]
    if request is not None:
        for media in request["content"].values():
            Draft202012Validator.check_schema(media["schema"])
            Draft202012Validator(media["schema"]).validate(media["example"])
    for status, response in operation["responses"].items():
        if not status.startswith("2"):
            continue
        media = response["content"]["application/json"]
        Draft202012Validator.check_schema(media["schema"])
        Draft202012Validator(media["schema"]).validate(media["example"])
for operation in bundle["mcp_operations"]:
    for direction in ("input", "output"):
        schema = operation[direction + "_schema"]
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(operation[direction + "_example"])
assert "anva" not in sys.modules
"""
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and test-owned script
        [sys.executable, "-I", "-c", script, str(bundle_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr

    rendered = bundle_path.read_text(encoding="utf-8").casefold()
    assert "#/components" not in rendered
    for forbidden in ("oracle", "grader", "expected_readiness", "expected_finding"):
        assert forbidden not in rendered


@pytest.mark.contract
def test_mcp_acceptance_examples_require_exact_provenance_fields() -> None:
    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    operations = {item["tool"]: item for item in bundle["mcp_operations"]}
    search = operations["anva.search"]
    context = operations["anva.get_context_packet"]
    Draft202012Validator(search["output_schema"]).validate(search["output_example"])
    Draft202012Validator(context["output_schema"]).validate(context["output_example"])

    invalid_search = deepcopy(search["output_example"])
    result = invalid_search["data"]["results"][0]
    result.pop("source_observation_id")
    with pytest.raises(ValidationError):
        Draft202012Validator(search["output_schema"]).validate(invalid_search)

    invalid_context = deepcopy(context["output_example"])
    citation = invalid_context["data"]["packet"]["items"][0]["anva_sources"][0]
    citation.pop("source_content_hash")
    with pytest.raises(ValidationError):
        Draft202012Validator(context["output_schema"]).validate(invalid_context)


@pytest.mark.contract
def test_public_contracts_are_packaged_for_archive_consumers() -> None:
    configuration = Path("pyproject.toml").read_text(encoding="utf-8")
    assert '"contracts" = "anva_public_contracts"' in configuration
