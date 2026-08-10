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
from anva.contracts.acceptance import (
    ACCEPTANCE_HTTP_OPERATION_IDS,
    HTTP_OPERATION_EXAMPLES,
    validate_acceptance_http_response,
)
from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.generate import openapi_document, rendered_artifacts
from anva.core.services.evidence_uploads import inspect_evidence_upload
from anva.mcp.contracts import validate_tool_output


def _operation(document: dict[str, object], operation_id: str) -> dict[str, object]:
    paths = cast(dict[str, object], document["paths"])
    for value in paths.values():
        path_item = cast(dict[str, object], value)
        for method in ("get", "post", "put", "patch", "delete"):
            candidate = path_item.get(method)
            if isinstance(candidate, dict) and candidate.get("operationId") == operation_id:
                return cast(dict[str, object], candidate)
    raise AssertionError(f"OpenAPI operation not found: {operation_id}")


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
            "admin_email": "operator@lantern.invalid",
            "repository_external_id": "github:synthetic/lantern",
            "repository_name": "lantern",
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
            standalone_media = cast(
                dict[str, object],
                cast(dict[str, object], standalone_response)["content"],
            )["application/json"]
            assert media["example"] == cast(dict[str, object], standalone_media)["example"]
            standalone_schema = cast(
                dict[str, object], cast(dict[str, object], standalone_media)["schema"]
            )
            Draft202012Validator.check_schema(standalone_schema)
            Draft202012Validator(standalone_schema).validate(
                cast(dict[str, object], standalone_media)["example"]
            )


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
    response_media = cast(dict[str, object], cast(dict[str, object], response)["content"])[
        "application/json"
    ]
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
