"""Artifact-only bootstrap request/response correlation contract coverage.

This module intentionally never imports :mod:`anva`. It exercises only the
checked-in JSON files in the same way an independent wheel consumer can.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

CONTRACT_ROOT = Path("contracts")
CORRELATION_KEY = "x-anva-request-response-correlation"
OPENAPI_REGISTRY_KEY = "x-anva-request-dependent-response-variants"


def _load(relative_path: str) -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads((CONTRACT_ROOT / relative_path).read_text(encoding="utf-8")),
    )


def _standalone_operation(bundle: dict[str, object], operation_id: str) -> dict[str, object]:
    return next(
        cast(dict[str, object], operation)
        for operation in cast(list[object], bundle["http_operations"])
        if cast(dict[str, object], operation)["operation_id"] == operation_id
    )


def _openapi_operations(document: dict[str, object]) -> dict[str, dict[str, object]]:
    operations: dict[str, dict[str, object]] = {}
    for path_item in cast(dict[str, object], document["paths"]).values():
        for method, raw_operation in cast(dict[str, object], path_item).items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            if isinstance(raw_operation, dict) and isinstance(
                raw_operation.get("operationId"), str
            ):
                operations[cast(str, raw_operation["operationId"])] = cast(
                    dict[str, object], raw_operation
                )
    return operations


def _resolve_local_ref(document: dict[str, object], reference: str) -> object:
    assert reference.startswith("#/"), reference
    value: object = document
    for raw_part in reference.removeprefix("#/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        assert isinstance(value, dict) and part in value, reference
        value = value[part]
    return value


def _correlation_schema(
    operation: dict[str, object],
    status: str,
    *,
    document: dict[str, object] | None = None,
) -> dict[str, object]:
    metadata = cast(dict[str, object], operation[CORRELATION_KEY])
    assert metadata["schema_version"] == "1.0"
    status_schemas = cast(dict[str, object], metadata["status_schemas"])
    schema = cast(dict[str, object], status_schemas[status])
    if "$ref" in schema:
        assert document is not None
        schema = cast(dict[str, object], _resolve_local_ref(document, cast(str, schema["$ref"])))
    return schema


def _bootstrap_examples(
    bundle: dict[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    operation = _standalone_operation(bundle, "bootstrapOrganization")
    request = cast(dict[str, object], operation["request"])
    request_media = cast(
        dict[str, object],
        cast(dict[str, object], request["content"])["application/json"],
    )
    scoped_request = deepcopy(cast(dict[str, object], request_media["example"]))
    response = cast(dict[str, object], operation["responses"])
    response_media = cast(
        dict[str, object],
        cast(
            dict[str, object],
            cast(dict[str, object], response["201"])["content"],
        )["application/json"],
    )
    scoped_response = deepcopy(cast(dict[str, object], response_media["example"]))
    legacy_request_without_reviewer: dict[str, object] = {
        "organization_slug": "legacy-without-reviewer",
        "organization_name": "Legacy without reviewer",
        "admin_email": "operator@legacy.invalid",
        "admin_display_name": "Legacy operator",
        "repository_external_id": "github:synthetic/legacy",
        "repository_name": "legacy",
        "idempotency_key": "a" * 64,
    }
    legacy_request_with_reviewer = {
        **legacy_request_without_reviewer,
        "independent_reviewer_name": "Independent legacy reviewer",
    }
    legacy_response_with_reviewer = deepcopy(scoped_response)
    legacy_response_with_reviewer["bootstrap_mode"] = "LEGACY"
    legacy_response_without_reviewer = deepcopy(legacy_response_with_reviewer)
    for field in (
        "reviewer_service_identity_id",
        "reviewer_token_id",
        "reviewer_token",
        "reviewer_expires_at",
    ):
        legacy_response_without_reviewer.pop(field)
    return (
        scoped_request,
        scoped_response,
        legacy_request_with_reviewer,
        legacy_response_with_reviewer,
        legacy_response_without_reviewer,
    )


def _unsafe_schema_paths(
    value: object,
    path: tuple[str | int, ...] = (),
) -> list[tuple[str | int, ...]]:
    if value is True:
        return [path]
    if not isinstance(value, dict):
        return []
    schema_type = value.get("type")
    is_object = schema_type == "object" or (
        isinstance(schema_type, list) and "object" in schema_type
    )
    is_array = schema_type == "array" or (isinstance(schema_type, list) and "array" in schema_type)
    found = (
        [path]
        if not value
        or ((is_object or "properties" in value) and value.get("additionalProperties") is not False)
        or (is_array and "items" not in value)
        else []
    )
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
                found.extend(_unsafe_schema_paths(child, (*path, keyword, key)))
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
            found.extend(_unsafe_schema_paths(value[keyword], (*path, keyword)))
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        children = value.get(keyword)
        if isinstance(children, list):
            for index, child in enumerate(children):
                found.extend(_unsafe_schema_paths(child, (*path, keyword, index)))
    return found


def _object_paths(value: object, path: tuple[str | int, ...] = ()) -> list[tuple[str | int, ...]]:
    if isinstance(value, list):
        return [
            nested
            for index, item in enumerate(value)
            for nested in _object_paths(item, (*path, index))
        ]
    if not isinstance(value, dict):
        return []
    return [
        path,
        *(nested for key, item in value.items() for nested in _object_paths(item, (*path, key))),
    ]


def _object_at(value: dict[str, object], path: tuple[str | int, ...]) -> dict[str, object]:
    current: object = value
    for part in path:
        current = (
            cast(dict[str, object], current)[part]
            if isinstance(part, str)
            else cast(list[object], current)[part]
        )
    return cast(dict[str, object], current)


@pytest.mark.contract
def test_packaged_bootstrap_exchange_schema_binds_request_status_and_response() -> None:
    bundle = _load("acceptance/v1/operations.json")
    operation = _standalone_operation(bundle, "bootstrapOrganization")
    schema = _correlation_schema(operation, "201")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    (
        scoped_request,
        scoped_response,
        legacy_request_with_reviewer,
        legacy_response_with_reviewer,
        legacy_response_without_reviewer,
    ) = _bootstrap_examples(bundle)
    legacy_request_without_reviewer = deepcopy(legacy_request_with_reviewer)
    legacy_request_without_reviewer.pop("independent_reviewer_name")

    canonical_exchanges: list[dict[str, object]] = [
        {"request": scoped_request, "status": 201, "response": scoped_response},
        {
            "request": legacy_request_with_reviewer,
            "status": 201,
            "response": legacy_response_with_reviewer,
        },
        {
            "request": legacy_request_without_reviewer,
            "status": 201,
            "response": legacy_response_without_reviewer,
        },
    ]
    for exchange in canonical_exchanges:
        validator.validate(exchange)

    relabeled_with_metadata = deepcopy(canonical_exchanges[0])
    cast(dict[str, object], relabeled_with_metadata["response"])["bootstrap_mode"] = "LEGACY"
    relabeled_without_metadata = deepcopy(relabeled_with_metadata)
    for field in (
        "reviewer_service_identity_id",
        "reviewer_token_id",
        "reviewer_token",
        "reviewer_expires_at",
    ):
        cast(dict[str, object], relabeled_without_metadata["response"]).pop(field)

    invalid_exchanges: list[dict[str, object]] = [
        relabeled_with_metadata,
        relabeled_without_metadata,
        {
            "request": legacy_request_with_reviewer,
            "status": 201,
            "response": scoped_response,
        },
        {
            "request": legacy_request_without_reviewer,
            "status": 201,
            "response": legacy_response_with_reviewer,
        },
        {
            "request": legacy_request_with_reviewer,
            "status": 201,
            "response": legacy_response_without_reviewer,
        },
        {
            "request": scoped_request,
            "status": 201,
            "response": legacy_response_with_reviewer,
        },
        {
            "request": legacy_request_without_reviewer,
            "status": 201,
            "response": scoped_response,
        },
        {"request": scoped_request, "status": 200, "response": scoped_response},
        {"request": scoped_request, "status": "201", "response": scoped_response},
        {"status": 201, "response": scoped_response},
        {"request": scoped_request, "response": scoped_response},
        {"request": scoped_request, "status": 201},
    ]
    missing_request_field = deepcopy(canonical_exchanges[0])
    cast(dict[str, object], missing_request_field["request"]).pop("scope")
    invalid_exchanges.append(missing_request_field)
    missing_response_field = deepcopy(canonical_exchanges[0])
    cast(dict[str, object], missing_response_field["response"]).pop("reviewer_token_id")
    invalid_exchanges.append(missing_response_field)
    for exchange in invalid_exchanges:
        with pytest.raises(ValidationError):
            validator.validate(exchange)

    for canonical in canonical_exchanges:
        for object_path in _object_paths(canonical):
            injected = deepcopy(canonical)
            _object_at(injected, object_path)["private_oracle_payload"] = {
                "answer": "must remain private"
            }
            with pytest.raises(ValidationError):
                validator.validate(injected)


@pytest.mark.contract
def test_request_dependent_correlations_are_complete_closed_and_openapi_resolvable() -> None:
    bundle = _load("acceptance/v1/operations.json")
    openapi = _load("openapi/v1/openapi.json")
    standalone_operations = {
        cast(str, cast(dict[str, object], operation)["operation_id"]): cast(
            dict[str, object], operation
        )
        for operation in cast(list[object], bundle["http_operations"])
    }
    openapi_operations = _openapi_operations(openapi)
    standalone_registry = {
        cast(str, cast(dict[str, object], item)["operation_id"]): cast(
            list[int], cast(dict[str, object], item)["statuses"]
        )
        for item in cast(list[object], bundle["request_dependent_response_variants"])
    }
    openapi_registry = {
        cast(str, cast(dict[str, object], item)["operation_id"]): cast(
            list[int], cast(dict[str, object], item)["statuses"]
        )
        for item in cast(list[object], openapi[OPENAPI_REGISTRY_KEY])
    }
    standalone_published = {
        operation_id
        for operation_id, operation in standalone_operations.items()
        if CORRELATION_KEY in operation
    }
    openapi_published = {
        operation_id
        for operation_id, operation in openapi_operations.items()
        if CORRELATION_KEY in operation
    }

    assert standalone_registry == openapi_registry
    assert set(standalone_registry) == standalone_published == openapi_published
    assert standalone_registry == {"bootstrapOrganization": [201]}

    for operation_id, statuses in standalone_registry.items():
        standalone_operation = standalone_operations[operation_id]
        openapi_operation = openapi_operations[operation_id]
        standalone_status_schemas = cast(
            dict[str, object],
            cast(dict[str, object], standalone_operation[CORRELATION_KEY])["status_schemas"],
        )
        openapi_status_schemas = cast(
            dict[str, object],
            cast(dict[str, object], openapi_operation[CORRELATION_KEY])["status_schemas"],
        )
        assert (
            set(standalone_status_schemas)
            == set(openapi_status_schemas)
            == {str(status) for status in statuses}
        )
        for status in statuses:
            standalone_schema = _correlation_schema(standalone_operation, str(status))
            openapi_schema = _correlation_schema(
                openapi_operation,
                str(status),
                document=openapi,
            )
            Draft202012Validator.check_schema(standalone_schema)
            Draft202012Validator.check_schema(openapi_schema)
            assert standalone_schema == openapi_schema
            assert _unsafe_schema_paths(standalone_schema) == []

            openapi_reference = cast(
                str,
                cast(dict[str, object], openapi_status_schemas[str(status)])["$ref"],
            )
            assert _resolve_local_ref(openapi, openapi_reference) == openapi_schema

    rendered = json.dumps(bundle, sort_keys=True).casefold()
    for forbidden in ("private_oracle_payload", "expected_readiness", "expected_finding"):
        assert forbidden not in rendered
