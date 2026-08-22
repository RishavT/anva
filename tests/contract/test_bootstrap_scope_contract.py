"""Public least-privilege bootstrap request contract coverage."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.contracts.acceptance import (
    HTTP_OPERATION_EXAMPLES,
    validate_acceptance_http_response,
)
from anva.contracts.generate import openapi_document, rendered_artifacts


def _bootstrap_request_schema() -> dict[str, object]:
    document = openapi_document()
    paths = cast(dict[str, object], document["paths"])
    bootstrap_path = cast(dict[str, object], paths["/bootstrap"])
    operation = cast(dict[str, object], bootstrap_path["post"])
    request_body = cast(dict[str, object], operation["requestBody"])
    content = cast(dict[str, object], request_body["content"])
    media = cast(dict[str, object], content["application/json"])
    return cast(dict[str, object], media["schema"])


def _bootstrap_response_schema() -> dict[str, object]:
    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    operation = next(
        item
        for item in bundle["http_operations"]
        if item["operation_id"] == "bootstrapOrganization"
    )
    response = cast(dict[str, object], operation["responses"])["201"]
    content = cast(dict[str, object], cast(dict[str, object], response)["content"])
    media = cast(dict[str, object], content["application/json"])
    return cast(dict[str, object], media["schema"])


@pytest.mark.contract
def test_bootstrap_public_contract_separates_scoped_and_legacy_requests() -> None:
    schema = _bootstrap_request_schema()
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    scoped = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["bootstrapOrganization"]["request"]),
    )
    legacy: dict[str, object] = {
        "organization_slug": "legacy-compatibility",
        "organization_name": "Legacy compatibility",
        "admin_email": "operator@legacy.invalid",
        "admin_display_name": "Legacy operator",
        "repository_external_id": "legacy:repository",
        "repository_name": "legacy",
        "independent_reviewer_name": "Legacy independent reviewer",
        "idempotency_key": "a" * 64,
    }

    validator.validate(scoped)
    validator.validate(legacy)
    assert "scope" in scoped
    for legacy_field in (
        "admin_email",
        "admin_display_name",
        "repository_external_id",
        "repository_name",
        "independent_reviewer_name",
    ):
        assert legacy_field not in scoped

    mixed = deepcopy(scoped)
    mixed["admin_email"] = "must-not-mix@scoped.invalid"
    with pytest.raises(ValidationError):
        validator.validate(mixed)

    missing_scope = {
        "organization_slug": scoped["organization_slug"],
        "organization_name": scoped["organization_name"],
    }
    with pytest.raises(ValidationError):
        validator.validate(missing_scope)

    nested_unknown = deepcopy(scoped)
    scope = cast(dict[str, object], nested_unknown["scope"])
    scope["private_oracle_payload"] = {"answer": "must remain private"}
    with pytest.raises(ValidationError):
        validator.validate(nested_unknown)


@pytest.mark.contract
def test_bootstrap_public_response_discriminator_requires_complete_reviewer_metadata() -> None:
    schema = _bootstrap_response_schema()
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    scoped = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["bootstrapOrganization"]["201"]),
    )
    reviewer_fields = (
        "reviewer_service_identity_id",
        "reviewer_token_id",
        "reviewer_token",
        "reviewer_expires_at",
    )

    validator.validate(scoped)
    assert scoped["bootstrap_mode"] == "SCOPED"
    for field in reviewer_fields:
        missing = deepcopy(scoped)
        missing.pop(field)
        with pytest.raises(ValidationError):
            validator.validate(missing)

    missing_all = deepcopy(scoped)
    for field in reviewer_fields:
        missing_all.pop(field)
    with pytest.raises(ValidationError):
        validator.validate(missing_all)

    legacy_without_reviewer = deepcopy(missing_all)
    legacy_without_reviewer["bootstrap_mode"] = "LEGACY"
    validator.validate(legacy_without_reviewer)
    legacy_with_reviewer = deepcopy(scoped)
    legacy_with_reviewer["bootstrap_mode"] = "LEGACY"
    validator.validate(legacy_with_reviewer)

    for field in reviewer_fields:
        partial_legacy = deepcopy(legacy_without_reviewer)
        partial_legacy[field] = scoped[field]
        with pytest.raises(ValidationError):
            validator.validate(partial_legacy)

    unknown_mode = deepcopy(scoped)
    unknown_mode["bootstrap_mode"] = "UNKNOWN"
    with pytest.raises(ValidationError):
        validator.validate(unknown_mode)


@pytest.mark.contract
def test_bootstrap_runtime_validation_binds_response_mode_to_request() -> None:
    scoped_request = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["bootstrapOrganization"]["request"]),
    )
    scoped_response = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["bootstrapOrganization"]["201"]),
    )
    legacy_request: dict[str, object] = {
        "organization_slug": "legacy",
        "organization_name": "Legacy",
        "admin_email": "operator@legacy.invalid",
        "admin_display_name": "Legacy operator",
        "repository_external_id": "legacy:repository",
        "repository_name": "legacy",
        "independent_reviewer_name": "Legacy reviewer",
    }

    validate_acceptance_http_response(
        "bootstrapOrganization",
        201,
        scoped_response,
        request_payload=scoped_request,
    )
    wrong_scoped_mode = deepcopy(scoped_response)
    wrong_scoped_mode["bootstrap_mode"] = "LEGACY"
    with pytest.raises(ValueError, match="Acceptance response contract failed"):
        validate_acceptance_http_response(
            "bootstrapOrganization",
            201,
            wrong_scoped_mode,
            request_payload=scoped_request,
        )

    legacy_response = deepcopy(scoped_response)
    legacy_response["bootstrap_mode"] = "LEGACY"
    validate_acceptance_http_response(
        "bootstrapOrganization", 201, legacy_response, request_payload=legacy_request
    )
    legacy_response["bootstrap_mode"] = "SCOPED"
    with pytest.raises(ValueError, match="Acceptance response contract failed"):
        validate_acceptance_http_response(
            "bootstrapOrganization", 201, legacy_response, request_payload=legacy_request
        )
