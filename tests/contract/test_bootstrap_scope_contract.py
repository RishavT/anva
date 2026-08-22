"""Public least-privilege bootstrap request contract coverage."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.contracts.acceptance import HTTP_OPERATION_EXAMPLES
from anva.contracts.generate import openapi_document


def _bootstrap_request_schema() -> dict[str, object]:
    document = openapi_document()
    paths = cast(dict[str, object], document["paths"])
    bootstrap_path = cast(dict[str, object], paths["/bootstrap"])
    operation = cast(dict[str, object], bootstrap_path["post"])
    request_body = cast(dict[str, object], operation["requestBody"])
    content = cast(dict[str, object], request_body["content"])
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
