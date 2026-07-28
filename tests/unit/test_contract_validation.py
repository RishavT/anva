"""Unit tests for independently versioned JSON contract validation."""

from __future__ import annotations

from copy import deepcopy

import pytest

from anva.contracts import (
    ContractValidationError,
    UnsupportedContractVersionError,
    validate_payload,
)
from anva.contracts.catalog import EXAMPLES


@pytest.mark.unit
@pytest.mark.parametrize("schema_name", sorted(EXAMPLES))
def test_canonical_contract_examples_validate(schema_name: str) -> None:
    validate_payload(schema_name, EXAMPLES[schema_name])


@pytest.mark.unit
def test_unsupported_breaking_version_is_actionable() -> None:
    payload = {**EXAMPLES["policy"], "schema_version": "2.0"}

    with pytest.raises(
        UnsupportedContractVersionError,
        match=r"Unsupported policy schema_version '2\.0'; supported versions: 1\.0",
    ):
        validate_payload("policy", payload)


@pytest.mark.unit
def test_unknown_contract_and_non_object_fail_clearly() -> None:
    with pytest.raises(ContractValidationError, match="Supported contracts"):
        validate_payload("missing", {})
    with pytest.raises(ContractValidationError, match="must be a JSON object"):
        validate_payload("finding", [])


@pytest.mark.unit
def test_finding_requires_anva_sources_and_rejects_legacy_name() -> None:
    payload = deepcopy(EXAMPLES["finding"])
    payload["brain_sources"] = payload.pop("anva_sources")

    with pytest.raises(ContractValidationError, match="brain_sources"):
        validate_payload("finding", payload)


@pytest.mark.unit
def test_validation_error_contains_nested_location() -> None:
    payload = deepcopy(EXAMPLES["knowledge-proposal"])
    payload["changes"][0]["operation"] = "DELETE"  # type: ignore[index]

    with pytest.raises(
        ContractValidationError,
        match=r"changes\.0\.operation",
    ):
        validate_payload("knowledge-proposal", payload)
