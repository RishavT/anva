"""Runtime validation with actionable contract-version failures."""

from __future__ import annotations

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.contracts.catalog import KNOWLEDGE_CHANGE, SCHEMA_VERSION, SCHEMAS


class ContractValidationError(ValueError):
    """A payload does not satisfy its named contract."""


class UnsupportedContractVersionError(ContractValidationError):
    """A caller requested a breaking or unknown contract version."""


def validate_payload(schema_name: str, payload: object) -> None:
    """Validate one external payload against a supported versioned schema."""
    schema = SCHEMAS.get(schema_name)
    if schema is None:
        supported = ", ".join(sorted(SCHEMAS))
        raise ContractValidationError(
            f"Unknown contract '{schema_name}'. Supported contracts: {supported}"
        )
    if not isinstance(payload, dict):
        raise ContractValidationError(f"{schema_name} payload must be a JSON object")

    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        raise UnsupportedContractVersionError(
            f"Unsupported {schema_name} schema_version {version!r}; "
            f"supported versions: {SCHEMA_VERSION}"
        )

    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    except ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ContractValidationError(
            f"Invalid {schema_name} payload at {location}: {error.message}"
        ) from error


def contract_input_byte_limit(schema_name: str) -> int:
    """Return an explicit public raw-input bound declared by a contract schema."""
    schema = SCHEMAS.get(schema_name)
    if schema is None:
        raise ContractValidationError(f"Unknown contract '{schema_name}'")
    input_metadata = schema.get("x-anva-input")
    if not isinstance(input_metadata, dict):
        raise ContractValidationError(f"Contract '{schema_name}' has no input metadata")
    byte_limit = input_metadata.get("byte_limit")
    if not isinstance(byte_limit, dict):
        raise ContractValidationError(f"Contract '{schema_name}' has no byte-limit metadata")
    value = byte_limit.get("maximum")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractValidationError(f"Contract '{schema_name}' has no raw-input byte bound")
    return value


def validate_knowledge_changes(payload: object) -> None:
    """Validate proposed changes against the canonical KnowledgeProposal item contract."""
    schema: dict[str, object] = {
        "type": "array",
        "minItems": 1,
        "maxItems": 100,
        "items": KNOWLEDGE_CHANGE,
    }
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    except ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ContractValidationError(
            f"Invalid knowledge proposal changes at {location}: {error.message}"
        ) from error
