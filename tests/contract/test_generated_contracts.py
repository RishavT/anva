"""Contract tests for deterministic OpenAPI, MCP, schemas, and examples."""

from __future__ import annotations

import json
from typing import cast

import pytest

from anva.contracts.catalog import SCHEMAS
from anva.contracts.generate import (
    check_artifacts,
    mcp_document,
    openapi_document,
    rendered_artifacts,
    validate_catalog,
)


@pytest.mark.contract
def test_contract_catalog_and_checked_in_generation_are_current() -> None:
    validate_catalog()
    first = rendered_artifacts()
    second = rendered_artifacts()

    assert first == second
    assert len(first) == 16
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
            "bearerFormat": "JWT",
        }
    }
    assert mcp["contract_version"] == "1"
    assert [tool["name"] for tool in tools] == [
        "anva.evaluate_change",
        "anva.submit_knowledge_proposal",
    ]


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
