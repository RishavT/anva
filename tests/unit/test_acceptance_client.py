"""Acceptance clients fail closed on public response-contract drift."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Self
from unittest.mock import patch

import pytest

from anva.acceptance.client import AcceptanceBoundaryError, PublicAPI
from anva.contracts.acceptance import HTTP_OPERATION_EXAMPLES
from anva.contracts.generate import rendered_artifacts
from anva.mcp.contracts import validate_tool_output


class _Response:
    def __init__(self, status: int, payload: dict[str, object]) -> None:
        self.status = status
        self._raw = json.dumps(payload).encode()

    def read(self, _limit: int) -> bytes:
        return self._raw

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


@pytest.mark.unit
def test_public_api_validates_declared_success_response_shape() -> None:
    valid = deepcopy(HTTP_OPERATION_EXAMPLES["connectFilesystemSource"]["201"])
    invalid = deepcopy(valid)
    invalid.pop("revision")
    api = PublicAPI("https://anva.invalid/api/v1")

    with patch(
        "anva.acceptance.client.urlopen",
        side_effect=[_Response(201, valid), _Response(201, invalid)],
    ):
        response = api.request(
            "POST",
            "/source-connections/filesystem",
            expected=frozenset({201}),
            operation_id="connectFilesystemSource",
        )
        with pytest.raises(AcceptanceBoundaryError) as failure:
            api.request(
                "POST",
                "/source-connections/filesystem",
                expected=frozenset({201}),
                operation_id="connectFilesystemSource",
            )

    assert response.payload == valid
    assert failure.value.code == "invalid_response_contract"


@pytest.mark.unit
def test_acceptance_mcp_outputs_require_complete_citation_provenance() -> None:
    bundle = json.loads(rendered_artifacts()[Path("acceptance/v1/operations.json")])
    operations = {item["tool"]: item for item in bundle["mcp_operations"]}
    for tool_name in ("anva.search", "anva.get_context_packet"):
        validate_tool_output(tool_name, operations[tool_name]["output_example"])

    invalid = deepcopy(operations["anva.get_context_packet"]["output_example"])
    invalid["data"]["packet"]["items"][0]["anva_sources"][0].pop("observed_at")
    with pytest.raises(ValueError, match="MCP output contract failed"):
        validate_tool_output("anva.get_context_packet", invalid)
