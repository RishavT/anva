"""Acceptance clients fail closed on public response-contract drift."""

from __future__ import annotations

import json
from copy import deepcopy
from email.message import Message
from io import BytesIO
from pathlib import Path
from typing import Self, cast
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from anva.acceptance.client import (
    MAX_RESPONSE_BYTES,
    AcceptanceBoundaryError,
    PublicAPI,
    StreamableHTTPMCP,
    _decoded_object,
)
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
    valid = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["connectFilesystemSource"]["201"]),
    )
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
def test_public_api_rejects_response_from_the_other_success_status() -> None:
    fresh = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["createEvidenceUploadAuthorization"]["201"]),
    )
    replay = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["createEvidenceUploadAuthorization"]["200"]),
    )
    api = PublicAPI("https://anva.invalid/api/v1")

    with patch(
        "anva.acceptance.client.urlopen",
        side_effect=[_Response(201, replay), _Response(200, fresh)],
    ):
        with pytest.raises(AcceptanceBoundaryError) as replay_as_fresh:
            api.request(
                "POST",
                "/repositories/00000000-0000-4000-8000-000000000004/"
                "pull-requests/17/evidence-upload-authorizations",
                expected=frozenset({200, 201}),
                operation_id="createEvidenceUploadAuthorization",
            )
        with pytest.raises(AcceptanceBoundaryError) as fresh_as_replay:
            api.request(
                "POST",
                "/repositories/00000000-0000-4000-8000-000000000004/"
                "pull-requests/17/evidence-upload-authorizations",
                expected=frozenset({200, 201}),
                operation_id="createEvidenceUploadAuthorization",
            )

    assert replay_as_fresh.value.code == "invalid_response_contract"
    assert fresh_as_replay.value.code == "invalid_response_contract"


@pytest.mark.unit
def test_public_api_rejects_scoped_bootstrap_response_with_legacy_or_partial_metadata() -> None:
    request = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["bootstrapOrganization"]["request"]),
    )
    valid = cast(
        dict[str, object],
        deepcopy(HTTP_OPERATION_EXAMPLES["bootstrapOrganization"]["201"]),
    )
    wrong_mode = deepcopy(valid)
    wrong_mode["bootstrap_mode"] = "LEGACY"
    partial = deepcopy(valid)
    partial.pop("reviewer_token_id")
    api = PublicAPI("https://anva.invalid/api/v1")

    with patch(
        "anva.acceptance.client.urlopen",
        side_effect=[_Response(201, valid), _Response(201, wrong_mode), _Response(201, partial)],
    ):
        assert (
            api.request(
                "POST",
                "/bootstrap",
                payload=request,
                expected=frozenset({201}),
                operation_id="bootstrapOrganization",
            ).payload
            == valid
        )
        with pytest.raises(AcceptanceBoundaryError) as wrong_mode_failure:
            api.request(
                "POST",
                "/bootstrap",
                payload=request,
                expected=frozenset({201}),
                operation_id="bootstrapOrganization",
            )
        with pytest.raises(AcceptanceBoundaryError) as partial_failure:
            api.request(
                "POST",
                "/bootstrap",
                payload=request,
                expected=frozenset({201}),
                operation_id="bootstrapOrganization",
            )

    assert wrong_mode_failure.value.code == "invalid_response_contract"
    assert partial_failure.value.code == "invalid_response_contract"


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


@pytest.mark.unit
def test_public_api_serializes_requests_and_redacts_transport_failures() -> None:
    api = PublicAPI("https://anva.invalid/api/v1", token="acceptance-token", timeout=12)
    with patch(
        "anva.acceptance.client.urlopen", return_value=_Response(202, {"ok": True})
    ) as open_url:
        response = api.request(
            "POST",
            "/evidence",
            payload={"z": 1, "a": "value"},
            headers={"X-Request-Source": "unit-test"},
            expected=frozenset({202}),
        )

    request = open_url.call_args.args[0]
    assert response.payload == {"ok": True}
    assert request.full_url == "https://anva.invalid/api/v1/evidence"
    assert request.data == b'{"a":"value","z":1}'
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Authorization") == "Bearer acceptance-token"
    assert request.get_header("X-request-source") == "unit-test"
    assert open_url.call_args.kwargs["timeout"] == 12

    with patch("anva.acceptance.client.urlopen", side_effect=URLError("private host detail")):
        with pytest.raises(AcceptanceBoundaryError, match="API is unavailable") as failure:
            api.request("GET", "/evidence")
    assert failure.value.code == "api_unavailable"
    assert "private host detail" not in str(failure.value)


@pytest.mark.unit
def test_public_api_rejects_invalid_inputs_and_reports_safe_http_errors() -> None:
    api = PublicAPI("https://anva.invalid/api/v1")
    for endpoint in (
        "ftp://anva.invalid/api/v1",
        "https://user@anva.invalid/api/v1",
        "https://anva.invalid/v2",
    ):
        with pytest.raises(ValueError):
            PublicAPI(endpoint)
    with pytest.raises(ValueError, match="path"):
        api.request("GET", "/safe/../escape")
    with pytest.raises(ValueError, match="mix"):
        api.request("POST", "/evidence", payload={}, content=b"bytes")
    with pytest.raises(ValueError, match="token"):
        api.with_token("")

    error = HTTPError(
        "https://anva.invalid",
        429,
        "too many",
        Message(),
        BytesIO(b'{"code":"rate_limited","detail":"internal"}'),
    )
    with patch("anva.acceptance.client.urlopen", side_effect=error):
        with pytest.raises(AcceptanceBoundaryError, match="rejected") as failure:
            api.request("GET", "/evidence", expected=frozenset({200}))
    assert failure.value.code == "rate_limited"
    assert failure.value.status == 429


@pytest.mark.unit
def test_response_and_mcp_boundaries_fail_closed_without_exposing_payloads() -> None:
    with pytest.raises(AcceptanceBoundaryError, match="invalid response"):
        _decoded_object(b"[")
    with pytest.raises(AcceptanceBoundaryError, match="invalid response"):
        _decoded_object(b"[]")
    with pytest.raises(AcceptanceBoundaryError, match="exceeded"):
        _decoded_object(b"x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(ValueError, match="MCP token"):
        StreamableHTTPMCP("https://anva.invalid/mcp", "")
