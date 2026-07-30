"""Bounds, validation, and redaction regressions for diagnostics."""

from __future__ import annotations

import json
from email.message import Message
from unittest.mock import Mock, patch

import pytest

from anva.skills.diagnostics import diagnose_skills


def _response(payload: object, *, content_type: str = "application/json") -> Mock:
    response = Mock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.headers = Message()
    response.headers["Content-Type"] = content_type
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    return response


def _valid_payload() -> dict[str, object]:
    return {
        "status": "available",
        "service": "anva-mcp",
        "transport": "streamable-http",
        "endpoint": "https://mcp.example.test/mcp",
        "contract_version": "1",
        "supported_contract_versions": ["1"],
        "supported_protocol_versions": ["2025-11-25"],
        "read_only": True,
        "authentication": {
            "type": "bearer",
            "scope": "organization-and-exact-repository",
            "rotation": True,
            "revocation": True,
        },
        "limits": {
            "page_size": 50,
            "input_bytes": 65536,
            "output_bytes": 65536,
            "source_excerpt_characters": 4000,
        },
    }


@pytest.mark.unit
def test_diagnostics_bounded_read_rejects_oversize_response() -> None:
    response = _response(_valid_payload())
    response.read.return_value = b"{" + (b"x" * 65536)
    with patch("anva.skills.diagnostics.urlopen", return_value=response):
        result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )

    assert response.read.call_args.args == (65537,)
    assert result["status"] == "unsupported"


@pytest.mark.unit
def test_diagnostics_rejects_wrong_content_type_and_unknown_fields() -> None:
    wrong_type = _response(_valid_payload(), content_type="text/plain")
    with patch("anva.skills.diagnostics.urlopen", return_value=wrong_type):
        type_result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )
    payload = _valid_payload()
    payload["unexpected"] = "CANARY-UNKNOWN-FIELD"
    unknown = _response(payload)
    with patch("anva.skills.diagnostics.urlopen", return_value=unknown):
        unknown_result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )

    assert type_result["status"] == "unsupported"
    assert unknown_result["status"] == "unsupported"
    assert "CANARY" not in json.dumps(unknown_result)


@pytest.mark.unit
def test_diagnostics_redacts_arbitrary_authentication_payload() -> None:
    payload = _valid_payload()
    authentication = payload["authentication"]
    assert isinstance(authentication, dict)
    payload["authentication"] = {
        **authentication,
        "token": "CANARY-AUTH-PAYLOAD",
    }
    response = _response(payload)
    with patch("anva.skills.diagnostics.urlopen", return_value=response):
        result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )

    assert result["status"] == "unsupported"
    assert "CANARY-AUTH-PAYLOAD" not in json.dumps(result)


@pytest.mark.unit
def test_diagnostics_does_not_echo_arbitrary_authentication_values() -> None:
    payload = _valid_payload()
    authentication = payload["authentication"]
    assert isinstance(authentication, dict)
    authentication["scope"] = "CANARY-ATTACKER-CONTROLLED-SCOPE"
    response = _response(payload)

    with patch("anva.skills.diagnostics.urlopen", return_value=response):
        result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )

    assert result["status"] == "unsupported"
    assert "CANARY" not in json.dumps(result)


@pytest.mark.unit
@pytest.mark.parametrize(
    "mutation",
    [
        "depth",
        "items",
        "string",
    ],
)
def test_diagnostics_rejects_depth_item_and_string_resource_exhaustion(
    mutation: str,
) -> None:
    payload = _valid_payload()
    if mutation == "depth":
        nested: object = "CANARY-DEEP-VALUE"
        for _ in range(12):
            nested = {"nested": nested}
        payload["authentication"] = nested
    elif mutation == "items":
        payload["supported_protocol_versions"] = [
            f"CANARY-PROTOCOL-{index}" for index in range(129)
        ]
    else:
        authentication = payload["authentication"]
        assert isinstance(authentication, dict)
        authentication["scope"] = "CANARY-" + ("x" * 4097)
    response = _response(payload)

    with patch("anva.skills.diagnostics.urlopen", return_value=response):
        result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )

    assert result["status"] == "unsupported"
    assert "CANARY" not in json.dumps(result)


@pytest.mark.unit
def test_diagnostics_rejects_declared_oversize_without_reading_body() -> None:
    response = _response(_valid_payload())
    response.headers["Content-Length"] = "65537"

    with patch("anva.skills.diagnostics.urlopen", return_value=response):
        result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
        )

    assert result["status"] == "unsupported"
    response.read.assert_not_called()
