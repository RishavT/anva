"""Truthful, bounded, and allowlisted product MCP diagnostics."""

from __future__ import annotations

import socket
from unittest.mock import Mock, patch

import pytest
from django.test import override_settings

from anva.integrations.mcp_diagnostics import (
    _DnsUnavailableError,
    _InvalidResponseError,
    _read_configured_diagnostics,
    probe_mcp_diagnostics,
)


def _payload() -> dict[str, object]:
    return {
        "status": "available",
        "service": "anva-mcp",
        "transport": "streamable-http",
        "endpoint": "http://mcp:8001/mcp",
        "contract_version": "1",
        "supported_contract_versions": ["1"],
        "supported_protocol_versions": ["2025-11-25"],
        "read_only": False,
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
@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (_DnsUnavailableError(), "dns_unavailable"),
        (ConnectionRefusedError(), "service_unavailable"),
        (TimeoutError(), "timeout"),
        (_InvalidResponseError(), "invalid_response"),
    ],
)
def test_product_diagnostic_network_failures_are_distinct_and_sanitized(
    error: Exception,
    status_code: str,
) -> None:
    with patch(
        "anva.integrations.mcp_diagnostics._read_configured_diagnostics",
        side_effect=error,
    ):
        result = probe_mcp_diagnostics()

    assert result["status_code"] == status_code
    assert result["compatible"] is False
    assert "error" not in result


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "status_code"),
    [
        ({"contract_version": "999"}, "version_mismatch"),
        (
            {
                "authentication": {
                    "type": "bearer",
                    "scope": "organization-and-exact-repository",
                    "rotation": True,
                    "revocation": False,
                }
            },
            "revocation_unsupported",
        ),
        ({"read_only": True}, "read_only"),
        ({}, "compatible"),
    ],
)
def test_product_diagnostic_capability_states_are_distinct(
    mutation: dict[str, object],
    status_code: str,
) -> None:
    payload = {**_payload(), **mutation}
    with patch(
        "anva.integrations.mcp_diagnostics._read_configured_diagnostics",
        return_value=payload,
    ):
        result = probe_mcp_diagnostics()

    assert result["status_code"] == status_code
    assert result["compatible"] is (status_code == "compatible")


@pytest.mark.unit
@override_settings(
    ANVA_MCP_URL="http://metadata.invalid/mcp",
    ANVA_MCP_ALLOWED_HOSTS=("mcp",),
)
def test_product_diagnostic_rejects_unallowlisted_host_before_dns_or_network() -> None:
    with patch("anva.integrations.mcp_diagnostics.socket.getaddrinfo") as resolver:
        with pytest.raises(ValueError, match="allowlist"):
            _read_configured_diagnostics()

    resolver.assert_not_called()


@pytest.mark.unit
@override_settings(
    ANVA_MCP_URL="http://mcp:8001/mcp",
    ANVA_MCP_ALLOWED_HOSTS=("mcp",),
)
def test_product_diagnostic_rejects_wrong_content_type_without_parsing_body() -> None:
    response = Mock()
    response.status = 200
    response.getheader.side_effect = lambda name, default=None: (
        "text/html" if name == "Content-Type" else default
    )
    connection = Mock()
    connection.getresponse.return_value = response
    connected_socket = Mock()

    with (
        patch(
            "anva.integrations.mcp_diagnostics.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8001))],
        ),
        patch(
            "anva.integrations.mcp_diagnostics.socket.socket",
            return_value=connected_socket,
        ),
        patch(
            "anva.integrations.mcp_diagnostics.http.client.HTTPConnection",
            return_value=connection,
        ),
        pytest.raises(ValueError, match="content type"),
    ):
        _read_configured_diagnostics()

    connected_socket.connect.assert_called_once_with(("127.0.0.1", 8001))
    connection.request.assert_called_once_with(
        "GET",
        "/diagnostics",
        headers={"Accept": "application/json", "Host": "mcp:8001"},
    )
    response.read.assert_not_called()
