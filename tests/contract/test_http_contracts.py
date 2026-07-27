"""Externally visible HTTP contract tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from io import BytesIO
from typing import Any
from unittest.mock import patch

import pytest
from django.test import Client

from anva.entrypoints.mcp import application
from anva.foundation.services import DependencyStatus, ReadinessStatus


@pytest.mark.contract
def test_api_liveness_contract(client: Client) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert set(response.json()) == {"status", "version"}
    assert response.json()["status"] == "alive"


@pytest.mark.contract
def test_api_readiness_contract(client: Client, ready_dependencies: None) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": [
            {"name": "database", "healthy": True, "detail": "available"},
            {"name": "object_storage", "healthy": True, "detail": "available"},
        ],
    }


@pytest.mark.contract
def test_api_health_endpoints_reject_unsupported_methods(client: Client) -> None:
    assert client.post("/health/live").status_code == 405
    assert client.post("/health/ready").status_code == 405


def call_mcp(path: str, method: str = "GET") -> tuple[str, dict[str, object]]:
    """Invoke the MCP WSGI contract without a listening socket."""
    result_status = ""

    def start_response(
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> Callable[[bytes], object]:
        del headers, exc_info
        nonlocal result_status
        result_status = status
        return BytesIO().write

    chunks = application(
        {"PATH_INFO": path, "REQUEST_METHOD": method},
        start_response,
    )
    return result_status, json.loads(b"".join(chunks))


@pytest.mark.contract
def test_mcp_explicitly_does_not_claim_protocol_readiness() -> None:
    status, payload = call_mcp("/mcp")

    assert status == "501 Not Implemented"
    assert payload["error"] == "mcp_not_implemented"


@pytest.mark.contract
def test_mcp_liveness_contract() -> None:
    status, payload = call_mcp("/health/live")

    assert status == "200 OK"
    assert payload["service"] == "mcp"
    assert payload["status"] == "alive"


@pytest.mark.contract
@pytest.mark.parametrize(
    ("healthy", "expected_http"),
    [(True, "200 OK"), (False, "503 Service Unavailable")],
)
def test_mcp_readiness_contract(healthy: bool, expected_http: str) -> None:
    dependency = DependencyStatus("database", healthy, "available" if healthy else "unavailable")
    readiness = ReadinessStatus("ready" if healthy else "not_ready", (dependency,))

    with patch("anva.foundation.services.readiness_status", return_value=readiness):
        status, payload = call_mcp("/health/ready")

    assert status == expected_http
    assert payload["status"] == readiness.status


@pytest.mark.contract
def test_mcp_rejects_unknown_routes_and_methods() -> None:
    assert call_mcp("/missing")[0] == "404 Not Found"
    assert call_mcp("/health/live", "POST")[0] == "405 Method Not Allowed"
