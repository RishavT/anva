"""Externally visible HTTP contract tests."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from io import BytesIO
from types import SimpleNamespace
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


@pytest.mark.contract
def test_source_lifecycle_http_contracts(client: Client) -> None:
    source_id = uuid.uuid4()
    run_id = uuid.uuid4()
    repository_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    source = SimpleNamespace(id=source_id, state="ACTIVE", revision=1)
    run = SimpleNamespace(
        id=run_id,
        source_connection_id=source_id,
        access_snapshot_id=uuid.uuid4(),
        scan_mode="FULL",
        state="REQUESTED",
    )
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.views.connect_filesystem_source",
            return_value=(source, True),
        ) as connect,
        patch(
            "anva.core.views.request_ingestion_sync",
            return_value=(run, True),
        ) as sync,
        patch(
            "anva.core.views.inspect_source",
            return_value={"id": str(source_id), "state": "ACTIVE"},
        ),
        patch(
            "anva.core.views.source_sync_runs",
            return_value=[{"id": str(run_id), "state": "REQUESTED"}],
        ),
    ):
        connected = client.post(
            "/api/v1/source-connections/filesystem",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "access_scope_id": str(scope_id),
                    "external_key": "fixture",
                    "display_name": "Fixture",
                    "root": "/fixtures/anva-test",
                }
            ),
            content_type="application/json",
        )
        requested = client.post(
            f"/api/v1/source-connections/{source_id}/sync",
            data=json.dumps({"scan_mode": "FULL"}),
            content_type="application/json",
        )
        inspected = client.get(f"/api/v1/source-connections/{source_id}")
        history = client.get(f"/api/v1/source-connections/{source_id}/sync-runs")

    assert connected.status_code == 201
    assert connected.json()["created"] is True
    assert requested.status_code == 202
    assert requested.json()["access_snapshot_id"] == str(run.access_snapshot_id)
    assert inspected.json() == {"id": str(source_id), "state": "ACTIVE"}
    assert history.json()["sync_runs"][0]["id"] == str(run_id)
    assert connect.call_args.kwargs["root"] == "/fixtures/anva-test"
    assert sync.call_args.kwargs["scan_mode"] == "FULL"


@pytest.mark.contract
def test_source_lifecycle_rejects_unsupported_methods(client: Client) -> None:
    source_id = uuid.uuid4()
    assert client.get("/api/v1/source-connections/filesystem").status_code == 405
    assert client.get(f"/api/v1/source-connections/{source_id}/sync").status_code == 405
    assert client.get(f"/api/v1/source-connections/{source_id}/resync").status_code == 405
