"""Unit tests for dependency health behavior."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from anva.foundation.services import (
    DependencyStatus,
    ReadinessStatus,
    check_database,
    check_object_storage,
)


@pytest.mark.unit
def test_readiness_requires_every_dependency() -> None:
    status = ReadinessStatus(
        status="not_ready",
        checks=(
            DependencyStatus("database", True, "available"),
            DependencyStatus("object_storage", False, "unavailable"),
        ),
    )

    assert not status.healthy
    assert status.as_dict()["status"] == "not_ready"


@pytest.mark.unit
@patch("anva.foundation.services.HTTPConnection")
def test_object_storage_health_has_bounded_success(mock_connection: MagicMock) -> None:
    response = mock_connection.return_value.getresponse.return_value
    response.status = 200

    status = check_object_storage()

    assert status == DependencyStatus("object_storage", True, "available")
    mock_connection.assert_called_once()
    assert mock_connection.call_args.kwargs["timeout"] == 2.0
    mock_connection.return_value.close.assert_called_once()


@pytest.mark.unit
@patch("anva.foundation.services.HTTPConnection")
def test_object_storage_health_redacts_connection_errors(mock_connection: MagicMock) -> None:
    mock_connection.return_value.request.side_effect = OSError("secret endpoint detail")

    status = check_object_storage()

    assert status == DependencyStatus("object_storage", False, "unavailable")
    assert "secret" not in status.detail


@pytest.mark.unit
def test_object_storage_health_rejects_non_http_configuration(
    settings: MagicMock,
) -> None:
    settings.OBJECT_STORAGE_ENDPOINT = "https://objects.example.test"

    assert check_object_storage() == DependencyStatus(
        "object_storage",
        False,
        "endpoint configuration is invalid",
    )


@pytest.mark.unit
@patch("anva.foundation.services.connection")
def test_database_health_returns_sanitized_adapter_failure(mock_connection: MagicMock) -> None:
    mock_connection.cursor.side_effect = RuntimeError("database password leaked here")

    status = check_database()

    assert status == DependencyStatus("database", False, "unavailable (RuntimeError)")
    assert "password" not in status.detail
