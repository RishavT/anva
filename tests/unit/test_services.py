"""Unit tests for dependency health behavior."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from anva.foundation.services import (
    DependencyStatus,
    ReadinessStatus,
    check_database,
    check_migrations,
    check_object_storage,
    readiness_status,
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
@override_settings(OBJECT_STORAGE_BUCKET="anva")
def test_object_storage_health_has_bounded_success(mock_connection: MagicMock) -> None:
    response = mock_connection.return_value.getresponse.return_value
    response.status = 200

    status = check_object_storage()

    assert status == DependencyStatus("object_storage", True, "available")
    mock_connection.assert_called_once()
    assert mock_connection.call_args.kwargs["timeout"] == 2.0
    request = mock_connection.return_value.request
    request.assert_called_once()
    assert request.call_args.args == ("HEAD", "/anva")
    headers = request.call_args.kwargs["headers"]
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=")
    assert "anva-local-only" not in str(headers)
    mock_connection.return_value.close.assert_called_once()


@pytest.mark.unit
@patch("anva.foundation.services.HTTPConnection")
def test_object_storage_health_redacts_connection_errors(mock_connection: MagicMock) -> None:
    mock_connection.return_value.request.side_effect = OSError("secret endpoint detail")

    status = check_object_storage()

    assert status == DependencyStatus("object_storage", False, "unavailable")
    assert "secret" not in status.detail


@pytest.mark.unit
def test_object_storage_health_rejects_unsafe_configuration(
    settings: MagicMock,
) -> None:
    settings.OBJECT_STORAGE_ENDPOINT = "https://user:password@objects.example.test?token=secret"

    assert check_object_storage() == DependencyStatus(
        "object_storage",
        False,
        "endpoint configuration is invalid",
    )


@pytest.mark.unit
@patch("anva.foundation.services.HTTPSConnection")
def test_object_storage_health_supports_authenticated_https(
    mock_connection: MagicMock,
    settings: MagicMock,
) -> None:
    settings.OBJECT_STORAGE_ENDPOINT = "https://objects.example.test:9443"
    settings.OBJECT_STORAGE_BUCKET = "governed-evidence"
    response = mock_connection.return_value.getresponse.return_value
    response.status = 200

    assert check_object_storage().healthy

    mock_connection.assert_called_once_with("objects.example.test", 9443, timeout=2.0)
    request = mock_connection.return_value.request
    assert request.call_args.args == ("HEAD", "/governed-evidence")
    assert request.call_args.kwargs["headers"]["Host"] == "objects.example.test:9443"


@pytest.mark.unit
@patch("anva.foundation.services.MigrationExecutor")
def test_migration_health_reports_current_or_pending_without_names(
    mock_executor: MagicMock,
) -> None:
    executor = mock_executor.return_value
    executor.loader.graph.leaf_nodes.return_value = [("core", "0020_operations")]
    executor.migration_plan.return_value = []

    assert check_migrations() == DependencyStatus("migrations", True, "current")

    executor.migration_plan.return_value = [(object(), False)]
    status = check_migrations()
    assert status == DependencyStatus("migrations", False, "pending")
    assert "core" not in status.detail


@pytest.mark.unit
def test_readiness_short_circuits_migrations_when_database_is_unavailable() -> None:
    database = DependencyStatus("database", False, "unavailable")
    storage = DependencyStatus("object_storage", True, "available")
    with (
        patch("anva.foundation.services.check_database", return_value=database),
        patch("anva.foundation.services.check_migrations") as migrations,
        patch("anva.foundation.services.check_object_storage", return_value=storage),
    ):
        status = readiness_status()

    assert not status.healthy
    assert status.checks[1] == DependencyStatus("migrations", False, "database unavailable")
    migrations.assert_not_called()


@pytest.mark.unit
@patch("anva.foundation.services.connection")
def test_database_health_returns_sanitized_adapter_failure(mock_connection: MagicMock) -> None:
    mock_connection.cursor.side_effect = RuntimeError("database password leaked here")

    status = check_database()

    assert status == DependencyStatus("database", False, "unavailable (RuntimeError)")
    assert "password" not in status.detail
