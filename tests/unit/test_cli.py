"""Unit tests for the administrative CLI contract."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from anva import __version__
from anva.entrypoints.cli import main
from anva.foundation.services import DependencyStatus, ReadinessStatus


@pytest.mark.unit
def test_version_command_does_not_initialize_django(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("anva.entrypoints.cli.configure_django") as configure:
        result = main(["version"])

    assert result == 0
    assert capsys.readouterr().out.strip() == __version__
    configure.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("healthy", "expected_code", "expected_status"),
    [(True, 0, "ready"), (False, 1, "not_ready")],
)
def test_status_command_returns_machine_readable_result(
    healthy: bool,
    expected_code: int,
    expected_status: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dependency = DependencyStatus("database", healthy, "available" if healthy else "unavailable")
    status = ReadinessStatus(expected_status, (dependency,))
    with (
        patch("anva.entrypoints.cli.configure_django"),
        patch("anva.foundation.services.readiness_status", return_value=status),
    ):
        result = main(["status"])

    assert result == expected_code
    assert json.loads(capsys.readouterr().out)["status"] == expected_status
