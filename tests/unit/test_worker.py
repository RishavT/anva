"""Unit tests for the bounded worker shell."""

from __future__ import annotations

import signal
from pathlib import Path
from unittest.mock import patch

import pytest

from anva.entrypoints.worker import Worker, main
from anva.foundation.services import DependencyStatus, ReadinessStatus


@pytest.mark.unit
def test_worker_rejects_invalid_poll_interval() -> None:
    with pytest.raises(ValueError, match="positive"):
        Worker(0)


@pytest.mark.unit
def test_worker_fails_closed_when_dependencies_are_unavailable() -> None:
    status = ReadinessStatus(
        "not_ready",
        (DependencyStatus("database", False, "unavailable"),),
    )

    with patch("anva.foundation.services.readiness_status", return_value=status):
        assert Worker(0.01).run() == 1


@pytest.mark.unit
def test_worker_marks_readiness_and_cleans_up(tmp_path: Path) -> None:
    status = ReadinessStatus(
        "ready",
        (
            DependencyStatus("database", True, "available"),
            DependencyStatus("object_storage", True, "available"),
        ),
    )
    ready_file = tmp_path / "run" / "worker-ready"
    worker = Worker(0.01)

    def stop_after_poll(poll_seconds: float) -> None:
        assert poll_seconds == 0.01
        assert ready_file.exists()
        worker.request_stop(signal.SIGTERM, None)

    with (
        patch("anva.foundation.services.readiness_status", return_value=status),
        patch("anva.entrypoints.worker.READY_FILE", ready_file),
        patch("anva.entrypoints.worker.time.sleep", side_effect=stop_after_poll),
    ):
        assert worker.run() == 0

    assert not ready_file.exists()


@pytest.mark.unit
@pytest.mark.parametrize("poll_seconds", ["immediately", "0", "-1"])
def test_worker_main_rejects_invalid_poll_interval(
    poll_seconds: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_WORKER_POLL_SECONDS", poll_seconds)
    with patch("anva.entrypoints.worker.configure_django"):
        assert main() == 2


@pytest.mark.unit
def test_worker_main_registers_signals_and_delegates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_WORKER_POLL_SECONDS", "1.5")
    with (
        patch("anva.entrypoints.worker.configure_django"),
        patch("anva.entrypoints.worker.signal.signal") as register_signal,
        patch("anva.entrypoints.worker.Worker.run", return_value=0) as run,
    ):
        assert main() == 0

    assert register_signal.call_count == 2
    run.assert_called_once_with()
