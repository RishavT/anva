"""Unit tests for the isolated GitHub worker process."""

from __future__ import annotations

import signal
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, patch

import pytest
from pytest_django.fixtures import SettingsWrapper

from anva.entrypoints.github_worker import (
    GitHubWorker,
    main,
    process_one_github_event,
)
from anva.foundation.services import DependencyStatus, ReadinessStatus
from anva.integrations.github.service import GITHUB_EVENT_JOB_KIND


@pytest.mark.unit
def test_github_event_worker_claims_only_github_event_jobs() -> None:
    with patch("anva.core.services.jobs.claim_next_job", return_value=None) as claim:
        assert process_one_github_event(worker_id="github-worker", lease_seconds=300) is False

    claim.assert_called_once_with(
        worker_id="github-worker",
        lease_seconds=300,
        allowed_kinds=frozenset({GITHUB_EVENT_JOB_KIND}),
    )


@pytest.mark.unit
@pytest.mark.parametrize("action", ["suspend", "unsuspend"])
def test_github_event_worker_builds_app_client_for_lifecycle_state_read(action: str) -> None:
    organization_id = uuid.uuid4()
    job_id = uuid.uuid4()
    delivery_id = uuid.uuid4()
    job = SimpleNamespace(
        id=job_id,
        organization_id=organization_id,
        payload={"delivery_id": str(delivery_id)},
    )
    delivery = SimpleNamespace(
        id=delivery_id,
        organization_id=organization_id,
        event_type="installation",
        action=action,
        installation=SimpleNamespace(external_id=67890),
    )
    delivery_query = MagicMock()
    delivery_query.get.return_value = delivery
    provider_client = MagicMock()

    with (
        patch("anva.core.services.jobs.claim_next_job", return_value=job),
        patch(
            "anva.core.models.GitHubWebhookDelivery.objects.select_related",
            return_value=delivery_query,
        ),
        patch(
            "anva.integrations.github.factory.live_client_for_installation",
            return_value=provider_client,
        ) as client_factory,
        patch("anva.integrations.github.service.process_delivery") as process_delivery,
        patch("anva.core.services.jobs.complete_job") as complete_job,
    ):
        assert process_one_github_event(worker_id="github-worker", lease_seconds=300) is True

    client_factory.assert_called_once_with(67890)
    process_delivery.assert_called_once_with(
        delivery_id=delivery_id,
        client=provider_client,
    )
    complete_job.assert_called_once_with(
        actor=ANY,
        job_id=job_id,
        worker_id="github-worker",
    )


@pytest.mark.unit
def test_github_worker_fails_closed_when_integration_is_disabled(
    settings: SettingsWrapper,
) -> None:
    settings.ANVA_GITHUB_ENABLED = False

    assert GitHubWorker(poll_seconds=0.01).run() == 2


@pytest.mark.unit
def test_github_worker_marks_readiness_and_cleans_up(
    tmp_path: Path,
    settings: SettingsWrapper,
) -> None:
    settings.ANVA_GITHUB_ENABLED = True
    status = ReadinessStatus(
        "ready",
        (
            DependencyStatus("database", True, "available"),
            DependencyStatus("object_storage", True, "available"),
        ),
    )
    ready_file = tmp_path / "run" / "github-worker-ready"
    worker = GitHubWorker(poll_seconds=0.01)

    def stop_after_poll(poll_seconds: float) -> None:
        assert poll_seconds == 0.01
        assert ready_file.exists()
        worker.request_stop(signal.SIGTERM, None)

    with (
        patch("anva.foundation.services.readiness_status", return_value=status),
        patch("anva.entrypoints.github_worker.READY_FILE", ready_file),
        patch("anva.entrypoints.github_worker.process_one_github_event", return_value=False),
        patch(
            "anva.integrations.github.publication.queue_completed_assurance_publications",
            return_value=0,
        ),
        patch(
            "anva.integrations.github.publication.dispatch_next_write",
            return_value=None,
        ),
        patch("anva.entrypoints.github_worker.time.sleep", side_effect=stop_after_poll),
    ):
        assert worker.run() == 0

    assert not ready_file.exists()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("poll_seconds", "lease_seconds"),
    [("immediately", "300"), ("0", "300"), ("1", "0")],
)
def test_github_worker_main_rejects_invalid_timing(
    poll_seconds: str,
    lease_seconds: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_GITHUB_WORKER_POLL_SECONDS", poll_seconds)
    monkeypatch.setenv("ANVA_GITHUB_WORKER_LEASE_SECONDS", lease_seconds)
    with patch("anva.entrypoints.github_worker.configure_django"):
        assert main() == 2
