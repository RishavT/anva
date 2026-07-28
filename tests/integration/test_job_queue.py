"""PostgreSQL job queue lease, retry, idempotency, and concurrency tests."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from django.db import close_old_connections, connection
from django.utils import timezone

from anva.core.exceptions import (
    IdempotencyConflictError,
    LeaseConflictError,
    ResourceNotFoundError,
)
from anva.core.models import AuditEvent, BackgroundJob, Organization, OutboxEvent
from anva.core.services.authorization import NOT_FOUND_MESSAGE
from anva.core.services.context import ActorContext
from anva.core.services.jobs import (
    claim_next_job,
    complete_job,
    enqueue_job,
    fail_job,
)


def actor_for(organization: Organization) -> ActorContext:
    return ActorContext(
        organization_id=organization.id,
        actor_type="SERVICE",
        actor_id="scheduler",
        authorization_path="internal:scheduler",
        request_id=uuid.uuid4(),
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_enqueue_is_idempotent_and_rejects_key_reuse() -> None:
    organization = Organization.objects.create(slug="jobs", name="Jobs")
    actor = actor_for(organization)

    first, created = enqueue_job(
        actor=actor,
        kind="source.sync",
        payload={"source_id": "17"},
        idempotency_key="source-sync-17",
    )
    second, created_again = enqueue_job(
        actor=actor,
        kind="source.sync",
        payload={"source_id": "17"},
        idempotency_key="source-sync-17",
    )

    assert created
    assert not created_again
    assert first.id == second.id
    assert AuditEvent.objects.filter(target_id=first.id).count() == 1
    assert OutboxEvent.objects.filter(aggregate_id=first.id).count() == 1
    with pytest.raises(IdempotencyConflictError):
        enqueue_job(
            actor=actor,
            kind="source.sync",
            payload={"source_id": "different"},
            idempotency_key="source-sync-17",
        )


@pytest.mark.integration
@pytest.mark.django_db
def test_failure_retains_attempt_and_retries_before_terminal_failure() -> None:
    organization = Organization.objects.create(slug="retry", name="Retry")
    actor = actor_for(organization)
    job, _ = enqueue_job(
        actor=actor,
        kind="assurance.evaluate",
        payload={"run_id": "42"},
        idempotency_key="assurance-42",
        max_attempts=2,
    )
    started = timezone.now()
    first_claim = claim_next_job(worker_id="worker-1", lease_seconds=30, now=started)
    assert first_claim is not None

    retry = fail_job(
        actor=actor,
        job_id=job.id,
        worker_id="worker-1",
        error_code="MODEL_TIMEOUT",
        retry_delay_seconds=5,
        now=started + timedelta(seconds=1),
    )
    assert retry.state == BackgroundJob.State.PENDING
    assert retry.attempt_count == 1
    assert retry.last_error == "MODEL_TIMEOUT"
    assert (
        claim_next_job(
            worker_id="worker-2",
            lease_seconds=30,
            now=started + timedelta(seconds=4),
        )
        is None
    )

    second_claim = claim_next_job(
        worker_id="worker-2",
        lease_seconds=30,
        now=started + timedelta(seconds=6),
    )
    assert second_claim is not None
    terminal = fail_job(
        actor=actor,
        job_id=job.id,
        worker_id="worker-2",
        error_code="MODEL_TIMEOUT",
        now=started + timedelta(seconds=7),
    )
    assert terminal.state == BackgroundJob.State.FAILED
    assert terminal.attempt_count == 2
    assert terminal.completed_at is not None
    assert AuditEvent.objects.filter(target_id=job.id).count() == 5
    assert OutboxEvent.objects.filter(aggregate_id=job.id).count() == 5


@pytest.mark.integration
@pytest.mark.django_db
def test_completion_requires_current_lease_and_is_idempotent() -> None:
    organization = Organization.objects.create(slug="lease", name="Lease")
    actor = actor_for(organization)
    job, _ = enqueue_job(
        actor=actor,
        kind="outbox.publish",
        payload={},
        idempotency_key="outbox-1",
    )
    started = timezone.now()
    assert claim_next_job(worker_id="worker-1", lease_seconds=5, now=started) is not None

    with pytest.raises(LeaseConflictError):
        complete_job(
            actor=actor,
            job_id=job.id,
            worker_id="worker-2",
            now=started + timedelta(seconds=1),
        )
    completed = complete_job(
        actor=actor,
        job_id=job.id,
        worker_id="worker-1",
        now=started + timedelta(seconds=1),
    )
    repeated = complete_job(
        actor=actor,
        job_id=job.id,
        worker_id="worker-1",
        now=started + timedelta(seconds=2),
    )

    assert completed.state == BackgroundJob.State.SUCCEEDED
    assert repeated.id == completed.id
    assert AuditEvent.objects.filter(target_id=job.id).count() == 3


@pytest.mark.integration
@pytest.mark.django_db
def test_job_terminal_noop_and_failure_hide_foreign_or_missing_ids() -> None:
    owner = Organization.objects.create(slug="job-owner", name="Job Owner")
    caller = Organization.objects.create(slug="job-caller", name="Job Caller")
    now = timezone.now()
    foreign_terminal = BackgroundJob.objects.create(
        organization=owner,
        kind="source.sync",
        payload={},
        state=BackgroundJob.State.SUCCEEDED,
        idempotency_key="foreign-terminal",
        completed_at=now,
    )
    foreign_running = BackgroundJob.objects.create(
        organization=owner,
        kind="source.sync",
        payload={},
        state=BackgroundJob.State.RUNNING,
        idempotency_key="foreign-running",
        attempt_count=1,
        lease_owner="worker",
        lease_expires_at=now + timedelta(minutes=1),
    )
    actor = actor_for(caller)
    missing_id = uuid.uuid4()

    operations: list[Callable[[], BackgroundJob]] = [
        lambda: complete_job(
            actor=actor,
            job_id=foreign_terminal.id,
            worker_id="worker",
            now=now,
        ),
        lambda: complete_job(
            actor=actor,
            job_id=missing_id,
            worker_id="worker",
            now=now,
        ),
        lambda: fail_job(
            actor=actor,
            job_id=foreign_running.id,
            worker_id="worker",
            error_code="FAILED",
            now=now,
        ),
        lambda: fail_job(
            actor=actor,
            job_id=missing_id,
            worker_id="worker",
            error_code="FAILED",
            now=now,
        ),
    ]
    errors: list[tuple[str, str]] = []
    for operation in operations:
        with pytest.raises(ResourceNotFoundError) as captured:
            operation()
        errors.append((captured.value.code, str(captured.value)))

    assert set(errors) == {("resource_not_found", NOT_FOUND_MESSAGE)}


@pytest.mark.integration
@pytest.mark.django_db
def test_expired_final_attempt_is_terminally_failed_and_retained() -> None:
    organization = Organization.objects.create(slug="expired", name="Expired")
    actor = actor_for(organization)
    job, _ = enqueue_job(
        actor=actor,
        kind="source.sync",
        payload={},
        idempotency_key="expired-final",
        max_attempts=1,
    )
    started = timezone.now()
    assert claim_next_job(worker_id="worker-1", lease_seconds=5, now=started) is not None

    assert (
        claim_next_job(
            worker_id="recovery-worker",
            lease_seconds=5,
            now=started + timedelta(seconds=6),
        )
        is None
    )
    job.refresh_from_db()
    assert job.state == BackgroundJob.State.FAILED
    assert job.attempt_count == 1
    assert job.last_error == "LEASE_EXPIRED_AFTER_FINAL_ATTEMPT"
    assert job.completed_at is not None


def claim_in_thread(worker_id: str) -> uuid.UUID | None:
    close_old_connections()
    try:
        claimed = claim_next_job(worker_id=worker_id, lease_seconds=30)
        return claimed.id if claimed is not None else None
    finally:
        connection.close()


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_concurrent_workers_claim_a_job_once() -> None:
    organization = Organization.objects.create(slug="concurrent", name="Concurrent")
    enqueue_job(
        actor=actor_for(organization),
        kind="source.sync",
        payload={"source_id": "shared"},
        idempotency_key="shared-job",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim_in_thread, ["worker-a", "worker-b"]))

    assert len([result for result in results if result is not None]) == 1
    job = BackgroundJob.objects.get()
    assert job.state == BackgroundJob.State.RUNNING
    assert job.attempt_count == 1
