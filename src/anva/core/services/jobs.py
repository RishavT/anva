"""PostgreSQL job claiming, leasing, retries, and idempotent completion."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from anva.core.exceptions import (
    IdempotencyConflictError,
    LeaseConflictError,
)
from anva.core.models import BackgroundJob, Organization
from anva.core.services.authorization import get_tenant_record_for_update
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition


def enqueue_job(
    *,
    actor: ActorContext,
    kind: str,
    payload: dict[str, object],
    idempotency_key: str,
    max_attempts: int = 3,
    priority: int = 0,
) -> tuple[BackgroundJob, bool]:
    """Create one job and outbox event, or return its exact idempotent predecessor."""
    if not kind.strip() or not idempotency_key.strip():
        raise ValueError("kind and idempotency_key are required")
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    with transaction.atomic():
        organization = Organization.objects.select_for_update().get(id=actor.organization_id)
        existing = BackgroundJob.objects.filter(
            organization=organization,
            idempotency_key=idempotency_key,
        ).first()
        if existing is not None:
            if existing.kind != kind or existing.payload != payload:
                raise IdempotencyConflictError(
                    "Job idempotency key was already used for different work"
                )
            return existing, False

        job = BackgroundJob.objects.create(
            organization=organization,
            kind=kind,
            payload=payload,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
            priority=priority,
        )
        record_transition(
            organization=organization,
            actor=actor,
            target_type="backgroundjob",
            target_id=job.id,
            from_state="",
            to_state=BackgroundJob.State.PENDING,
            revision=0,
            metadata={"kind": kind},
        )
        return job, True


def claim_next_job(
    *,
    worker_id: str,
    lease_seconds: int,
    allowed_kinds: frozenset[str] | None = None,
    now: datetime | None = None,
) -> BackgroundJob | None:
    """Atomically claim one available or expired job using `SKIP LOCKED`."""
    if not worker_id.strip():
        raise ValueError("worker_id is required")
    if lease_seconds < 1:
        raise ValueError("lease_seconds must be positive")
    claimed_at = now or timezone.now()
    with transaction.atomic():
        exhausted_jobs = list(
            BackgroundJob.objects.select_for_update(skip_locked=True)
            .select_related("organization")
            .filter(
                state=BackgroundJob.State.RUNNING,
                lease_expires_at__lte=claimed_at,
                attempt_count__gte=F("max_attempts"),
            )
            .order_by("lease_expires_at")[:100]
        )
        for exhausted in exhausted_jobs:
            exhausted.state = BackgroundJob.State.FAILED
            exhausted.lease_owner = None
            exhausted.lease_expires_at = None
            exhausted.completed_at = claimed_at
            exhausted.last_error = "LEASE_EXPIRED_AFTER_FINAL_ATTEMPT"
            exhausted.save(
                update_fields=[
                    "state",
                    "lease_owner",
                    "lease_expires_at",
                    "completed_at",
                    "last_error",
                    "updated_at",
                ]
            )
            exhausted_actor = ActorContext(
                organization_id=exhausted.organization_id,
                actor_type="SERVICE",
                actor_id=worker_id,
                authorization_path="internal:job-claim",
                request_id=uuid.uuid4(),
            )
            record_transition(
                organization=exhausted.organization,
                actor=exhausted_actor,
                target_type="backgroundjob",
                target_id=exhausted.id,
                from_state=BackgroundJob.State.RUNNING,
                to_state=BackgroundJob.State.FAILED,
                revision=exhausted.attempt_count,
                metadata={"error_code": exhausted.last_error},
            )

        eligible = Q(
            state=BackgroundJob.State.PENDING,
            available_at__lte=claimed_at,
            attempt_count__lt=F("max_attempts"),
        ) | Q(
            state=BackgroundJob.State.RUNNING,
            lease_expires_at__lte=claimed_at,
            attempt_count__lt=F("max_attempts"),
        )
        candidates = (
            BackgroundJob.objects.select_for_update(skip_locked=True)
            .select_related("organization")
            .filter(eligible)
        )
        if allowed_kinds is not None:
            candidates = candidates.filter(kind__in=allowed_kinds)
        job = candidates.order_by("-priority", "available_at", "created_at").first()
        if job is None:
            return None

        previous_state = str(job.state)
        job.state = BackgroundJob.State.RUNNING
        job.attempt_count += 1
        job.lease_owner = worker_id
        job.lease_expires_at = claimed_at + timedelta(seconds=lease_seconds)
        job.save(
            update_fields=[
                "state",
                "attempt_count",
                "lease_owner",
                "lease_expires_at",
                "updated_at",
            ]
        )
        actor = ActorContext(
            organization_id=job.organization_id,
            actor_type="SERVICE",
            actor_id=worker_id,
            authorization_path="internal:job-claim",
            request_id=uuid.uuid4(),
        )
        record_transition(
            organization=job.organization,
            actor=actor,
            target_type="backgroundjob",
            target_id=job.id,
            from_state=previous_state,
            to_state=BackgroundJob.State.RUNNING,
            revision=job.attempt_count,
            metadata={"lease_owner": worker_id},
        )
        return job


def require_current_lease(
    *,
    job: BackgroundJob,
    worker_id: str,
    now: datetime,
) -> None:
    """Fail closed when a worker no longer owns a live lease."""
    if (
        job.state != BackgroundJob.State.RUNNING
        or job.lease_owner != worker_id
        or job.lease_expires_at is None
        or job.lease_expires_at <= now
    ):
        raise LeaseConflictError("Worker does not own a current lease for this job")


def complete_job(
    *,
    actor: ActorContext,
    job_id: uuid.UUID,
    worker_id: str,
    now: datetime | None = None,
) -> BackgroundJob:
    """Complete a leased job exactly once."""
    completed_at = now or timezone.now()
    with transaction.atomic():
        job = get_tenant_record_for_update(
            queryset=BackgroundJob.objects.select_related("organization"),
            record_id=job_id,
            organization_id=actor.organization_id,
        )
        if job.state == BackgroundJob.State.SUCCEEDED:
            return job
        require_current_lease(job=job, worker_id=worker_id, now=completed_at)
        job.state = BackgroundJob.State.SUCCEEDED
        job.lease_owner = None
        job.lease_expires_at = None
        job.completed_at = completed_at
        job.save(
            update_fields=[
                "state",
                "lease_owner",
                "lease_expires_at",
                "completed_at",
                "updated_at",
            ]
        )
        record_transition(
            organization=job.organization,
            actor=actor,
            target_type="backgroundjob",
            target_id=job.id,
            from_state=BackgroundJob.State.RUNNING,
            to_state=BackgroundJob.State.SUCCEEDED,
            revision=job.attempt_count,
        )
        return job


def fail_job(
    *,
    actor: ActorContext,
    job_id: uuid.UUID,
    worker_id: str,
    error_code: str,
    retry_delay_seconds: int = 0,
    now: datetime | None = None,
) -> BackgroundJob:
    """Retain attempt history and either retry or terminally fail a leased job."""
    if retry_delay_seconds < 0:
        raise ValueError("retry_delay_seconds cannot be negative")
    failed_at = now or timezone.now()
    with transaction.atomic():
        job = get_tenant_record_for_update(
            queryset=BackgroundJob.objects.select_related("organization"),
            record_id=job_id,
            organization_id=actor.organization_id,
        )
        require_current_lease(job=job, worker_id=worker_id, now=failed_at)
        next_state = (
            BackgroundJob.State.FAILED
            if job.attempt_count >= job.max_attempts
            else BackgroundJob.State.PENDING
        )
        job.state = next_state
        job.lease_owner = None
        job.lease_expires_at = None
        job.last_error = error_code
        job.available_at = failed_at + timedelta(seconds=retry_delay_seconds)
        job.completed_at = failed_at if next_state == BackgroundJob.State.FAILED else None
        job.save(
            update_fields=[
                "state",
                "lease_owner",
                "lease_expires_at",
                "last_error",
                "available_at",
                "completed_at",
                "updated_at",
            ]
        )
        record_transition(
            organization=job.organization,
            actor=actor,
            target_type="backgroundjob",
            target_id=job.id,
            from_state=BackgroundJob.State.RUNNING,
            to_state=next_state,
            revision=job.attempt_count,
            metadata={"error_code": error_code},
        )
        return job


def cancel_job(
    *,
    actor: ActorContext,
    job_id: uuid.UUID,
    worker_id: str,
    error_code: str,
    now: datetime | None = None,
) -> BackgroundJob:
    """Cancel non-retryable leased work while retaining an observable reason."""
    cancelled_at = now or timezone.now()
    with transaction.atomic():
        job = get_tenant_record_for_update(
            queryset=BackgroundJob.objects.select_related("organization"),
            record_id=job_id,
            organization_id=actor.organization_id,
        )
        if job.state == BackgroundJob.State.CANCELLED:
            return job
        require_current_lease(job=job, worker_id=worker_id, now=cancelled_at)
        job.state = BackgroundJob.State.CANCELLED
        job.lease_owner = None
        job.lease_expires_at = None
        job.last_error = error_code
        job.completed_at = cancelled_at
        job.save(
            update_fields=[
                "state",
                "lease_owner",
                "lease_expires_at",
                "last_error",
                "completed_at",
                "updated_at",
            ]
        )
        record_transition(
            organization=job.organization,
            actor=actor,
            target_type="backgroundjob",
            target_id=job.id,
            from_state=BackgroundJob.State.RUNNING,
            to_state=BackgroundJob.State.CANCELLED,
            revision=job.attempt_count,
            metadata={"error_code": error_code},
        )
        return job
