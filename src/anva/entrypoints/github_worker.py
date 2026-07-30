"""Dedicated GitHub event and outbound-write process with isolated credentials."""

from __future__ import annotations

import logging
import os
import signal
import socket
import time
import uuid
from pathlib import Path
from types import FrameType

from anva.entrypoints.bootstrap import configure_django

LOGGER = logging.getLogger(__name__)
READY_FILE = Path("/app/run/github-worker-ready")


def process_one_github_event(*, worker_id: str, lease_seconds: int) -> bool:
    """Claim only GitHub event jobs and dispatch through the provider adapter."""
    from anva.core.models import GitHubWebhookDelivery
    from anva.core.services.context import ActorContext
    from anva.core.services.jobs import claim_next_job, complete_job, fail_job
    from anva.integrations.github.client import GitHubClientError
    from anva.integrations.github.factory import live_client_for_installation
    from anva.integrations.github.service import GITHUB_EVENT_JOB_KIND, process_delivery

    job = claim_next_job(
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        allowed_kinds=frozenset({GITHUB_EVENT_JOB_KIND}),
    )
    if job is None:
        return False
    actor = ActorContext(
        organization_id=job.organization_id,
        actor_type="SERVICE",
        actor_id=worker_id,
        authorization_path="internal:github-worker",
        request_id=uuid.uuid4(),
    )
    try:
        delivery_id = uuid.UUID(str(job.payload["delivery_id"]))
        delivery = GitHubWebhookDelivery.objects.select_related("installation").get(
            id=delivery_id,
            organization_id=job.organization_id,
        )
        client = (
            live_client_for_installation(delivery.installation.external_id)
            if delivery.event_type == "pull_request"
            or (
                delivery.event_type == "installation"
                and delivery.action in {"suspend", "unsuspend"}
            )
            else None
        )
        process_delivery(delivery_id=delivery.id, client=client)
        complete_job(actor=actor, job_id=job.id, worker_id=worker_id)
    except GitHubClientError as error:
        fail_job(
            actor=actor,
            job_id=job.id,
            worker_id=worker_id,
            error_code=error.code,
            retry_delay_seconds=max(error.retry_after_seconds or 5, 5),
        )
    except (KeyError, TypeError, ValueError):
        LOGGER.exception("invalid GitHub event job")
        fail_job(
            actor=actor,
            job_id=job.id,
            worker_id=worker_id,
            error_code="github_event_job_invalid",
        )
    except Exception:
        LOGGER.exception("GitHub event processing failed")
        fail_job(
            actor=actor,
            job_id=job.id,
            worker_id=worker_id,
            error_code="github_event_processing_failed",
            retry_delay_seconds=5,
        )
    return True


class GitHubWorker:
    """Bounded worker for ingress processing, publication materialization, and writes."""

    def __init__(self, *, poll_seconds: float, lease_seconds: int = 300) -> None:
        if poll_seconds <= 0 or lease_seconds < 1:
            raise ValueError("GitHub worker timing must be positive")
        self.poll_seconds = poll_seconds
        self.lease_seconds = lease_seconds
        self.worker_id = f"github:{socket.gethostname()}:{os.getpid()}"
        self.running = True

    def request_stop(self, signum: int, frame: FrameType | None) -> None:
        del frame
        LOGGER.info("GitHub worker stop requested", extra={"signal": signum})
        self.running = False

    def run(self) -> int:
        from django.conf import settings

        from anva.foundation.services import readiness_status
        from anva.integrations.github.factory import live_client_for_installation
        from anva.integrations.github.publication import (
            dispatch_next_write,
            queue_completed_assurance_publications,
        )

        if not settings.ANVA_GITHUB_ENABLED:
            LOGGER.error("GitHub worker cannot start while integration is disabled")
            return 2
        status = readiness_status()
        if not status.healthy:
            LOGGER.error("GitHub worker dependencies unavailable", extra=status.as_dict())
            return 1
        READY_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        READY_FILE.touch(mode=0o600)
        LOGGER.info("GitHub worker ready", extra={"worker_id": self.worker_id})
        try:
            while self.running:
                processed = process_one_github_event(
                    worker_id=self.worker_id,
                    lease_seconds=self.lease_seconds,
                )
                queued = queue_completed_assurance_publications(limit=100)
                write = dispatch_next_write(
                    worker_id=self.worker_id,
                    client_for_installation=live_client_for_installation,
                )
                if not processed and queued == 0 and write is None:
                    time.sleep(self.poll_seconds)
        finally:
            READY_FILE.unlink(missing_ok=True)
        return 0


def main() -> int:
    configure_django()
    try:
        worker = GitHubWorker(
            poll_seconds=float(os.getenv("ANVA_GITHUB_WORKER_POLL_SECONDS", "5")),
            lease_seconds=int(os.getenv("ANVA_GITHUB_WORKER_LEASE_SECONDS", "300")),
        )
    except ValueError:
        LOGGER.error("GitHub worker timing is invalid")
        return 2
    signal.signal(signal.SIGTERM, worker.request_stop)
    signal.signal(signal.SIGINT, worker.request_stop)
    return worker.run()


if __name__ == "__main__":
    raise SystemExit(main())
