"""Dedicated background worker process boundary."""

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
READY_FILE = Path("/app/run/worker-ready")


def process_one_job(*, worker_id: str, lease_seconds: int) -> bool:
    """Claim and safely dispatch at most one allowlisted job."""
    from anva.core.services.context import ActorContext
    from anva.core.services.job_handlers import HANDLERS, dispatch_job
    from anva.core.services.jobs import (
        cancel_job,
        claim_next_job,
        complete_job,
        fail_job,
    )
    from anva.ingestion.errors import IngestionError

    job = claim_next_job(
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        allowed_kinds=frozenset(HANDLERS),
    )
    if job is None:
        return False
    actor = ActorContext(
        organization_id=job.organization_id,
        actor_type="SERVICE",
        actor_id=worker_id,
        authorization_path="internal:worker",
        request_id=uuid.uuid4(),
    )
    try:
        dispatch_job(job, worker_id)
        complete_job(
            actor=actor,
            job_id=job.id,
            worker_id=worker_id,
        )
    except IngestionError as error:
        if error.is_transient:
            fail_job(
                actor=actor,
                job_id=job.id,
                worker_id=worker_id,
                error_code=error.code,
                retry_delay_seconds=5,
            )
        else:
            cancel_job(
                actor=actor,
                job_id=job.id,
                worker_id=worker_id,
                error_code=error.code,
            )
    except Exception:
        LOGGER.exception(
            "job handler failed",
            extra={"job_id": str(job.id), "job_kind": job.kind},
        )
        fail_job(
            actor=actor,
            job_id=job.id,
            worker_id=worker_id,
            error_code="internal_job_failure",
            retry_delay_seconds=5,
        )
    return True


class Worker:
    """Bounded stoppable PostgreSQL job worker."""

    def __init__(self, poll_seconds: float, lease_seconds: int = 300) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        if lease_seconds < 1:
            raise ValueError("lease_seconds must be positive")
        self.poll_seconds = poll_seconds
        self.lease_seconds = lease_seconds
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}"
        self.running = True

    def request_stop(self, signum: int, frame: FrameType | None) -> None:
        """Stop after the current bounded polling interval."""
        del frame
        LOGGER.info("worker stop requested", extra={"signal": signum})
        self.running = False

    def run(self) -> int:
        """Announce readiness, then claim and dispatch bounded jobs."""
        from anva.foundation.services import readiness_status

        status = readiness_status()
        if not status.healthy:
            LOGGER.error("worker dependencies unavailable", extra=status.as_dict())
            return 1

        READY_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        READY_FILE.touch(mode=0o600)
        LOGGER.info("worker ready", extra={"worker_id": self.worker_id})
        try:
            while self.running:
                processed = process_one_job(
                    worker_id=self.worker_id,
                    lease_seconds=self.lease_seconds,
                )
                if not processed:
                    time.sleep(self.poll_seconds)
        finally:
            READY_FILE.unlink(missing_ok=True)
        return 0


def main() -> int:
    """Configure dependencies and run the worker."""
    configure_django()
    raw_poll_seconds = os.getenv("ANVA_WORKER_POLL_SECONDS", "5")
    raw_lease_seconds = os.getenv("ANVA_WORKER_LEASE_SECONDS", "300")
    try:
        poll_seconds = float(raw_poll_seconds)
        lease_seconds = int(raw_lease_seconds)
        worker = Worker(poll_seconds, lease_seconds)
    except ValueError:
        LOGGER.error("Worker poll and lease settings must be positive numbers")
        return 2

    signal.signal(signal.SIGTERM, worker.request_stop)
    signal.signal(signal.SIGINT, worker.request_stop)
    return worker.run()


if __name__ == "__main__":
    raise SystemExit(main())
