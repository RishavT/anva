"""Explicit allowlist registry for background job handlers."""

from __future__ import annotations

from collections.abc import Callable

from anva.core.models import BackgroundJob
from anva.core.services.ingestion import INGESTION_JOB_KIND, execute_ingestion_job
from anva.ingestion.errors import IngestionError

type JobHandler = Callable[[BackgroundJob, str], None]


def _ingestion_handler(job: BackgroundJob, worker_id: str) -> None:
    execute_ingestion_job(job=job, worker_id=worker_id)


HANDLERS: dict[str, JobHandler] = {
    INGESTION_JOB_KIND: _ingestion_handler,
}


def dispatch_job(job: BackgroundJob, worker_id: str) -> None:
    """Dispatch only registered kinds; payloads can never select executable code."""
    handler = HANDLERS.get(job.kind)
    if handler is None:
        raise IngestionError(
            "unregistered_job_kind",
            "Background job kind is not registered",
        )
    handler(job, worker_id)
