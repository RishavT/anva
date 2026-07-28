"""Allowlist behavior for the background job dispatcher."""

from __future__ import annotations

import pytest

from anva.core.models import BackgroundJob
from anva.core.services.job_handlers import dispatch_job
from anva.ingestion.errors import IngestionError


@pytest.mark.unit
def test_unregistered_job_kinds_are_inert() -> None:
    job = BackgroundJob(
        kind="python:os.system",
        payload={"callable": "os.system", "arguments": ["untrusted-command"]},
    )

    with pytest.raises(IngestionError, match="not registered") as failure:
        dispatch_job(job, "worker-test")

    assert failure.value.code == "unregistered_job_kind"
