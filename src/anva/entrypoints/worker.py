"""Dedicated background worker process boundary."""

from __future__ import annotations

import logging
import os
import signal
import time
from pathlib import Path
from types import FrameType

from anva.entrypoints.bootstrap import configure_django

LOGGER = logging.getLogger(__name__)
READY_FILE = Path("/app/run/worker-ready")


class Worker:
    """Minimal stoppable worker that introduces no workflow-engine dependency."""

    def __init__(self, poll_seconds: float) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        self.poll_seconds = poll_seconds
        self.running = True

    def request_stop(self, signum: int, frame: FrameType | None) -> None:
        """Stop after the current bounded polling interval."""
        del frame
        LOGGER.info("worker stop requested", extra={"signal": signum})
        self.running = False

    def run(self) -> int:
        """Announce readiness, then hold the process boundary for future jobs."""
        from anva.foundation.services import readiness_status

        status = readiness_status()
        if not status.healthy:
            LOGGER.error("worker dependencies unavailable", extra=status.as_dict())
            return 1

        READY_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        READY_FILE.touch(mode=0o600)
        LOGGER.info("worker ready; no job handlers are registered in foundation issue #1")
        try:
            while self.running:
                time.sleep(self.poll_seconds)
        finally:
            READY_FILE.unlink(missing_ok=True)
        return 0


def main() -> int:
    """Configure dependencies and run the worker."""
    configure_django()
    raw_poll_seconds = os.getenv("ANVA_WORKER_POLL_SECONDS", "5")
    try:
        poll_seconds = float(raw_poll_seconds)
        worker = Worker(poll_seconds)
    except ValueError:
        LOGGER.error("ANVA_WORKER_POLL_SECONDS must be a positive number")
        return 2

    signal.signal(signal.SIGTERM, worker.request_stop)
    signal.signal(signal.SIGINT, worker.request_stop)
    return worker.run()


if __name__ == "__main__":
    raise SystemExit(main())
