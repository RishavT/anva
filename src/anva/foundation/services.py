"""Service-layer operations for process and dependency health."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from http.client import HTTPConnection
from typing import Final
from urllib.parse import urlparse

from django.conf import settings
from django.db import connection

HEALTH_TIMEOUT_SECONDS: Final[float] = 2.0


@dataclass(frozen=True, slots=True)
class DependencyStatus:
    """A non-secret health assertion for one required dependency."""

    name: str
    healthy: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ReadinessStatus:
    """The deterministic readiness result exposed by every process."""

    status: str
    checks: tuple[DependencyStatus, ...]

    @property
    def healthy(self) -> bool:
        """Return true only when every required dependency is healthy."""
        return all(check.healthy for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        """Serialize without exposing endpoints or credentials."""
        return {
            "status": self.status,
            "checks": [asdict(check) for check in self.checks],
        }


def check_database() -> DependencyStatus:
    """Verify that PostgreSQL accepts a bounded, read-only query."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
    except Exception as error:  # Django adapters expose several backend-specific errors.
        return DependencyStatus(
            name="database",
            healthy=False,
            detail=f"unavailable ({type(error).__name__})",
        )
    return DependencyStatus(
        name="database",
        healthy=result == (1,),
        detail="available" if result == (1,) else "unexpected response",
    )


def check_object_storage() -> DependencyStatus:
    """Verify MinIO's unauthenticated health endpoint with a strict timeout."""
    parsed = urlparse(settings.OBJECT_STORAGE_ENDPOINT)
    if parsed.scheme != "http" or not parsed.hostname:
        return DependencyStatus(
            name="object_storage",
            healthy=False,
            detail="endpoint configuration is invalid",
        )

    client = HTTPConnection(
        parsed.hostname,
        parsed.port or 80,
        timeout=HEALTH_TIMEOUT_SECONDS,
    )
    try:
        client.request("GET", "/minio/health/live")
        response = client.getresponse()
        response.read()
    except OSError:
        return DependencyStatus(
            name="object_storage",
            healthy=False,
            detail="unavailable",
        )
    finally:
        client.close()
    return DependencyStatus(
        name="object_storage",
        healthy=response.status == 200,
        detail="available" if response.status == 200 else f"returned HTTP {response.status}",
    )


def readiness_status() -> ReadinessStatus:
    """Compute readiness through service-owned dependency checks."""
    checks = (check_database(), check_object_storage())
    healthy = all(check.healthy for check in checks)
    return ReadinessStatus(status="ready" if healthy else "not_ready", checks=checks)
