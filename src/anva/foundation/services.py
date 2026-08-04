"""Service-layer operations for process and dependency health."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.client import HTTPConnection, HTTPSConnection
from typing import Final
from urllib.parse import urlparse

from django.conf import settings
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

HEALTH_TIMEOUT_SECONDS: Final[float] = 2.0


def _signing_key(secret: str, *, date: str, region: str) -> bytes:
    date_key = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def _bucket_headers(*, host: str, path: str, now: datetime) -> dict[str, str]:
    """Create a minimal AWS Signature V4 HEAD request without exposing credentials."""
    timestamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    date = timestamp[:8]
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = (
        f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{timestamp}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join(
        ("HEAD", path, "", canonical_headers, signed_headers, payload_hash)
    )
    scope = f"{date}/{settings.OBJECT_STORAGE_REGION}/s3/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            timestamp,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )
    signature = hmac.new(
        _signing_key(
            str(settings.OBJECT_STORAGE_SECRET_KEY),
            date=date,
            region=str(settings.OBJECT_STORAGE_REGION),
        ),
        string_to_sign.encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Host": host,
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Date": timestamp,
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            f"Credential={settings.OBJECT_STORAGE_ACCESS_KEY}/{scope},"
            f"SignedHeaders={signed_headers},Signature={signature}"
        ),
    }


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
    """Verify authenticated access to the configured S3-compatible bucket."""
    parsed = urlparse(settings.OBJECT_STORAGE_ENDPOINT)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return DependencyStatus(
            name="object_storage",
            healthy=False,
            detail="endpoint configuration is invalid",
        )

    connection_class = HTTPSConnection if parsed.scheme == "https" else HTTPConnection
    client = connection_class(
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
        timeout=HEALTH_TIMEOUT_SECONDS,
    )
    try:
        bucket_path = f"/{settings.OBJECT_STORAGE_BUCKET}"
        client.request(
            "HEAD",
            bucket_path,
            headers=_bucket_headers(host=parsed.netloc, path=bucket_path, now=datetime.now(UTC)),
        )
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
        detail="available" if response.status == 200 else "unavailable",
    )


def check_migrations() -> DependencyStatus:
    """Require every checked-in Django migration to be applied before traffic."""
    try:
        executor = MigrationExecutor(connection)
        pending = executor.migration_plan(executor.loader.graph.leaf_nodes())
    except Exception as error:  # Migration loaders expose backend-specific errors.
        return DependencyStatus(
            name="migrations",
            healthy=False,
            detail=f"unavailable ({type(error).__name__})",
        )
    return DependencyStatus(
        name="migrations",
        healthy=not pending,
        detail="current" if not pending else "pending",
    )


def readiness_status() -> ReadinessStatus:
    """Compute readiness through service-owned dependency checks."""
    database = check_database()
    checks = (
        database,
        check_migrations()
        if database.healthy
        else DependencyStatus("migrations", False, "database unavailable"),
        check_object_storage(),
    )
    healthy = all(check.healthy for check in checks)
    return ReadinessStatus(status="ready" if healthy else "not_ready", checks=checks)
