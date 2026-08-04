"""Fail-closed identity checks for destructive Compose storage operations."""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import unquote, urlsplit


def verify_compose_database_identity(environment: Mapping[str, str]) -> None:
    """Require the application URL to identify this Compose project's PostgreSQL store."""
    database_url = environment.get("ANVA_DATABASE_URL", "")
    database_name = environment.get("ANVA_POSTGRES_DB", "")
    database_user = environment.get("ANVA_POSTGRES_USER", "")
    database_password = environment.get("ANVA_POSTGRES_PASSWORD", "")
    if not all((database_url, database_name, database_user, database_password)):
        raise ValueError("Compose database identity is incomplete")
    parsed = urlsplit(database_url)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Application database URL has an invalid port") from error
    if (
        parsed.scheme != "postgresql"
        or parsed.hostname != "postgres"
        or port != 5432
        or parsed.query
        or parsed.fragment
        or unquote(parsed.path.removeprefix("/")) != database_name
        or unquote(parsed.username or "") != database_user
        or unquote(parsed.password or "") != database_password
    ):
        raise ValueError("Application database URL does not match the Compose PostgreSQL store")


def verify_compose_object_storage_identity(environment: Mapping[str, str]) -> None:
    """Require application object storage to identify bundled Compose MinIO."""
    endpoint = environment.get("ANVA_OBJECT_STORAGE_ENDPOINT", "")
    bucket = environment.get("ANVA_OBJECT_STORAGE_BUCKET", "")
    access_key = environment.get("ANVA_OBJECT_STORAGE_ACCESS_KEY", "")
    secret_key = environment.get("ANVA_OBJECT_STORAGE_SECRET_KEY", "")
    minio_bucket = environment.get("ANVA_MINIO_BUCKET", "")
    minio_user = environment.get("ANVA_MINIO_ROOT_USER", "")
    minio_password = environment.get("ANVA_MINIO_ROOT_PASSWORD", "")
    if not all(
        (
            endpoint,
            bucket,
            access_key,
            secret_key,
            minio_bucket,
            minio_user,
            minio_password,
        )
    ):
        raise ValueError("Compose object-storage identity is incomplete")
    if endpoint != "http://minio:9000":
        raise ValueError("Application object storage is not the bundled Compose MinIO service")
    if bucket != minio_bucket:
        raise ValueError("Application object-storage bucket does not match Compose MinIO")
    if access_key != minio_user or secret_key != minio_password:
        raise ValueError("Application object-storage access does not match Compose MinIO")


def main() -> int:
    """Validate storage identity without printing any configured values."""
    try:
        verify_compose_database_identity(os.environ)
        verify_compose_object_storage_identity(os.environ)
    except ValueError as error:
        print(f"Operations storage identity check failed: {error}")
        return 2
    print("Operations storage identity check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
