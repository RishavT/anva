"""Unit tests for fail-closed destructive-operation store identity."""

from __future__ import annotations

import pytest

from anva.operations_safety import (
    main,
    verify_compose_database_identity,
    verify_compose_object_storage_identity,
)


def _environment() -> dict[str, str]:
    return {
        "ANVA_DATABASE_URL": "postgresql://anva:secret@postgres:5432/anva",
        "ANVA_POSTGRES_DB": "anva",
        "ANVA_POSTGRES_USER": "anva",
        "ANVA_POSTGRES_PASSWORD": "secret",
        "ANVA_OBJECT_STORAGE_ENDPOINT": "http://minio:9000",
        "ANVA_OBJECT_STORAGE_BUCKET": "anva-objects",
        "ANVA_OBJECT_STORAGE_ACCESS_KEY": "anva-minio",
        "ANVA_OBJECT_STORAGE_SECRET_KEY": "minio-secret",
        "ANVA_MINIO_BUCKET": "anva-objects",
        "ANVA_MINIO_ROOT_USER": "anva-minio",
        "ANVA_MINIO_ROOT_PASSWORD": "minio-secret",
    }


@pytest.mark.unit
def test_compose_database_identity_accepts_exact_application_store() -> None:
    verify_compose_database_identity(_environment())


@pytest.mark.unit
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ANVA_DATABASE_URL", "postgresql://anva:secret@external:5432/anva"),
        ("ANVA_DATABASE_URL", "postgresql://anva:secret@postgres:5433/anva"),
        ("ANVA_DATABASE_URL", "postgresql://other:secret@postgres:5432/anva"),
        ("ANVA_DATABASE_URL", "postgresql://anva:wrong@postgres:5432/anva"),
        ("ANVA_DATABASE_URL", "postgresql://anva:secret@postgres:5432/other"),
        ("ANVA_POSTGRES_DB", "other"),
        ("ANVA_POSTGRES_USER", "other"),
        ("ANVA_POSTGRES_PASSWORD", "other"),
    ],
)
def test_compose_database_identity_rejects_any_store_mismatch(key: str, value: str) -> None:
    environment = _environment()
    environment[key] = value

    with pytest.raises(ValueError, match="does not match"):
        verify_compose_database_identity(environment)


@pytest.mark.unit
def test_compose_object_storage_identity_accepts_exact_bundled_minio() -> None:
    verify_compose_object_storage_identity(_environment())


@pytest.mark.unit
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ANVA_OBJECT_STORAGE_ENDPOINT", "https://objects.example.invalid"),
        ("ANVA_OBJECT_STORAGE_ENDPOINT", "http://minio:9001"),
        ("ANVA_OBJECT_STORAGE_ENDPOINT", "http://minio:9000/other"),
        ("ANVA_OBJECT_STORAGE_BUCKET", "external-bucket"),
        ("ANVA_OBJECT_STORAGE_ACCESS_KEY", "external-access"),
        ("ANVA_OBJECT_STORAGE_SECRET_KEY", "external-secret"),
        ("ANVA_MINIO_BUCKET", "other-local-bucket"),
        ("ANVA_MINIO_ROOT_USER", "other-local-user"),
        ("ANVA_MINIO_ROOT_PASSWORD", "other-local-secret"),
    ],
)
def test_compose_object_storage_identity_rejects_external_or_mismatched_store(
    key: str,
    value: str,
) -> None:
    environment = _environment()
    environment[key] = value

    with pytest.raises(ValueError, match="bundled|does not match"):
        verify_compose_object_storage_identity(environment)


@pytest.mark.unit
def test_operations_guard_fails_without_disclosing_storage_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = _environment()
    environment["ANVA_OBJECT_STORAGE_ENDPOINT"] = "https://objects.example.invalid"
    environment["ANVA_OBJECT_STORAGE_SECRET_KEY"] = "hostile-object-secret"  # noqa: S105
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    assert main() == 2

    output = capsys.readouterr().out
    assert "Operations storage identity check failed" in output
    assert "objects.example.invalid" not in output
    assert "hostile-object-secret" not in output
    assert environment["ANVA_POSTGRES_PASSWORD"] not in output
