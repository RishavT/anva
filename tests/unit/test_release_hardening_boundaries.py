"""Static boundary checks for release and destructive operations tooling."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml


def _service(name: str) -> dict[str, object]:
    payload = cast(dict[str, object], yaml.safe_load(Path("compose.yaml").read_text()))
    services = cast(dict[str, dict[str, object]], payload["services"])
    return services[name]


@pytest.mark.unit
def test_backup_and_restore_jobs_use_application_store_configuration_and_pinned_generation() -> (
    None
):
    minio = _service("minio")
    minio_init = _service("minio-init")
    operations_guard = _service("operations-guard")
    backup_database = _service("backup-database")
    backup_objects = _service("backup-objects")
    restore_database = _service("restore-database")
    restore_objects = _service("restore-objects")

    database_environment = cast(dict[str, str], backup_database["environment"])
    assert database_environment["PGHOST"] == "postgres"
    assert database_environment["PGPORT"] == "5432"
    assert database_environment["PGDATABASE"].startswith("${ANVA_POSTGRES_DB:")
    assert database_environment["PGUSER"].startswith("${ANVA_POSTGRES_USER:")
    assert database_environment["PGPASSWORD"].startswith("${ANVA_POSTGRES_PASSWORD:")
    guard_environment = cast(dict[str, str], operations_guard["environment"])
    assert guard_environment["ANVA_DATABASE_URL"].startswith("${ANVA_DATABASE_URL:")
    assert guard_environment["ANVA_POSTGRES_DB"].startswith("${ANVA_POSTGRES_DB:")
    assert guard_environment["ANVA_POSTGRES_USER"].startswith("${ANVA_POSTGRES_USER:")
    assert guard_environment["ANVA_POSTGRES_PASSWORD"].startswith("${ANVA_POSTGRES_PASSWORD:")
    assert guard_environment["ANVA_OBJECT_STORAGE_ENDPOINT"] == (
        "${ANVA_OBJECT_STORAGE_ENDPOINT:-http://minio:9000}"
    )
    assert guard_environment["ANVA_OBJECT_STORAGE_BUCKET"].startswith(
        "${ANVA_OBJECT_STORAGE_BUCKET:"
    )
    assert guard_environment["ANVA_OBJECT_STORAGE_ACCESS_KEY"].startswith(
        "${ANVA_OBJECT_STORAGE_ACCESS_KEY:"
    )
    assert guard_environment["ANVA_OBJECT_STORAGE_SECRET_KEY"].startswith(
        "${ANVA_OBJECT_STORAGE_SECRET_KEY:"
    )
    assert guard_environment["ANVA_MINIO_BUCKET"].startswith("${ANVA_MINIO_BUCKET:")
    assert guard_environment["ANVA_MINIO_ROOT_USER"].startswith("${ANVA_MINIO_ROOT_USER:")
    assert guard_environment["ANVA_MINIO_ROOT_PASSWORD"].startswith("${ANVA_MINIO_ROOT_PASSWORD:")
    minio_environment = cast(dict[str, str], minio["environment"])
    minio_init_environment = cast(dict[str, str], minio_init["environment"])
    minio_init_command = " ".join(cast(list[str], minio_init["command"]))
    assert guard_environment["ANVA_MINIO_ROOT_USER"] == minio_environment["MINIO_ROOT_USER"]
    assert guard_environment["ANVA_MINIO_ROOT_PASSWORD"] == minio_environment["MINIO_ROOT_PASSWORD"]
    assert guard_environment["ANVA_MINIO_BUCKET"] == minio_init_environment["ANVA_MINIO_BUCKET"]
    assert "local/$${ANVA_MINIO_BUCKET}" in minio_init_command
    assert "ANVA_OBJECT_STORAGE_BUCKET" not in minio_init_command

    object_environment = cast(dict[str, str], backup_objects["environment"])
    assert set(object_environment) >= {
        "ANVA_OBJECT_STORAGE_ENDPOINT",
        "ANVA_OBJECT_STORAGE_BUCKET",
        "ANVA_OBJECT_STORAGE_ACCESS_KEY",
        "ANVA_OBJECT_STORAGE_SECRET_KEY",
    }
    assert "MINIO_ROOT_USER" not in object_environment
    assert "MINIO_ROOT_PASSWORD" not in object_environment

    for service in (restore_database, restore_objects):
        environment = cast(dict[str, str], service["environment"])
        command = " ".join(cast(list[str], service["command"]))
        assert "ANVA_BACKUP_GENERATION" in environment
        assert "/backup/current" not in command
        assert "/backup/generations/$${generation}" in command


@pytest.mark.unit
def test_operations_are_serialized_and_rehearsal_forces_clone_local_stores() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    backup = makefile.split("\nbackup:\n", 1)[1].split("\nbackup-verify:\n", 1)[0]
    restore = makefile.split("\nrestore:\n", 1)[1].split("\nmigration-rehearsal:\n", 1)[0]
    rehearsal = makefile.split("\nmigration-rehearsal:\n", 1)[1].split("\nrelease-clean:\n", 1)[0]

    assert "override OPERATIONS_LOCK_CONTAINER := $(COMPOSE_PROJECT)-operations-lock" in makefile
    for recipe in (backup, restore, rehearsal):
        assert '--name "$$lock_container"' in recipe
        assert 'docker rm --force "$$lock_container"' in recipe
        assert "trap cleanup EXIT" in recipe
        assert "run --rm --no-deps operations-guard" in recipe
        assert recipe.index("operations-guard") < recipe.index("$(COMPOSE) stop")

    assert "backup --directory /backup current" in restore
    assert 'export ANVA_BACKUP_GENERATION="$$backup_generation"' in restore
    assert restore.count("run --rm restore-") == 2
    assert "ANVA_DATABASE_URL=postgresql://anva_rehearsal:" in makefile
    assert "ANVA_OBJECT_STORAGE_ENDPOINT=http://minio:9000" in makefile
    assert "ANVA_MINIO_BUCKET=anva-rehearsal" in makefile
    assert "docker compose -f compose.yaml -p $(REHEARSAL_PROJECT)" in makefile
    assert rehearsal.count('ANVA_BACKUP_GENERATION="$$backup_generation"') >= 3
    assert "--profile operations run --rm restore-database" in rehearsal
    assert "--profile operations run --rm restore-objects" in rehearsal
    assert "migrate core 0019 --noinput" in rehearsal


@pytest.mark.unit
def test_release_gate_validates_current_report_before_using_waivers() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    gate = makefile.split("\nrelease-scan-gate: release-scan\n", 1)[1].split(
        "\nrelease-manifest:\n", 1
    )[0]

    assert "--report /release/anva-image-vulnerabilities.json" in gate
    assert gate.index("python -m anva.release exceptions") < gate.index("--ignorefile")


@pytest.mark.unit
def test_docker_context_excludes_runtime_artifacts_but_keeps_release_inputs() -> None:
    entries = set(Path(".dockerignore").read_text(encoding="utf-8").splitlines())

    assert {".secrets/", "secrets/", "backups/", "release/"} <= entries
    assert {".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "build/", "dist/"} <= entries
    assert "docs/**" in entries
    assert "!docs/releases/mvp-013.md" in entries
    assert "!docs/security/vulnerability-exceptions.json" in entries
