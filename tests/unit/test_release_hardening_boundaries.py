"""Static boundary checks for release and destructive operations tooling."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path
from typing import cast

import pytest
import yaml
from packaging.requirements import Requirement


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
    gate = makefile.split("\nrelease-scan-gate:\n", 1)[1].split("\nrelease-manifest:\n", 1)[0]

    assert "--report /release/anva-image-vulnerabilities.json" in gate
    assert 'test -f "$(ANVA_RELEASE_RISK_DECISION_INPUT)"' in gate
    assert 'cp "$(ANVA_RELEASE_RISK_DECISION_INPUT)" "$$staged"' in gate
    assert 'mv "$$staged" "$$canonical"' in gate
    assert "python -m anva.release decision-ignore" in gate
    assert "docs/security/vulnerability-exceptions" not in gate
    assert gate.index("python -m anva.release decision-ignore") < gate.index("--ignorefile")


@pytest.mark.unit
def test_local_release_gate_fails_closed_without_external_decision(tmp_path: Path) -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    gate = makefile.split("\nrelease-scan-gate:\n", 1)[1].split("\nrelease-manifest:\n", 1)[0]
    guard = gate.splitlines()[0].strip().removeprefix("@")
    result = subprocess.run(  # noqa: S603 - fixed executable and arguments under test.
        ["/bin/sh", "-eu", "-c", guard],
        check=False,
        capture_output=True,
        cwd=tmp_path,
        text=True,
    )
    assert result.returncode != 0
    assert "ANVA_RELEASE_RISK_DECISION_INPUT is required" in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    "failing_stage", [None, "release-build", "release-scan", "release-scan-gate"]
)
def test_release_artifacts_is_sequential_under_parallel_make(
    tmp_path: Path, failing_stage: str | None
) -> None:
    log = tmp_path / "order.log"
    stub = tmp_path / "Makefile"
    stages = (
        ("release-build", "build"),
        ("release-scan", "scan"),
        ("release-scan-gate", "gate"),
        ("release-manifest", "manifest"),
    )
    recipes = []
    for target, label in stages:
        recipes.append(f"{target}:\n\t@echo {label} >> $(LOG)")
        if target == failing_stage:
            recipes.append("\t@false")
    recipes.append(
        "release-artifacts:\n"
        "\t+$(MAKE) release-build\n"
        "\t+$(MAKE) release-scan\n"
        "\t+$(MAKE) release-scan-gate\n"
        "\t+$(MAKE) release-manifest"
    )
    stub.write_text("\n".join(recipes) + "\n", encoding="utf-8")
    result = subprocess.run(  # noqa: S603 - resolved Make executable with fixed arguments.
        ["/usr/bin/make", "-f", str(stub), "-j8", "release-artifacts", f"LOG={log}"],
        check=False,
        capture_output=True,
        cwd=tmp_path,
        text=True,
    )
    labels = [label for _target, label in stages]
    if failing_stage is None:
        assert result.returncode == 0, result.stderr
        assert log.read_text(encoding="utf-8").splitlines() == labels
    else:
        assert result.returncode != 0
        failure_index = [target for target, _label in stages].index(failing_stage)
        assert log.read_text(encoding="utf-8").splitlines() == labels[: failure_index + 1]


@pytest.mark.unit
def test_release_artifacts_orchestrates_without_parallel_prerequisites() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("\nrelease-artifacts:\n", 1)[1].split("\nreset:\n", 1)[0]
    assert recipe.splitlines()[:4] == [
        "\t+$(MAKE) release-build",
        "\t+$(MAKE) release-scan",
        "\t+$(MAKE) release-scan-gate",
        "\t+$(MAKE) release-manifest",
    ]
    clean = makefile.split("\nrelease-clean:\n", 1)[1].split("\nrelease-image-build:\n", 1)[0]
    assert "ANVA_RELEASE_RISK_DECISION_INPUT" not in clean


@pytest.mark.unit
def test_github_release_binds_risk_after_digest_before_manifest_and_attestation() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    proposal = workflow.index("name: Create canonical exact-candidate risk proposal")
    protected_environment = workflow.index("environment: release")
    digest = workflow.index("name: Resolve the exact image digest without remote publication")
    approval = workflow.index("name: Bind approved residual risk")
    manifest = workflow.index("make release-manifest", approval)
    publish = workflow.index("name: Publish the exact version image")
    attestation = workflow.index("name: Attest the GHCR image")

    assert proposal < protected_environment < digest < approval < manifest < publish < attestation
    assert "IMAGE_REFERENCE: ${{ steps.image.outputs.reference }}" in workflow
    assert "IMAGE_DIGEST: ${{ steps.image.outputs.digest }}" in workflow
    assert 'ANVA_RELEASE_IMAGE_REFERENCE="$IMAGE_REFERENCE"' in workflow
    assert 'ANVA_RELEASE_IMAGE_ID="$IMAGE_DIGEST"' in workflow
    assert "environment: release" in workflow
    assert "subject-path: release/*" in workflow


@pytest.mark.unit
def test_release_manifest_gate_verifies_generated_bundle_and_all_worktree_dirt() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    gate = makefile.split("\nrelease-manifest:\n", 1)[1].split("\nrelease-artifacts:", 1)[0]
    compose = cast(dict[str, object], yaml.safe_load(Path("compose.release.yaml").read_text()))
    services = cast(dict[str, dict[str, object]], compose["services"])
    scanner_volumes = cast(list[str], services["release-scanner"]["volumes"])
    scanner = services["release-scanner"]

    assert "set -eu" in gate
    assert "--ignored=matching" in gate
    assert "--untracked-files=all" in gate
    assert "python -m anva.release verify" in gate
    assert "--worktree-status /dev/stdin --release-path release" in gate
    assert gate.index("python -m anva.release manifest") < gate.index(
        "python -m anva.release verify"
    )
    assert "release-trivy-cache:${ANVA_TRIVY_CACHE_DIR:-/tmp}" in scanner_volumes
    assert "./release/.trivy-cache:/cache" not in scanner_volumes
    assert cast(dict[str, str], scanner["environment"])["TRIVY_CACHE_DIR"] == (
        "${ANVA_TRIVY_CACHE_DIR:-/tmp}"
    )
    assert scanner["user"] == "${ANVA_HOST_UID:-1000}:${ANVA_HOST_GID:-1000}"
    assert scanner["read_only"] is True
    assert scanner["cap_drop"] == ["ALL"]
    assert scanner["security_opt"] == ["no-new-privileges:true"]
    assert "/var/run/docker.sock:/var/run/docker.sock:ro" in scanner_volumes
    assert "tmpfs" not in scanner


@pytest.mark.unit
def test_docker_context_excludes_runtime_artifacts_but_keeps_release_inputs() -> None:
    entries = set(Path(".dockerignore").read_text(encoding="utf-8").splitlines())

    assert {".secrets/", "secrets/", "backups/", "release/"} <= entries
    assert {".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "build/", "dist/"} <= entries
    assert "docs/**" in entries
    assert "!docs/releases/mvp-013.md" in entries
    assert not any(entry.startswith("!docs/security/vulnerability-exceptions") for entry in entries)


@pytest.mark.unit
def test_gnu_make_is_pinned_to_test_stage_only() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    runtime = dockerfile.split("FROM base AS runtime\n", 1)[1].split("FROM base AS test\n", 1)[0]
    test_stage = dockerfile.split("FROM base AS test\n", 1)[1].split(
        "FROM test AS browser-test\n", 1
    )[0]
    assert "make=" not in runtime
    assert "make=4.4.1-2" in test_stage
    assert "/var/log/dpkg.log" in test_stage


@pytest.mark.unit
def test_release_builder_locks_build_backends_and_packages_offline() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    build_requires = cast(list[str], project["build-system"]["requires"])
    release_requires = cast(list[str], project["dependency-groups"]["release"])
    assert release_requires == build_requires

    lock = tomllib.loads(Path("uv.lock").read_text(encoding="utf-8"))
    packages = cast(list[dict[str, object]], lock["package"])
    root = next(package for package in packages if package["name"] == "anva")
    dev_dependencies = cast(dict[str, list[dict[str, str]]], root["dev-dependencies"])
    metadata = cast(dict[str, dict[str, list[dict[str, str]]]], root["metadata"])
    locked_release = dev_dependencies["release"]
    metadata_release = metadata["requires-dev"]["release"]
    requirements = [Requirement(value) for value in build_requires]
    assert [dependency["name"] for dependency in locked_release] == [
        requirement.name for requirement in requirements
    ]
    assert [
        f"{dependency['name']}{dependency['specifier']}" for dependency in metadata_release
    ] == (build_requires)
    locked_packages = {cast(str, package["name"]): package for package in packages}
    for requirement in requirements:
        locked_version = cast(str, locked_packages[requirement.name]["version"])
        assert requirement.specifier.contains(locked_version, prereleases=True)

    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    release_builder = dockerfile[
        dockerfile.index("FROM base AS release-builder") : dockerfile.index(
            "FROM release-builder AS wheel-builder"
        )
    ]
    wheel_builder = dockerfile[
        dockerfile.index("FROM release-builder AS wheel-builder") : dockerfile.index(
            "FROM base AS runtime"
        )
    ]
    runtime = dockerfile[
        dockerfile.index("FROM base AS runtime") : dockerfile.index("FROM base AS test")
    ]
    assert "uv sync --frozen --no-install-project --no-default-groups --group release" in (
        release_builder
    )
    assert "uv build --python /app/.venv/bin/python --no-build-isolation --offline" in (
        wheel_builder.replace("\\\n    ", "")
    )
    assert "FROM base AS runtime" in runtime
    assert "release-builder" not in runtime
    assert "UV_COMPILE_BYTECODE=false uv pip install --no-cache --no-deps" in runtime
    assert 'rm "${dist_info}/uv_cache.json"' in runtime
    assert "uv_cache\\.json,|d'" in runtime
    assert "/var/cache/ldconfig/aux-cache" in dockerfile
    assert "/var/log/apt/history.log" in dockerfile
    assert "/var/log/apt/term.log" in dockerfile
    assert "/var/log/dpkg.log" in dockerfile

    release_compose = cast(
        dict[str, object], yaml.safe_load(Path("compose.release.yaml").read_text())
    )
    services = cast(dict[str, dict[str, object]], release_compose["services"])
    service = services["release-builder"]
    build = cast(dict[str, str], service["build"])
    assert build["target"] == "release-builder"
    assert service["network_mode"] == "none"

    makefile = Path("Makefile").read_text(encoding="utf-8")
    image_build = makefile.split("\nrelease-image-build:\n", 1)[1].split("\nrelease-build:", 1)[0]
    assert "docker buildx bake -f compose.yaml api" in image_build
    assert "api.output=type=docker,rewrite-timestamp=true" in image_build
    assert "ANVA_BUILD_INPUT_SHA256=$(ANVA_IMAGE_BUILD_INPUT_SHA256)" in image_build
    assert "release-build: release-image-build release-package-files" in makefile
    release_build = makefile.split("\nrelease-package-files: release-clean\n", 1)[1].split(
        "\nrelease-build:", 1
    )[0]
    assert "uv build --python /app/.venv/bin/python" in release_build
    assert "--no-build-isolation --offline --wheel --out-dir /release" in release_build
    cleanup = "python -m anva.release cleanup-uv-build --directory /release"
    assert cleanup in release_build
    assert release_build.index("uv build") < release_build.index(cleanup)
    assert release_build.index(cleanup) < release_build.index("skills package")
