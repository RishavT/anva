"""Resolved deployment contracts for the #44 drill overlays."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
APP_IMAGE = "${ANVA_DRILL_IMAGE:?set the exact candidate ghcr.io/rishavt/anva@sha256 digest}"
FINALIZER_HOME = "/" + "tmp/gh-home"
FINALIZER_CACHE = "/" + "tmp/gh-cache"
APP_SERVICES = (
    "api",
    "worker",
    "migrate",
    "github-worker",
    "mcp",
    "mcp-read-only",
    "cli",
    "decommission-cleanup-operator",
    "demo",
    "operations-guard",
    "backup-manifest",
    "drill-decommission-operator",
    "drill-tool",
    "drill-finalizer",
)


class _ComposeLoader(yaml.SafeLoader):
    pass


_ComposeLoader.add_constructor("!reset", lambda loader, node: None)


def _drill_compose() -> dict[str, Any]:
    loaded = yaml.load(
        (ROOT / "compose.drill.yaml").read_text(encoding="utf-8"),
        _ComposeLoader,  # noqa: S506 - loader subclasses SafeLoader and only adds !reset.
    )
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


@pytest.mark.unit
def test_drill_overlay_pins_public_runtime_tls_and_scrape_images() -> None:
    compose = _drill_compose()
    services = compose["services"]

    for name in APP_SERVICES:
        assert services[name]["image"] == APP_IMAGE
        assert services[name]["build"] is None
        assert services[name]["pull_policy"] == "always"
    assert "ports" not in services["api"]
    assert services["drill-tls"]["image"].startswith("nginx@sha256:")
    assert services["drill-scrape"]["image"].startswith("curlimages/curl@sha256:")
    assert services["drill-tls"]["ports"] == ["127.0.0.1:${ANVA_DRILL_HTTPS_PORT:-8443}:8443"]
    assert services["drill-untrusted-probe"]["networks"] == ["backend"]
    for name in (
        "backup-database",
        "backup-objects",
        "restore-database",
        "restore-objects",
    ):
        assert services[name]["networks"] == ["backend"]
    assert services["drill-tool"]["network_mode"] == "none"
    finalizer = services["drill-finalizer"]
    assert finalizer["user"] == "${ANVA_DRILL_TOOL_USER:-65532:65532}"
    assert finalizer["cap_drop"] == ["ALL"]
    assert finalizer["read_only"] is True
    assert finalizer["networks"] == ["finalizer-egress"]
    assert finalizer["security_opt"] == ["no-new-privileges:true"]
    assert finalizer["environment"]["HOME"] == FINALIZER_HOME
    assert finalizer["environment"]["XDG_CACHE_HOME"] == FINALIZER_CACHE
    assert all("docker.sock" not in volume for volume in finalizer["volumes"])
    assert any("/gh-config:ro" in volume for volume in finalizer["volumes"])
    assert any("/usr/local/bin/gh:ro" in volume for volume in finalizer["volumes"])
    assert services["drill-tool"]["user"] == "${ANVA_DRILL_TOOL_USER:-65532:65532}"
    operator = services["drill-decommission-operator"]
    assert operator["user"] == "${ANVA_DRILL_TOOL_USER:-65532:65532}"
    assert operator["cap_drop"] == ["ALL"]
    assert operator["read_only"] is True
    assert operator["security_opt"] == ["no-new-privileges:true"]
    assert operator["tmpfs"] == services["drill-tool"]["tmpfs"]
    assert operator["networks"] == ["backend"]
    assert "ports" not in operator
    assert "volumes" not in operator
    assert operator["secrets"] == ["decommission_operator_credential"]
    operator_environment = operator["environment"]
    assert operator_environment["ANVA_ENV"] == "production"
    assert operator_environment["ANVA_DEBUG"] == "false"
    assert (
        "ANVA_DRILL_OBJECT_STORAGE_SECRET" in operator_environment["ANVA_OBJECT_STORAGE_SECRET_KEY"]
    )
    broad_temporary_mount = "/" + "tmp:"
    assert all(broad_temporary_mount not in volume for volume in services["drill-tool"]["volumes"])
    assert (
        services["drill-tls"]["networks"]["backend"]["ipv4_address"]
        == "${ANVA_DRILL_PROXY_IP:-172.31.44.10}"
    )


@pytest.mark.unit
def test_resolved_drill_compose_has_no_local_build_and_one_candidate_image() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable for resolved Compose validation")
    candidate = f"ghcr.io/rishavt/anva@sha256:{'a' * 64}"
    environment = {
        **os.environ,
        "ANVA_DRILL_IMAGE": candidate,
        "ANVA_DRILL_SOURCE_COMMIT": "3bea51afbfb0e3128cd600b107ff661cc85fa438",
        "ANVA_DRILL_OBJECT_STORAGE_SECRET": "test-object-secret",
        "ANVA_DRILL_BOOTSTRAP_SECRET": "test-bootstrap-secret",
        "ANVA_DRILL_METRICS_TOKEN": "test-metrics-secret",
        "ANVA_DRILL_SECRET_KEY": "test-app-secret",
        "ANVA_DRILL_TOKEN_PEPPER": "test-token-pepper",
        "ANVA_DRILL_TOOL_USER": "12345:23456",
        "ANVA_DRILL_INPUT_DIR": str((ROOT / "deploy/drill").resolve()),
        "ANVA_DRILL_GH_CONFIG_DIR": str((ROOT / "deploy/drill").resolve()),
        "ANVA_DRILL_GH_BIN": shutil.which("gh") or "/usr/bin/gh",
    }
    completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [
            docker,
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.drill.yaml",
            "--profile",
            "operations",
            "--profile",
            "tools",
            "--profile",
            "demo",
            "--profile",
            "mcp-test",
            "--profile",
            "github",
            "--profile",
            "drill-tools",
            "--profile",
            "drill-finalize",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    services = cast(dict[str, dict[str, object]], json.loads(completed.stdout)["services"])
    for name in (
        "backup-database",
        "backup-objects",
        "restore-database",
        "restore-objects",
    ):
        networks = cast(dict[str, object], services[name]["networks"])
        assert set(networks) == {"backend"}
    guard_networks = cast(dict[str, object], services["operations-guard"]["networks"])
    assert set(guard_networks) == {"default"}
    finalizer = services["drill-finalizer"]
    finalizer_environment = cast(dict[str, str], finalizer["environment"])
    assert finalizer_environment["HOME"] == FINALIZER_HOME
    assert finalizer_environment["XDG_CACHE_HOME"] == FINALIZER_CACHE
    assert finalizer["read_only"] is True
    assert set(cast(dict[str, object], finalizer["networks"])) == {"finalizer-egress"}
    assert "ports" not in finalizer
    operator = services["drill-decommission-operator"]
    assert operator["user"] == "12345:23456"
    assert operator["cap_drop"] == ["ALL"]
    assert operator["read_only"] is True
    assert operator["security_opt"] == ["no-new-privileges:true"]
    assert set(cast(dict[str, object], operator["networks"])) == {"backend"}
    assert "ports" not in operator
    assert "volumes" not in operator
    assert operator["secrets"] == [
        {
            "source": "decommission_operator_credential",
            "target": "/run/secrets/decommission_operator_credential",
        }
    ]
    operator_environment = cast(dict[str, str], operator["environment"])
    assert operator_environment["ANVA_ENV"] == "production"
    assert operator_environment["ANVA_DATABASE_URL"] == (
        "postgresql://anva:anva-local-only@postgres:5432/anva"
    )
    assert operator_environment["ANVA_OBJECT_STORAGE_ENDPOINT"] == "http://minio:9000"
    assert operator_environment["ANVA_OBJECT_STORAGE_BUCKET"] == "anva"
    assert operator_environment["ANVA_OBJECT_STORAGE_ACCESS_KEY"] == "anva-local"
    assert (
        operator_environment["ANVA_OBJECT_STORAGE_SECRET_KEY"]
        == environment["ANVA_DRILL_OBJECT_STORAGE_SECRET"]
    )
    for name in APP_SERVICES:
        assert services[name]["image"] == candidate
        assert "build" not in services[name]
        assert services[name]["pull_policy"] == "always"


@pytest.mark.unit
def test_drill_overlay_has_exact_proxy_and_https_security_contract() -> None:
    raw = (ROOT / "compose.drill.yaml").read_text(encoding="utf-8")
    nginx = (ROOT / "deploy/drill/nginx.conf").read_text(encoding="utf-8")

    assert "ANVA_TRUSTED_PROXY_IPS: ${ANVA_DRILL_PROXY_IP:-172.31.44.10}" in raw
    assert "ANVA_ENV: production" in raw
    assert "ANVA_DRILL_SECRET_KEY:?" in raw
    assert "listen 8443 ssl" in nginx
    assert "proxy_set_header X-Forwarded-Proto https" in nginx
    assert "listen 8080" not in nginx
    assert "proxy_pass http://api:8000" in nginx


@pytest.mark.unit
def test_all_pinned_app_services_and_object_store_share_production_secrets() -> None:
    compose = _drill_compose()
    services = compose["services"]

    for name in ("api", "worker", "migrate"):
        environment = services[name]["environment"]
        assert environment["ANVA_ENV"] == "production"
        assert environment["ANVA_DEBUG"] == "false"
        assert "ANVA_DRILL_OBJECT_STORAGE_SECRET" in environment["ANVA_OBJECT_STORAGE_SECRET_KEY"]
    assert (
        services["minio"]["environment"]["MINIO_ROOT_PASSWORD"]
        == (services["minio-init"]["environment"]["MINIO_ROOT_PASSWORD"])
    )


@pytest.mark.unit
def test_restore_fault_overlay_is_deterministic_and_nonzero() -> None:
    compose = yaml.safe_load(
        (ROOT / "compose.drill.restore-fault.yaml").read_text(encoding="utf-8")
    )
    command = compose["services"]["restore-objects"]["command"]

    assert command[-1].endswith("exit 44")
    assert "DRILL_OBJECT_RESTORE_FAULT" in command[-1]


@pytest.mark.unit
def test_make_targets_bind_restore_failure_storage_interruption_and_retry() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert "drill-network-preflight:" in makefile
    assert "drill-restore-fault:" in makefile
    assert "verify-restore-fault.sh" in makefile
    assert "status=$$?" in makefile
    assert 'ANVA_DRILL_TOOL_USER="$$(id -u):$$(id -g)" $(DRILL_COMPOSE)' in makefile
    assert "drill-storage-interrupt:" in makefile
    assert "drill-storage-resume:" in makefile
    assert "drill-decommission-retry:" in makefile
    assert "retry-decommission-cleanup" in makefile
    assert 'mktemp -d "$${TMPDIR:-/tmp}/anva-issue44-' in makefile
    assert '--owned-network "$(DRILL_PROJECT)_backend"' in makefile
    assert "anva-issue44-networks.json" not in makefile
    assert "drill-evidence-provisional-validate:" in makefile
    assert "drill-evidence-final-validate:" in makefile
    assert "--profile drill-finalize run --rm --no-deps drill-finalizer" in makefile
    assert "PYTHONPATH=src python3 -m anva.operator_drill finalize" not in makefile
    assert "GH_CONFIG_DIR is required" in makefile
    assert "ANVA_DRILL_IMAGE" in makefile
    assert "ANVA_DRILL_SOURCE_COMMIT" in makefile
    assert "ANVA_DRILL_PRODUCT_SOURCE_COMMIT" in makefile
    assert '--operator-source-commit "$(ANVA_DRILL_PRODUCT_SOURCE_COMMIT)"' in makefile
    assert "org.opencontainers.image.revision" in makefile
    assert "product source does not match immutable image revision" in makefile
    assert '--product-version "$(ANVA_VERSION)"' in makefile
    assert "--operator-cli-in-product" in makefile


@pytest.mark.unit
def test_spoof_probe_requires_exact_redirect_and_rejects_transport_or_server_errors() -> None:
    command = " ".join((_drill_compose())["services"]["drill-untrusted-probe"]["command"])

    assert 'test "$$code" = 301' in command
    assert 'test "$$code" != 200' not in command
    assert "--fail" not in command  # preserve the HTTP status for the exact assertion


@pytest.mark.unit
def test_tracked_evidence_guide_records_published_pending_release_boundary() -> None:
    guide = yaml.safe_load(
        (ROOT / "deploy/drill/evidence-template.json").read_text(encoding="utf-8")
    )

    assert guide["product_version"] == "0.1.6"
    assert guide["product_source_commit"] == "RUNTIME_REQUIRED_COMMIT"
    assert guide["product_image_digest"] == "RUNTIME_REQUIRED_SHA256"
    assert guide["release_run_id"] == "RUNTIME_REQUIRED_POSITIVE_INTEGER"
    assert guide["release_status"] == "CANDIDATE_NOT_PUBLISHED_OPERATOR_ACCEPTANCE_FORBIDDEN"
    assert guide["completion_event"] == "github_anchor"
    assert guide["approval_actor"] == "RishavT"


@pytest.mark.unit
def test_signoff_workflow_is_protected_pinned_and_minimally_permissioned() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/operator-drill-signoff.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["anchor"]

    assert job["environment"] == "release"
    assert job["runs-on"] == "ubuntu-24.04"
    assert workflow["permissions"] == {"contents": "read"}
    assert job["permissions"] == {
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
    }
    uses = [step["uses"] for step in job["steps"] if "uses" in step]
    assert all("@" in value and len(value.rsplit("@", 1)[1].split()[0]) == 40 for value in uses)
    assert any("attest-build-provenance" in value for value in uses)
    assert any("actions/attest@" in value for value in uses)


@pytest.mark.unit
def test_runbook_never_claims_the_human_drill_is_automated() -> None:
    runbook = (ROOT / "docs/runbooks/operator-acceptance-drill.md").read_text(encoding="utf-8")
    normalized = " ".join(runbook.split())

    assert "PENDING_RISHAV_EXECUTION" in runbook
    assert "NOT_ACCEPTED_OPERATOR_TOOL_PREDATES_SOURCE_ROLE_CONTRACT" in runbook
    assert "Only Rishav" in runbook
    assert "must not be inferred from command success" in runbook
    assert (
        "does not by itself execute a genuine human exercise or authorize a release" in normalized
    )
    assert "now-complete issue #44" in normalized
