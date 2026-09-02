"""Resolved deployment contracts for the #44 drill overlays."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
APP_DIGEST = "sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d"


@pytest.mark.unit
def test_drill_overlay_pins_public_runtime_tls_and_scrape_images() -> None:
    compose = yaml.safe_load((ROOT / "compose.drill.yaml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert services["api"]["image"] == f"ghcr.io/rishavt/anva@{APP_DIGEST}"
    assert "ports" not in services["api"]
    assert services["drill-tls"]["image"].startswith("nginx@sha256:")
    assert services["drill-scrape"]["image"].startswith("curlimages/curl@sha256:")
    assert services["drill-tls"]["ports"] == ["127.0.0.1:${ANVA_DRILL_HTTPS_PORT:-8443}:8443"]
    assert services["drill-untrusted-probe"]["networks"] == ["backend"]
    assert services["drill-tool"]["network_mode"] == "none"
    finalizer = services["drill-finalizer"]
    assert finalizer["user"] == "${ANVA_DRILL_TOOL_USER:-65532:65532}"
    assert finalizer["cap_drop"] == ["ALL"]
    assert finalizer["read_only"] is True
    assert finalizer["networks"] == ["finalizer-egress"]
    assert finalizer["security_opt"] == ["no-new-privileges:true"]
    assert all("docker.sock" not in volume for volume in finalizer["volumes"])
    assert any("/gh-config:ro" in volume for volume in finalizer["volumes"])
    assert any("/usr/local/bin/gh:ro" in volume for volume in finalizer["volumes"])
    assert services["drill-tool"]["user"] == "${ANVA_DRILL_TOOL_USER:-65532:65532}"
    broad_temporary_mount = "/" + "tmp:"
    assert all(broad_temporary_mount not in volume for volume in services["drill-tool"]["volumes"])
    assert (
        services["drill-tls"]["networks"]["backend"]["ipv4_address"]
        == "${ANVA_DRILL_PROXY_IP:-172.31.44.10}"
    )


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
    compose = yaml.safe_load((ROOT / "compose.drill.yaml").read_text(encoding="utf-8"))
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


@pytest.mark.unit
def test_spoof_probe_requires_exact_redirect_and_rejects_transport_or_server_errors() -> None:
    command = " ".join(
        (yaml.safe_load((ROOT / "compose.drill.yaml").read_text(encoding="utf-8")))["services"][
            "drill-untrusted-probe"
        ]["command"]
    )

    assert 'test "$$code" = 301' in command
    assert 'test "$$code" != 200' not in command
    assert "--fail" not in command  # preserve the HTTP status for the exact assertion


@pytest.mark.unit
def test_tracked_evidence_guide_records_exact_not_accepted_release_boundary() -> None:
    guide = yaml.safe_load(
        (ROOT / "deploy/drill/evidence-template.json").read_text(encoding="utf-8")
    )

    assert guide["product_source_commit"] == "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac"
    assert guide["release_status"] == "NOT_ACCEPTED"
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

    assert "PENDING_RISHAV_EXECUTION" in runbook
    assert "Only Rishav" in runbook
    assert "must not be inferred from command success" in runbook
    assert "does not close #44" in runbook
