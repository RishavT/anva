"""Contracts for authoritative public release and installation guidance."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[2]
README = ROOT / "README.md"
INSTALL_RUNBOOK = ROOT / "docs" / "runbooks" / "install-upgrade-uninstall.md"
EXCEPTIONS = ROOT / "docs" / "security" / "vulnerability-exceptions.json"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_RUNBOOK = ROOT / "docs" / "releases" / "github-native-release.md"


def test_readme_reports_the_exact_current_approved_residual_risk() -> None:
    readme = README.read_text(encoding="utf-8")
    exceptions = json.loads(EXCEPTIONS.read_text(encoding="utf-8"))
    cve_count = len(exceptions["exceptions"])
    tuple_count = sum(len(item["packages"]) for item in exceptions["exceptions"])

    assert cve_count == 13
    assert tuple_count == 16
    assert exceptions["expires_at"] == "2026-09-25"
    normalized_readme = " ".join(readme.split())
    assert (
        f"exact approved {cve_count}-CVE/{tuple_count}-package-tuple no-fix set "
        f"through {exceptions['expires_at']}"
    ) in normalized_readme
    assert "14 reviewed no-vendor-fix exceptions" not in readme
    assert "2026-08-18" not in readme


def test_authoritative_install_docs_are_candidate_neutral() -> None:
    authoritative = "\n".join(
        (README.read_text(encoding="utf-8"), INSTALL_RUNBOOK.read_text(encoding="utf-8"))
    )

    assert "94231d7e" not in authoritative
    assert "MVP-013 has no tag" not in authoritative
    assert "no release tag" not in authoritative
    assert "no published package/image" not in authoritative


def test_install_runbook_matches_github_release_assets_and_image() -> None:
    runbook = INSTALL_RUNBOOK.read_text(encoding="utf-8")
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    for workflow_contract in (
        "ANVA_VERSION: 0.1.0",
        "ANVA_IMAGE_REPOSITORY: ghcr.io/rishavt/anva",
        'gh release download "$RELEASE_TAG"',
        'gh attestation verify "$artifact"',
        'gh attestation verify "oci://${image}"',
        "anva-install-${ANVA_VERSION}.tar.gz",
        'docker pull "$image"',
        'docker tag "$image" "${ANVA_IMAGE_REPOSITORY}:${ANVA_VERSION}"',
        "up --no-build --wait",
    ):
        assert workflow_contract in workflow

    for documented_contract in (
        "gh release download v0.1.0 --repo rishavt/anva --dir anva-v0.1.0",
        "sha256sum --check SHA256SUMS",
        'gh attestation verify "$artifact" --repo rishavt/anva',
        "anva-install-0.1.0.tar.gz",
        'gh attestation verify "oci://${ANVA_RELEASE_IMAGE}" --repo rishavt/anva',
        'docker pull "${ANVA_RELEASE_IMAGE}"',
        'docker tag "${ANVA_RELEASE_IMAGE}" ghcr.io/rishavt/anva:0.1.0',
        "tar -xzf anva-v0.1.0/anva-install-0.1.0.tar.gz -C anva-install",
        "cd anva-install/anva-0.1.0",
        "export ANVA_IMAGE_REPOSITORY=ghcr.io/rishavt/anva",
        "export ANVA_VERSION=0.1.0",
        "docker compose up --no-build --wait",
        "## Source-checkout fallback",
    ):
        assert documented_contract in runbook


def test_release_recovery_documents_separate_workflow_and_source_identities() -> None:
    recovery = RELEASE_RUNBOOK.read_text(encoding="utf-8")
    normalized = " ".join(recovery.split())

    assert "--ref main -f tag=v0.1.0" in recovery
    assert "--ref v0.1.0" not in recovery
    assert "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac" in recovery
    assert "Do not move, delete, or recreate the tag" in normalized
    assert "before the correction is reviewed and merged" in normalized
    assert "prepares the run-owned Trivy cache before checking out the tag" in normalized
