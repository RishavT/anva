"""Contracts for v0.1.3 release and installation guidance."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
INSTALL = ROOT / "docs" / "runbooks" / "install-upgrade-uninstall.md"
RELEASE = ROOT / "docs" / "releases" / "github-native-release.md"
READINESS = ROOT / "docs" / "releases" / "current-release-readiness.md"
NOTES = ROOT / "docs" / "releases" / "v0.1.3.md"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
HISTORICAL_REPAIR = ROOT / ".github" / "workflows" / "release-metadata-repair.yml"
V012_NOTES = ROOT / "docs" / "releases" / "v0.1.2.md"


def test_active_release_guidance_agrees_on_exact_v012_identity() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    for document in (INSTALL, RELEASE, READINESS, NOTES):
        text = document.read_text(encoding="utf-8")
        assert "v0.1.3" in text
    assert "ANVA_VERSION: 0.1.3" in workflow
    assert "default: v0.1.3" in workflow
    assert "group: release-v0.1.3" in workflow
    assert "ANVA_SOURCE_VERSION=0.1.3" in INSTALL.read_text(encoding="utf-8")
    assert "anva-install-0.1.3.tar.gz" in INSTALL.read_text(encoding="utf-8")


def test_runtime_build_and_compose_defaults_agree_on_v012() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == "0.1.3"
    assert '__version__ = "0.1.3"' in (ROOT / "src/anva/__init__.py").read_text()
    assert "ANVA_VERSION ?= 0.1.3" in (ROOT / "Makefile").read_text()
    assert "ARG ANVA_VERSION=0.1.3" in (ROOT / "Dockerfile").read_text()
    for name in ("compose.yaml", "compose.acceptance.yaml", "compose.acceptance.case.yaml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "ANVA_VERSION:-0.1.0" not in text
        assert "ANVA_VERSION:-0.1.3" in text


def test_release_docs_require_separate_exact_source_and_human_risk_approval() -> None:
    release = " ".join(RELEASE.read_text(encoding="utf-8").split())
    readiness = " ".join(READINESS.read_text(encoding="utf-8").split())
    notes = " ".join(NOTES.read_text(encoding="utf-8").split())
    assert "requires the full lowercase candidate commit" in release
    assert '-f tag=v0.1.3 -f source_commit="$ANVA_SOURCE_COMMIT"' in release
    assert "v0.1.0 approval cannot be replayed" in release
    assert "explicit RishavT decision" in readiness
    assert "v0.1.0 vulnerability exception is historical evidence" in notes
    assert "protected `release` environment" in release


def test_install_guidance_verifies_download_attestation_digest_and_no_build() -> None:
    install = INSTALL.read_text(encoding="utf-8")
    for contract in (
        "gh release download v0.1.3",
        "sha256sum --check SHA256SUMS",
        'gh attestation verify "$artifact"',
        "ANVA_SOURCE_PREDICATE_TYPE=https://github.com/RishavT/anva/attestations/source/v1",
        'gh attestation verify "oci://${ANVA_RELEASE_IMAGE}"',
        'docker pull "${ANVA_RELEASE_IMAGE}"',
        "docker compose up --no-build --wait",
        "export ANVA_VERSION=0.1.3",
    ):
        assert contract in install


def test_v010_metadata_repair_remains_historically_pinned() -> None:
    repair = HISTORICAL_REPAIR.read_text(encoding="utf-8")
    assert "Repair v0.1.0 release metadata" in repair
    assert "ANVA_RELEASE_TAG: v0.1.0" in repair
    assert "group: release-v0.1.0" in repair
    assert "v0.1.3" not in repair


def test_v012_history_distinguishes_build_approval_from_release_approval() -> None:
    readiness = " ".join(READINESS.read_text(encoding="utf-8").split())
    historical = " ".join(V012_NOTES.read_text(encoding="utf-8").split())
    for document in (readiness, historical):
        assert "33703772407" in document
        assert "exactly one RishavT `Build and attest` environment approval" in document
        assert "no generated or attested risk decision" in document
        assert "no publish/verify approval" in document
    assert "cancelled with zero approvals" in readiness
    assert "Both attempts were aborted with zero approvals" not in readiness
