"""Contracts for v0.1.6 release and installation guidance."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]
INSTALL = ROOT / "docs" / "runbooks" / "install-upgrade-uninstall.md"
RELEASE = ROOT / "docs" / "releases" / "github-native-release.md"
READINESS = ROOT / "docs" / "releases" / "current-release-readiness.md"
NOTES = ROOT / "docs" / "releases" / "v0.1.6.md"
README = ROOT / "README.md"
CHECKLIST = ROOT / "docs" / "releases" / "release-checklist.md"
COMPATIBILITY = ROOT / "docs" / "releases" / "compatibility.md"
MATRIX = ROOT / "docs" / "releases" / "requirements-evidence-matrix.md"
OWNERSHIP = ROOT / "docs" / "releases" / "release-ownership.md"
MVP_SUMMARY = ROOT / "docs" / "releases" / "mvp-013.md"
MANIFEST_GUIDE = ROOT / "docs" / "releases" / "release-manifest.md"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
HISTORICAL_REPAIR = ROOT / ".github" / "workflows" / "release-metadata-repair.yml"
V012_NOTES = ROOT / "docs" / "releases" / "v0.1.2.md"
V013_NOTES = ROOT / "docs" / "releases" / "v0.1.3.md"
V014_NOTES = ROOT / "docs" / "releases" / "v0.1.4.md"


def test_active_release_guidance_agrees_on_exact_v016_identity() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    for document in (INSTALL, RELEASE, READINESS, NOTES):
        text = document.read_text(encoding="utf-8")
        assert "v0.1.6" in text
    assert "ANVA_VERSION: 0.1.6" in workflow
    assert "default: v0.1.6" in workflow
    assert "group: release-v0.1.6" in workflow
    assert "ANVA_SOURCE_VERSION=0.1.6" in INSTALL.read_text(encoding="utf-8")
    assert "anva-install-0.1.6.tar.gz" in INSTALL.read_text(encoding="utf-8")


def test_published_v016_records_are_current_and_prepare_v017_fix_forward() -> None:
    source = "e89b06aed8207cc32eee0eeebde4a2731f0c0203"
    image = (
        "ghcr.io/rishavt/anva@sha256:"
        "916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb"
    )
    required = (source, image, "33781714974", "33910747236")
    for document in (NOTES, READINESS, CHECKLIST, MATRIX, MVP_SUMMARY):
        text = document.read_text(encoding="utf-8")
        for value in required:
            assert value in text, f"{document.name} is missing {value}"
    for document in (README, NOTES, READINESS, CHECKLIST, COMPATIBILITY):
        text = document.read_text(encoding="utf-8")
        assert "v0.1.7" in text, f"{document.name} lacks the fix-forward version"
    assert "12 public assets" in NOTES.read_text(encoding="utf-8")


def test_active_v016_records_do_not_claim_published_or_closed_gates_are_pending() -> None:
    forbidden_by_document = {
        README: (
            "Published `v0.1.5` remains the immutable predecessor",
            "its still-open human gates",
        ),
        NOTES: ("Status: release preparation", "No `v0.1.6` tag"),
        READINESS: ("is in release preparation", "Human acceptance #44 | Still separate"),
        COMPATIBILITY: ("human gates #43 and #44 remain open",),
        CHECKLIST: (
            "Human gates #43/#44 remain open",
            "Human completion remains blocked on #43 and #44",
        ),
        MATRIX: ("#43/#44 human gates", "#42, #44, and umbrella #13 remain open"),
        OWNERSHIP: ("does not claim a completed operator exercise",),
        MVP_SUMMARY: ("human acceptance gates #43 and #44 remain open",),
    }
    for document, forbidden_values in forbidden_by_document.items():
        text = document.read_text(encoding="utf-8")
        for value in forbidden_values:
            assert value not in text, f"{document.name} retains stale claim: {value}"


def test_published_docs_explain_build_stage_publication_status_semantics() -> None:
    manifest = MANIFEST_GUIDE.read_text(encoding="utf-8")
    notes = NOTES.read_text(encoding="utf-8")
    assert "generated_unpublished" in manifest
    assert "build-stage" in manifest
    assert "does not mean that v0.1.6 remained unpublished" in manifest
    assert "generated_unpublished" in notes
    assert "build-stage" in notes


def test_runtime_build_and_compose_defaults_agree_on_v016() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["version"] == "0.1.6"
    assert '__version__ = "0.1.6"' in (ROOT / "src/anva/__init__.py").read_text()
    assert "ANVA_VERSION ?= 0.1.6" in (ROOT / "Makefile").read_text()
    assert "ARG ANVA_VERSION=0.1.6" in (ROOT / "Dockerfile").read_text()
    for name in ("compose.yaml", "compose.acceptance.yaml", "compose.acceptance.case.yaml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "ANVA_VERSION:-0.1.0" not in text
        assert "ANVA_VERSION:-0.1.6" in text


def test_release_docs_require_separate_exact_source_and_human_risk_approval() -> None:
    release = " ".join(RELEASE.read_text(encoding="utf-8").split())
    readiness = " ".join(READINESS.read_text(encoding="utf-8").split())
    notes = " ".join(NOTES.read_text(encoding="utf-8").split())
    assert "requires the full lowercase candidate commit" in release
    assert '-f tag=v0.1.6 -f source_commit="$ANVA_SOURCE_COMMIT"' in release
    assert (
        "successful v0.1.5 approval and its associated evidence authorize only the "
        "immutable v0.1.5 release; they cannot be replayed or used to authorize v0.1.6" in release
    )
    assert (
        "v0.1.0 approval remains older historical evidence and likewise cannot "
        "authorize v0.1.6" in release
    )
    assert "explicit RishavT decision" in readiness
    assert "v0.1.0 vulnerability exception is historical evidence" in notes
    assert "protected `release` environment" in release


def test_release_rollback_uses_exact_verified_v015_predecessor() -> None:
    release = " ".join(RELEASE.read_text(encoding="utf-8").split())
    assert "rollback predecessor is the verified v0.1.5 image" in release
    assert (
        "ghcr.io/rishavt/anva@sha256:"
        "19488230c6f7900cda33bd11adc7f1ad824d23b77ee87fd65ac883cd0dacc725" in release
    )
    assert "previous verified v0.1.0 digest" not in release


def test_install_guidance_verifies_download_attestation_digest_and_no_build() -> None:
    install = INSTALL.read_text(encoding="utf-8")
    for contract in (
        "gh release download v0.1.6",
        "sha256sum --check SHA256SUMS",
        'gh attestation verify "$artifact"',
        "ANVA_SOURCE_PREDICATE_TYPE=https://github.com/RishavT/anva/attestations/source/v1",
        'gh attestation verify "oci://${ANVA_RELEASE_IMAGE}"',
        'docker pull "${ANVA_RELEASE_IMAGE}"',
        "docker compose up --no-build --wait",
        "export ANVA_VERSION=0.1.6",
    ):
        assert contract in install


def test_v010_metadata_repair_remains_historically_pinned() -> None:
    repair = HISTORICAL_REPAIR.read_text(encoding="utf-8")
    assert "Repair v0.1.0 release metadata" in repair
    assert "ANVA_RELEASE_TAG: v0.1.0" in repair
    assert "group: release-v0.1.0" in repair
    assert "v0.1.6" not in repair


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


def test_v013_history_records_failed_decision_readback_without_publication() -> None:
    readiness = " ".join(READINESS.read_text(encoding="utf-8").split())
    historical = " ".join(V013_NOTES.read_text(encoding="utf-8").split())
    for document in (readiness, historical):
        assert "33713418248" in document
        assert "exactly one RishavT `Build and attest` environment approval" in document
        assert "decision-attestation" in document
        assert "zero Publish or Verify approvals" in document
        assert "No v0.1.3 GHCR image or GitHub Release" in document


def test_v014_history_records_successful_readback_and_failed_registry_copy() -> None:
    readiness = " ".join(READINESS.read_text(encoding="utf-8").split())
    historical = " ".join(V014_NOTES.read_text(encoding="utf-8").split())
    for document in (readiness, historical):
        assert "33718942806" in document
        assert "exactly one RishavT `Build and attest` environment approval" in document
        assert "passed" in document and "attestation readback" in document
        assert "mode-0600 auth bind" in document
        assert "zero Publish or Verify approvals" in document
        assert "No v0.1.4 GHCR image or GitHub Release" in document
