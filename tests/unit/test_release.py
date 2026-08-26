"""Unit tests for deterministic release inventory generation."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from anva.release import (
    build_release_manifest,
    build_trivy_ignorefile,
    remove_uv_build_gitignore,
    verify_release_manifest,
    verify_release_worktree_status,
)


@pytest.mark.unit
def test_uv_build_gitignore_cleanup_accepts_only_exact_regular_byproduct(
    tmp_path: Path,
) -> None:
    generated = tmp_path / ".gitignore"
    generated.write_bytes(b"*")

    remove_uv_build_gitignore(tmp_path)

    assert not generated.exists()

    for content in (b"*\n", b"*\nextra\n", b"!.keep\n"):
        generated.write_bytes(content)
        with pytest.raises(ValueError, match="unexpected content"):
            remove_uv_build_gitignore(tmp_path)
        assert generated.read_bytes() == content
        generated.unlink()

    target = tmp_path / "target"
    target.write_bytes(b"*")
    generated.symlink_to(target)
    with pytest.raises(ValueError, match="regular non-symlink"):
        remove_uv_build_gitignore(tmp_path)
    assert generated.is_symlink()
    assert target.read_bytes() == b"*"


@pytest.mark.unit
def test_uv_build_gitignore_cleanup_rejects_missing_or_unsafe_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="did not create"):
        remove_uv_build_gitignore(tmp_path)

    real_directory = tmp_path / "real"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="regular directory"):
        remove_uv_build_gitignore(linked_directory)


def _write_release_artifacts(directory: Path) -> None:
    for name in (
        "anva-0.1.0-py3-none-any.whl",
        "anva-install-0.1.0.tar.gz",
        "anva-codex-skills-1.0.0.tar.gz",
        "anva-claude-skills-1.0.0.tar.gz",
        "anva-image.spdx.json",
        "anva-image.cyclonedx.json",
        "anva-image-vulnerabilities.json",
        "anva-source-security.json",
        "vulnerability-exceptions.json",
    ):
        (directory / name).write_bytes(f"artifact:{name}\n".encode())


def _write_trivy_report(path: Path, vulnerabilities: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps({"Results": [{"Vulnerabilities": vulnerabilities}]}),
        encoding="utf-8",
    )


@pytest.mark.unit
def test_uv_build_cleanup_to_verified_manifest_boundary_is_fail_closed(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    _write_release_artifacts(release)
    (release / ".gitignore").write_bytes(b"*")
    commit = "a" * 40
    image_id = f"sha256:{'b' * 64}"

    remove_uv_build_gitignore(release)
    manifest = build_release_manifest(
        directory=release,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
        source_date_epoch=1_756_684_800,
    )
    verified = verify_release_manifest(
        directory=release,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
    )
    status = (
        b"".join(f"!! release/{record['path']}\0".encode() for record in verified["artifacts"])
        + b"!! release/release-manifest.json\0!! release/SHA256SUMS\0"
    )
    verify_release_worktree_status(
        status=status,
        release_path=Path("release"),
        manifest=manifest,
    )

    with pytest.raises(ValueError, match="unrelated.cache"):
        verify_release_worktree_status(
            status=status + b"!! unrelated.cache\0",
            release_path=Path("release"),
            manifest=manifest,
        )


@pytest.mark.unit
def test_release_manifest_covers_required_artifacts_and_is_reproducible(tmp_path: Path) -> None:
    _write_release_artifacts(tmp_path)

    first = build_release_manifest(
        directory=tmp_path,
        source_commit="a" * 40,
        image_reference="anva:0.1.0",
        image_id=f"sha256:{'b' * 64}",
        source_date_epoch=1_756_684_800,
    )
    first_manifest = (tmp_path / "release-manifest.json").read_bytes()
    first_checksums = (tmp_path / "SHA256SUMS").read_bytes()
    second = build_release_manifest(
        directory=tmp_path,
        source_commit="a" * 40,
        image_reference="anva:0.1.0",
        image_id=f"sha256:{'b' * 64}",
        source_date_epoch=1_756_684_800,
    )

    assert second == first
    assert (tmp_path / "release-manifest.json").read_bytes() == first_manifest
    assert (tmp_path / "SHA256SUMS").read_bytes() == first_checksums
    manifest = json.loads(first_manifest)
    assert manifest["schema_version"] == 2
    assert manifest["artifact_kind"] == "anva.generated-release-manifest"
    assert manifest["publication_status"] == "generated_unpublished"
    assert len(manifest["artifacts"]) == 9
    assert "release-manifest.json" in first_checksums.decode()
    assert "SHA256SUMS" not in first_checksums.decode()


@pytest.mark.unit
def test_tracked_release_manifest_schema_matches_generated_contract(tmp_path: Path) -> None:
    schema = json.loads(
        Path("docs/releases/release-manifest.schema.json").read_text(encoding="utf-8")
    )
    assert schema["properties"]["schema_version"]["const"] == 2
    assert schema["properties"]["artifact_kind"]["const"] == ("anva.generated-release-manifest")
    assert schema["properties"]["publication_status"]["const"] == ("generated_unpublished")
    assert set(schema["required"]) == set(schema["properties"])


@pytest.mark.unit
def test_release_verifier_rejects_stale_candidate_and_tampering(tmp_path: Path) -> None:
    _write_release_artifacts(tmp_path)
    commit = "a" * 40
    image_id = f"sha256:{'b' * 64}"
    build_release_manifest(
        directory=tmp_path,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
        source_date_epoch=1_756_684_800,
    )
    verified = verify_release_manifest(
        directory=tmp_path,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
    )
    assert verified["source_commit"] == commit

    with pytest.raises(ValueError, match="source commit does not match"):
        verify_release_manifest(
            directory=tmp_path,
            source_commit="c" * 40,
            image_reference="anva:0.1.0",
            image_id=image_id,
        )
    (tmp_path / "anva-0.1.0-py3-none-any.whl").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="has changed|checksum mismatch"):
        verify_release_manifest(
            directory=tmp_path,
            source_commit=commit,
            image_reference="anva:0.1.0",
            image_id=image_id,
        )


@pytest.mark.unit
def test_release_verifier_rejects_duplicate_manifest_keys(tmp_path: Path) -> None:
    _write_release_artifacts(tmp_path)
    commit = "a" * 40
    image_id = f"sha256:{'b' * 64}"
    build_release_manifest(
        directory=tmp_path,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
        source_date_epoch=1_756_684_800,
    )
    manifest_path = tmp_path / "release-manifest.json"
    content = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        content.replace('"schema_version": 2,', '"schema_version": 1, "schema_version": 2,'),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate key"):
        verify_release_manifest(
            directory=tmp_path,
            source_commit=commit,
            image_reference="anva:0.1.0",
            image_id=image_id,
        )


@pytest.mark.unit
def test_release_verifier_rejects_traversal_symlink_and_unrecorded_artifact(
    tmp_path: Path,
) -> None:
    _write_release_artifacts(tmp_path)
    commit = "a" * 40
    image_id = f"sha256:{'b' * 64}"
    build_release_manifest(
        directory=tmp_path,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
        source_date_epoch=1_756_684_800,
    )
    manifest_path = tmp_path / "release-manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["artifacts"][0]["path"] = "../escape"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe or duplicated"):
        verify_release_manifest(
            directory=tmp_path,
            source_commit=commit,
            image_reference="anva:0.1.0",
            image_id=image_id,
        )

    build_release_manifest(
        directory=tmp_path,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
        source_date_epoch=1_756_684_800,
    )
    (tmp_path / "unexpected.txt").write_text("not inventoried", encoding="utf-8")
    with pytest.raises(ValueError, match="unrecorded publishable"):
        verify_release_manifest(
            directory=tmp_path,
            source_commit=commit,
            image_reference="anva:0.1.0",
            image_id=image_id,
        )
    (tmp_path / "unexpected.txt").unlink()
    artifact = tmp_path / "anva-0.1.0-py3-none-any.whl"
    artifact.unlink()
    artifact.symlink_to(tmp_path / "anva-image.spdx.json")
    with pytest.raises(ValueError, match="unsafe"):
        verify_release_manifest(
            directory=tmp_path,
            source_commit=commit,
            image_reference="anva:0.1.0",
            image_id=image_id,
        )


@pytest.mark.unit
@pytest.mark.parametrize("name", [".gitignore", ".credentials", "..hidden"])
def test_release_manifest_rejects_every_extra_dotfile(tmp_path: Path, name: str) -> None:
    _write_release_artifacts(tmp_path)
    (tmp_path / name).write_text("untrusted ignored dirt\n", encoding="utf-8")

    with pytest.raises(ValueError, match="safe portable basenames"):
        build_release_manifest(
            directory=tmp_path,
            source_commit="a" * 40,
            image_reference="anva:0.1.0",
            image_id=f"sha256:{'b' * 64}",
            source_date_epoch=1_756_684_800,
        )


@pytest.mark.unit
def test_release_worktree_allows_only_verified_ignored_bundle(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    release = repository / "release"
    release.mkdir(parents=True)
    _write_release_artifacts(release)
    commit = "a" * 40
    image_id = f"sha256:{'b' * 64}"
    manifest = build_release_manifest(
        directory=release,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
        source_date_epoch=1_756_684_800,
    )
    verified = verify_release_manifest(
        directory=release,
        source_commit=commit,
        image_reference="anva:0.1.0",
        image_id=image_id,
    )
    assert verified == manifest
    status = (
        b"".join(f"!! release/{record['path']}\0".encode() for record in verified["artifacts"])
        + b"!! release/release-manifest.json\0!! release/SHA256SUMS\0"
    )
    verify_release_worktree_status(status=status, release_path=Path("release"), manifest=verified)

    with pytest.raises(ValueError, match="unrelated.tmp"):
        verify_release_worktree_status(
            status=status + b"?? unrelated.tmp\0",
            release_path=Path("release"),
            manifest=verified,
        )
    with pytest.raises(ValueError, match="tracked.txt"):
        verify_release_worktree_status(
            status=status + b" M tracked.txt\0",
            release_path=Path("release"),
            manifest=verified,
        )


@pytest.mark.unit
def test_release_worktree_rejects_unrelated_ignored_dirt(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    release = repository / "release"
    release.mkdir(parents=True)
    _write_release_artifacts(release)
    manifest = build_release_manifest(
        directory=release,
        source_commit="a" * 40,
        image_reference="anva:0.1.0",
        image_id=f"sha256:{'b' * 64}",
        source_date_epoch=1_756_684_800,
    )
    with pytest.raises(ValueError, match="secret.cache"):
        verify_release_worktree_status(
            status=b"!! secret.cache\0",
            release_path=Path("release"),
            manifest=manifest,
        )


@pytest.mark.unit
def test_release_manifest_rejects_missing_scan_artifact(tmp_path: Path) -> None:
    (tmp_path / "anva-0.1.0-py3-none-any.whl").write_bytes(b"wheel")

    with pytest.raises(ValueError, match="missing required artifact"):
        build_release_manifest(
            directory=tmp_path,
            source_commit="a" * 40,
            image_reference="anva:0.1.0",
            image_id=f"sha256:{'b' * 64}",
            source_date_epoch=1_756_684_800,
        )


@pytest.mark.unit
def test_vulnerability_exceptions_are_bounded_expiring_and_reproducible(
    tmp_path: Path,
) -> None:
    source = tmp_path / "exceptions.json"
    report = tmp_path / "image-vulnerabilities.json"
    output = tmp_path / ".trivyignore"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reviewed_at": "2026-08-04",
                "expires_at": "2026-08-18",
                "policy": "Temporary reviewed exceptions require an exact release-image rescan.",
                "exceptions": [
                    {
                        "id": "CVE-2026-12345",
                        "severity": "HIGH",
                        "packages": ["example-package"],
                        "disposition": "temporarily_accepted_no_upstream_fix",
                        "rationale": (
                            "No vendor-fixed package exists; this exception expires and "
                            "requires an exact-image rescan."
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _write_trivy_report(
        report,
        [
            {
                "VulnerabilityID": "CVE-2026-12345",
                "PkgName": "example-package",
                "Severity": "HIGH",
                "Status": "affected",
            }
        ],
    )

    first = build_trivy_ignorefile(
        input_path=source,
        vulnerability_report_path=report,
        output_path=output,
        current_date=date(2026, 8, 4),
    )
    first_bytes = output.read_bytes()
    second = build_trivy_ignorefile(
        input_path=source,
        vulnerability_report_path=report,
        output_path=output,
        current_date=date(2026, 8, 5),
    )

    assert first == second == ("CVE-2026-12345",)
    assert output.read_bytes() == first_bytes == b"CVE-2026-12345\n"


@pytest.mark.unit
def test_vulnerability_exceptions_fail_closed_after_expiry(tmp_path: Path) -> None:
    source = tmp_path / "exceptions.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reviewed_at": "2026-08-04",
                "expires_at": "2026-08-05",
                "policy": "Temporary reviewed exceptions require an exact release-image rescan.",
                "exceptions": [
                    {
                        "id": "CVE-2026-12345",
                        "severity": "CRITICAL",
                        "packages": ["example-package"],
                        "disposition": "temporarily_accepted_no_upstream_fix",
                        "rationale": (
                            "No vendor-fixed package exists; this exception expires and "
                            "requires an exact-image rescan."
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not currently valid"):
        build_trivy_ignorefile(
            input_path=source,
            vulnerability_report_path=tmp_path / "image-vulnerabilities.json",
            output_path=tmp_path / ".trivyignore",
            current_date=date(2026, 8, 6),
        )


@pytest.mark.unit
def test_checked_in_vulnerability_exceptions_match_current_review(tmp_path: Path) -> None:
    identifiers = build_trivy_ignorefile(
        input_path=Path("docs/security/vulnerability-exceptions.json"),
        vulnerability_report_path=Path(
            "tests/fixtures/release/vulnerability-exceptions-sanitized-trivy.json"
        ),
        output_path=tmp_path / ".trivyignore",
        current_date=date(2026, 8, 4),
    )

    assert len(identifiers) == 14
    assert identifiers[0] == "CVE-2023-45853"
    assert identifiers[-1] == "CVE-2026-9538"


@pytest.mark.unit
def test_sanitized_exception_fixture_covers_exact_reviewed_tuples() -> None:
    exceptions = json.loads(
        Path("docs/security/vulnerability-exceptions.json").read_text(encoding="utf-8")
    )["exceptions"]
    report = json.loads(
        Path("tests/fixtures/release/vulnerability-exceptions-sanitized-trivy.json").read_text(
            encoding="utf-8"
        )
    )
    vulnerabilities = report["Results"][0]["Vulnerabilities"]

    reviewed = {
        (exception["id"], package, exception["severity"])
        for exception in exceptions
        for package in exception["packages"]
    }
    observed = {
        (
            vulnerability["VulnerabilityID"],
            vulnerability["PkgName"],
            vulnerability["Severity"],
        )
        for vulnerability in vulnerabilities
    }

    assert observed == reviewed
    assert {vulnerability["Status"] for vulnerability in vulnerabilities} == {
        "affected",
        "fix_deferred",
        "will_not_fix",
    }
    expected_statuses = {
        "CVE-2023-45853": "will_not_fix",
        "CVE-2025-69720": "affected",
        "CVE-2025-7458": "affected",
        "CVE-2026-13221": "affected",
        "CVE-2026-41992": "fix_deferred",
        "CVE-2026-42496": "fix_deferred",
        "CVE-2026-42497": "fix_deferred",
        "CVE-2026-48962": "affected",
        "CVE-2026-53615": "affected",
        "CVE-2026-54369": "fix_deferred",
        "CVE-2026-57432": "affected",
        "CVE-2026-57433": "affected",
        "CVE-2026-8376": "affected",
        "CVE-2026-9538": "fix_deferred",
    }
    assert {
        vulnerability["VulnerabilityID"]: vulnerability["Status"]
        for vulnerability in vulnerabilities
    } == expected_statuses
    assert all(vulnerability["FixedVersion"] is None for vulnerability in vulnerabilities)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("vulnerabilities", "message"),
    [
        ([], "absent from the current image report"),
        (
            [
                {
                    "VulnerabilityID": "CVE-2026-12345",
                    "PkgName": "moved-package",
                    "Severity": "HIGH",
                    "Status": "affected",
                }
            ],
            "package set changed",
        ),
        (
            [
                {
                    "VulnerabilityID": "CVE-2026-12345",
                    "PkgName": "example-package",
                    "Severity": "HIGH",
                    "Status": "affected",
                    "FixedVersion": "2.0.0",
                }
            ],
            "available fixed version",
        ),
        (
            [
                {
                    "VulnerabilityID": "CVE-2026-12345",
                    "PkgName": "example-package",
                    "Severity": "HIGH",
                    "Status": "fixed",
                }
            ],
            "no-upstream-fix state",
        ),
    ],
)
def test_vulnerability_exceptions_match_current_unfixed_image_tuple(
    tmp_path: Path,
    vulnerabilities: list[dict[str, object]],
    message: str,
) -> None:
    source = tmp_path / "exceptions.json"
    report = tmp_path / "image-vulnerabilities.json"
    output = tmp_path / ".trivyignore"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "reviewed_at": "2026-08-04",
                "expires_at": "2026-08-18",
                "policy": "Temporary reviewed exceptions require an exact release-image rescan.",
                "exceptions": [
                    {
                        "id": "CVE-2026-12345",
                        "severity": "HIGH",
                        "packages": ["example-package"],
                        "disposition": "temporarily_accepted_no_upstream_fix",
                        "rationale": (
                            "No vendor-fixed package exists; this exception expires and "
                            "requires an exact-image rescan."
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _write_trivy_report(report, vulnerabilities)

    with pytest.raises(ValueError, match=message):
        build_trivy_ignorefile(
            input_path=source,
            vulnerability_report_path=report,
            output_path=output,
            current_date=date(2026, 8, 4),
        )

    assert not output.exists()
