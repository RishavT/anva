"""Unit tests for deterministic and safe host skill archives."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from anva.skills.packages import (
    _archive_bytes,
    build_distributions,
    check_distributions,
    verify_distributions,
)

PACKAGE_ROOT = Path(__file__).parents[2] / "packages" / "anva-skills"


@pytest.mark.unit
def test_skill_archives_are_reproducible_and_verify_against_committed_inputs(
    tmp_path: Path,
) -> None:
    first = build_distributions(PACKAGE_ROOT, tmp_path / "first")
    second = build_distributions(PACKAGE_ROOT, tmp_path / "second")

    assert first == second
    assert verify_distributions(tmp_path / "first") == {
        "status": "verified",
        "archives": sorted(first),
    }
    assert check_distributions(PACKAGE_ROOT, tmp_path / "first") == []


@pytest.mark.unit
def test_skill_archive_builder_normalizes_metadata_and_refuses_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "skill.md").write_text("safe", encoding="utf-8")
    archive = _archive_bytes(source, "anva-codex")

    archive_path = tmp_path / "archive.tar.gz"
    archive_path.write_bytes(archive)
    with tarfile.open(archive_path, "r:gz") as opened:
        member = opened.getmember("anva-codex/nested/skill.md")
        assert (member.mode, member.mtime, member.uid, member.gid) == (0o644, 0, 0, 0)
        assert opened.extractfile(member).read() == b"safe"  # type: ignore[union-attr]

    (source / "unsafe").symlink_to(source / "nested" / "skill.md")
    with pytest.raises(ValueError, match="Refusing symlink"):
        _archive_bytes(source, "anva-codex")


@pytest.mark.unit
def test_distribution_verifier_rejects_tampered_checksums_and_unsafe_members(
    tmp_path: Path,
) -> None:
    build_distributions(PACKAGE_ROOT, tmp_path)
    (tmp_path / "SHA256SUMS").write_text("not a checksum\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid entry"):
        verify_distributions(tmp_path)

    build_distributions(PACKAGE_ROOT, tmp_path)
    archive = next(tmp_path.glob("*.tar.gz"))
    archive.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="Checksum mismatch"):
        verify_distributions(tmp_path)
