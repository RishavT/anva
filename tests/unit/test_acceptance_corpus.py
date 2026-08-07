"""Adversarial tests for the oracle-isolated acceptance corpus adapter."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from anva.acceptance.corpus import (
    AcceptanceCorpusError,
    AdapterLimits,
    canonicalize_corpus,
    verify_canonical_corpus,
)

ManifestMutation = Callable[[dict[str, object]], None]


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _file_records(manifest: dict[str, object]) -> list[dict[str, object]]:
    records = manifest["files"]
    assert isinstance(records, list)
    assert all(isinstance(record, dict) for record in records)
    return cast(list[dict[str, object]], records)


def _manifest_limits(manifest: dict[str, object]) -> dict[str, object]:
    limits = manifest["limits"]
    assert isinstance(limits, dict)
    return cast(dict[str, object], limits)


def _public_bundle(
    root: Path,
    *,
    mutation: ManifestMutation | None = None,
) -> tuple[Path, str, dict[str, object]]:
    payload = root / "payload" / "organization"
    payload.mkdir(parents=True)
    first = payload / "decision.md"
    second = payload / "policy.yaml"
    first.write_bytes(b"# Public decision\n")
    second.write_bytes(b"owner: platform\n")
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for path in (first, second)
    ]
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "corpus_id": "halcyon-messy-organization-tst-008",
        "generated_at": "2026-07-28T12:00:00Z",
        "source_commit": "a" * 40,
        "files": records,
        "limits": {
            "max_files": 200,
            "max_total_bytes": 10_485_760,
            "max_file_bytes": 1_048_576,
            "max_depth": 8,
        },
    }
    if mutation is not None:
        mutation(manifest)
    manifest_bytes = _canonical_json(manifest)
    (root / "acceptance-corpus.json").write_bytes(manifest_bytes)
    return root, hashlib.sha256(manifest_bytes).hexdigest(), manifest


def _make_writable(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o700)
        elif not path.is_symlink():
            path.chmod(0o600)
    root.chmod(0o700)


@pytest.mark.unit
def test_canonicalization_is_pinned_deterministic_and_verifiable(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    first_root = tmp_path / "canonical-one"
    second_root = tmp_path / "canonical-two"
    first_root.mkdir()
    second_root.mkdir()
    try:
        first = canonicalize_corpus(
            raw_root=raw,
            canonical_root=first_root,
            manifest_sha256=pin,
        )
        second = canonicalize_corpus(
            raw_root=raw,
            canonical_root=second_root,
            manifest_sha256=pin,
        )

        assert first == second
        assert first.file_count == 2
        assert first.total_bytes == 34
        assert (first_root / "payload/organization/decision.md").read_bytes() == (
            b"# Public decision\n"
        )
        assert not (first_root / "acceptance-corpus.json").exists()
        assert verify_canonical_corpus(first_root) == first
        assert stat.S_IMODE(first_root.stat().st_mode) == 0o555
        assert stat.S_IMODE((first_root / "payload").stat().st_mode) == 0o555
        assert (
            stat.S_IMODE((first_root / "payload/organization/decision.md").stat().st_mode) == 0o444
        )
    finally:
        _make_writable(first_root)
        _make_writable(second_root)


@pytest.mark.unit
def test_canonicalization_rejects_wrong_pin_and_nonempty_output(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    with pytest.raises(AcceptanceCorpusError, match="operator pin") as mismatch:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256="f" * 64,
        )
    assert mismatch.value.code == "manifest_pin_mismatch"

    (canonical / "stale").write_text("stale", encoding="utf-8")
    with pytest.raises(AcceptanceCorpusError) as nonempty:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )
    assert nonempty.value.code == "canonical_not_empty"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("unsafe_path", "expected_code"),
    [
        ("../escape.md", "invalid_manifest"),
        ("/absolute.md", "invalid_manifest"),
        ("C:/drive.md", "invalid_manifest"),
        ("payload\\backslash.md", "invalid_manifest"),
        ("payload/../escape.md", "invalid_manifest"),
        ("payload//empty.md", "invalid_manifest"),
        ("payload/oracle/answer.json", "forbidden_control_path"),
        ("payload/.anva/corpus/oracle.json", "forbidden_control_path"),
        ("payload/grader.py", "forbidden_control_path"),
    ],
)
def test_manifest_rejects_unsafe_and_control_paths(
    tmp_path: Path,
    unsafe_path: str,
    expected_code: str,
) -> None:
    def mutation(manifest: dict[str, object]) -> None:
        records = manifest["files"]
        assert isinstance(records, list)
        record = records[0]
        assert isinstance(record, dict)
        record["path"] = unsafe_path

    raw, pin, _ = _public_bundle(tmp_path / "raw", mutation=mutation)
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    with pytest.raises(AcceptanceCorpusError) as rejected:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )
    assert rejected.value.code == expected_code


@pytest.mark.unit
def test_manifest_rejects_nul_duplicate_unsorted_and_limits(tmp_path: Path) -> None:
    def nul_path(manifest: dict[str, object]) -> None:
        _file_records(manifest)[0]["path"] = "payload/nul\x00.md"

    def duplicate_path(manifest: dict[str, object]) -> None:
        records = _file_records(manifest)
        records[1]["path"] = records[0]["path"]

    def reverse_paths(manifest: dict[str, object]) -> None:
        _file_records(manifest).reverse()

    def one_file(manifest: dict[str, object]) -> None:
        _manifest_limits(manifest)["max_files"] = 1

    def one_file_byte(manifest: dict[str, object]) -> None:
        _manifest_limits(manifest)["max_file_bytes"] = 1

    def one_total_byte(manifest: dict[str, object]) -> None:
        _manifest_limits(manifest)["max_total_bytes"] = 1

    def one_level(manifest: dict[str, object]) -> None:
        _manifest_limits(manifest)["max_depth"] = 1

    mutations: tuple[tuple[str, ManifestMutation], ...] = (
        ("invalid_manifest", nul_path),
        ("duplicate_path", duplicate_path),
        ("noncanonical_order", reverse_paths),
        ("file_count_exceeded", one_file),
        ("file_too_large", one_file_byte),
        ("total_bytes_exceeded", one_total_byte),
        ("depth_exceeded", one_level),
    )
    for index, (expected_code, mutation) in enumerate(mutations):
        case_root = tmp_path / str(index)
        raw, pin, _ = _public_bundle(case_root / "raw", mutation=mutation)
        canonical = case_root / "canonical"
        canonical.mkdir()
        with pytest.raises(AcceptanceCorpusError) as rejected:
            canonicalize_corpus(
                raw_root=raw,
                canonical_root=canonical,
                manifest_sha256=pin,
            )
        assert rejected.value.code == expected_code


@pytest.mark.unit
def test_manifest_limits_cannot_relax_operator_limits(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    with pytest.raises(AcceptanceCorpusError) as rejected:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
            operator_limits=AdapterLimits(max_files=100),
        )
    assert rejected.value.code == "declared_limit_exceeded"


@pytest.mark.unit
def test_adapter_rejects_unlisted_symlink_hardlink_and_special_files(tmp_path: Path) -> None:
    cases = ("unlisted", "symlink", "hardlink", "special")
    for case in cases:
        case_root = tmp_path / case
        raw, pin, _ = _public_bundle(case_root / "raw")
        decision = raw / "payload/organization/decision.md"
        if case == "unlisted":
            (raw / "payload/organization/hidden.txt").write_text("hidden", encoding="utf-8")
        elif case == "symlink":
            (raw / "payload/organization/link").symlink_to(decision)
        elif case == "hardlink":
            os.link(decision, raw / "payload/organization/second-link")
        else:
            os.mkfifo(raw / "payload/organization/fifo")
        canonical = case_root / "canonical"
        canonical.mkdir()
        with pytest.raises(AcceptanceCorpusError):
            canonicalize_corpus(
                raw_root=raw,
                canonical_root=canonical,
                manifest_sha256=pin,
            )


@pytest.mark.unit
def test_hash_or_size_mismatch_leaves_canonical_root_empty(tmp_path: Path) -> None:
    def mutation(manifest: dict[str, object]) -> None:
        records = manifest["files"]
        assert isinstance(records, list)
        record = records[1]
        assert isinstance(record, dict)
        record["sha256"] = "0" * 64

    raw, pin, _ = _public_bundle(tmp_path / "raw", mutation=mutation)
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    with pytest.raises(AcceptanceCorpusError) as rejected:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )
    assert rejected.value.code == "content_mismatch"
    assert not tuple(canonical.iterdir())


@pytest.mark.unit
def test_destination_io_failure_is_safe_and_leaves_no_output(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir(mode=0o500)
    try:
        with pytest.raises(AcceptanceCorpusError) as rejected:
            canonicalize_corpus(
                raw_root=raw,
                canonical_root=canonical,
                manifest_sha256=pin,
            )
        assert rejected.value.code == "canonical_unavailable"
        assert str(rejected.value) == "Canonical corpus output is unavailable"
        assert str(canonical) not in str(rejected.value)
        assert not tuple(canonical.iterdir())
    finally:
        canonical.chmod(0o700)


@pytest.mark.unit
def test_canonical_verification_detects_tampering(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    try:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )
        decision = canonical / "payload/organization/decision.md"
        decision.chmod(0o600)
        decision.write_bytes(b"tampered\n")
        with pytest.raises(AcceptanceCorpusError) as rejected:
            verify_canonical_corpus(canonical)
        assert rejected.value.code == "content_mismatch"
    finally:
        _make_writable(canonical)
