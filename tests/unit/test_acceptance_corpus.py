"""Adversarial tests for the oracle-isolated acceptance corpus adapter."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from anva.acceptance.corpus import (
    AcceptanceCorpusError,
    AdapterLimits,
    CanonicalCorpus,
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


def _verify(root: Path, expected: CanonicalCorpus) -> CanonicalCorpus:
    return verify_canonical_corpus(
        root,
        expected_manifest_sha256=expected.manifest_sha256,
        expected_source_fingerprint=expected.source_fingerprint,
        expected_canonical_manifest_sha256=expected.canonical_manifest_sha256,
    )


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
        assert _verify(first_root, first) == first
        assert stat.S_IMODE(first_root.stat().st_mode) == 0o555
        assert stat.S_IMODE((first_root / "payload").stat().st_mode) == 0o555
        assert (
            stat.S_IMODE((first_root / "payload/organization/decision.md").stat().st_mode) == 0o444
        )
    finally:
        _make_writable(first_root)
        _make_writable(second_root)


@pytest.mark.unit
@pytest.mark.parametrize(
    "changed_pin",
    ("manifest", "fingerprint", "canonical_manifest"),
)
def test_verification_rejects_each_independent_operator_pin(
    tmp_path: Path,
    changed_pin: str,
) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    expected = canonicalize_corpus(
        raw_root=raw,
        canonical_root=canonical,
        manifest_sha256=pin,
    )
    pins = {
        "manifest": expected.manifest_sha256,
        "fingerprint": expected.source_fingerprint,
        "canonical_manifest": expected.canonical_manifest_sha256,
    }
    pins[changed_pin] = "f" * 64
    try:
        with pytest.raises(AcceptanceCorpusError) as rejected:
            verify_canonical_corpus(
                canonical,
                expected_manifest_sha256=pins["manifest"],
                expected_source_fingerprint=pins["fingerprint"],
                expected_canonical_manifest_sha256=pins["canonical_manifest"],
            )
        assert rejected.value.code == "verification_pin_mismatch"
    finally:
        _make_writable(canonical)


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
def test_large_unlisted_inventory_is_rejected_without_output(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    unlisted = raw / "payload/organization"
    for index in range(2_000):
        (unlisted / f"entry-{index:04d}").write_bytes(b"x")
    canonical = tmp_path / "canonical"
    canonical.mkdir()

    with pytest.raises(AcceptanceCorpusError) as rejected:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )

    assert rejected.value.code == "unlisted_entry"
    assert not tuple(canonical.iterdir())


@pytest.mark.unit
def test_streamed_inventory_has_a_hard_entry_ceiling(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()

    with (
        patch("anva.acceptance.corpus.HARD_MAX_INVENTORY_ENTRIES", 1),
        pytest.raises(AcceptanceCorpusError) as rejected,
    ):
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )

    assert rejected.value.code == "inventory_limit_exceeded"
    assert not tuple(canonical.iterdir())


@pytest.mark.unit
def test_inventory_scans_do_not_materialize_scandir_iterators() -> None:
    source = Path("src/anva/acceptance/corpus.py").read_text(encoding="utf-8")

    assert "tuple(os.scandir" not in source
    assert "list(os.scandir" not in source


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
def test_mid_write_failure_is_redacted_and_leaves_no_partial_output(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    real_write = os.write
    failed = False

    def fail_after_partial_write(descriptor: int, content: object) -> int:
        nonlocal failed
        if not failed:
            failed = True
            real_write(descriptor, memoryview(cast(bytes, content))[:1])
            raise OSError(f"CANARY partial write at {canonical}")
        return real_write(descriptor, cast(bytes, content))

    with (
        patch("anva.acceptance.corpus.os.write", side_effect=fail_after_partial_write),
        pytest.raises(AcceptanceCorpusError) as rejected,
    ):
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )

    assert rejected.value.code == "canonical_unavailable"
    assert str(rejected.value) == "Canonical corpus output is unavailable"
    assert "CANARY" not in str(rejected.value)
    assert str(canonical) not in str(rejected.value)
    assert not tuple(canonical.iterdir())


@pytest.mark.unit
@pytest.mark.parametrize("failure_call", (1, 2))
def test_fsync_failure_is_redacted_and_leaves_no_partial_output(
    tmp_path: Path,
    failure_call: int,
) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    real_fsync = os.fsync
    fsync_calls = 0

    def fail_selected_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == failure_call:
            raise OSError(f"CANARY fsync failure at {canonical}")
        real_fsync(descriptor)

    with (
        patch("anva.acceptance.corpus.os.fsync", side_effect=fail_selected_fsync),
        pytest.raises(AcceptanceCorpusError) as rejected,
    ):
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )

    assert rejected.value.code == "canonical_unavailable"
    assert str(rejected.value) == "Canonical corpus output is unavailable"
    assert "CANARY" not in str(rejected.value)
    assert str(canonical) not in str(rejected.value)
    assert not tuple(canonical.iterdir())


@pytest.mark.unit
def test_unprovable_cleanup_returns_volume_discard_error_without_traceback(
    tmp_path: Path,
) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    canary = f"CANARY cleanup failure at {canonical}"

    try:
        with (
            patch("anva.acceptance.corpus.os.fsync", side_effect=OSError(canary)),
            patch("anva.acceptance.corpus._cleanup_canonical_output", return_value=False),
            pytest.raises(AcceptanceCorpusError) as rejected,
        ):
            canonicalize_corpus(
                raw_root=raw,
                canonical_root=canonical,
                manifest_sha256=pin,
            )

        assert rejected.value.code == "canonical_cleanup_failed"
        assert str(rejected.value) == (
            "Canonical corpus cleanup failed; discard the ephemeral volume"
        )
        assert rejected.value.__cause__ is None
        assert "CANARY" not in str(rejected.value)
        assert str(canonical) not in str(rejected.value)
    finally:
        _make_writable(canonical)
        for path in sorted(canonical.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            path.rmdir() if path.is_dir() else path.unlink()


@pytest.mark.unit
def test_canonical_verification_detects_tampering(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    try:
        result = canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=pin,
        )
        decision = canonical / "payload/organization/decision.md"
        decision.chmod(0o600)
        decision.write_bytes(b"tampered\n")
        with pytest.raises(AcceptanceCorpusError) as rejected:
            _verify(canonical, result)
        assert rejected.value.code == "content_mismatch"
    finally:
        _make_writable(canonical)


@pytest.mark.unit
def test_self_consistent_substituted_volume_fails_operator_pins(tmp_path: Path) -> None:
    raw, pin, _ = _public_bundle(tmp_path / "raw")
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    original = canonicalize_corpus(
        raw_root=raw,
        canonical_root=canonical,
        manifest_sha256=pin,
    )
    try:
        _make_writable(canonical)
        replacement = b"# Substituted public decision\n"
        decision = canonical / "payload/organization/decision.md"
        decision.write_bytes(replacement)
        manifest_path = canonical / "canonical-manifest.json"
        manifest = cast(dict[str, object], json.loads(manifest_path.read_bytes()))
        records = _file_records(manifest)
        record = next(
            item for item in records if item["path"] == decision.relative_to(canonical).as_posix()
        )
        record["sha256"] = hashlib.sha256(replacement).hexdigest()
        record["size_bytes"] = len(replacement)
        replacement_manifest_sha256 = "b" * 64
        manifest["input_manifest_sha256"] = replacement_manifest_sha256
        identity = {
            "schema_version": "1.0",
            "corpus_id": manifest["corpus_id"],
            "source_commit": manifest["source_commit"],
            "files": records,
        }
        replacement_fingerprint = hashlib.sha256(_canonical_json(identity)).hexdigest()
        manifest["source_fingerprint"] = replacement_fingerprint
        replacement_manifest = _canonical_json(manifest)
        manifest_path.write_bytes(replacement_manifest)
        replacement_canonical_sha256 = hashlib.sha256(replacement_manifest).hexdigest()

        replacement_result = verify_canonical_corpus(
            canonical,
            expected_manifest_sha256=replacement_manifest_sha256,
            expected_source_fingerprint=replacement_fingerprint,
            expected_canonical_manifest_sha256=replacement_canonical_sha256,
        )
        assert replacement_result.source_fingerprint == replacement_fingerprint

        with pytest.raises(AcceptanceCorpusError) as rejected:
            verify_canonical_corpus(
                canonical,
                expected_manifest_sha256=original.manifest_sha256,
                expected_source_fingerprint=original.source_fingerprint,
                expected_canonical_manifest_sha256=replacement_canonical_sha256,
            )
        assert rejected.value.code == "verification_pin_mismatch"
    finally:
        _make_writable(canonical)
