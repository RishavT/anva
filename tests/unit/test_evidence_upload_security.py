"""TST-007 byte classes exercise the production bounded upload parser."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from anva.core.services.evidence_uploads import (
    GAP_ARCHIVE_BAD_FORMAT,
    GAP_ARCHIVE_PATH_INVALID,
    GAP_ARCHIVE_SPECIAL_FILE,
    GAP_MANIFEST_MALFORMED,
    GAP_MANIFEST_SCHEMA_INVALID,
    GAP_MANIFEST_TOO_LARGE,
    GAP_SECRET_PATTERN_DETECTED,
    GAP_UPLOAD_DIGEST_MISMATCH,
    EvidenceUploadError,
    InspectedUpload,
    inspect_evidence_upload,
)

HEAD = "a" * 40


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def results_bytes(*, check_name: str = "unit") -> bytes:
    return canonical_json(
        {
            "schema_version": 1,
            "head_sha": HEAD,
            "checks": [{"name": check_name, "status": "PASSED"}],
        }
    )


def zip_bytes(entries: list[tuple[str, bytes, int]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name, content, mode in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, content)
    return output.getvalue()


def safe_zip() -> bytes:
    results = results_bytes()
    manifest = canonical_json(
        {
            "schema_version": 1,
            "head_sha": HEAD,
            "results_path": "artifacts/results.json",
            "content_hash": hashlib.sha256(results).hexdigest(),
        }
    )
    return zip_bytes(
        [
            ("artifacts/manifest.json", manifest, 0o600),
            ("artifacts/results.json", results, 0o600),
        ]
    )


def safe_tar() -> bytes:
    results = results_bytes()
    manifest = canonical_json(
        {
            "schema_version": 1,
            "head_sha": HEAD,
            "results_path": "artifacts/results.json",
            "content_hash": hashlib.sha256(results).hexdigest(),
        }
    )
    output = io.BytesIO()
    entries = (
        ("artifacts/manifest.json", manifest),
        ("artifacts/results.json", results),
    )
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o600
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    logical_size = len(entries) * 1_024 + 1_024
    return output.getvalue()[:logical_size]


def inspect(
    value: bytes,
    *,
    digest: str | None = None,
    commit_sha: str = HEAD,
) -> InspectedUpload:
    return inspect_evidence_upload(
        io.BytesIO(value),
        content_length=len(value),
        expected_size=len(value),
        expected_sha256=digest or hashlib.sha256(value).hexdigest(),
        commit_sha=commit_sha,
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "code"),
    [
        (b'{"schema_version":1', GAP_MANIFEST_MALFORMED),
        (canonical_json({"padding": "x" * 600}), GAP_MANIFEST_TOO_LARGE),
        (canonical_json({"schema_version": 1}), GAP_MANIFEST_SCHEMA_INVALID),
        (
            results_bytes(check_name="ghp_TST007_secret_canary_7H2K9M4P"),
            GAP_SECRET_PATTERN_DETECTED,
        ),
    ],
)
def test_json_rejection_classes_fail_closed_with_stable_safe_codes(
    value: bytes,
    code: str,
) -> None:
    with pytest.raises(EvidenceUploadError) as raised:
        inspect(value)

    assert raised.value.code == code
    assert "ghp_" not in raised.value.safe_message


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "mode", "code"),
    [
        ("artifacts/../results.json", 0o600, GAP_ARCHIVE_PATH_INVALID),
        ("artifacts/run.sh", 0o700, GAP_ARCHIVE_SPECIAL_FILE),
    ],
)
def test_hostile_traversal_and_executable_zip_entries_fail_without_extraction(
    name: str,
    mode: int,
    code: str,
) -> None:
    hostile = zip_bytes([(name, b"#!/bin/sh\nexit 0\n", mode)])

    with pytest.raises(EvidenceUploadError) as raised:
        inspect(hostile)

    assert raised.value.code == code


@pytest.mark.unit
def test_declared_digest_mismatch_rejects_before_parsing() -> None:
    value = results_bytes()

    with pytest.raises(EvidenceUploadError) as raised:
        inspect(value, digest="0" * 64)

    assert raised.value.code == GAP_UPLOAD_DIGEST_MISMATCH


@pytest.mark.unit
def test_safe_exact_two_member_zip_is_accepted_as_inert_bytes() -> None:
    value = safe_zip()

    inspected = inspect(value)

    assert inspected.content_hash == hashlib.sha256(value).hexdigest()
    assert inspected.verified_size == len(value)
    assert inspected.detected_media_type == "application/zip"
    assert inspected.archive_summary["member_count"] == 2
    assert inspected.archive_summary["check_count"] == 1


@pytest.mark.unit
def test_safe_exact_two_member_tar_and_zero_record_padding_are_accepted() -> None:
    value = safe_tar()

    inspected = inspect(value)
    padded = inspect(value + b"\x00" * 512)

    assert inspected.detected_media_type == "application/x-tar"
    assert inspected.archive_summary["member_count"] == 2
    assert inspected.archive_summary["check_count"] == 1
    assert padded.verified_size == len(value) + 512


@pytest.mark.unit
@pytest.mark.parametrize(
    "trailer",
    [
        b"MZhostile-executable",
        b"#!/bin/sh\nexit 0\n",
        safe_zip(),
        safe_tar()[:512],
    ],
    ids=["mz", "shebang", "zip", "tar"],
)
@pytest.mark.parametrize("archive", [safe_zip(), safe_tar()], ids=["zip", "tar"])
def test_archive_trailing_executable_or_polyglot_bytes_fail_closed(
    archive: bytes,
    trailer: bytes,
) -> None:
    hostile = archive + trailer

    with pytest.raises(EvidenceUploadError) as raised:
        inspect(hostile)

    assert raised.value.code == GAP_ARCHIVE_BAD_FORMAT


@pytest.mark.unit
@pytest.mark.parametrize(
    ("filename", "expected_sha256", "code"),
    [
        (
            "scn_drift.json.upload",
            "7b3199a0944001af205a2bd932d500b18cfebebc376b362eb19ea1f55c4fbe3c",
            GAP_MANIFEST_MALFORMED,
        ),
        (
            "scn_elder.json.upload",
            "bc63913f2a32c1b8b4578a2acfbd3ddbce30f20c3f103782c1f2c663bd214c9f",
            GAP_MANIFEST_TOO_LARGE,
        ),
        (
            "scn_flint.json.upload",
            "e70d12d49a52e9aab07320fde80b190b1980e66bc4bda394b8f2fe6f3c81e7d1",
            GAP_MANIFEST_SCHEMA_INVALID,
        ),
        (
            "scn_glass.zip.upload",
            "d0c89e82046b3f61ec3793382e68f1f17b8f4187cb994f6e008db8a50b3c2d50",
            GAP_ARCHIVE_PATH_INVALID,
        ),
        (
            "scn_harbor.json.upload",
            "8c84957062b97c350f9df7806ea9f8b36e025140d97fde71988e5e147292a797",
            GAP_SECRET_PATTERN_DETECTED,
        ),
    ],
)
def test_raw_tst007_rejection_artifact_classes_pass_the_product_inspector(
    filename: str,
    expected_sha256: str,
    code: str,
) -> None:
    value = (Path("tests/fixtures/tst007") / filename).read_bytes()
    assert hashlib.sha256(value).hexdigest() == expected_sha256

    with pytest.raises(EvidenceUploadError) as raised:
        inspect(value)

    assert raised.value.code == code


@pytest.mark.unit
def test_tst007_safe_artifact_uses_explicit_git_sha1_compatibility_adapter() -> None:
    raw = Path("tests/fixtures/tst007/scn_linden.zip.upload").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "19f81a35213a2c613e2c42c363e15a0d65115a1db083ff1d43821a4c502eb979"
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        manifest = json.loads(archive.read("artifacts/manifest.json"))
        results = json.loads(archive.read("artifacts/results.json"))
    raw_head = results["head_sha"]
    assert isinstance(raw_head, str) and len(raw_head) == 64
    product_head = raw_head[:40]

    with pytest.raises(EvidenceUploadError) as raw_rejection:
        inspect(raw, commit_sha=product_head)
    assert raw_rejection.value.code == GAP_MANIFEST_SCHEMA_INVALID

    results["head_sha"] = product_head
    adapted_results = canonical_json(results)
    manifest["head_sha"] = product_head
    manifest["content_hash"] = hashlib.sha256(adapted_results).hexdigest()
    adapted = zip_bytes(
        [
            ("artifacts/manifest.json", canonical_json(manifest), 0o644),
            ("artifacts/results.json", adapted_results, 0o644),
        ]
    )

    assert hashlib.sha256(adapted).digest() != hashlib.sha256(raw).digest()
    inspected = inspect(adapted, commit_sha=product_head)
    assert inspected.detected_media_type == "application/zip"
    assert inspected.archive_summary["member_count"] == 2
    assert inspected.archive_summary["check_count"] == 1


@pytest.mark.unit
def test_upload_implementation_has_no_extraction_or_execution_calls() -> None:
    source = Path("src/anva/core/services/evidence_uploads.py").read_text()
    tree = ast.parse(source)
    forbidden = {
        "eval",
        "exec",
        "extract",
        "extractall",
        "os.system",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.run",
    }
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            prefix = node.func.value.id if isinstance(node.func.value, ast.Name) else ""
            calls.add(f"{prefix}.{node.func.attr}" if prefix else node.func.attr)

    assert calls.isdisjoint(forbidden)
