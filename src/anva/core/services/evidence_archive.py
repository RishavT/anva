"""Bounded, non-executing inspection for evidence uploads."""

from __future__ import annotations

import hashlib
import hmac
import json
import posixpath
import re
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import IO, Any, Final

from anva.core.exceptions import DomainOperationError
from anva.core.logging import redact_text
from anva.core.models import EvidenceBlob
from anva.core.services.hostile_inputs import validate_full_commit

GAP_UPLOAD_TOO_LARGE: Final = "UPLOAD_TOO_LARGE"
GAP_UPLOAD_SIZE_MISMATCH: Final = "UPLOAD_SIZE_MISMATCH"
GAP_UPLOAD_DIGEST_MISMATCH: Final = "UPLOAD_DIGEST_MISMATCH"
GAP_MEDIA_TYPE_NOT_ALLOWED: Final = "MEDIA_TYPE_NOT_ALLOWED"
GAP_MANIFEST_TOO_LARGE: Final = "MANIFEST_TOO_LARGE"
GAP_MANIFEST_MALFORMED: Final = "MANIFEST_MALFORMED"
GAP_MANIFEST_SCHEMA_INVALID: Final = "MANIFEST_SCHEMA_INVALID"
GAP_EVIDENCE_HEAD_MISMATCH: Final = "EVIDENCE_HEAD_MISMATCH"
GAP_MANIFEST_CONTENT_HASH_MISMATCH: Final = "MANIFEST_CONTENT_HASH_MISMATCH"
GAP_SECRET_PATTERN_DETECTED: Final = "SECRET_PATTERN_DETECTED"  # noqa: S105
GAP_ARCHIVE_BAD_FORMAT: Final = "ARCHIVE_BAD_FORMAT"
GAP_ARCHIVE_ENCRYPTED: Final = "ARCHIVE_ENCRYPTED"
GAP_ARCHIVE_METADATA_REJECTED: Final = "ARCHIVE_METADATA_REJECTED"
GAP_ARCHIVE_COMPRESSION_UNSUPPORTED: Final = "ARCHIVE_COMPRESSION_UNSUPPORTED"
GAP_ARCHIVE_MEMBER_COUNT_EXCEEDED: Final = "ARCHIVE_MEMBER_COUNT_EXCEEDED"
GAP_ARCHIVE_MEMBER_COMPRESSED_LIMIT: Final = "ARCHIVE_MEMBER_COMPRESSED_LIMIT"
GAP_ARCHIVE_MEMBER_EXPANDED_LIMIT: Final = "ARCHIVE_MEMBER_EXPANDED_LIMIT"
GAP_ARCHIVE_EXPANDED_LIMIT: Final = "ARCHIVE_EXPANDED_LIMIT"
GAP_ARCHIVE_COMPRESSION_RATIO: Final = "ARCHIVE_COMPRESSION_RATIO"
GAP_ARCHIVE_PATH_INVALID: Final = "ARCHIVE_PATH_INVALID"
GAP_ARCHIVE_DUPLICATE_PATH: Final = "ARCHIVE_DUPLICATE_PATH"
GAP_ARCHIVE_DEPTH_EXCEEDED: Final = "ARCHIVE_DEPTH_EXCEEDED"
GAP_ARCHIVE_SPECIAL_FILE: Final = "ARCHIVE_SPECIAL_FILE"
GAP_ARCHIVE_NESTED: Final = "ARCHIVE_NESTED"
GAP_ARCHIVE_SCHEMA_INVALID: Final = "ARCHIVE_SCHEMA_INVALID"

_SAFE_MESSAGES: Final[dict[str, str]] = {
    GAP_UPLOAD_TOO_LARGE: "The uploaded artifact exceeds the byte limit.",
    GAP_UPLOAD_SIZE_MISMATCH: "The uploaded artifact size does not match its authorization.",
    GAP_UPLOAD_DIGEST_MISMATCH: "The uploaded artifact digest does not match its authorization.",
    GAP_MEDIA_TYPE_NOT_ALLOWED: "The uploaded artifact type is not allowed.",
    GAP_MANIFEST_TOO_LARGE: "The evidence manifest exceeds its byte limit.",
    GAP_MANIFEST_MALFORMED: "The evidence JSON is not well-formed.",
    GAP_MANIFEST_SCHEMA_INVALID: "The evidence JSON does not have the approved shape.",
    GAP_EVIDENCE_HEAD_MISMATCH: "The evidence is not bound to the evaluated commit.",
    GAP_MANIFEST_CONTENT_HASH_MISMATCH: "The manifest does not bind the results bytes.",
    GAP_SECRET_PATTERN_DETECTED: "The uploaded artifact contains credential material.",
    GAP_ARCHIVE_BAD_FORMAT: "The uploaded archive is malformed.",
    GAP_ARCHIVE_ENCRYPTED: "Encrypted archive members are not accepted.",
    GAP_ARCHIVE_METADATA_REJECTED: "The archive contains unsupported metadata.",
    GAP_ARCHIVE_COMPRESSION_UNSUPPORTED: "The archive compression method is not supported.",
    GAP_ARCHIVE_MEMBER_COUNT_EXCEEDED: "The archive contains too many members.",
    GAP_ARCHIVE_MEMBER_COMPRESSED_LIMIT: "An archive member exceeds its compressed limit.",
    GAP_ARCHIVE_MEMBER_EXPANDED_LIMIT: "An archive member exceeds its expanded limit.",
    GAP_ARCHIVE_EXPANDED_LIMIT: "The archive exceeds its cumulative expanded limit.",
    GAP_ARCHIVE_COMPRESSION_RATIO: "An archive member exceeds its compression-ratio limit.",
    GAP_ARCHIVE_PATH_INVALID: "The archive contains an unsafe member path.",
    GAP_ARCHIVE_DUPLICATE_PATH: "Archive paths collide after canonicalization.",
    GAP_ARCHIVE_DEPTH_EXCEEDED: "An archive member exceeds the path-depth limit.",
    GAP_ARCHIVE_SPECIAL_FILE: "The archive contains a link or special file.",
    GAP_ARCHIVE_NESTED: "Nested archives are not accepted.",
    GAP_ARCHIVE_SCHEMA_INVALID: "The archive does not have the approved evidence shape.",
}

_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_ZIP_SIGNATURES: Final = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_TAR_MAGIC_OFFSET: Final = 257
_TAR_MAGICS: Final = (b"ustar\x00", b"ustar ")
_ALLOWED_ZIP_COMPRESSION: Final = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_UPLOAD_SECRET_PATTERNS: Final = (
    re.compile(r"\bghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
)
_NESTED_ARCHIVE_SUFFIXES: Final = {
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".txz",
    ".xz",
    ".zip",
}
_EXECUTABLE_SUFFIXES: Final = {".bat", ".cmd", ".com", ".exe", ".ps1", ".sh"}
_EXECUTABLE_MAGICS: Final = (b"#!", b"\x7fELF", b"MZ")


class EvidenceUploadError(DomainOperationError):
    """Safe, stable upload failure without byte, token, object-key, or endpoint detail."""

    def __init__(self, code: str, message: str, http_status: int = 400) -> None:
        self.code = code
        self.safe_message = message
        self.http_status = http_status
        super().__init__(message)


class _UnsafeUploadError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _DuplicateJsonKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class UploadLimits:
    """All parser/resource limits; defaults reproduce the TST-007 contract."""

    max_upload_bytes: int = 4_096
    max_manifest_bytes: int = 512
    max_archive_entries: int = 8
    max_archive_depth: int = 4
    max_member_compressed_bytes: int = 1_024
    max_member_expanded_bytes: int = 1_024
    max_archive_expanded_bytes: int = 1_536
    max_compression_ratio: int = 50
    chunk_bytes: int = 256

    def __post_init__(self) -> None:
        values = (
            self.max_upload_bytes,
            self.max_manifest_bytes,
            self.max_archive_entries,
            self.max_archive_depth,
            self.max_member_compressed_bytes,
            self.max_member_expanded_bytes,
            self.max_archive_expanded_bytes,
            self.max_compression_ratio,
            self.chunk_bytes,
        )
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise ValueError("Upload limits must be positive integers")
        if self.max_manifest_bytes > self.max_upload_bytes:
            raise ValueError("Manifest limit cannot exceed upload limit")
        if self.chunk_bytes > self.max_member_expanded_bytes:
            raise ValueError("Chunk limit cannot exceed member expanded limit")


DEFAULT_UPLOAD_LIMITS: Final = UploadLimits()


@dataclass(frozen=True, slots=True)
class InspectedUpload:
    content_hash: str
    verified_size: int
    detected_media_type: str
    archive_summary: dict[str, object]


def _validate_digest(value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("declared_sha256 must be a lowercase SHA-256 digest")
    return value


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJsonKeyError(key)
        value[key] = child
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _parse_json(value: bytes) -> Any:
    try:
        return json.loads(
            value.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise _UnsafeUploadError(GAP_MANIFEST_MALFORMED) from error


def _scan_secret_bytes(value: bytes) -> None:
    text = value.decode("utf-8", errors="ignore")
    if redact_text(text) != text or any(
        pattern.search(text) for pattern in _UPLOAD_SECRET_PATTERNS
    ):
        raise _UnsafeUploadError(GAP_SECRET_PATTERN_DETECTED)


def _validate_results(value: Any, commit_sha: str, *, max_checks: int) -> int:
    if not isinstance(value, dict) or set(value) != {"schema_version", "head_sha", "checks"}:
        raise _UnsafeUploadError(GAP_MANIFEST_SCHEMA_INVALID)
    checks = value["checks"]
    if (
        isinstance(value["schema_version"], bool)
        or value["schema_version"] != 1
        or not isinstance(value["head_sha"], str)
        or not isinstance(checks, list)
        or not 1 <= len(checks) <= max_checks
    ):
        raise _UnsafeUploadError(GAP_MANIFEST_SCHEMA_INVALID)
    if value["head_sha"] != commit_sha:
        raise _UnsafeUploadError(GAP_EVIDENCE_HEAD_MISMATCH)
    names: set[str] = set()
    for check in checks:
        if (
            not isinstance(check, dict)
            or set(check) != {"name", "status"}
            or not isinstance(check["name"], str)
            or not 1 <= len(check["name"]) <= 128
            or check["name"] in names
            or check["status"] not in {"PASSED", "FAILED"}
        ):
            raise _UnsafeUploadError(GAP_MANIFEST_SCHEMA_INVALID)
        names.add(check["name"])
    return len(checks)


def _validate_manifest(value: Any, commit_sha: str) -> str:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "head_sha",
        "results_path",
        "content_hash",
    }:
        raise _UnsafeUploadError(GAP_MANIFEST_SCHEMA_INVALID)
    if (
        isinstance(value["schema_version"], bool)
        or value["schema_version"] != 1
        or value["head_sha"] != commit_sha
        or value["results_path"] != "artifacts/results.json"
        or not isinstance(value["content_hash"], str)
        or _SHA256_PATTERN.fullmatch(value["content_hash"]) is None
    ):
        raise _UnsafeUploadError(GAP_MANIFEST_SCHEMA_INVALID)
    return value["content_hash"]


def _sniff_media_type(prefix: bytes) -> str | None:
    if prefix.startswith(_ZIP_SIGNATURES):
        return EvidenceBlob.MediaType.ZIP
    if (
        len(prefix) >= _TAR_MAGIC_OFFSET + 6
        and prefix[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + 6] in _TAR_MAGICS
    ):
        return EvidenceBlob.MediaType.TAR
    if prefix.lstrip(b" \t\r\n").startswith((b"{", b"[")):
        return EvidenceBlob.MediaType.JSON
    return None


def _canonical_archive_path(filename: str, limits: UploadLimits) -> tuple[str, str]:
    normalized_unicode = unicodedata.normalize("NFC", filename)
    components = filename.split("/")
    canonical = posixpath.normpath(normalized_unicode)
    if (
        not filename
        or normalized_unicode != filename
        or "\x00" in filename
        or "\\" in filename
        or filename.startswith("/")
        or re.match(r"^[A-Za-z]:", filename)
        or ".." in components
        or canonical != filename
        or any(not component or component in {".", ".."} for component in components)
        or any(component.endswith((" ", ".")) for component in components)
        or ":" in filename
        or not canonical.startswith("artifacts/")
    ):
        raise _UnsafeUploadError(GAP_ARCHIVE_PATH_INVALID)
    if len(components) > limits.max_archive_depth:
        raise _UnsafeUploadError(GAP_ARCHIVE_DEPTH_EXCEEDED)
    _scan_secret_bytes(filename.encode())
    return canonical, canonical.casefold()


def _nested_archive(filename: str, content: bytes) -> bool:
    suffixes = {suffix.casefold() for suffix in PurePosixPath(filename).suffixes}
    if suffixes & _NESTED_ARCHIVE_SUFFIXES:
        return True
    return bool(
        content.startswith(_ZIP_SIGNATURES)
        or (
            len(content) >= _TAR_MAGIC_OFFSET + 6
            and content[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + 6] in _TAR_MAGICS
        )
    )


def _inspect_documents(
    contents: dict[str, bytes],
    *,
    commit_sha: str,
    limits: UploadLimits,
) -> tuple[str, str, int]:
    if set(contents) != {"artifacts/manifest.json", "artifacts/results.json"}:
        raise _UnsafeUploadError(GAP_ARCHIVE_SCHEMA_INVALID)
    manifest_bytes = contents["artifacts/manifest.json"]
    results_bytes = contents["artifacts/results.json"]
    if len(manifest_bytes) > limits.max_manifest_bytes:
        raise _UnsafeUploadError(GAP_MANIFEST_TOO_LARGE)
    manifest = _parse_json(manifest_bytes)
    expected_results_hash = _validate_manifest(manifest, commit_sha)
    results = _parse_json(results_bytes)
    check_count = _validate_results(results, commit_sha, max_checks=limits.max_archive_entries)
    results_hash = hashlib.sha256(results_bytes).hexdigest()
    if not hmac.compare_digest(expected_results_hash, results_hash):
        raise _UnsafeUploadError(GAP_MANIFEST_CONTENT_HASH_MISMATCH)
    return hashlib.sha256(manifest_bytes).hexdigest(), results_hash, check_count


def _read_member_stream(
    stream: IO[bytes],
    *,
    limits: UploadLimits,
    cumulative_expanded: int,
) -> tuple[bytes, int]:
    content = bytearray()
    while True:
        remaining = limits.max_member_expanded_bytes - len(content)
        chunk = stream.read(min(limits.chunk_bytes, remaining + 1))
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > limits.max_member_expanded_bytes:
            raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_EXPANDED_LIMIT)
        if cumulative_expanded + len(content) > limits.max_archive_expanded_bytes:
            raise _UnsafeUploadError(GAP_ARCHIVE_EXPANDED_LIMIT)
    return bytes(content), cumulative_expanded + len(content)


def _validate_archive_content(filename: str, content: bytes) -> None:
    _scan_secret_bytes(content)
    if PurePosixPath(filename).suffix.casefold() in _EXECUTABLE_SUFFIXES or content.startswith(
        _EXECUTABLE_MAGICS
    ):
        raise _UnsafeUploadError(GAP_ARCHIVE_SPECIAL_FILE)
    if _nested_archive(filename, content):
        raise _UnsafeUploadError(GAP_ARCHIVE_NESTED)


def _inspect_zip(
    spool: IO[bytes],
    *,
    commit_sha: str,
    limits: UploadLimits,
) -> dict[str, object]:
    try:
        spool.seek(0)
        archive = zipfile.ZipFile(spool, mode="r")
        members = archive.infolist()
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, zipfile.LargeZipFile) as error:
        raise _UnsafeUploadError(GAP_ARCHIVE_BAD_FORMAT) from error
    with archive:
        if archive.comment:
            raise _UnsafeUploadError(GAP_ARCHIVE_METADATA_REJECTED)
        if not 1 <= len(members) <= limits.max_archive_entries:
            raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_COUNT_EXCEEDED)
        collision_keys: set[str] = set()
        prepared: list[tuple[zipfile.ZipInfo, str]] = []
        declared_expanded = 0
        declared_compressed = 0
        for info in members:
            if info.comment or info.extra:
                raise _UnsafeUploadError(GAP_ARCHIVE_METADATA_REJECTED)
            canonical, collision_key = _canonical_archive_path(info.orig_filename, limits)
            if collision_key in collision_keys:
                raise _UnsafeUploadError(GAP_ARCHIVE_DUPLICATE_PATH)
            collision_keys.add(collision_key)
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if info.is_dir() or file_type not in {0, stat.S_IFREG} or mode & 0o111:
                raise _UnsafeUploadError(GAP_ARCHIVE_SPECIAL_FILE)
            if info.flag_bits & 0x1:
                raise _UnsafeUploadError(GAP_ARCHIVE_ENCRYPTED)
            if info.compress_type not in _ALLOWED_ZIP_COMPRESSION:
                raise _UnsafeUploadError(GAP_ARCHIVE_COMPRESSION_UNSUPPORTED)
            if info.compress_size > limits.max_member_compressed_bytes:
                raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_COMPRESSED_LIMIT)
            if info.file_size > limits.max_member_expanded_bytes:
                raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_EXPANDED_LIMIT)
            if (
                canonical == "artifacts/manifest.json"
                and info.file_size > limits.max_manifest_bytes
            ):
                raise _UnsafeUploadError(GAP_MANIFEST_TOO_LARGE)
            declared_expanded += info.file_size
            declared_compressed += info.compress_size
            if declared_expanded > limits.max_archive_expanded_bytes:
                raise _UnsafeUploadError(GAP_ARCHIVE_EXPANDED_LIMIT)
            ratio = (
                float("inf")
                if info.file_size and info.compress_size == 0
                else info.file_size / max(info.compress_size, 1)
            )
            if ratio > limits.max_compression_ratio:
                raise _UnsafeUploadError(GAP_ARCHIVE_COMPRESSION_RATIO)
            prepared.append((info, canonical))

        contents: dict[str, bytes] = {}
        cumulative_expanded = 0
        for info, canonical in prepared:
            try:
                with archive.open(info, mode="r") as member_stream:
                    content, cumulative_expanded = _read_member_stream(
                        member_stream,
                        limits=limits,
                        cumulative_expanded=cumulative_expanded,
                    )
            except _UnsafeUploadError:
                raise
            except (
                zipfile.BadZipFile,
                EOFError,
                OSError,
                RuntimeError,
                zipfile.LargeZipFile,
                zlib.error,
            ) as error:
                raise _UnsafeUploadError(GAP_ARCHIVE_BAD_FORMAT) from error
            if len(content) != info.file_size:
                raise _UnsafeUploadError(GAP_ARCHIVE_BAD_FORMAT)
            _validate_archive_content(canonical, content)
            contents[canonical] = content

    manifest_hash, results_hash, check_count = _inspect_documents(
        contents,
        commit_sha=commit_sha,
        limits=limits,
    )
    return {
        "format": "ZIP",
        "member_count": len(members),
        "compressed_bytes": declared_compressed,
        "expanded_bytes": declared_expanded,
        "manifest_sha256": manifest_hash,
        "results_sha256": results_hash,
        "check_count": check_count,
    }


def _inspect_tar(
    spool: IO[bytes],
    *,
    commit_sha: str,
    limits: UploadLimits,
) -> dict[str, object]:
    try:
        spool.seek(0)
        archive = tarfile.open(fileobj=spool, mode="r:")
    except (tarfile.TarError, EOFError, OSError) as error:
        raise _UnsafeUploadError(GAP_ARCHIVE_BAD_FORMAT) from error
    collision_keys: set[str] = set()
    contents: dict[str, bytes] = {}
    expanded_bytes = 0
    member_count = 0
    with archive:
        try:
            while True:
                info = archive.next()
                if info is None:
                    break
                member_count += 1
                if member_count > limits.max_archive_entries:
                    raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_COUNT_EXCEEDED)
                canonical, collision_key = _canonical_archive_path(info.name, limits)
                if collision_key in collision_keys:
                    raise _UnsafeUploadError(GAP_ARCHIVE_DUPLICATE_PATH)
                collision_keys.add(collision_key)
                if (
                    not info.isfile()
                    or info.issym()
                    or info.islnk()
                    or info.isdev()
                    or info.isfifo()
                    or info.mode & 0o111
                ):
                    raise _UnsafeUploadError(GAP_ARCHIVE_SPECIAL_FILE)
                if info.pax_headers or info.sparse is not None:
                    raise _UnsafeUploadError(GAP_ARCHIVE_METADATA_REJECTED)
                if info.size > limits.max_member_expanded_bytes:
                    raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_EXPANDED_LIMIT)
                if canonical == "artifacts/manifest.json" and info.size > limits.max_manifest_bytes:
                    raise _UnsafeUploadError(GAP_MANIFEST_TOO_LARGE)
                member_stream = archive.extractfile(info)
                if member_stream is None:
                    raise _UnsafeUploadError(GAP_ARCHIVE_SPECIAL_FILE)
                with member_stream:
                    content, expanded_bytes = _read_member_stream(
                        member_stream,
                        limits=limits,
                        cumulative_expanded=expanded_bytes,
                    )
                if len(content) != info.size:
                    raise _UnsafeUploadError(GAP_ARCHIVE_BAD_FORMAT)
                _validate_archive_content(canonical, content)
                contents[canonical] = content
        except _UnsafeUploadError:
            raise
        except (tarfile.TarError, EOFError, OSError) as error:
            raise _UnsafeUploadError(GAP_ARCHIVE_BAD_FORMAT) from error
    if member_count == 0:
        raise _UnsafeUploadError(GAP_ARCHIVE_MEMBER_COUNT_EXCEEDED)
    manifest_hash, results_hash, check_count = _inspect_documents(
        contents,
        commit_sha=commit_sha,
        limits=limits,
    )
    return {
        "format": "TAR",
        "member_count": member_count,
        "compressed_bytes": expanded_bytes,
        "expanded_bytes": expanded_bytes,
        "manifest_sha256": manifest_hash,
        "results_sha256": results_hash,
        "check_count": check_count,
    }


def _inspect_spool(
    spool: IO[bytes],
    *,
    digest: str,
    size: int,
    commit_sha: str,
    limits: UploadLimits,
) -> InspectedUpload:
    spool.seek(0)
    raw_bytes = spool.read(size + 1)
    _scan_secret_bytes(raw_bytes)
    spool.seek(0)
    prefix = spool.read(min(size, max(512, _TAR_MAGIC_OFFSET + 6)))
    detected_media_type = _sniff_media_type(prefix)
    if detected_media_type is None:
        raise _UnsafeUploadError(GAP_MEDIA_TYPE_NOT_ALLOWED)
    if detected_media_type == EvidenceBlob.MediaType.JSON:
        if size > limits.max_manifest_bytes:
            raise _UnsafeUploadError(GAP_MANIFEST_TOO_LARGE)
        spool.seek(0)
        document_bytes = spool.read(size + 1)
        _scan_secret_bytes(document_bytes)
        document = _parse_json(document_bytes)
        check_count = _validate_results(
            document,
            commit_sha,
            max_checks=limits.max_archive_entries,
        )
        summary: dict[str, object] = {
            "format": "JSON",
            "member_count": 1,
            "compressed_bytes": size,
            "expanded_bytes": size,
            "results_sha256": digest,
            "check_count": check_count,
        }
    elif detected_media_type == EvidenceBlob.MediaType.ZIP:
        summary = _inspect_zip(spool, commit_sha=commit_sha, limits=limits)
    else:
        summary = _inspect_tar(spool, commit_sha=commit_sha, limits=limits)
    spool.seek(0)
    return InspectedUpload(
        content_hash=digest,
        verified_size=size,
        detected_media_type=detected_media_type,
        archive_summary=summary,
    )


def _receive_and_inspect(
    stream: IO[bytes],
    *,
    content_length: int | None,
    expected_size: int,
    expected_sha256: str,
    commit_sha: str,
    limits: UploadLimits,
) -> tuple[IO[bytes], InspectedUpload]:
    if content_length is not None and (
        isinstance(content_length, bool)
        or content_length < 0
        or content_length > limits.max_upload_bytes
    ):
        raise _UnsafeUploadError(GAP_UPLOAD_TOO_LARGE)
    if content_length is not None and content_length != expected_size:
        raise _UnsafeUploadError(GAP_UPLOAD_SIZE_MISMATCH)
    spool = tempfile.SpooledTemporaryFile(
        max_size=limits.max_manifest_bytes,
        mode="w+b",
    )
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = stream.read(limits.chunk_bytes)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise _UnsafeUploadError(GAP_MANIFEST_MALFORMED)
            size += len(chunk)
            if size > limits.max_upload_bytes:
                raise _UnsafeUploadError(GAP_UPLOAD_TOO_LARGE)
            digest.update(chunk)
            spool.write(chunk)
        if size != expected_size:
            raise _UnsafeUploadError(GAP_UPLOAD_SIZE_MISMATCH)
        actual_digest = digest.hexdigest()
        if not hmac.compare_digest(actual_digest, expected_sha256):
            raise _UnsafeUploadError(GAP_UPLOAD_DIGEST_MISMATCH)
        inspected = _inspect_spool(
            spool,
            digest=actual_digest,
            size=size,
            commit_sha=commit_sha,
            limits=limits,
        )
        return spool, inspected
    except BaseException:
        spool.close()
        raise


def inspect_evidence_upload(
    stream: IO[bytes],
    *,
    content_length: int | None,
    expected_size: int,
    expected_sha256: str,
    commit_sha: str,
    limits: UploadLimits = DEFAULT_UPLOAD_LIMITS,
) -> InspectedUpload:
    """Inspect a bounded stream for tests and non-persisting callers."""
    _validate_digest(expected_sha256)
    validate_full_commit(commit_sha)
    try:
        spool, inspected = _receive_and_inspect(
            stream,
            content_length=content_length,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            commit_sha=commit_sha,
            limits=limits,
        )
    except _UnsafeUploadError as error:
        raise EvidenceUploadError(
            error.code,
            _SAFE_MESSAGES[error.code],
            413 if error.code == GAP_UPLOAD_TOO_LARGE else 400,
        ) from None
    spool.close()
    return inspected
