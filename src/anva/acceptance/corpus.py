"""Fail-closed copying of a public corpus into an oracle-isolated canonical root."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from anva.contracts.validation import ContractValidationError, validate_payload

INPUT_MANIFEST_NAME = "acceptance-corpus.json"
CANONICAL_MANIFEST_NAME = "canonical-manifest.json"
MAX_MANIFEST_BYTES = 1_000_000
HARD_MAX_INVENTORY_ENTRIES = 20_000
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
DRIVE_PATH_PATTERN = re.compile(r"^[A-Za-z]:")
FORBIDDEN_PARTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "grader",
        "graders",
        "held-control",
        "held_control",
        "oracle",
        "oracles",
    }
)
FORBIDDEN_NAMES = frozenset(
    {
        "grader.json",
        "grader.py",
        "oracle.json",
    }
)


class AcceptanceCorpusError(ValueError):
    """A public corpus failed an isolation or integrity invariant."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AdapterLimits:
    """Operator-owned ceilings that an input manifest cannot relax."""

    max_files: int = 10_000
    max_total_bytes: int = 1_073_741_824
    max_file_bytes: int = 268_435_456
    max_depth: int = 32

    def validate(self) -> None:
        if not 1 <= self.max_files <= 10_000:
            raise AcceptanceCorpusError("invalid_limits", "max_files is outside the hard bound")
        if not 1 <= self.max_total_bytes <= 1_073_741_824:
            raise AcceptanceCorpusError(
                "invalid_limits", "max_total_bytes is outside the hard bound"
            )
        if not 1 <= self.max_file_bytes <= 268_435_456:
            raise AcceptanceCorpusError(
                "invalid_limits", "max_file_bytes is outside the hard bound"
            )
        if not 1 <= self.max_depth <= 32:
            raise AcceptanceCorpusError("invalid_limits", "max_depth is outside the hard bound")


@dataclass(frozen=True)
class CorpusFile:
    """One validated public regular file."""

    path: str
    sha256: str
    size_bytes: int

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class CanonicalCorpus:
    """Stable identity emitted after canonicalization or verification."""

    corpus_id: str
    manifest_sha256: str
    source_fingerprint: str
    canonical_manifest_sha256: str
    file_count: int
    total_bytes: int

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "verified",
            "corpus_id": self.corpus_id,
            "manifest_sha256": self.manifest_sha256,
            "source_fingerprint": self.source_fingerprint,
            "canonical_manifest_sha256": self.canonical_manifest_sha256,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _validate_root(path: Path, *, empty: bool) -> Path:
    if path.is_symlink():
        raise AcceptanceCorpusError("unsafe_root", "Acceptance root cannot be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise AcceptanceCorpusError("unsafe_root", "Acceptance root is unavailable") from error
    if not resolved.is_dir():
        raise AcceptanceCorpusError("unsafe_root", "Acceptance root must be a directory")
    if empty:
        try:
            next(resolved.iterdir())
        except StopIteration:
            pass
        else:
            raise AcceptanceCorpusError(
                "canonical_not_empty", "Canonical corpus root must be fresh and empty"
            )
    return resolved


def _read_regular_file(root: Path, relative: PurePosixPath, *, max_bytes: int) -> bytes:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    current_fd = os.open(root, directory_flags)
    try:
        for part in relative.parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=current_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise AcceptanceCorpusError(
                    "unsupported_file", "Acceptance inputs must be singly linked regular files"
                )
            if before.st_size > max_bytes:
                raise AcceptanceCorpusError("file_too_large", "Acceptance input exceeds byte limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, min(64 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise AcceptanceCorpusError(
                        "file_too_large", "Acceptance input exceeds byte limit"
                    )
            after = os.fstat(file_fd)
            stable = (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if not stable:
                raise AcceptanceCorpusError(
                    "source_changed", "Acceptance input changed while it was being read"
                )
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    except OSError as error:
        raise AcceptanceCorpusError(
            "unsafe_path", "Acceptance input path could not be opened safely"
        ) from error
    finally:
        os.close(current_fd)


def _load_input_manifest(raw_root: Path, pinned_sha256: str) -> tuple[dict[str, object], str]:
    if SHA256_PATTERN.fullmatch(pinned_sha256) is None:
        raise AcceptanceCorpusError(
            "invalid_manifest_pin", "Manifest SHA-256 pin must be 64 lowercase hex characters"
        )
    raw = _read_regular_file(
        raw_root,
        PurePosixPath(INPUT_MANIFEST_NAME),
        max_bytes=MAX_MANIFEST_BYTES,
    )
    digest = hashlib.sha256(raw).hexdigest()
    if not secrets.compare_digest(digest, pinned_sha256):
        raise AcceptanceCorpusError(
            "manifest_pin_mismatch", "Acceptance manifest does not match the operator pin"
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
        validate_payload("acceptance-corpus", payload)
    except (ContractValidationError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceCorpusError("invalid_manifest", "Acceptance manifest is invalid") from error
    return cast(dict[str, object], payload), digest


def _manifest_files(
    manifest: dict[str, object], operator_limits: AdapterLimits
) -> tuple[tuple[CorpusFile, ...], AdapterLimits]:
    limits = cast(dict[str, int], manifest["limits"])
    declared = AdapterLimits(
        max_files=limits["max_files"],
        max_total_bytes=limits["max_total_bytes"],
        max_file_bytes=limits["max_file_bytes"],
        max_depth=limits["max_depth"],
    )
    declared.validate()
    operator_limits.validate()
    if (
        declared.max_files > operator_limits.max_files
        or declared.max_total_bytes > operator_limits.max_total_bytes
        or declared.max_file_bytes > operator_limits.max_file_bytes
        or declared.max_depth > operator_limits.max_depth
    ):
        raise AcceptanceCorpusError(
            "declared_limit_exceeded", "Manifest limits exceed operator-owned ceilings"
        )

    records = cast(list[dict[str, object]], manifest["files"])
    if len(records) > declared.max_files:
        raise AcceptanceCorpusError("file_count_exceeded", "Manifest file count exceeds its limit")
    files: list[CorpusFile] = []
    observed: set[str] = set()
    total_bytes = 0
    for record in records:
        path = cast(str, record["path"])
        digest = cast(str, record["sha256"])
        size_bytes = cast(int, record["size_bytes"])
        parts = path.split("/")
        pure = PurePosixPath(path)
        lowered = tuple(part.casefold() for part in parts[1:])
        if (
            "\x00" in path
            or "\\" in path
            or DRIVE_PATH_PATTERN.match(path)
            or pure.is_absolute()
            or pure.as_posix() != path
            or any(part in {"", ".", ".."} for part in parts)
            or len(parts) < 2
            or parts[0] != "payload"
        ):
            raise AcceptanceCorpusError("unsafe_path", "Manifest contains an unsafe file path")
        if any(part in FORBIDDEN_PARTS for part in lowered) or lowered[-1] in FORBIDDEN_NAMES:
            raise AcceptanceCorpusError(
                "forbidden_control_path", "Manifest exposes a forbidden control path"
            )
        if path in observed:
            raise AcceptanceCorpusError("duplicate_path", "Manifest contains a duplicate path")
        if len(path.encode("utf-8")) > 1_000:
            raise AcceptanceCorpusError("path_too_long", "Manifest path exceeds byte limit")
        if len(parts) - 1 > declared.max_depth:
            raise AcceptanceCorpusError("depth_exceeded", "Manifest path exceeds depth limit")
        if size_bytes > declared.max_file_bytes:
            raise AcceptanceCorpusError("file_too_large", "Manifest file exceeds byte limit")
        observed.add(path)
        total_bytes += size_bytes
        if total_bytes > declared.max_total_bytes:
            raise AcceptanceCorpusError(
                "total_bytes_exceeded", "Manifest total bytes exceed the declared limit"
            )
        files.append(CorpusFile(path=path, sha256=digest, size_bytes=size_bytes))
    if [item.path for item in files] != sorted(item.path for item in files):
        raise AcceptanceCorpusError("noncanonical_order", "Manifest files must be path-sorted")
    return tuple(files), declared


def _verify_raw_inventory(
    raw_root: Path,
    files: tuple[CorpusFile, ...],
    *,
    declared_max_files: int,
) -> None:
    expected_files = {INPUT_MANIFEST_NAME, *(item.path for item in files)}
    expected_directories = {"payload"}
    for item in files:
        relative_path = PurePosixPath(item.path)
        expected_directories.update(
            parent.as_posix() for parent in relative_path.parents if parent.parts
        )

    pending = [raw_root]
    observed_files: set[str] = set()
    observed_data_files = 0
    observed_entries = 0
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as error:
            raise AcceptanceCorpusError(
                "source_unavailable", "Acceptance input directory cannot be read"
            ) from error
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > HARD_MAX_INVENTORY_ENTRIES:
                    raise AcceptanceCorpusError(
                        "inventory_limit_exceeded",
                        "Acceptance input exceeds the hard inventory limit",
                    )
                entry_path = Path(entry.path)
                relative = entry_path.relative_to(raw_root).as_posix()
                try:
                    metadata = os.lstat(entry_path)
                except OSError as error:
                    raise AcceptanceCorpusError(
                        "source_unavailable", "Acceptance input entry cannot be inspected"
                    ) from error
                if stat.S_ISLNK(metadata.st_mode):
                    raise AcceptanceCorpusError(
                        "symlink_rejected", "Acceptance input has a symlink"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    if relative not in expected_directories:
                        raise AcceptanceCorpusError(
                            "unlisted_entry", "Acceptance input has an unlisted directory"
                        )
                    pending.append(entry_path)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise AcceptanceCorpusError(
                        "unsupported_file", "Acceptance input has an unsupported file"
                    )
                if relative != INPUT_MANIFEST_NAME:
                    observed_data_files += 1
                    if observed_data_files > declared_max_files:
                        raise AcceptanceCorpusError(
                            "file_count_exceeded",
                            "Acceptance input exceeds the declared file limit",
                        )
                if relative not in expected_files:
                    raise AcceptanceCorpusError(
                        "unlisted_entry", "Acceptance input has an unlisted file"
                    )
                observed_files.add(relative)
    if observed_files != expected_files:
        raise AcceptanceCorpusError(
            "inventory_mismatch", "Acceptance input does not match the manifest inventory"
        )


def _verify_canonical_inventory(
    canonical_root: Path,
    files: tuple[CorpusFile, ...],
) -> None:
    expected_files = {CANONICAL_MANIFEST_NAME, *(item.path for item in files)}
    expected_directories = {"payload"}
    for item in files:
        relative_path = PurePosixPath(item.path)
        expected_directories.update(
            parent.as_posix() for parent in relative_path.parents if parent.parts
        )

    pending = [canonical_root]
    observed_files: set[str] = set()
    observed_entries = 0
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as error:
            raise AcceptanceCorpusError(
                "canonical_unavailable", "Canonical corpus cannot be read"
            ) from error
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > HARD_MAX_INVENTORY_ENTRIES:
                    raise AcceptanceCorpusError(
                        "inventory_limit_exceeded",
                        "Canonical corpus exceeds the hard inventory limit",
                    )
                entry_path = Path(entry.path)
                relative = entry_path.relative_to(canonical_root).as_posix()
                try:
                    metadata = os.lstat(entry_path)
                except OSError as error:
                    raise AcceptanceCorpusError(
                        "canonical_unavailable",
                        "Canonical corpus entry cannot be inspected",
                    ) from error
                if stat.S_ISLNK(metadata.st_mode):
                    raise AcceptanceCorpusError(
                        "symlink_rejected", "Canonical corpus has a symlink"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    if relative not in expected_directories:
                        raise AcceptanceCorpusError(
                            "unlisted_entry", "Canonical corpus has an unlisted directory"
                        )
                    pending.append(entry_path)
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise AcceptanceCorpusError(
                        "unsupported_file", "Canonical corpus has an unsupported file"
                    )
                if relative not in expected_files:
                    raise AcceptanceCorpusError(
                        "unlisted_entry", "Canonical corpus has an unlisted file"
                    )
                observed_files.add(relative)
    if observed_files != expected_files:
        raise AcceptanceCorpusError(
            "inventory_mismatch", "Canonical corpus does not match its manifest"
        )


def _source_fingerprint(corpus_id: str, source_commit: str, files: tuple[CorpusFile, ...]) -> str:
    identity = {
        "schema_version": "1.0",
        "corpus_id": corpus_id,
        "source_commit": source_commit,
        "files": [item.as_dict() for item in files],
    }
    return hashlib.sha256(_canonical_json(identity)).hexdigest()


def _write_atomic(path: Path, content: bytes, tracked_files: list[Path]) -> None:
    """Publish one complete file without ever exposing a partial destination."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    temporary = path.with_name(f".{path.name}.anva-{secrets.token_hex(16)}.tmp")
    tracked_files.append(path)
    tracked_files.append(temporary)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("Acceptance output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _cleanup_canonical_output(
    canonical: Path,
    tracked_files: list[Path],
    tracked_directories: list[Path],
) -> bool:
    """Best-effort cleanup that never replaces the original failure with a traceback."""
    clean = True
    for directory in tracked_directories:
        try:
            if directory.exists() and not directory.is_symlink():
                directory.chmod(0o700)
        except OSError:
            clean = False
    try:
        root_info = canonical.stat(follow_symlinks=False)
        if root_info.st_uid == os.geteuid():
            canonical.chmod(0o700)
        elif not (root_info.st_uid == 10001 and root_info.st_gid == 10001
                  and stat.S_IMODE(root_info.st_mode) == 0o1777):
            clean = False
    except OSError:
        clean = False
    for path in reversed(tracked_files):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            clean = False
    for directory in reversed(tracked_directories):
        try:
            directory.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            clean = False
    try:
        if any(canonical.iterdir()):
            clean = False
    except OSError:
        clean = False
    return clean


def canonicalize_corpus(
    *,
    raw_root: Path,
    canonical_root: Path,
    manifest_sha256: str,
    operator_limits: AdapterLimits | None = None,
) -> CanonicalCorpus:
    """Verify and copy exactly one pinned public corpus into a fresh canonical root."""
    raw = _validate_root(raw_root, empty=False)
    canonical = _validate_root(canonical_root, empty=True)
    if raw == canonical or raw.is_relative_to(canonical) or canonical.is_relative_to(raw):
        raise AcceptanceCorpusError(
            "overlapping_roots", "Raw and canonical acceptance roots must be disjoint"
        )
    manifest, observed_manifest_sha256 = _load_input_manifest(raw, manifest_sha256)
    files, declared_limits = _manifest_files(manifest, operator_limits or AdapterLimits())
    _verify_raw_inventory(
        raw,
        files,
        declared_max_files=declared_limits.max_files,
    )

    created_files: list[Path] = []
    published_files: list[Path] = []
    created_directories: list[Path] = []
    try:
        for item in files:
            relative = PurePosixPath(item.path)
            content = _read_regular_file(raw, relative, max_bytes=item.size_bytes)
            if len(content) != item.size_bytes or not secrets.compare_digest(
                hashlib.sha256(content).hexdigest(), item.sha256
            ):
                raise AcceptanceCorpusError(
                    "content_mismatch", "Acceptance input does not match its manifest"
                )
            destination = canonical.joinpath(*relative.parts)
            missing: list[Path] = []
            current = destination.parent
            while current != canonical and not current.exists():
                missing.append(current)
                current = current.parent
            for directory in reversed(missing):
                created_directories.append(directory)
                directory.mkdir(mode=0o700)
            _write_atomic(destination, content, created_files)
            published_files.append(destination)

        corpus_id = cast(str, manifest["corpus_id"])
        source_commit = cast(str, manifest["source_commit"])
        fingerprint = _source_fingerprint(corpus_id, source_commit, files)
        canonical_manifest = {
            "schema_version": "1.0",
            "corpus_id": corpus_id,
            "generated_at": manifest["generated_at"],
            "source_commit": source_commit,
            "input_manifest_sha256": observed_manifest_sha256,
            "source_fingerprint": fingerprint,
            "files": [item.as_dict() for item in files],
        }
        canonical_bytes = _canonical_json(canonical_manifest)
        canonical_manifest_path = canonical / CANONICAL_MANIFEST_NAME
        _write_atomic(canonical_manifest_path, canonical_bytes, created_files)
        published_files.append(canonical_manifest_path)
        for path in published_files:
            path.chmod(0o444)
        for path in reversed(created_directories):
            path.chmod(0o555)
        root_info = canonical.stat(follow_symlinks=False)
        if root_info.st_uid == os.geteuid():
            canonical.chmod(0o555)
        elif not (root_info.st_uid == 10001 and root_info.st_gid == 10001
                  and stat.S_IMODE(root_info.st_mode) == 0o1777):
            raise OSError("canonical volume root ownership is invalid")
        return CanonicalCorpus(
            corpus_id=corpus_id,
            manifest_sha256=observed_manifest_sha256,
            source_fingerprint=fingerprint,
            canonical_manifest_sha256=hashlib.sha256(canonical_bytes).hexdigest(),
            file_count=len(files),
            total_bytes=sum(item.size_bytes for item in files),
        )
    except OSError as error:
        cleaned = _cleanup_canonical_output(canonical, created_files, created_directories)
        if not cleaned:
            raise AcceptanceCorpusError(
                "canonical_cleanup_failed",
                "Canonical corpus cleanup failed; discard the ephemeral volume",
            ) from None
        raise AcceptanceCorpusError(
            "canonical_unavailable", "Canonical corpus output is unavailable"
        ) from error
    except Exception:
        cleaned = _cleanup_canonical_output(canonical, created_files, created_directories)
        if not cleaned:
            raise AcceptanceCorpusError(
                "canonical_cleanup_failed",
                "Canonical corpus cleanup failed; discard the ephemeral volume",
            ) from None
        raise


def verify_canonical_corpus(
    canonical_root: Path,
    *,
    expected_manifest_sha256: str,
    expected_source_fingerprint: str,
    expected_canonical_manifest_sha256: str,
) -> CanonicalCorpus:
    """Re-verify a canonical root against three operator-pinned identities."""
    pins = (
        expected_manifest_sha256,
        expected_source_fingerprint,
        expected_canonical_manifest_sha256,
    )
    if any(SHA256_PATTERN.fullmatch(pin) is None for pin in pins):
        raise AcceptanceCorpusError(
            "invalid_verification_pin",
            "Acceptance verification pins must be 64 lowercase hex characters",
        )
    canonical = _validate_root(canonical_root, empty=False)
    manifest_bytes = _read_regular_file(
        canonical,
        PurePosixPath(CANONICAL_MANIFEST_NAME),
        max_bytes=MAX_MANIFEST_BYTES,
    )
    canonical_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if not secrets.compare_digest(
        canonical_manifest_sha256,
        expected_canonical_manifest_sha256,
    ):
        raise AcceptanceCorpusError(
            "verification_pin_mismatch",
            "Canonical corpus does not match the operator-pinned identity",
        )
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceCorpusError(
            "invalid_canonical_manifest", "Canonical manifest is invalid"
        ) from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "corpus_id",
        "generated_at",
        "source_commit",
        "input_manifest_sha256",
        "source_fingerprint",
        "files",
    }:
        raise AcceptanceCorpusError("invalid_canonical_manifest", "Canonical manifest is invalid")
    if manifest.get("schema_version") != "1.0":
        raise AcceptanceCorpusError(
            "invalid_canonical_manifest", "Canonical manifest version is unsupported"
        )
    corpus_id = manifest.get("corpus_id")
    source_commit = manifest.get("source_commit")
    input_manifest_sha256 = manifest.get("input_manifest_sha256")
    source_fingerprint = manifest.get("source_fingerprint")
    raw_records = manifest.get("files")
    if (
        not isinstance(corpus_id, str)
        or not isinstance(source_commit, str)
        or re.fullmatch(r"[a-f0-9]{40}", source_commit) is None
        or not isinstance(input_manifest_sha256, str)
        or SHA256_PATTERN.fullmatch(input_manifest_sha256) is None
        or not isinstance(source_fingerprint, str)
        or SHA256_PATTERN.fullmatch(source_fingerprint) is None
        or not isinstance(raw_records, list)
    ):
        raise AcceptanceCorpusError("invalid_canonical_manifest", "Canonical manifest is invalid")
    files: list[CorpusFile] = []
    observed_paths: set[str] = set()
    for record in raw_records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size_bytes"}:
            raise AcceptanceCorpusError(
                "invalid_canonical_manifest", "Canonical file inventory is invalid"
            )
        path = record.get("path")
        digest = record.get("sha256")
        size = record.get("size_bytes")
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise AcceptanceCorpusError(
                "invalid_canonical_manifest", "Canonical file inventory is invalid"
            )
        parts = path.split("/")
        pure = PurePosixPath(path)
        lowered = tuple(part.casefold() for part in parts[1:])
        if (
            "\x00" in path
            or "\\" in path
            or DRIVE_PATH_PATTERN.match(path)
            or pure.is_absolute()
            or pure.as_posix() != path
            or any(part in {"", ".", ".."} for part in parts)
            or len(parts) < 2
            or parts[0] != "payload"
            or any(part in FORBIDDEN_PARTS for part in lowered)
            or lowered[-1] in FORBIDDEN_NAMES
            or len(parts) - 1 > 32
            or len(path.encode("utf-8")) > 1_000
            or size > 268_435_456
            or path in observed_paths
        ):
            raise AcceptanceCorpusError(
                "invalid_canonical_manifest", "Canonical file path is invalid"
            )
        observed_paths.add(path)
        files.append(CorpusFile(path=path, sha256=digest, size_bytes=size))
    file_tuple = tuple(files)
    if (
        not 1 <= len(file_tuple) <= 10_000
        or sum(item.size_bytes for item in file_tuple) > 1_073_741_824
        or [item.path for item in file_tuple] != sorted(item.path for item in file_tuple)
    ):
        raise AcceptanceCorpusError(
            "invalid_canonical_manifest", "Canonical file inventory is invalid"
        )
    expected_fingerprint = _source_fingerprint(corpus_id, source_commit, file_tuple)
    if (
        not secrets.compare_digest(input_manifest_sha256, expected_manifest_sha256)
        or not secrets.compare_digest(source_fingerprint, expected_source_fingerprint)
        or not secrets.compare_digest(source_fingerprint, expected_fingerprint)
    ):
        raise AcceptanceCorpusError(
            "verification_pin_mismatch",
            "Canonical corpus does not match the operator-pinned identity",
        )
    _verify_canonical_inventory(canonical, file_tuple)
    for item in file_tuple:
        content = _read_regular_file(
            canonical,
            PurePosixPath(item.path),
            max_bytes=item.size_bytes,
        )
        if len(content) != item.size_bytes or not secrets.compare_digest(
            hashlib.sha256(content).hexdigest(), item.sha256
        ):
            raise AcceptanceCorpusError(
                "content_mismatch", "Canonical corpus content does not match"
            )
    return CanonicalCorpus(
        corpus_id=corpus_id,
        manifest_sha256=input_manifest_sha256,
        source_fingerprint=source_fingerprint,
        canonical_manifest_sha256=canonical_manifest_sha256,
        file_count=len(file_tuple),
        total_bytes=sum(item.size_bytes for item in file_tuple),
    )
