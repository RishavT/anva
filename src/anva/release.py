"""Deterministic release inventory and checksum generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from datetime import UTC, date, datetime
from pathlib import Path

from anva import __version__

COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
IMAGE_ID_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
VULNERABILITY_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
EXPECTED_ARTIFACT_SUFFIXES = (
    ".whl",
    "install-0.1.0.tar.gz",
    "-codex-skills-1.0.0.tar.gz",
    "-claude-skills-1.0.0.tar.gz",
    "image.spdx.json",
    "image.cyclonedx.json",
    "image-vulnerabilities.json",
    "source-security.json",
    "vulnerability-exceptions.json",
)
GENERATED_METADATA_NAMES = frozenset({"release-manifest.json", "SHA256SUMS"})
SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
MANIFEST_LIMITATIONS = (
    "The recorded image ID identifies the locally verified OCI image.",
    "A registry digest and signed tag are recorded only by the publication step.",
    "External fresh-agent and human acceptance evidence is not generated here.",
)
UV_BUILD_GITIGNORE_CONTENT = b"*"


def remove_uv_build_gitignore(directory: Path) -> None:
    """Remove only uv's exact build-directory ignore-file byproduct."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Release directory must be a regular directory")
    path = directory / ".gitignore"
    try:
        initial = path.lstat()
    except FileNotFoundError as error:
        raise ValueError("uv build did not create its expected .gitignore") from error
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError("uv build .gitignore must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        content = os.read(descriptor, len(UV_BUILD_GITIGNORE_CONTENT) + 1)
    finally:
        os.close(descriptor)
    current = path.lstat()
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError("uv build .gitignore changed while it was validated")
    if content != UV_BUILD_GITIGNORE_CONTENT:
        raise ValueError("uv build .gitignore has unexpected content")
    path.unlink()


def _artifact_files(directory: Path) -> tuple[Path, ...]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Release directory must be a regular directory")
    files = tuple(
        path
        for path in sorted(directory.iterdir())
        if path.name not in GENERATED_METADATA_NAMES
        and not path.name.endswith(".tmp")
        and path.name not in {".gitkeep", ".trivy-cache", ".trivyignore"}
    )
    if not files or len(files) > 100:
        raise ValueError("Release artifact count must be between 1 and 100")
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Release artifacts must be regular non-symlink files")
    names = tuple(path.name for path in files)
    if any(SAFE_ARTIFACT_NAME.fullmatch(name) is None for name in names):
        raise ValueError("Release artifact names must be safe portable basenames")
    for suffix in EXPECTED_ARTIFACT_SUFFIXES:
        if not any(name.endswith(suffix) for name in names):
            raise ValueError(f"Release is missing required artifact suffix: {suffix}")
    return files


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Release manifest contains duplicate key: {key}")
        result[key] = value
    return result


def build_release_manifest(
    *,
    directory: Path,
    source_commit: str,
    image_reference: str,
    image_id: str,
    source_date_epoch: int,
) -> dict[str, object]:
    """Write a release manifest and checksum file for an exact local image."""
    if COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise ValueError("Source commit must be a full lowercase Git SHA")
    if IMAGE_ID_PATTERN.fullmatch(image_id) is None:
        raise ValueError("Image ID must be a sha256 digest")
    if not image_reference or any(character.isspace() for character in image_reference):
        raise ValueError("Image reference must be non-empty and contain no whitespace")
    if source_date_epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must not be negative")
    resolved = directory.resolve()
    artifacts = _artifact_files(resolved)
    records = [
        {"path": path.name, "size": path.stat().st_size, "sha256": _sha256(path)}
        for path in artifacts
    ]
    manifest: dict[str, object] = {
        "schema_version": 2,
        "artifact_kind": "anva.generated-release-manifest",
        "publication_status": "generated_unpublished",
        "anva_version": __version__,
        "source_commit": source_commit,
        "source_date_epoch": source_date_epoch,
        "created_at": datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat(),
        "image": {"reference": image_reference, "id": image_id},
        "artifacts": records,
        "limitations": list(MANIFEST_LIMITATIONS),
    }
    manifest_path = resolved / "release-manifest.json"
    manifest_path.write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    checksummed = (*artifacts, manifest_path)
    checksum_path = resolved / "SHA256SUMS"
    checksum_path.write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksummed),
        encoding="utf-8",
    )
    return manifest


def verify_release_manifest(
    *,
    directory: Path,
    source_commit: str,
    image_reference: str,
    image_id: str,
) -> dict[str, object]:
    """Fail closed unless generated release metadata matches the exact candidate."""
    if COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise ValueError("Source commit must be a full lowercase Git SHA")
    if IMAGE_ID_PATTERN.fullmatch(image_id) is None:
        raise ValueError("Image ID must be a sha256 digest")
    resolved = directory.resolve()
    if directory.is_symlink() or not resolved.is_dir():
        raise ValueError("Release directory must be a regular directory")
    manifest_path = resolved / "release-manifest.json"
    checksum_path = resolved / "SHA256SUMS"
    for path in (manifest_path, checksum_path):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Generated release metadata is missing or unsafe: {path.name}")
        if path.stat().st_size > 8_000_000:
            raise ValueError(f"Generated release metadata is too large: {path.name}")
    try:
        manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=_unique_json_object)
    except json.JSONDecodeError as error:
        raise ValueError("Release manifest is not valid JSON") from error
    required_keys = {
        "schema_version",
        "artifact_kind",
        "publication_status",
        "anva_version",
        "source_commit",
        "source_date_epoch",
        "created_at",
        "image",
        "artifacts",
        "limitations",
    }
    if not isinstance(manifest, dict) or set(manifest) != required_keys:
        raise ValueError("Release manifest structure is invalid")
    if (
        manifest.get("schema_version") != 2
        or manifest.get("artifact_kind") != "anva.generated-release-manifest"
        or manifest.get("publication_status") != "generated_unpublished"
    ):
        raise ValueError("Release manifest is not a current generated release asset")
    if manifest.get("source_commit") != source_commit:
        raise ValueError("Release manifest source commit does not match the exact candidate")
    if manifest.get("image") != {"reference": image_reference, "id": image_id}:
        raise ValueError("Release manifest image does not match the exact candidate")
    source_date_epoch = manifest.get("source_date_epoch")
    if (
        manifest.get("anva_version") != __version__
        or not isinstance(source_date_epoch, int)
        or isinstance(source_date_epoch, bool)
        or source_date_epoch < 0
        or manifest.get("created_at")
        != datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat()
        or manifest.get("limitations") != list(MANIFEST_LIMITATIONS)
    ):
        raise ValueError("Release manifest provenance metadata is invalid")
    records = manifest.get("artifacts")
    if not isinstance(records, list) or not 1 <= len(records) <= 100:
        raise ValueError("Release manifest artifact inventory is invalid")
    expected_lines: list[str] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise ValueError("Release manifest artifact record is invalid")
        name, size, digest = record.get("path"), record.get("size"), record.get("sha256")
        if (
            not isinstance(name, str)
            or SAFE_ARTIFACT_NAME.fullmatch(name) is None
            or name in GENERATED_METADATA_NAMES
            or name in seen
        ):
            raise ValueError("Release manifest artifact path is unsafe or duplicated")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("Release manifest artifact size is invalid")
        if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ValueError("Release manifest artifact digest is invalid")
        path = resolved / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
            raise ValueError(f"Release artifact is missing, unsafe, or has changed: {name}")
        if _sha256(path) != digest:
            raise ValueError(f"Release artifact checksum mismatch: {name}")
        expected_lines.append(f"{digest}  {name}\n")
        seen.add(name)
    actual_files = {path.name for path in _artifact_files(resolved)}
    if actual_files != seen:
        raise ValueError("Release directory has missing or unrecorded publishable artifacts")
    expected_lines.append(f"{_sha256(manifest_path)}  release-manifest.json\n")
    if checksum_path.read_text(encoding="utf-8") != "".join(expected_lines):
        raise ValueError("SHA256SUMS is stale, malformed, or does not match the manifest")
    return manifest


def verify_release_worktree_status(
    *, status: bytes, release_path: Path, manifest: dict[str, object]
) -> None:
    """Validate NUL-delimited Git status supplied by the trusted release host."""
    if len(status) > 8_000_000:
        raise ValueError("Git worktree status exceeds 8 MB")
    if release_path.is_absolute() or any(part in {"", ".", ".."} for part in release_path.parts):
        raise ValueError("Release directory path is unsafe")
    records = manifest.get("artifacts")
    if not isinstance(records, list):  # pragma: no cover - verified caller invariant.
        raise ValueError("Release manifest artifact inventory is invalid")
    allowed = {(release_path / str(record["path"])).as_posix() for record in records} | {
        (release_path / name).as_posix() for name in GENERATED_METADATA_NAMES
    }
    unexpected: list[str] = []
    entries = status.split(b"\0")
    index = 0
    while index < len(entries):
        entry = entries[index]
        index += 1
        if not entry:
            continue
        decoded = entry.decode("utf-8", errors="strict")
        if len(decoded) < 4 or decoded[2] != " ":
            raise ValueError("Git worktree status output is malformed")
        status, path = decoded[:2], decoded[3:]
        paths = [path]
        if "R" in status or "C" in status:
            if index >= len(entries) or not entries[index]:
                raise ValueError("Git worktree status rename output is malformed")
            paths.append(entries[index].decode("utf-8", errors="strict"))
            index += 1
        if status != "!!" or any(candidate not in allowed for candidate in paths):
            unexpected.extend(paths)
    if unexpected:
        summary = ", ".join(sorted(unexpected)[:10])
        raise ValueError(f"Release requires a clean exact worktree; unexpected paths: {summary}")


def build_trivy_ignorefile(
    *,
    input_path: Path,
    vulnerability_report_path: Path,
    output_path: Path,
    current_date: date | None = None,
) -> tuple[str, ...]:
    """Validate reviewed, expiring exceptions and render Trivy's exact ignore list."""
    if input_path.is_symlink() or not input_path.is_file():
        raise ValueError("Vulnerability exception input must be a regular file")
    if input_path.stat().st_size > 128_000:
        raise ValueError("Vulnerability exception input exceeds 128 KB")
    payload = json.loads(input_path.read_bytes())
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "reviewed_at",
        "expires_at",
        "policy",
        "exceptions",
    }:
        raise ValueError("Vulnerability exception document is invalid")
    if payload.get("schema_version") != 1:
        raise ValueError("Vulnerability exception schema version is unsupported")
    policy = payload.get("policy")
    if not isinstance(policy, str) or not 20 <= len(policy) <= 1_000:
        raise ValueError("Vulnerability exception policy is invalid")
    try:
        reviewed_at = date.fromisoformat(str(payload["reviewed_at"]))
        expires_at = date.fromisoformat(str(payload["expires_at"]))
    except (TypeError, ValueError) as error:
        raise ValueError("Vulnerability exception dates are invalid") from error
    today = current_date or datetime.now(UTC).date()
    if reviewed_at > today or expires_at < today:
        raise ValueError("Vulnerability exception review is not currently valid")
    if expires_at < reviewed_at or (expires_at - reviewed_at).days > 30:
        raise ValueError("Vulnerability exceptions may be approved for at most 30 days")
    exceptions = payload.get("exceptions")
    if not isinstance(exceptions, list) or not 1 <= len(exceptions) <= 100:
        raise ValueError("Vulnerability exceptions must contain 1 to 100 entries")
    report_entries = _trivy_report_entries(vulnerability_report_path)
    identifiers: list[str] = []
    for exception in exceptions:
        if not isinstance(exception, dict) or set(exception) != {
            "id",
            "severity",
            "packages",
            "disposition",
            "rationale",
        }:
            raise ValueError("Vulnerability exception entry is invalid")
        identifier = exception.get("id")
        severity = exception.get("severity")
        packages = exception.get("packages")
        disposition = exception.get("disposition")
        rationale = exception.get("rationale")
        if (
            not isinstance(identifier, str)
            or VULNERABILITY_ID_PATTERN.fullmatch(identifier) is None
        ):
            raise ValueError("Vulnerability exception identifier is invalid")
        if identifier in identifiers:
            raise ValueError("Vulnerability exception identifiers must be unique")
        if severity not in {"HIGH", "CRITICAL"}:
            raise ValueError("Vulnerability exception severity is invalid")
        if (
            not isinstance(packages, list)
            or not 1 <= len(packages) <= 20
            or not all(
                isinstance(package, str)
                and 1 <= len(package) <= 100
                and re.fullmatch(r"[A-Za-z0-9+_.:-]+", package) is not None
                for package in packages
            )
            or len(set(packages)) != len(packages)
        ):
            raise ValueError("Vulnerability exception packages are invalid")
        if disposition != "temporarily_accepted_no_upstream_fix":
            raise ValueError("Vulnerability exception disposition is invalid")
        if not isinstance(rationale, str) or not 40 <= len(rationale) <= 2_000:
            raise ValueError("Vulnerability exception rationale is invalid")
        matches = report_entries.get(identifier, ())
        if not matches:
            raise ValueError("Vulnerability exception is absent from the current image report")
        observed_packages = {match[0] for match in matches}
        if observed_packages != set(packages):
            raise ValueError("Vulnerability exception package set changed in the current image")
        for _package, observed_severity, status, fixed_version in matches:
            if observed_severity != severity:
                raise ValueError("Vulnerability exception severity changed in the current image")
            if fixed_version not in {None, ""}:
                raise ValueError("Vulnerability exception has an available fixed version")
            if status not in {"affected", "fix_deferred", "will_not_fix"}:
                raise ValueError("Vulnerability exception is not in a no-upstream-fix state")
        identifiers.append(identifier)
    if output_path.exists() and (output_path.is_symlink() or not output_path.is_file()):
        raise ValueError("Trivy ignore output must be a regular file")
    parent = output_path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("Trivy ignore output directory must be a regular directory")
    temporary = output_path.with_name(f"{output_path.name}.tmp")
    if temporary.exists() and (temporary.is_symlink() or not temporary.is_file()):
        raise ValueError("Trivy ignore temporary output is unsafe")
    temporary.write_text("".join(f"{identifier}\n" for identifier in sorted(identifiers)))
    temporary.replace(output_path)
    return tuple(sorted(identifiers))


def _trivy_report_entries(
    report_path: Path,
) -> dict[str, tuple[tuple[str, str, str, str | None], ...]]:
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError("Trivy vulnerability report must be a regular file")
    if report_path.stat().st_size > 64_000_000:
        raise ValueError("Trivy vulnerability report exceeds 64 MB")
    payload = json.loads(report_path.read_bytes())
    if not isinstance(payload, dict):
        raise ValueError("Trivy vulnerability report is invalid")
    results = payload.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy vulnerability report is invalid")
    entries: dict[str, list[tuple[str, str, str, str | None]]] = {}
    count = 0
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy vulnerability report is invalid")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy vulnerability report is invalid")
        for vulnerability in vulnerabilities:
            count += 1
            if count > 100_000 or not isinstance(vulnerability, dict):
                raise ValueError("Trivy vulnerability report is invalid")
            identifier = vulnerability.get("VulnerabilityID")
            package = vulnerability.get("PkgName")
            severity = vulnerability.get("Severity")
            status = vulnerability.get("Status")
            fixed_version = vulnerability.get("FixedVersion")
            if (
                not isinstance(identifier, str)
                or not isinstance(package, str)
                or not isinstance(severity, str)
                or not isinstance(status, str)
                or (fixed_version is not None and not isinstance(fixed_version, str))
            ):
                raise ValueError("Trivy vulnerability report is invalid")
            entries.setdefault(identifier, []).append((package, severity, status, fixed_version))
    return {identifier: tuple(records) for identifier, records in entries.items()}


def main() -> int:
    """Generate release metadata from explicit immutable identifiers."""
    parser = argparse.ArgumentParser(prog="python -m anva.release")
    commands = parser.add_subparsers(dest="command", required=True)
    manifest_parser = commands.add_parser("manifest")
    manifest_parser.add_argument("--directory", required=True, type=Path)
    manifest_parser.add_argument("--source-commit", required=True)
    manifest_parser.add_argument("--image-reference", required=True)
    manifest_parser.add_argument("--image-id", required=True)
    manifest_parser.add_argument(
        "--source-date-epoch",
        type=int,
        default=int(os.getenv("SOURCE_DATE_EPOCH", "1756684800")),
    )
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--directory", required=True, type=Path)
    verify_parser.add_argument("--worktree-status", type=Path)
    verify_parser.add_argument("--release-path", type=Path)
    verify_parser.add_argument("--source-commit", required=True)
    verify_parser.add_argument("--image-reference", required=True)
    verify_parser.add_argument("--image-id", required=True)
    exception_parser = commands.add_parser("exceptions")
    exception_parser.add_argument("--input", required=True, type=Path)
    exception_parser.add_argument("--report", required=True, type=Path)
    exception_parser.add_argument("--output", required=True, type=Path)
    cleanup_parser = commands.add_parser("cleanup-uv-build")
    cleanup_parser.add_argument("--directory", required=True, type=Path)
    arguments = parser.parse_args()
    if arguments.command == "cleanup-uv-build":
        remove_uv_build_gitignore(arguments.directory)
        print(json.dumps({"status": "removed", "artifact": ".gitignore"}))
        return 0
    if arguments.command == "exceptions":
        identifiers = build_trivy_ignorefile(
            input_path=arguments.input,
            vulnerability_report_path=arguments.report,
            output_path=arguments.output,
        )
        print(json.dumps({"status": "validated", "exceptions": len(identifiers)}))
        return 0
    if arguments.command == "verify":
        verified = verify_release_manifest(
            directory=arguments.directory,
            source_commit=str(arguments.source_commit),
            image_reference=str(arguments.image_reference),
            image_id=str(arguments.image_id),
        )
        if arguments.worktree_status is not None:
            if arguments.release_path is None:
                raise ValueError("--release-path is required with --worktree-status")
            status_path = arguments.worktree_status
            if status_path != Path("/dev/stdin") and (
                status_path.is_symlink() or not status_path.is_file()
            ):
                raise ValueError("Worktree status input must be a regular file")
            verify_release_worktree_status(
                status=status_path.read_bytes(),
                release_path=arguments.release_path,
                manifest=verified,
            )
        records = verified["artifacts"]
        if not isinstance(records, list):  # pragma: no cover - verifier invariant.
            raise RuntimeError("Release artifact inventory is invalid")
        print(json.dumps({"status": "verified", "artifacts": len(records)}))
        return 0
    manifest = build_release_manifest(
        directory=arguments.directory,
        source_commit=str(arguments.source_commit),
        image_reference=str(arguments.image_reference),
        image_id=str(arguments.image_id),
        source_date_epoch=int(arguments.source_date_epoch),
    )
    artifact_records = manifest["artifacts"]
    if not isinstance(artifact_records, list):  # pragma: no cover - internal invariant.
        raise RuntimeError("Release artifact inventory is invalid")
    print(json.dumps({"status": "created", "artifacts": len(artifact_records)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
