"""Deterministic release inventory and checksum generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path

from anva import __version__

COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
IMAGE_ID_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
VULNERABILITY_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
EXPECTED_ARTIFACT_SUFFIXES = (
    ".whl",
    "-codex-skills-1.0.0.tar.gz",
    "-claude-skills-1.0.0.tar.gz",
    "image.spdx.json",
    "image.cyclonedx.json",
    "image-vulnerabilities.json",
    "source-security.json",
    "vulnerability-exceptions.json",
)


def _artifact_files(directory: Path) -> tuple[Path, ...]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Release directory must be a regular directory")
    files = tuple(
        path
        for path in sorted(directory.iterdir())
        if path.name not in {"SHA256SUMS", "release-manifest.json"}
        and not path.name.endswith(".tmp")
        and path.name not in {".gitkeep", ".trivy-cache", ".trivyignore"}
    )
    if not files or len(files) > 100:
        raise ValueError("Release artifact count must be between 1 and 100")
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Release artifacts must be regular non-symlink files")
    names = tuple(path.name for path in files)
    for suffix in EXPECTED_ARTIFACT_SUFFIXES:
        if not any(name.endswith(suffix) for name in names):
            raise ValueError(f"Release is missing required artifact suffix: {suffix}")
    return files


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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
        "schema_version": 1,
        "anva_version": __version__,
        "source_commit": source_commit,
        "source_date_epoch": source_date_epoch,
        "created_at": datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat(),
        "image": {"reference": image_reference, "id": image_id},
        "artifacts": records,
        "limitations": [
            "The recorded image ID identifies the locally verified OCI image.",
            "A registry digest and signed tag are recorded only by the publication step.",
            "External fresh-agent and human acceptance evidence is not generated here.",
        ],
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
    exception_parser = commands.add_parser("exceptions")
    exception_parser.add_argument("--input", required=True, type=Path)
    exception_parser.add_argument("--report", required=True, type=Path)
    exception_parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if arguments.command == "exceptions":
        identifiers = build_trivy_ignorefile(
            input_path=arguments.input,
            vulnerability_report_path=arguments.report,
            output_path=arguments.output,
        )
        print(json.dumps({"status": "validated", "exceptions": len(identifiers)}))
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
