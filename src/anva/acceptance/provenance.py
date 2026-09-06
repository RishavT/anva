"""Immutable build and host-launch provenance for sealed acceptance."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import cast

from anva.contracts.validation import ContractValidationError, validate_payload

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")
IMAGE_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
REQUIRED_LAUNCH_SERVICES = frozenset(
    {
        "api",
        "worker",
        "mcp",
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    }
)


class AcceptanceProvenanceError(ValueError):
    """The running package does not match its immutable build declaration."""

    def __init__(self, message: str, *, reason_code: str = "provenance_rejected") -> None:
        super().__init__(message)
        self.reason_code = reason_code


def package_sha256(package_root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in package_root.rglob("*.py") if path.is_file())
    if not files:
        raise AcceptanceProvenanceError("Running Anva package inventory is empty")
    for path in files:
        relative = path.relative_to(package_root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def attest_build_provenance(
    path: Path,
    *,
    expected_commit: str,
    expected_build_input_sha256: str,
) -> dict[str, str]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 4096
        or stat.S_IMODE(path.stat().st_mode) & 0o222
    ):
        raise AcceptanceProvenanceError("Anva build provenance is unavailable or mutable")
    try:
        payload = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceProvenanceError("Anva build provenance is invalid") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "product_commit",
        "build_input_sha256",
        "package_sha256",
    }:
        raise AcceptanceProvenanceError("Anva build provenance is invalid")
    values = cast(dict[str, object], payload)
    if (
        values.get("schema_version") != 1
        or values.get("product_commit") != expected_commit
        or values.get("build_input_sha256") != expected_build_input_sha256
        or COMMIT_PATTERN.fullmatch(str(values.get("product_commit", ""))) is None
        or SHA256_PATTERN.fullmatch(str(values.get("build_input_sha256", ""))) is None
        or SHA256_PATTERN.fullmatch(str(values.get("package_sha256", ""))) is None
    ):
        raise AcceptanceProvenanceError("Anva build provenance does not match exact pins")
    observed_package = package_sha256(Path(__file__).resolve().parents[1])
    if observed_package != values["package_sha256"]:
        raise AcceptanceProvenanceError("Running Anva package does not match its build provenance")
    return {
        "product_commit": cast(str, values["product_commit"]),
        "build_input_sha256": cast(str, values["build_input_sha256"]),
        "package_sha256": cast(str, values["package_sha256"]),
    }


def attest_launch_manifest(
    path: Path,
    *,
    expected_commit: str,
    expected_build_input_sha256: str,
    expected_package_sha256: str,
    expected_image_sha256: str,
    expected_image_reference: str,
    expected_service: str,
) -> str:
    """Verify the immutable host attestation for the actual Docker launch."""
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise AcceptanceProvenanceError(
            "Anva launch manifest is missing; run `make acceptance-launch-manifest`",
            reason_code="launch_manifest_missing",
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AcceptanceProvenanceError(
            "Anva launch manifest must be a regular non-symlink file",
            reason_code="launch_manifest_permissions",
        )
    if metadata.st_size > 32_768:
        raise AcceptanceProvenanceError(
            "Anva launch manifest exceeds its public size bound",
            reason_code="launch_manifest_size",
        )
    if stat.S_IMODE(metadata.st_mode) & 0o222:
        raise AcceptanceProvenanceError(
            "Anva launch manifest must be read-only; run `chmod a-w` on the manifest",
            reason_code="launch_manifest_permissions",
        )
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise AcceptanceProvenanceError(
            "Anva launch manifest cannot be read",
            reason_code="launch_manifest_permissions",
        ) from error
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceProvenanceError(
            "Anva launch manifest is malformed JSON; regenerate it with "
            "`make acceptance-launch-manifest`",
            reason_code="launch_manifest_malformed",
        ) from error
    if isinstance(payload, dict):
        candidate_services = payload.get("services")
        if (
            isinstance(candidate_services, dict)
            and set(candidate_services) != REQUIRED_LAUNCH_SERVICES
        ):
            raise AcceptanceProvenanceError(
                "Anva launch manifest service inventory differs",
                reason_code="launch_manifest_service_set_mismatch",
            )
    try:
        validate_payload("launch-manifest", payload)
    except ContractValidationError as error:
        raise AcceptanceProvenanceError(
            "Anva launch manifest does not satisfy the public v1 schema; regenerate it with "
            "`make acceptance-launch-manifest`",
            reason_code="launch_manifest_schema",
        ) from error
    assert isinstance(payload, dict)
    values = cast(dict[str, object], payload)
    engine_image_id = f"sha256:{expected_image_sha256}"
    services = values.get("services")
    if values.get("product_commit") != expected_commit:
        raise AcceptanceProvenanceError(
            "Anva launch manifest product commit is stale",
            reason_code="launch_manifest_product_commit_mismatch",
        )
    if values.get("build_input_sha256") != expected_build_input_sha256:
        raise AcceptanceProvenanceError(
            "Anva launch manifest build input is stale",
            reason_code="launch_manifest_build_input_mismatch",
        )
    if values.get("package_sha256") != expected_package_sha256:
        raise AcceptanceProvenanceError(
            "Anva launch manifest package identity differs",
            reason_code="launch_manifest_package_mismatch",
        )
    if values.get("engine_image_id") != engine_image_id:
        raise AcceptanceProvenanceError(
            "Anva launch manifest image ID differs",
            reason_code="launch_manifest_image_mismatch",
        )
    if values.get("image_reference") != expected_image_reference:
        raise AcceptanceProvenanceError(
            "Anva launch manifest image reference differs",
            reason_code="launch_manifest_image_reference_mismatch",
        )
    if not isinstance(services, dict) or set(services) != REQUIRED_LAUNCH_SERVICES:
        raise AcceptanceProvenanceError(
            "Anva launch manifest service inventory differs",
            reason_code="launch_manifest_service_set_mismatch",
        )
    if expected_service not in REQUIRED_LAUNCH_SERVICES:
        raise AcceptanceProvenanceError(
            "Requested acceptance launch service is unsupported",
            reason_code="launch_manifest_service_mismatch",
        )
    for service_name, service_value in services.items():
        if not isinstance(service_value, dict) or set(service_value) != {
            "config_sha256",
            "engine_image_id",
            "image_reference",
        }:
            raise AcceptanceProvenanceError(
                "Anva launch manifest service is invalid",
                reason_code="launch_manifest_service_mismatch",
            )
        service = cast(dict[str, object], service_value)
        if (
            service.get("engine_image_id") != engine_image_id
            or service.get("image_reference") != expected_image_reference
            or SHA256_PATTERN.fullmatch(str(service.get("config_sha256", ""))) is None
            or service_name not in REQUIRED_LAUNCH_SERVICES
        ):
            raise AcceptanceProvenanceError(
                "Anva launch manifest service does not match exact image identity",
                reason_code="launch_manifest_service_mismatch",
            )
    return hashlib.sha256(raw).hexdigest()
