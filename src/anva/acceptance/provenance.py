"""Immutable runtime build-provenance attestation for sealed acceptance."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import cast

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")


class AcceptanceProvenanceError(ValueError):
    """The running package does not match its immutable build declaration."""


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
    expected_image_sha256: str,
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
        "image_sha256",
        "package_sha256",
    }:
        raise AcceptanceProvenanceError("Anva build provenance is invalid")
    values = cast(dict[str, object], payload)
    if (
        values.get("schema_version") != 1
        or values.get("product_commit") != expected_commit
        or values.get("image_sha256") != expected_image_sha256
        or COMMIT_PATTERN.fullmatch(str(values.get("product_commit", ""))) is None
        or SHA256_PATTERN.fullmatch(str(values.get("image_sha256", ""))) is None
        or SHA256_PATTERN.fullmatch(str(values.get("package_sha256", ""))) is None
    ):
        raise AcceptanceProvenanceError("Anva build provenance does not match exact pins")
    observed_package = package_sha256(Path(__file__).resolve().parents[1])
    if observed_package != values["package_sha256"]:
        raise AcceptanceProvenanceError("Running Anva package does not match its build provenance")
    return {
        "product_commit": cast(str, values["product_commit"]),
        "image_sha256": cast(str, values["image_sha256"]),
        "package_sha256": cast(str, values["package_sha256"]),
    }
