"""Shared rejection rules for hostile declarative governance input."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from anva.core.logging import redact_text

FULL_COMMIT = re.compile(r"^[a-f0-9]{40}$")
SENSITIVE_KEY = re.compile(
    r"(?i)(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|password|passwd|private[_-]?key|cookie|session|"
    r"credential|signature|security[_-]?token)"
)


def validate_full_commit(value: str) -> None:
    """Require a full lowercase Git object identifier."""
    if FULL_COMMIT.fullmatch(value) is None:
        raise ValueError("commit_sha must be a full 40-character lowercase hexadecimal SHA")


def validate_relative_artifact_path(value: str) -> None:
    """Reject absolute, traversal, Windows, control, and ambiguous artifact paths."""
    if not value:
        return
    if len(value) > 2_000:
        raise ValueError("Artifact reference is too long")
    if "\\" in value or "\x00" in value or any(ord(character) < 32 for character in value):
        raise ValueError("Artifact reference contains unsafe characters")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError("Artifact reference must be a normalized relative POSIX path")
    if str(path) != value:
        raise ValueError("Artifact reference must be normalized")


def is_secret_bearing_query_key(value: str) -> bool:
    """Recognize provider-neutral signed-query credentials case-insensitively."""
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return bool(
        SENSITIVE_KEY.search(value)
        or normalized.endswith(("credential", "signature", "securitytoken"))
        or normalized
        in {
            "accesskey",
            "accesskeyid",
            "googleaccessid",
            "keypairid",
            "sig",
            "token",
        }
    )


def reject_secrets(value: object, *, depth: int = 0) -> None:
    """Reject likely credentials instead of storing or returning a redacted surrogate."""
    if depth > 20:
        raise ValueError("Input nesting is too deep")
    if isinstance(value, dict):
        for key, child in value.items():
            if SENSITIVE_KEY.search(str(key)):
                raise ValueError("Input contains a forbidden secret-bearing field")
            reject_secrets(child, depth=depth + 1)
        return
    if isinstance(value, list):
        for child in value:
            reject_secrets(child, depth=depth + 1)
        return
    if isinstance(value, str):
        if len(value) > 50_000:
            raise ValueError("Input string is too large")
        if redact_text(value) != value:
            raise ValueError("Input contains credential material")
