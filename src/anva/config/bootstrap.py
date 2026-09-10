"""Load bootstrap credentials without exposing them through process metadata."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path

MAX_BOOTSTRAP_SECRET_BYTES = 4096


class BootstrapSecretError(ValueError):
    """A bootstrap secret source failed its public, non-sensitive contract."""


def load_bootstrap_secret(
    environment: Mapping[str, str] | None = None,
    *,
    default: str = "",
) -> str:
    """Read one direct value or a protected absolute file with fail-closed checks."""
    values = os.environ if environment is None else environment
    direct = values.get("ANVA_BOOTSTRAP_SECRET", "")
    raw_path = values.get("ANVA_BOOTSTRAP_SECRET_FILE", "")
    if direct and raw_path:
        raise BootstrapSecretError(
            "ANVA_BOOTSTRAP_SECRET and ANVA_BOOTSTRAP_SECRET_FILE are mutually exclusive"
        )
    if not raw_path:
        return direct or default
    path = Path(raw_path)
    if not path.is_absolute():
        raise BootstrapSecretError("ANVA_BOOTSTRAP_SECRET_FILE must be absolute")
    try:
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or mode not in {0o400, 0o440, 0o444, 0o600}
            or (mode == 0o600 and info.st_uid != os.geteuid())
            or not 1 <= info.st_size <= MAX_BOOTSTRAP_SECRET_BYTES
        ):
            raise BootstrapSecretError("ANVA_BOOTSTRAP_SECRET_FILE is unsafe")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise BootstrapSecretError("ANVA_BOOTSTRAP_SECRET_FILE changed during open")
            value = os.read(descriptor, MAX_BOOTSTRAP_SECRET_BYTES + 1)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BootstrapSecretError("ANVA_BOOTSTRAP_SECRET_FILE is unreadable") from error
    if len(value) != info.st_size or b"\n" in value or b"\r" in value:
        raise BootstrapSecretError(
            "ANVA_BOOTSTRAP_SECRET_FILE must contain one line without newline"
        )
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BootstrapSecretError("ANVA_BOOTSTRAP_SECRET_FILE must be UTF-8") from error
    if not decoded or decoded != decoded.strip():
        raise BootstrapSecretError("ANVA_BOOTSTRAP_SECRET_FILE value is invalid")
    return decoded
