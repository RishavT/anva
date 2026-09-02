#!/usr/bin/env python3
"""Run one release scanner command and retain safe, canonical engine diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

MAX_LOG_BYTES = 64 * 1024
SENSITIVE_VALUE = re.compile(
    r"(?im)\b(authorization|password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*)[^\r\n]*"
)
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sanitize(raw: bytes) -> tuple[str, bool]:
    truncated = len(raw) > MAX_LOG_BYTES
    text = raw[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
    text = SENSITIVE_VALUE.sub(r"\1\2[REDACTED]", text)
    text = GITHUB_TOKEN.sub("[REDACTED_GITHUB_TOKEN]", text)
    if truncated:
        text += "\n[truncated at 65536 bytes]\n"
    return text, truncated


def _scanner_argv(command: list[str]) -> list[str] | None:
    try:
        return command[command.index("release-scanner") + 1 :]
    except ValueError:
        return None


def _option_values(argv: list[str], option: str) -> list[str]:
    values: list[str] = []
    for index, value in enumerate(argv):
        if value == option:
            if index + 1 >= len(argv):
                raise ValueError(f"{option} requires a value")
            values.append(argv[index + 1])
    return values


def _effective_scanner_identity(command: list[str]) -> dict[str, object] | None:
    argv = _scanner_argv(command)
    if argv is None:
        return None
    if len(argv) < 2 or argv[0] not in {"image", "filesystem"}:
        raise ValueError("effective scanner command and target are required")
    scanners = _option_values(argv, "--scanners")
    formats = _option_values(argv, "--format")
    outputs = _option_values(argv, "--output")
    if len(scanners) != 1 or len(formats) != 1 or len(outputs) != 1:
        raise ValueError(
            "effective scanner command requires one scanners, format, and output option"
        )
    return {
        "scanner_set": sorted(filter(None, scanners[0].split(","))),
        "target": argv[-1],
        "format": formats[0],
        "output": outputs[0],
        "skip_dirs": sorted(_option_values(argv, "--skip-dirs")),
        "skip_files": sorted(_option_values(argv, "--skip-files")),
        "scanner_argv": argv,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    parser.add_argument("--status-output", required=True)
    parser.add_argument("--log-output", required=True)
    parser.add_argument("--scanner-image", required=True)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--compose-file", action="append", required=True)
    parser.add_argument("--scanner-set", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--format", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--skip-dir", action="append", default=[])
    parser.add_argument("--skip-file", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("scanner command is required after --")

    declared = {
        "scanner_set": sorted(filter(None, args.scanner_set.split(","))),
        "target": args.target,
        "format": args.format,
        "output": args.output,
        "skip_dirs": sorted(args.skip_dir),
        "skip_files": sorted(args.skip_file),
    }
    try:
        effective = _effective_scanner_identity(command)
    except ValueError as error:
        parser.error(str(error))
    if effective is not None:
        for field, declared_value in declared.items():
            if effective[field] != declared_value:
                parser.error(f"declared {field} does not match effective scanner argv")

    completed = subprocess.run(command, capture_output=True, check=False)  # noqa: S603
    sanitized_log, truncated = _sanitize(completed.stderr)
    Path(args.log_output).write_text(sanitized_log, encoding="utf-8")
    identity = {
        "stage": args.stage,
        "compose_files": sorted(args.compose_file),
        "compose_project": args.compose_project,
        "scanner_image": args.scanner_image,
        "scanner_version": args.scanner_version,
        **declared,
        # This is a reviewed, fixed workflow command (never scanner output or a secret).
        # Retaining it makes every effective subcommand/option independently auditable.
        "command_argv": command,
        "scanner_argv": effective["scanner_argv"] if effective is not None else command,
    }
    status = {
        "schema_version": 1,
        "kind": "anva.release-scan-stage-status",
        "classification": "passed" if completed.returncode == 0 else "engine_error",
        "engine_exit_code": completed.returncode,
        "command_identity": identity,
        "command_identity_sha256": _sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ),
        "stdout_sha256": _sha256(completed.stdout),
        "sanitized_log_sha256": _sha256(Path(args.log_output).read_bytes()),
        "log_truncated": truncated,
    }
    Path(args.status_output).write_text(
        json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0 if completed.returncode == 0 else 20


if __name__ == "__main__":
    raise SystemExit(main())
