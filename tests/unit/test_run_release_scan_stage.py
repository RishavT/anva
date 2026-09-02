from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

RUNNER = Path(__file__).parents[2] / "scripts" / "run_release_scan_stage.py"


def test_real_subprocess_failure_is_recorded_and_redacted(tmp_path: Path) -> None:
    status = tmp_path / "status.json"
    log = tmp_path / "scan.log"
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(RUNNER),
            "--stage",
            "spdx",
            "--status-output",
            str(status),
            "--log-output",
            str(log),
            "--scanner-image",
            "trivy@sha256:fixture",
            "--scanner-version",
            "Version: fixture",
            "--compose-project",
            "candidate-1",
            "--compose-file",
            "compose.release.yaml",
            "--compose-file",
            "compose.yaml",
            "--scanner-set",
            "vuln",
            "--target",
            "image:tag",
            "--format",
            "spdx-json",
            "--output",
            "/release/image.spdx.json",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=do-not-retain\\n' >&2; exit 17",
        ],
        check=False,
    )
    manifest = json.loads(status.read_text())
    assert result.returncode == 20
    assert manifest["classification"] == "engine_error"
    assert manifest["engine_exit_code"] == 17
    assert manifest["command_identity"]["compose_files"] == ["compose.release.yaml", "compose.yaml"]
    assert manifest["command_identity"]["format"] == "spdx-json"
    assert "do-not-retain" not in log.read_text()


def test_real_subprocess_success_is_recorded(tmp_path: Path) -> None:
    status = tmp_path / "status.json"
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(RUNNER),
            "--stage",
            "cyclonedx",
            "--status-output",
            str(status),
            "--log-output",
            str(tmp_path / "log"),
            "--scanner-image",
            "trivy@sha256:fixture",
            "--scanner-version",
            "fixture",
            "--compose-project",
            "candidate",
            "--compose-file",
            "compose.yaml",
            "--scanner-set",
            "vuln",
            "--target",
            "image:tag",
            "--format",
            "cyclonedx",
            "--output",
            "/release/image.cdx.json",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ],
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(status.read_text())["classification"] == "passed"


@pytest.mark.parametrize(
    ("stage", "subcommand", "scanners", "format_name", "target", "skips"),
    [
        ("image-vulnerability", "image", "vuln", "json", "image:tag", []),
        ("spdx", "image", "vuln", "spdx-json", "image:tag", []),
        ("cyclonedx", "image", "vuln", "cyclonedx", "image:tag", []),
        (
            "source",
            "filesystem",
            "vuln,secret,misconfig",
            "json",
            "/workspace",
            [
                "/workspace/.git",
                "/workspace/.secrets",
                "/workspace/secrets",
                "/workspace/backups",
                "/workspace/release",
                "/workspace/.venv",
                "/workspace/.pytest_cache",
                "/workspace/.mypy_cache",
                "/workspace/.ruff_cache",
                "/workspace/htmlcov",
            ],
        ),
    ],
)
def test_structured_identity_exactly_matches_effective_argv(
    tmp_path: Path,
    stage: str,
    subcommand: str,
    scanners: str,
    format_name: str,
    target: str,
    skips: list[str],
) -> None:
    case = tmp_path / stage
    case.mkdir()
    output = f"/release/{stage}.json"
    declared_skips = [item for path in reversed(skips) for item in ("--skip-dir", path)]
    effective_skips = [item for path in skips for item in ("--skip-dirs", path)]
    scanner_argv = [
        subcommand,
        "--scanners",
        scanners,
        "--format",
        format_name,
        *effective_skips,
        *(["--skip-files", "/workspace/.env"] if stage == "source" else []),
        "--output",
        output,
        target,
    ]
    command = ["/bin/true", "release-scanner", *scanner_argv]
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(RUNNER),
            "--stage",
            stage,
            "--status-output",
            str(case / "status.json"),
            "--log-output",
            str(case / "log"),
            "--scanner-image",
            "trivy@sha256:fixture",
            "--scanner-version",
            "fixture",
            "--compose-project",
            "candidate",
            "--compose-file",
            "compose.yaml",
            "--scanner-set",
            scanners,
            "--target",
            target,
            "--format",
            format_name,
            "--output",
            output,
            *declared_skips,
            *(["--skip-file", "/workspace/.env"] if stage == "source" else []),
            "--",
            *command,
        ],
        check=False,
    )
    assert result.returncode == 0
    identity = json.loads((case / "status.json").read_text())["command_identity"]
    assert identity["scanner_set"] == sorted(scanners.split(","))
    assert identity["skip_dirs"] == sorted(skips)
    assert identity["skip_files"] == (["/workspace/.env"] if stage == "source" else [])
    assert identity["scanner_argv"] == scanner_argv


def test_structured_identity_mismatch_fails_before_execution(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(RUNNER),
            "--stage",
            "spdx",
            "--status-output",
            str(tmp_path / "status"),
            "--log-output",
            str(tmp_path / "log"),
            "--scanner-image",
            "fixture",
            "--scanner-version",
            "fixture",
            "--compose-project",
            "candidate",
            "--compose-file",
            "compose.yaml",
            "--scanner-set",
            "vuln",
            "--target",
            "wrong:tag",
            "--format",
            "spdx-json",
            "--output",
            "/release/a.json",
            "--",
            "/bin/true",
            "release-scanner",
            "image",
            "--scanners",
            "vuln",
            "--format",
            "spdx-json",
            "--output",
            "/release/a.json",
            "actual:tag",
        ],
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "status").exists()
