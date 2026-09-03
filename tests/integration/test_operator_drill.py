"""Command and shell behavior for the #44 drill harness."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from anva.operator_drill import main

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_closed_event_commands_round_trip(tmp_path: Path) -> None:
    drill_id = "11111111-1111-4111-8111-111111111111"
    assert (
        main(
            [
                "create-evidence",
                "--drill-id",
                drill_id,
                "--source-revision",
                "d" * 40,
                "--product-version",
                "0.1.5",
                "--product-source-commit",
                "d" * 40,
                "--operator-cli-in-product",
                "--image-digest",
                "sha256:" + "2" * 64,
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    evidence = next(tmp_path.glob("*.jsonl"))
    before = evidence.read_bytes()
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "check_code": "PROXY_SPOOF",
                "redirect_code": 301,
                "outcome": "PASS",
                "correlation_id": "22222222-2222-4222-8222-222222222222",
            }
        )
    )
    assert main(["record-check", str(evidence), "--event-json", str(event)]) == 0
    assert evidence.read_bytes().startswith(before)
    assert main(["validate-provisional", str(evidence)]) == 0
    assert main(["validate-final", str(evidence)]) == 2


@pytest.mark.integration
@pytest.mark.parametrize(
    ("status", "marker", "writers", "accepted"),
    [
        (44, "DRILL_OBJECT_RESTORE_FAULT\n", "", True),
        (0, "DRILL_OBJECT_RESTORE_FAULT\n", "", False),
        (43, "DRILL_OBJECT_RESTORE_FAULT\n", "", False),
        (44, "daemon error\n", "", False),
        (44, "DRILL_OBJECT_RESTORE_FAULT\ndaemon error\n", "", False),
        (44, "DRILL_OBJECT_RESTORE_FAULT\n", "api", False),
    ],
)
def test_restore_fault_requires_exact_44_marker_and_stopped_writers(
    tmp_path: Path, status: int, marker: str, writers: str, accepted: bool
) -> None:
    log = tmp_path / "restore.log"
    log.write_text(marker)
    result = subprocess.run(  # noqa: S603
        [
            "/bin/sh",
            str(ROOT / "deploy/drill/verify-restore-fault.sh"),
            str(status),
            str(log),
            writers,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted


@pytest.mark.integration
def test_drill_up_failure_traps_exact_project_cleanup(tmp_path: Path) -> None:
    binary = tmp_path / "docker"
    calls = tmp_path / "calls"
    binary.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$*" >> "$DRILL_TEST_CALLS"\n'
        "case \"$*\" in *'run --rm migrate'*) exit 17;; esac\n"
        "exit 0\n"
    )
    binary.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "DRILL_PROJECT": "anva-i80-trap-test",
        "DRILL_TEST_CALLS": str(calls),
    }
    result = subprocess.run(  # noqa: S603
        ["/bin/sh", str(ROOT / "deploy/drill/drill-up.sh")],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 17
    output = calls.read_text()
    assert "-p anva-i80-trap-test" in output
    assert "down --volumes --remove-orphans" in output
    assert "-p anva " not in output


@pytest.mark.integration
@pytest.mark.parametrize("interrupt", [signal.SIGHUP, signal.SIGINT, signal.SIGTERM])
def test_drill_up_signals_trap_exact_project_cleanup(
    tmp_path: Path, interrupt: signal.Signals
) -> None:
    binary = tmp_path / "docker"
    calls = tmp_path / "calls"
    ready = tmp_path / "ready"
    binary.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$*" >> "$DRILL_TEST_CALLS"\n'
        'case "$*" in *\'run --rm drill-certgen\'*) touch "$DRILL_TEST_READY"; sleep 1;; esac\n'
        "exit 0\n"
    )
    binary.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "DRILL_PROJECT": "anva-i80-signal-test",
        "DRILL_TEST_CALLS": str(calls),
        "DRILL_TEST_READY": str(ready),
    }
    process = subprocess.Popen(  # noqa: S603
        ["/bin/sh", str(ROOT / "deploy/drill/drill-up.sh")],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(100):
        if ready.exists():
            break
        time.sleep(0.01)
    assert ready.exists()
    process.send_signal(interrupt)
    process.communicate(timeout=5)
    assert process.returncode != 0
    assert "-p anva-i80-signal-test" in calls.read_text()
    assert "down --volumes --remove-orphans" in calls.read_text()
