from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"
COMPOSE = Path(__file__).parents[2] / "compose.yaml"


@pytest.mark.unit
def test_ci_runs_compose_with_the_checkout_owner_identity() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["compose-checks"]["steps"]
    check_step = next(
        step for step in steps if step.get("name") == "Run the same checks as local development"
    )

    command = check_step["run"]
    assert command.index("test ! -e .ci-artifacts") < command.index("mkdir .ci-artifacts")
    assert 'ANVA_HOST_UID="$(id -u)"' in command
    assert 'ANVA_HOST_GID="$(id -g)"' in command
    assert "ANVA_CANVAS_PERFORMANCE_ROOT=/workspace/.ci-artifacts/performance" in command
    assert "ANVA_CANVAS_SCREENSHOT_ROOT=/workspace/.ci-artifacts/screenshots" in command


@pytest.mark.unit
def test_ci_exercises_pinned_skopeo_auth_mount_identity() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["compose-checks"]["steps"]
    check_step = next(
        step for step in steps if step.get("name") == "Verify pinned Skopeo auth mount identity"
    )

    assert check_step["run"] == "tests/release/test_skopeo_auth_mount.sh"


@pytest.mark.unit
def test_browser_compose_forwards_current_run_canvas_evidence_roots() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    environment = compose["services"]["browser-test"]["environment"]

    assert environment["ANVA_CANVAS_PERFORMANCE_ROOT"] == (
        "${ANVA_CANVAS_PERFORMANCE_ROOT:-docs/evidence/issue-012/performance}"
    )
    assert environment["ANVA_CANVAS_SCREENSHOT_ROOT"] == (
        "${ANVA_CANVAS_SCREENSHOT_ROOT:-docs/evidence/issue-012/screenshots}"
    )


@pytest.mark.unit
def test_ci_retains_canvas_performance_evidence_even_after_a_failure() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    steps = jobs["compose-checks"]["steps"]
    artifact_step = next(
        step for step in steps if step.get("name") == "Retain Canvas performance evidence"
    )

    assert artifact_step["if"] == "always()"
    assert artifact_step["uses"] == (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    )
    assert artifact_step["with"] == {
        "name": "canvas-performance-${{ github.run_id }}",
        "path": ".ci-artifacts/performance/browser.json\n"
        ".ci-artifacts/screenshots/05-canvas-300-node-performance.png\n",
        "if-no-files-found": "error",
        "retention-days": 14,
    }
    assert "docs/evidence" not in artifact_step["with"]["path"]
