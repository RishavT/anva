from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"


@pytest.mark.unit
def test_ci_runs_compose_with_the_checkout_owner_identity() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["compose-checks"]["steps"]
    check_step = next(
        step for step in steps if step.get("name") == "Run the same checks as local development"
    )

    assert check_step["run"] == ('ANVA_HOST_UID="$(id -u)" ANVA_HOST_GID="$(id -g)" make ci')


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
        "path": "docs/evidence/issue-012/performance/browser.json\n"
        "docs/evidence/issue-012/screenshots/05-canvas-300-node-performance.png\n",
        "if-no-files-found": "warn",
        "retention-days": 14,
    }
