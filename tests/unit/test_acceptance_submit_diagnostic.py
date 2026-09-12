"""Submission failures retain bounded metadata without exposing review secrets."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from anva.acceptance.client import AcceptanceBoundaryError
from anva.acceptance.runner import AcceptanceRunner, RunnerConfig


def _runner(state_directory: Path) -> AcceptanceRunner:
    runner = object.__new__(AcceptanceRunner)
    runner.config = RunnerConfig(
        api_url="http://api.invalid/api/v1",
        mcp_url="http://mcp.invalid/mcp",
        canonical_root=state_directory / "canonical",
        state_path=state_directory / "resume.json",
        output_root=state_directory / "output",
        manifest_sha256="a" * 64,
        source_fingerprint="b" * 64,
        canonical_manifest_sha256="c" * 64,
        product_commit="d" * 40,
        product_image_sha256="e" * 64,
        product_image_reference="anva:test",
        build_input_sha256="f" * 64,
        launch_service="acceptance-review-submit",
    )
    runner._diagnostic_run_id = "unavailable"
    return runner


@pytest.mark.parametrize(
    ("code", "status", "reason"),
    [
        ("denied", 403, "authorization_rejected"),
        ("invalid_input", 400, "boundary_rejected"),
        ("lease_conflict", 409, "boundary_rejected"),
        ("invalid_response_contract", 201, "boundary_rejected"),
        ("api_unavailable", None, "boundary_unavailable"),
    ],
)
def test_submit_failure_retains_sanitized_status(
    tmp_path: Path, code: str, status: int | None, reason: str
) -> None:
    tmp_path.chmod(0o700)
    runner = _runner(tmp_path)
    error = AcceptanceBoundaryError(code, "PRIVATE-RESPONSE-CANARY", status=status)
    with patch.object(runner, "_submit_review_once", side_effect=error):
        with pytest.raises(AcceptanceBoundaryError) as caught:
            runner.submit_review(
                reviewer_token="PRIVATE-TOKEN-CANARY",
                handoff_path=Path("PRIVATE-CLAIM-CANARY"),
                result_path=Path("PRIVATE-FINDING-CANARY"),
            )
    assert caught.value is error
    raw = (tmp_path / "operator-diagnostic.json").read_text()
    diagnostic = json.loads(raw)
    assert diagnostic["stage"] == "review_submission"
    assert diagnostic["reason_code"] == reason
    assert diagnostic.get("boundary_status") == status
    assert "CANARY" not in raw
    assert (tmp_path / "operator-diagnostic.json").stat().st_mode & 0o777 == 0o600


def test_submit_diagnostic_io_failure_preserves_original_error(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    error = AcceptanceBoundaryError("api_unavailable", "PRIVATE-CANARY")
    with (
        patch.object(runner, "_submit_review_once", side_effect=error),
        patch("anva.acceptance.runner._write_operator_diagnostic", side_effect=OSError),
        pytest.raises(AcceptanceBoundaryError) as caught,
    ):
        runner.submit_review(reviewer_token="secret", handoff_path=tmp_path, result_path=tmp_path)
    assert caught.value is error
