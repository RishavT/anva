"""Unit tests for the administrative CLI contract."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from anva import __version__
from anva.entrypoints.cli import main
from anva.foundation.services import DependencyStatus, ReadinessStatus


@pytest.mark.unit
def test_version_command_does_not_initialize_django(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("anva.entrypoints.cli.configure_django") as configure:
        result = main(["version"])

    assert result == 0
    assert capsys.readouterr().out.strip() == __version__
    configure.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("healthy", "expected_code", "expected_status"),
    [(True, 0, "ready"), (False, 1, "not_ready")],
)
def test_status_command_returns_machine_readable_result(
    healthy: bool,
    expected_code: int,
    expected_status: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dependency = DependencyStatus("database", healthy, "available" if healthy else "unavailable")
    status = ReadinessStatus(expected_status, (dependency,))
    with (
        patch("anva.entrypoints.cli.configure_django"),
        patch("anva.foundation.services.readiness_status", return_value=status),
    ):
        result = main(["status"])

    assert result == expected_code
    assert json.loads(capsys.readouterr().out)["status"] == expected_status


@pytest.mark.unit
def test_source_command_requires_environment_token_without_initializing_django(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ANVA_TOKEN", raising=False)
    with patch("anva.entrypoints.cli.configure_django") as configure:
        result = main(["source", "inspect", str(uuid.uuid4())])

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "missing_token"
    configure.assert_not_called()


@pytest.mark.unit
def test_source_sync_cli_calls_versioned_api_without_printing_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_id = uuid.uuid4()
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-CLI-TOKEN")
    response = patch("anva.entrypoints.cli.urlopen")
    with response as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"id": str(source_id), "state": "REQUESTED"}
        ).encode()
        result = main(
            [
                "source",
                "--api-url",
                "https://anva.example/api/v1",
                "sync",
                str(source_id),
            ]
        )

    assert result == 0
    output = capsys.readouterr().out
    assert json.loads(output)["state"] == "REQUESTED"
    request = open_url.call_args.args[0]
    assert request.full_url == (f"https://anva.example/api/v1/source-connections/{source_id}/sync")
    assert request.method == "POST"
    assert "CANARY-CLI-TOKEN" not in output


@pytest.mark.unit
def test_evidence_cli_submits_bounded_manifest_without_printing_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository_id = uuid.uuid4()
    manifest = tmp_path / "evidence.json"
    manifest.write_text(json.dumps({"repository_id": str(repository_id)}))
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-EVIDENCE-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"manifest_id": str(uuid.uuid4()), "created": True}
        ).encode()
        result = main(
            [
                "evidence",
                "--api-url",
                "https://anva.example/api/v1",
                "submit",
                "--repository-id",
                str(repository_id),
                "--pull-request-number",
                "42",
                "--manifest",
                str(manifest),
            ]
        )

    assert result == 0
    output = capsys.readouterr().out
    request = open_url.call_args.args[0]
    assert request.full_url.endswith(f"/repositories/{repository_id}/pull-requests/42/evidence")
    assert "CANARY-EVIDENCE-TOKEN" not in output


@pytest.mark.unit
def test_governance_cli_rejects_symlink_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository_id = uuid.uuid4()
    target = tmp_path / "policy.json"
    target.write_text("{}")
    link = tmp_path / "linked-policy.json"
    link.symlink_to(target)
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-TOKEN")

    result = main(
        [
            "policy",
            "import",
            "--repository-id",
            str(repository_id),
            "--file",
            str(link),
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "invalid_input"
