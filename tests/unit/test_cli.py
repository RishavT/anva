"""Unit tests for the administrative CLI contract."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from email.message import Message
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from anva import __version__
from anva.entrypoints.cli import main
from anva.foundation.services import DependencyStatus, ReadinessStatus


@pytest.mark.unit
def test_acceptance_cli_canonicalizes_without_initializing_django(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw = tmp_path / "raw"
    canonical = tmp_path / "canonical"
    payload = raw / "payload"
    payload.mkdir(parents=True)
    canonical.mkdir()
    public_file = payload / "source.md"
    public_file.write_bytes(b"public\n")
    manifest = {
        "schema_version": "1.0",
        "corpus_id": "public-corpus",
        "generated_at": "2026-08-07T00:00:00Z",
        "source_commit": "a" * 40,
        "files": [
            {
                "path": "payload/source.md",
                "sha256": hashlib.sha256(public_file.read_bytes()).hexdigest(),
                "size_bytes": public_file.stat().st_size,
            }
        ],
        "limits": {
            "max_files": 1,
            "max_total_bytes": 1024,
            "max_file_bytes": 1024,
            "max_depth": 1,
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (raw / "acceptance-corpus.json").write_bytes(manifest_bytes)
    pin = hashlib.sha256(manifest_bytes).hexdigest()

    try:
        with patch("anva.entrypoints.cli.configure_django") as configure:
            result = main(
                [
                    "acceptance",
                    "canonicalize",
                    "--raw-root",
                    str(raw),
                    "--canonical-root",
                    str(canonical),
                    "--manifest-sha256",
                    pin,
                    "--max-files",
                    "1",
                    "--max-total-bytes",
                    "1024",
                    "--max-file-bytes",
                    "1024",
                    "--max-depth",
                    "1",
                ]
            )
        assert result == 0
        assert json.loads(capsys.readouterr().out)["status"] == "canonicalized"
        configure.assert_not_called()

        assert main(["acceptance", "verify", "--canonical-root", str(canonical)]) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "verified"
    finally:
        for path in canonical.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        canonical.chmod(0o700)


@pytest.mark.unit
def test_acceptance_cli_returns_safe_structured_rejection(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw = tmp_path / "raw"
    canonical = tmp_path / "canonical"
    raw.mkdir()
    canonical.mkdir()
    (raw / "acceptance-corpus.json").write_text("{}", encoding="utf-8")

    result = main(
        [
            "acceptance",
            "canonicalize",
            "--raw-root",
            str(raw),
            "--canonical-root",
            str(canonical),
            "--manifest-sha256",
            "f" * 64,
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out) == {
        "code": "manifest_pin_mismatch",
        "message": "Acceptance manifest does not match the operator pin",
    }


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
def test_system_maintenance_cleanup_is_local_bounded_and_hides_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch("anva.entrypoints.cli.configure_django") as configure,
        patch(
            "anva.core.services.operations.purge_expired_pre_auth_rate_buckets",
            return_value=37,
        ) as purge,
    ):
        result = main(
            [
                "maintenance",
                "purge-preauth-rate-buckets",
                "--limit",
                "17",
            ]
        )

    assert result == 0
    configure.assert_called_once_with()
    purge.assert_called_once_with(limit=17)
    assert json.loads(capsys.readouterr().out) == {
        "operation": "purge_pre_auth_rate_buckets",
        "status": "completed",
    }


@pytest.mark.unit
def test_system_maintenance_cleanup_has_a_bounded_compose_invocation() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    recipe = makefile.split("\nrate-limit-cleanup:\n", 1)[1].split("\nrelease-clean:\n", 1)[0]

    assert "$(COMPOSE) --profile tools run --rm cli" in recipe
    assert "python -m anva.entrypoints.cli maintenance purge-preauth-rate-buckets" in recipe


@pytest.mark.unit
def test_backup_manifest_is_created_verified_and_detects_tampering(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "database.dump").write_bytes(b"postgres-backup")
    objects = tmp_path / "objects"
    objects.mkdir()
    sentinel = objects / ".anva-installation-sentinel"
    sentinel.write_bytes(b"anva-object-storage-sentinel-v1\n")

    assert main(["backup", "--directory", str(tmp_path), "manifest"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "created"
    manifest = json.loads((tmp_path / "manifest.json").read_bytes())
    assert manifest["schema_version"] == 1
    assert {record["path"] for record in manifest["files"]} == {
        "database.dump",
        "objects/.anva-installation-sentinel",
    }

    assert main(["backup", "--directory", str(tmp_path), "verify"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "verified"
    sentinel.write_bytes(b"tampered")
    assert main(["backup", "--directory", str(tmp_path), "verify"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "backup_invalid"


@pytest.mark.unit
def test_backup_manifest_rejects_symlinked_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "database.dump").write_bytes(b"postgres-backup")
    objects = tmp_path / "objects"
    objects.mkdir()
    sentinel = objects / ".anva-installation-sentinel"
    sentinel.symlink_to(tmp_path / "database.dump")

    assert main(["backup", "--directory", str(tmp_path), "manifest"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "backup_invalid"


@pytest.mark.unit
def test_backup_generation_is_verified_before_atomic_activation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    generation = "20260804T120000Z-1234"
    generation_path = tmp_path / "generations" / generation
    objects = generation_path / "objects"
    objects.mkdir(parents=True)
    (generation_path / "database.dump").write_bytes(b"postgres-backup")
    (objects / ".anva-installation-sentinel").write_bytes(b"anva-object-storage-sentinel-v1\n")

    manifest_args = [
        "backup",
        "--directory",
        str(tmp_path),
        "--generation",
        generation,
        "manifest",
    ]
    assert main(manifest_args) == 0
    capsys.readouterr()
    assert not (tmp_path / "current").exists()

    activate_args = [
        "backup",
        "--directory",
        str(tmp_path),
        "--generation",
        generation,
        "activate",
    ]
    assert main(activate_args) == 0
    assert (tmp_path / "current").read_text(encoding="ascii") == f"{generation}\n"
    assert json.loads(capsys.readouterr().out)["status"] == "activated"

    assert main(["backup", "--directory", str(tmp_path), "current"]) == 0
    assert capsys.readouterr().out == f"{generation}\n"

    assert main(["backup", "--directory", str(tmp_path), "verify"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "verified"


@pytest.mark.unit
def test_backup_activation_rejects_invalid_or_incomplete_generation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "generations" / "20260804T120000Z-99").mkdir(parents=True)

    assert (
        main(
            [
                "backup",
                "--directory",
                str(tmp_path),
                "--generation",
                "../unsafe",
                "activate",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["code"] == "backup_invalid"
    assert not (tmp_path / "current").exists()

    assert main(["backup", "--directory", str(tmp_path), "current"]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "backup_invalid"

    assert (
        main(
            [
                "backup",
                "--directory",
                str(tmp_path),
                "--generation",
                "20260804T120000Z-99",
                "activate",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["code"] == "backup_invalid"
    assert not (tmp_path / "current").exists()


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


@pytest.mark.unit
def test_assurance_cli_reads_bounded_diff_and_posts_manual_ingestion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository_id = uuid.uuid4()
    metadata = tmp_path / "pr.json"
    metadata.write_text(
        json.dumps(
            {
                "access_scope_id": str(uuid.uuid4()),
                "base_commit": "a" * 40,
                "head_commit": "b" * 40,
                "title": "Change",
                "description": "",
                "target_branch": "main",
                "is_draft": False,
                "state": "OPEN",
            }
        )
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-ASSURANCE-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"pull_request_revision_id": str(uuid.uuid4()), "created": True}
        ).encode()
        result = main(
            [
                "assurance",
                "--api-url",
                "https://anva.example/api/v1",
                "ingest",
                "--repository-id",
                str(repository_id),
                "--pull-request-number",
                "7",
                "--metadata",
                str(metadata),
                "--diff",
                str(diff),
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    assert request.full_url.endswith(f"/repositories/{repository_id}/pull-requests/7/manual-diff")
    assert json.loads(request.data)["unified_diff"].startswith("diff --git")
    assert "CANARY-ASSURANCE-TOKEN" not in capsys.readouterr().out


@pytest.mark.unit
def test_assurance_cli_rejects_symlink_diff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    metadata = tmp_path / "pr.json"
    metadata.write_text("{}")
    target = tmp_path / "change.diff"
    target.write_text("diff")
    linked = tmp_path / "linked.diff"
    linked.symlink_to(target)
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-ASSURANCE-TOKEN")

    result = main(
        [
            "assurance",
            "ingest",
            "--repository-id",
            str(uuid.uuid4()),
            "--pull-request-number",
            "7",
            "--metadata",
            str(metadata),
            "--diff",
            str(linked),
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "invalid_input"


@pytest.mark.unit
def test_github_configure_cli_posts_bounded_file_without_printing_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository_id = uuid.uuid4()
    configuration = tmp_path / "github-binding.json"
    configuration.write_text(
        json.dumps(
            {
                "access_scope_id": str(uuid.uuid4()),
                "installation_id": 7001,
                "account_id": 9001,
                "account_login": "anva-example",
                "account_type": "Organization",
                "repository_selection": "selected",
                "permissions": {
                    "checks": "write",
                    "contents": "read",
                    "issues": "write",
                    "pull_requests": "read",
                },
                "external_repository_id": 8001,
                "full_name": "anva/example",
                "default_branch": "main",
                "private": True,
                "archived": False,
                "auto_assurance": False,
                "policy_version_ids": [],
            }
        )
    )
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-GITHUB-ADMIN-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"id": str(uuid.uuid4()), "state": "ACTIVE", "created": True}
        ).encode()
        result = main(
            [
                "github",
                "--api-url",
                "https://anva.example/api/v1",
                "configure",
                "--repository-id",
                str(repository_id),
                "--config",
                str(configuration),
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    assert request.method == "POST"
    assert request.full_url.endswith(f"/repositories/{repository_id}/github-binding")
    assert json.loads(request.data)["installation_id"] == 7001
    assert "CANARY-GITHUB-ADMIN-TOKEN" not in capsys.readouterr().out


@pytest.mark.unit
@pytest.mark.parametrize(
    ("command", "method", "suffix"),
    [
        ("status", "GET", ""),
        ("revoke", "POST", "/revoke"),
    ],
)
def test_github_status_and_revoke_cli_use_versioned_binding_api(
    command: str,
    method: str,
    suffix: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository_id = uuid.uuid4()
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-GITHUB-ADMIN-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = json.dumps(
            {"id": str(uuid.uuid4()), "state": "ACTIVE"}
        ).encode()
        result = main(
            [
                "github",
                "--api-url",
                "https://anva.example/api/v1",
                command,
                "--repository-id",
                str(repository_id),
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    assert request.method == method
    assert request.full_url == (
        f"https://anva.example/api/v1/repositories/{repository_id}/github-binding{suffix}"
    )
    assert "CANARY-GITHUB-ADMIN-TOKEN" not in capsys.readouterr().out


@pytest.mark.unit
def test_evaluator_submit_reads_claim_token_only_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    task_id = uuid.uuid4()
    result_file = tmp_path / "result.json"
    result_file.write_text("{}")
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-ASSURANCE-TOKEN")
    monkeypatch.setenv("ANVA_EVALUATOR_CLAIM_TOKEN", "CANARY-CLAIM-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = b'{"created": true}'
        result = main(
            [
                "evaluator",
                "submit",
                str(task_id),
                "--claimant",
                "review-agent",
                "--result",
                str(result_file),
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    body = json.loads(request.data)
    assert body["claim_token"] == os.environ["ANVA_EVALUATOR_CLAIM_TOKEN"]
    assert "CANARY-CLAIM-TOKEN" not in capsys.readouterr().out


@pytest.mark.unit
@pytest.mark.parametrize(
    ("command", "expected_suffix"),
    [
        ("status", "/assurance-runs/{run_id}"),
        ("report", "/assurance-runs/{run_id}/report"),
    ],
)
def test_assurance_cli_read_commands_use_get_without_a_body(
    command: str,
    expected_suffix: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_id = uuid.uuid4()
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-READ-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = b'{"state":"COMPLETED"}'
        result = main(
            [
                "assurance",
                "--api-url",
                "https://anva.example/api/v1/",
                command,
                str(run_id),
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    assert request.full_url.endswith(expected_suffix.format(run_id=run_id))
    assert request.method == "GET"
    assert request.data is None
    assert "CANARY-READ-TOKEN" not in capsys.readouterr().out


@pytest.mark.unit
def test_assurance_cli_start_posts_exact_input_document(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    revision_id = uuid.uuid4()
    inputs = tmp_path / "inputs.json"
    inputs.write_text(
        json.dumps(
            {
                "policy_version_ids": [str(uuid.uuid4())],
                "reference_time": "2026-07-28T00:00:00Z",
                "deterministic_checks": [],
            }
        )
    )
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-START-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = b'{"created":true}'
        result = main(
            [
                "assurance",
                "start",
                "--pull-request-revision-id",
                str(revision_id),
                "--inputs",
                str(inputs),
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    assert request.full_url.endswith(f"/pull-request-revisions/{revision_id}/assurance-runs")
    assert request.method == "POST"
    assert json.loads(request.data) == json.loads(inputs.read_text())


@pytest.mark.unit
def test_evaluator_cli_claim_posts_lease_and_claimant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_id = uuid.uuid4()
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-EVALUATOR-TOKEN")
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        open_url.return_value.__enter__.return_value.read.return_value = b'{"status":"EMPTY"}'
        result = main(
            [
                "evaluator",
                "--api-url",
                "https://anva.example/api/v1",
                "claim",
                "--repository-id",
                str(repository_id),
                "--claimant",
                "fresh-review-agent",
                "--lease-seconds",
                "45",
            ]
        )

    assert result == 0
    request = open_url.call_args.args[0]
    assert request.full_url.endswith(f"/repositories/{repository_id}/evaluator-tasks/claim")
    assert json.loads(request.data) == {
        "claimant": "fresh-review-agent",
        "lease_seconds": 45,
    }


@pytest.mark.unit
def test_evaluator_cli_submit_fails_closed_without_claim_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result_file = tmp_path / "result.json"
    result_file.write_text("{}")
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-EVALUATOR-TOKEN")
    monkeypatch.delenv("ANVA_EVALUATOR_CLAIM_TOKEN", raising=False)

    result = main(
        [
            "evaluator",
            "submit",
            str(uuid.uuid4()),
            "--claimant",
            "fresh-review-agent",
            "--result",
            str(result_file),
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "missing_claim_token"


@pytest.mark.unit
def test_assurance_cli_requires_api_token_before_network_access(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ANVA_TOKEN", raising=False)
    with patch("anva.entrypoints.cli.urlopen") as open_url:
        result = main(["assurance", "status", str(uuid.uuid4())])

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "missing_token"
    open_url.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("network_error", [URLError("offline"), TimeoutError()])
def test_assurance_cli_returns_stable_api_unavailable_error(
    network_error: Exception,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-NETWORK-TOKEN")
    with patch("anva.entrypoints.cli.urlopen", side_effect=network_error):
        result = main(["assurance", "status", str(uuid.uuid4())])

    assert result == 1
    assert json.loads(capsys.readouterr().out) == {
        "code": "api_unavailable",
        "message": "Anva API is unavailable",
    }


@pytest.mark.unit
def test_assurance_cli_prints_structured_http_error_without_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-HTTP-TOKEN")
    error = HTTPError(
        "https://anva.example/api/v1/assurance-runs/missing",
        404,
        "Not Found",
        Message(),
        BytesIO(b'{"code":"not_found","message":"Missing"}'),
    )
    with patch("anva.entrypoints.cli.urlopen", side_effect=error):
        result = main(["assurance", "status", str(uuid.uuid4())])

    assert result == 1
    output = capsys.readouterr().out
    assert json.loads(output)["code"] == "not_found"
    assert "CANARY-HTTP-TOKEN" not in output


@pytest.mark.unit
@pytest.mark.parametrize("contents", [b"", b"\xff"])
def test_assurance_cli_rejects_empty_or_non_utf8_diff(
    contents: bytes,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text("{}")
    diff = tmp_path / "change.diff"
    diff.write_bytes(contents)
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-DIFF-TOKEN")

    result = main(
        [
            "assurance",
            "ingest",
            "--repository-id",
            str(uuid.uuid4()),
            "--pull-request-number",
            "1",
            "--metadata",
            str(metadata),
            "--diff",
            str(diff),
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["code"] == "invalid_input"
