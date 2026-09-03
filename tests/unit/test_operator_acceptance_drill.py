"""Fail-closed contracts for the disposable #44 operator drill ledger."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from anva.operator_drill import (
    AUTOMATED_SEQUENCE,
    DECISION_ROLES,
    DECISION_SEQUENCE,
    PRODUCT_SOURCE_COMMIT,
    EvidenceRejectedError,
    _reject_unsafe_strings,
    _seal,
    _validate_payload,
    append_event,
    build_evidence,
    finalize_with_github_anchor,
    main,
    preflight_network,
    record_release_boundary,
    validate_evidence,
    validate_final_evidence,
)

DRILL_ID = "11111111-1111-4111-8111-111111111111"
COMMIT = "d" * 40
IMAGE = "sha256:" + "2" * 64
CORRELATION = "22222222-2222-4222-8222-222222222222"


def _check_payload(code: str) -> dict[str, object]:
    common: dict[str, object] = {
        "check_code": code,
        "outcome": "PASS",
        "correlation_id": CORRELATION,
    }
    observations: dict[str, dict[str, object]] = {
        "METRICS_AUTH": {
            "missing_token_code": 404,
            "wrong_token_code": 404,
            "correct_token_code": 200,
            "metric_sample_count": 18,
        },
        "PROXY_SPOOF": {"redirect_code": 301},
        "RESTORE_FAULT": {
            "exit_code": 44,
            "marker_code": "DRILL_OBJECT_RESTORE_FAULT",
            "writers_running": 0,
        },
        "STORAGE_INTERRUPT": {
            "interrupted_state": "UNAVAILABLE",
            "failure_code": "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED",
            "resumed_state": "AVAILABLE",
        },
        "DECOMMISSION_RETRY": {
            "initial_state": "FAILED",
            "initial_error_code": "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED",
            "final_state": "COMPLETED",
            "final_error_code": "NONE",
            "attempt_delta": 1,
        },
    }
    return {**common, **observations[code]}


@pytest.mark.unit
def test_network_preflight_ignores_only_exact_owned_network() -> None:
    networks = [{"Name": "task_backend", "IPAM": {"Config": [{"Subnet": "172.30.44.0/24"}]}}]
    assert (
        preflight_network(
            subnet="172.30.44.0/24",
            proxy_ip="172.30.44.10",
            networks=networks,
            owned_network="task_backend",
        )["status"]
        == "available"
    )
    with pytest.raises(ValueError):
        preflight_network(subnet="172.30.44.0/24", proxy_ip="172.30.44.10", networks=networks)


def _create(tmp_path: Path) -> Path:
    assert (
        main(
            [
                "create-evidence",
                "--drill-id",
                DRILL_ID,
                "--source-revision",
                COMMIT,
                "--image-digest",
                IMAGE,
                "--product-version",
                "0.1.0",
                "--product-source-commit",
                PRODUCT_SOURCE_COMMIT,
                "--output-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    return next(tmp_path.glob("*.jsonl"))


@pytest.mark.unit
def test_header_is_closed_and_v010_remains_not_accepted(tmp_path: Path) -> None:
    path = _create(tmp_path)
    header = json.loads(path.read_text().splitlines()[0])
    assert set(header["payload"]) == {"drill_id", "release_boundary", "runtime", "schema_version"}
    assert header["payload"]["release_boundary"]["product_source_commit"] == PRODUCT_SOURCE_COMMIT
    assert header["payload"]["release_boundary"]["status"] == "NOT_ACCEPTED"
    with pytest.raises(EvidenceRejectedError):
        validate_evidence([header], require_anchor=True)


@pytest.mark.unit
def test_release_boundary_accepts_only_exact_v012_same_source_product_cli() -> None:
    eligible = record_release_boundary(
        product_version="0.1.3",
        product_source_commit=COMMIT,
        operator_source_commit=COMMIT,
        operator_cli_in_product=True,
    )
    assert eligible["status"] == "ELIGIBLE_FOR_HUMAN_ACCEPTANCE"
    for version in ("0.1.0", "0.1.1", "1.0.0"):
        rejected = record_release_boundary(
            product_version=version,
            product_source_commit=COMMIT,
            operator_source_commit=COMMIT,
            operator_cli_in_product=True,
        )
        assert rejected["status"] == "NOT_ACCEPTED"


@pytest.mark.unit
def test_local_collector_accepts_only_closed_machine_schemas(tmp_path: Path) -> None:
    path = _create(tmp_path)
    before = path.read_bytes()
    event = append_event(
        path,
        "automated_result",
        _check_payload("METRICS_AUTH"),
    )
    assert event["event_id"] == "00000000000000000001" and path.read_bytes().startswith(before)
    append_event(
        path,
        "decision_proposal",
        {
            "decision_code": "ESCALATE_METRICS_PROXY",
            "correlation_id": CORRELATION,
            "outcome": "PROPOSED",
            "participant_code": "RISHAVT",
            "role_code": "PLATFORM_OPERATOR",
        },
    )
    append_event(
        path,
        "cleanup",
        {"cleanup_code": "TASK_RESOURCES_ABSENT", "outcome": "COMPLETE", "resource_count": 0},
    )
    for forbidden in ("signoff", "human_decision", "github_anchor"):
        with pytest.raises(EvidenceRejectedError):
            append_event(path, forbidden, {})
    with pytest.raises(EvidenceRejectedError):
        append_event(
            path,
            "automated_result",
            {
                "check_code": "METRICS_AUTH",
                "observed_code": 200,
                "outcome": "PASS",
                "sample_count": 1,
                "correlation_id": CORRELATION,
                "notes": "safe-looking",
            },
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "ghp_abcdefgh12345678",
        "github_pat_abcdef_12345678",
        "sk-abcdefghijkl",
        "sk-proj-abcdefghijkl",
        "Bearer abcdefghijkl",
        "Authorization: value",
        "Cookie=session",
        "api-key=value",
        "secret=value",
        "bucket/key",
        "John Smith",
        "operator@example.com",
        "+91 98765 43210",
    ],
)
def test_redaction_rejects_prefix_and_person_object_bypasses(value: str) -> None:
    with pytest.raises(EvidenceRejectedError):
        _reject_unsafe_strings({"allowed": value})


@pytest.mark.unit
def test_rehashing_fabricated_signoff_and_truncation_fail(tmp_path: Path) -> None:
    path = _create(tmp_path)
    ledger = [json.loads(line) for line in path.read_text().splitlines()]
    fake = _seal(
        {
            "event_id": "00000000000000000001",
            "event_type": "signoff",
            "payload": {"outcome": "COMPLETE"},
            "previous_hash": ledger[0]["event_hash"],
            "recorded_at": "2026-01-01T00:00:00Z",
        }
    )
    with pytest.raises(EvidenceRejectedError):
        validate_evidence([*ledger, fake], require_anchor=True)
    with pytest.raises(EvidenceRejectedError):
        validate_evidence([], require_anchor=True)


@pytest.mark.unit
def test_current_v010_refuses_anchor_before_any_gh_call(tmp_path: Path) -> None:
    path = _create(tmp_path)
    anchor = tmp_path / "anchor.json"
    anchor.write_text(
        json.dumps(
            {
                "decision_code_hash": "a" * 64,
                "drill_id": DRILL_ID,
                "ledger_sha256": "b" * 64,
                "operator_source_commit": COMMIT,
                "product_source_commit": PRODUCT_SOURCE_COMMIT,
                "run_id": 1,
                "tail_hash": "c" * 64,
            }
        )
    )
    calls: list[list[str]] = []

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    with pytest.raises(EvidenceRejectedError, match="NOT_ACCEPTED"):
        finalize_with_github_anchor(path, anchor, runner=runner)
    assert calls == []


@pytest.mark.unit
def test_exact_verified_anchor_requires_rishav_release_approval(tmp_path: Path) -> None:
    path, anchor = _eligible_ledger_and_anchor(tmp_path)
    runner = _github_runner("RishavT")

    finalize_with_github_anchor(path, anchor, runner=runner)
    with path.open() as handle:
        validate_evidence([json.loads(line) for line in handle], require_anchor=True)


def _eligible_ledger_and_anchor(tmp_path: Path) -> tuple[Path, Path]:
    header = build_evidence(drill_id=DRILL_ID, source_revision=COMMIT, image_digest=IMAGE)
    header["payload"]["release_boundary"] = {
        "operator_cli_binding": "PRODUCT_IMAGE",
        "operator_cli_in_product": True,
        "operator_source_commit": COMMIT,
        "product_source_commit": COMMIT,
        "product_version": "0.1.3",
        "status": "ELIGIBLE_FOR_HUMAN_ACCEPTANCE",
    }
    path = tmp_path / "ledger.jsonl"
    path.write_text(json.dumps(_seal(header), sort_keys=True) + "\n")
    for code in AUTOMATED_SEQUENCE:
        append_event(path, "automated_result", _check_payload(code))
    for code in DECISION_SEQUENCE:
        append_event(
            path,
            "decision_proposal",
            {
                "decision_code": code,
                "correlation_id": CORRELATION,
                "outcome": "PROPOSED",
                "participant_code": "RISHAVT",
                "role_code": DECISION_ROLES[code],
            },
        )
    append_event(
        path,
        "cleanup",
        {"cleanup_code": "TASK_RESOURCES_ABSENT", "outcome": "COMPLETE", "resource_count": 0},
    )
    ledger_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    tail = json.loads(path.read_text().splitlines()[-1])["event_hash"]
    decision_hash = hashlib.sha256(
        json.dumps(list(DECISION_SEQUENCE), separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    anchor_data = {
        "decision_code_hash": decision_hash,
        "drill_id": DRILL_ID,
        "ledger_sha256": ledger_sha,
        "operator_source_commit": COMMIT,
        "product_source_commit": COMMIT,
        "run_id": 42,
        "tail_hash": tail,
    }
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(anchor_data))
    return path, anchor


def _github_runner(actor: str) -> Callable[..., subprocess.CompletedProcess[str]]:
    responses = iter(
        [
            "[]",
            json.dumps(
                {
                    "event": "workflow_dispatch",
                    "path": ".github/workflows/operator-drill-signoff.yml",
                    "head_branch": "main",
                    "conclusion": "success",
                }
            ),
            json.dumps(
                [
                    {
                        "state": "approved",
                        "user": {"login": actor},
                        "environments": [{"name": "release"}],
                    }
                ]
            ),
        ]
    )

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, next(responses), "")

    return runner


@pytest.mark.unit
def test_forged_actor_and_stale_anchor_cannot_complete(tmp_path: Path) -> None:
    path, anchor = _eligible_ledger_and_anchor(tmp_path)
    before = path.read_bytes()
    with pytest.raises(EvidenceRejectedError, match="RishavT"):
        finalize_with_github_anchor(path, anchor, runner=_github_runner("rishav-bot"))
    assert path.read_bytes() == before
    stale = json.loads(anchor.read_text())
    stale["tail_hash"] = "f" * 64
    anchor.write_text(json.dumps(stale))
    with pytest.raises(EvidenceRejectedError, match="exact current ledger"):
        finalize_with_github_anchor(path, anchor, runner=_github_runner("RishavT"))
    assert path.read_bytes() == before


@pytest.mark.unit
def test_final_validation_reverifies_external_proof_and_rejects_truncation(tmp_path: Path) -> None:
    path, anchor = _eligible_ledger_and_anchor(tmp_path)
    finalize_with_github_anchor(path, anchor, runner=_github_runner("RishavT"))
    validate_final_evidence(path, runner=_github_runner("RishavT"))
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    with pytest.raises(EvidenceRejectedError):
        validate_final_evidence(path, runner=_github_runner("RishavT"))


@pytest.mark.unit
def test_cli_rejects_fabricated_attestation_and_tail_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, anchor = _eligible_ledger_and_anchor(tmp_path)
    finalize_with_github_anchor(path, anchor, runner=_github_runner("RishavT"))
    fake_gh = tmp_path / "gh"
    fake_gh.write_text("#!/bin/sh\nexit 19\n")
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    assert main(["validate-final", str(path)]) == 2
    path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    assert main(["validate-final", str(path)]) == 2


@pytest.mark.unit
@pytest.mark.parametrize("mutation", ["missing", "failed", "duplicate", "out_of_order", "empty"])
def test_completion_state_machine_rejects_incomplete_transcripts(
    tmp_path: Path, mutation: str
) -> None:
    path, anchor = _eligible_ledger_and_anchor(tmp_path)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    if mutation == "missing":
        del events[2]
    elif mutation == "failed":
        events[1]["payload"]["outcome"] = "FAIL"
    elif mutation == "duplicate":
        events.insert(2, events[1])
    elif mutation == "out_of_order":
        events[1], events[2] = events[2], events[1]
    else:
        events[1]["payload"]["metric_sample_count"] = 0
    rebuilt: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        unsigned = {
            "event_id": f"{index:020d}",
            "event_type": event["event_type"],
            "payload": event["payload"],
            "previous_hash": rebuilt[-1]["event_hash"] if rebuilt else None,
            "recorded_at": event["recorded_at"],
        }
        rebuilt.append(_seal(unsigned))
    path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in rebuilt))
    with pytest.raises(EvidenceRejectedError):
        finalize_with_github_anchor(path, anchor, runner=_github_runner("RishavT"))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("code", "field", "wrong"),
    [
        ("METRICS_AUTH", "wrong_token_code", 200),
        ("PROXY_SPOOF", "redirect_code", 302),
        ("RESTORE_FAULT", "exit_code", 0),
        ("STORAGE_INTERRUPT", "resumed_state", "UNAVAILABLE"),
        ("DECOMMISSION_RETRY", "attempt_delta", 2),
    ],
)
def test_each_automated_contract_rejects_behavioral_mismatch(
    tmp_path: Path, code: str, field: str, wrong: object
) -> None:
    path = _create(tmp_path)
    payload = _check_payload(code)
    payload[field] = wrong
    with pytest.raises(EvidenceRejectedError):
        append_event(path, "automated_result", payload)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("code", "field"),
    [
        ("METRICS_AUTH", "missing_token_code"),
        ("METRICS_AUTH", "wrong_token_code"),
        ("METRICS_AUTH", "correct_token_code"),
        ("METRICS_AUTH", "metric_sample_count"),
        ("PROXY_SPOOF", "redirect_code"),
        ("RESTORE_FAULT", "exit_code"),
        ("RESTORE_FAULT", "writers_running"),
        ("DECOMMISSION_RETRY", "attempt_delta"),
    ],
)
def test_automated_numeric_fields_reject_json_boole(tmp_path: Path, code: str, field: str) -> None:
    path = _create(tmp_path)
    payload = _check_payload(code)
    payload[field] = False
    with pytest.raises(EvidenceRejectedError):
        append_event(path, "automated_result", payload)


@pytest.mark.unit
def test_cleanup_and_anchor_numeric_fields_reject_json_boole(tmp_path: Path) -> None:
    path = _create(tmp_path)
    with pytest.raises(EvidenceRejectedError):
        append_event(
            path,
            "cleanup",
            {
                "cleanup_code": "TASK_RESOURCES_ABSENT",
                "outcome": "COMPLETE",
                "resource_count": False,
            },
        )
    with pytest.raises(EvidenceRejectedError):
        _validate_payload(
            "github_anchor",
            {
                "decision_code_hash": "a" * 64,
                "drill_id": DRILL_ID,
                "ledger_sha256": "b" * 64,
                "operator_source_commit": COMMIT,
                "product_source_commit": COMMIT,
                "run_id": True,
                "tail_hash": "c" * 64,
            },
        )
