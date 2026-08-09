"""Security and determinism coverage for acceptance state and public export."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from anva.acceptance.export import AcceptanceExportError, seal_results
from anva.acceptance.runner import _run_reference_time
from anva.acceptance.state import AcceptanceStateError, ResumeState, load_state, save_state
from anva.contracts.validation import validate_payload


@pytest.mark.unit
def test_run_reference_precommit_uses_later_clock_and_bounded_activation_grace() -> None:
    assert (
        _run_reference_time(
            "2030-01-01T00:00:00Z",
            now=datetime(2026, 1, 1, tzinfo=UTC),
            sync_timeout_seconds=300,
        )
        == "2030-01-01T00:10:00Z"
    )
    assert (
        _run_reference_time(
            "2026-01-01T00:00:00Z",
            now=datetime(2031, 6, 1, 12, 34, 56, 999999, tzinfo=UTC),
            sync_timeout_seconds=60,
        )
        == "2031-06-01T12:40:56Z"
    )


def _state() -> ResumeState:
    return ResumeState(
        corpus_id="halcyon-messy-organization-tst-008",
        run_id="anva:acceptance-run",
        reference_time="2026-07-28T12:00:00Z",
        product_version="0.1.0",
        identities={"organization_id": "00000000-0000-4000-8000-000000000001"},
        hashes={
            "manifest_sha256": "a" * 64,
            "source_fingerprint": "b" * 64,
            "canonical_manifest_sha256": "c" * 64,
            "canonical_input_sha256": "d" * 64,
            "product_commit": "e" * 40,
            "corpus_commit": "f" * 40,
            "base_commit": "1" * 40,
            "head_commit": "2" * 40,
            "new_head_commit": "3" * 40,
        },
    )


@pytest.mark.unit
def test_resume_state_is_private_atomic_and_rejects_tamper_or_credentials(tmp_path: Path) -> None:
    path = tmp_path / "state" / "resume.json"
    state = _state()
    save_state(path, state)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_state(path).as_dict() == state.as_dict()
    assert not list(path.parent.glob("*.tmp"))

    payload = json.loads(path.read_bytes())
    payload["token"] = "must-never-persist"  # noqa: S105 - rejection canary
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(AcceptanceStateError, match="invalid|unsupported"):
        load_state(path)

    payload.pop("token")
    payload["hashes"]["head_commit"] = "not-a-hash"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(AcceptanceStateError, match="hash"):
        load_state(path)

    path.parent.chmod(0o755)
    with pytest.raises(AcceptanceStateError, match="unavailable"):
        load_state(path)
    with pytest.raises(AcceptanceStateError, match="unsafe"):
        save_state(path, state)


def _seal(root: Path, *, corpus_id: str = "halcyon-messy-organization-tst-008") -> str:
    return seal_results(
        output_root=root,
        corpus_id=corpus_id,
        manifest_sha256="a" * 64,
        source_fingerprint="b" * 64,
        run_id="anva:acceptance-run",
        started_at="2026-07-28T12:00:00Z",
        completed_at="2026-07-28T12:00:00Z",
        product_version="0.1.0",
        product_commit="c" * 40,
        product_image_sha256="1" * 64,
        product_package_sha256="2" * 64,
        corpus_commit="d" * 40,
        canonical_manifest_sha256="3" * 64,
        canonical_input_sha256="e" * 64,
        head_commit="f" * 40,
        assurance_input_sha256="7" * 64,
        reference_time_sha256="8" * 64,
        review_result_sha256="4" * 64,
        search_output={
            "contract_version": "1",
            "tool": "anva.search",
            "data": {
                "results": [
                    {
                        "chunk_id": "opaque-result",
                        "content_hash": "9" * 64,
                        "pointer": "line:7",
                        "canonical_url": "file:///docs/knowledge/current.md",
                        "content": "sensitive source body must not be exported",
                    }
                ]
            },
        },
        context_output={
            "contract_version": "1",
            "tool": "anva.get_context_packet",
            "data": {
                "packet": {
                    "items": [
                        {
                            "anva_sources": [
                                {
                                    "canonical_url": "file:///docs/knowledge/current.md",
                                    "locator": "line:7",
                                    "source_content_hash": "9" * 64,
                                }
                            ]
                        }
                    ]
                }
            },
        },
        canvas_output={
            "nodes": [{"id": "node-1", "type": "GOAL", "label": "Connected product goal"}],
            "edges": [],
            "truncated": False,
        },
        report_output={
            "assurance_run_id": "00000000-0000-4000-8000-000000000601",
            "readiness": "READY",
            "head_commit": "f" * 40,
            "renderer_version": "assurance-report-v1",
            "content_hash": "8" * 64,
            "markdown": "full report body is content-minimized",
            "limitations": [],
        },
        findings_output={
            "assurance_run_id": "00000000-0000-4000-8000-000000000601",
            "findings": [],
        },
    )


@pytest.mark.unit
def test_public_export_is_deterministic_content_minimized_and_checksum_complete(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_hash = _seal(first)
    second_hash = _seal(second)

    assert first_hash == second_hash
    first_files = {
        path.relative_to(first).as_posix(): path.read_bytes()
        for path in first.rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(second).as_posix(): path.read_bytes()
        for path in second.rglob("*")
        if path.is_file()
    }
    assert first_files == second_files
    envelope = json.loads(first_files["acceptance-result.json"])
    validate_payload("acceptance-result", envelope)
    assert any(
        artifact["kind"] == "knowledge_retrieval_results" for artifact in envelope["artifacts"]
    )
    rendered = b"\n".join(first_files.values())
    assert b"sensitive source body" not in rendered
    assert b"full report body" not in rendered
    sums = first_files["SHA256SUMS"].decode().splitlines()
    assert len(sums) == len(first_files) - 1
    assert not list(tmp_path.glob(".*.sealing"))
    with pytest.raises(AcceptanceExportError, match="already exists"):
        _seal(first)


@pytest.mark.unit
def test_public_export_rejects_private_oracle_markers_before_publication(tmp_path: Path) -> None:
    with pytest.raises(AcceptanceExportError, match="private marker"):
        _seal(tmp_path / "sealed", corpus_id="private-oracle-control")
    assert not (tmp_path / "sealed").exists()
