"""Boundary-only orchestration, evaluator pause/resume, and exact-head regression tests."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from anva.acceptance.client import APIResponse
from anva.acceptance.corpus import canonicalize_corpus
from anva.acceptance.runner import AcceptanceRunner, AcceptanceRunnerError, RunnerConfig
from anva.acceptance.state import load_state
from anva.contracts.catalog import EXAMPLES


def _id(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012d}"


class FakeProduct:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None, dict[str, object] | None]] = []
        self.assurance_starts = 0
        self.upload_authorization_calls = 0
        self.manual_heads: list[str] = []
        self.request_id = _id(901)

    def request(
        self,
        token: str | None,
        method: str,
        path: str,
        payload: dict[str, object] | None,
        content: bytes | None,
    ) -> APIResponse:
        self.calls.append((method, path, token, payload))
        if path == "/bootstrap":
            assert token is None
            return APIResponse(
                201,
                {
                    "organization_id": _id(1),
                    "repository_id": _id(2),
                    "access_scope_id": _id(3),
                    "token": "initiator-token-material",
                    "reviewer_token": "reviewer-token-material",
                    "expires_at": "2026-08-04T12:00:00Z",
                    "reviewer_expires_at": "2026-08-04T12:00:00Z",
                },
            )
        assert token in {"initiator-token-material", "reviewer-token-material"}
        if path == "/source-connections/filesystem":
            return APIResponse(201, {"id": _id(4)})
        if path.endswith("/sync"):
            return APIResponse(202, {"id": _id(5)})
        if path.endswith("/sync-runs"):
            return APIResponse(200, {"sync_runs": [{"id": _id(5), "state": "COMPLETED"}]})
        if path == "/canvas/query":
            return APIResponse(
                200,
                {
                    "nodes": [{"id": _id(41), "type": "GOAL", "label": "Connected goal"}],
                    "edges": [],
                    "truncated": False,
                },
            )
        if path == "/work-items/import":
            return APIResponse(
                201,
                {"work_item_id": _id(6), "work_item_revision_id": _id(7)},
            )
        if path == "/policies/import":
            return APIResponse(201, {"policy_id": _id(8), "policy_version_id": _id(9)})
        if path == "/policies/simulate":
            return APIResponse(201, {"policy_evaluation_id": _id(10)})
        if path.endswith("/manual-diff"):
            assert payload is not None
            head = cast(str, payload["head_commit"])
            self.manual_heads.append(head)
            revision = _id(20 + len(self.manual_heads))
            return APIResponse(
                201,
                {
                    "pull_request_revision_id": revision,
                    "diff_hash": hashlib.sha256(head.encode()).hexdigest(),
                },
            )
        if path.endswith("/evidence-upload-authorizations"):
            self.upload_authorization_calls += 1
            if self.upload_authorization_calls == 1:
                return APIResponse(
                    200,
                    {
                        "authorization_id": _id(29),
                        "upload_token": None,
                    },
                )
            return APIResponse(
                201,
                {
                    "authorization_id": _id(30),
                    "upload_token": "single-use-upload-material",
                    "upload_path": f"/api/v1/evidence-upload-authorizations/{_id(30)}/content",
                },
            )
        if path.endswith(f"/{_id(30)}/content"):
            assert method == "PUT" and content is not None
            decoded = json.loads(content)
            assert decoded == {
                "checks": [{"name": "EXACT_HEAD_PROOF", "status": "PASSED"}],
                "head_sha": self.manual_heads[0],
                "schema_version": 1,
            }
            return APIResponse(201, {"evidence_blob_id": _id(31)})
        if path.endswith("/evidence"):
            return APIResponse(
                201,
                {"manifest_id": _id(32), "evidence_ids": [_id(33)]},
            )
        if path.endswith("/assurance-runs"):
            self.assurance_starts += 1
            primary = self.assurance_starts == 1
            return APIResponse(
                201,
                {
                    "assurance_run_id": _id(34 if primary else 36),
                    "evaluator_task_id": _id(35 if primary else 37),
                    "input_hash": "7" * 64,
                },
            )
        if path == f"/assurance-runs/{_id(36)}":
            return APIResponse(200, {"state": "STALE", "readiness": "STALE"})
        if path.endswith("/evaluator-tasks/claim"):
            assert token == "reviewer-token-material"  # noqa: S105 - synthetic fixture
            return APIResponse(
                200,
                {
                    "task_id": _id(35),
                    "claim_token": "lease-bound-claim-material",
                    "request": {
                        "request_id": self.request_id,
                        "assurance_run_id": _id(34),
                        "organization_id": _id(1),
                        "commit_sha": self.manual_heads[0],
                    },
                },
            )
        if path == f"/evaluator-tasks/{_id(35)}/submit":
            assert token == "reviewer-token-material"  # noqa: S105 - synthetic fixture
            return APIResponse(201, {"assurance_run_id": _id(34), "report_id": _id(38)})
        if path == f"/assurance-runs/{_id(34)}":
            return APIResponse(
                200,
                {"state": "COMPLETED", "readiness": "READY", "head_commit": self.manual_heads[0]},
            )
        if path == f"/assurance-runs/{_id(34)}/report":
            return APIResponse(
                200,
                {
                    "assurance_run_id": _id(34),
                    "readiness": "READY",
                    "head_commit": self.manual_heads[0],
                    "renderer_version": "assurance-report-v1",
                    "content_hash": "8" * 64,
                    "limitations": [],
                },
            )
        if path == f"/assurance-runs/{_id(34)}/findings":
            return APIResponse(200, {"assurance_run_id": _id(34), "findings": []})
        raise AssertionError(f"Unexpected fake public API path: {method} {path}")


class FakeAPI:
    def __init__(self, product: FakeProduct, token: str | None) -> None:
        self.product = product
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: frozenset[int] = frozenset({200}),
    ) -> APIResponse:
        del headers, expected
        return self.product.request(self.token, method, path, payload, content)


class FakeMCP:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
        self.calls.append(tool_name)
        if tool_name == "anva.search":
            return {
                "contract_version": "1",
                "tool": tool_name,
                "data": {
                    "results": [
                        {
                            "id": "opaque",
                            "content_hash": "6" * 64,
                            "path": "docs/knowledge/current.md",
                            "score": 1.0,
                        }
                    ]
                },
                "next_cursor": None,
            }
        return {
            "contract_version": "1",
            "tool": tool_name,
            "data": {"packet_id": _id(40), "created": False, "packet": {}},
        }


def _runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AcceptanceRunner, FakeProduct]:
    fixture = Path("tests/fixtures/acceptance-public")
    raw = tmp_path / "raw"
    canonical = tmp_path / "canonical"
    (tmp_path / "results").mkdir()
    shutil.copytree(fixture, raw)
    canonical.mkdir()
    pin = hashlib.sha256((raw / "acceptance-corpus.json").read_bytes()).hexdigest()
    corpus = canonicalize_corpus(raw_root=raw, canonical_root=canonical, manifest_sha256=pin)
    product = FakeProduct()
    fake_mcp = FakeMCP()
    monkeypatch.setattr(
        "anva.acceptance.runner.PublicAPI",
        lambda _url, token=None: FakeAPI(product, token),
    )
    monkeypatch.setattr(
        "anva.acceptance.runner.StreamableHTTPMCP",
        lambda _url, _token: fake_mcp,
    )
    runner = AcceptanceRunner(
        RunnerConfig(
            api_url="http://api:8000/api/v1",
            mcp_url="http://mcp:8001/mcp",
            canonical_root=canonical,
            state_path=tmp_path / "state" / "resume.json",
            output_root=tmp_path / "results" / "sealed",
            manifest_sha256=corpus.manifest_sha256,
            source_fingerprint=corpus.source_fingerprint,
            canonical_manifest_sha256=corpus.canonical_manifest_sha256,
            product_commit="d" * 40,
            credential_output=tmp_path / "credentials" / "credentials.json",
            sync_timeout_seconds=1,
        )
    )
    return runner, product


@pytest.mark.unit
def test_runner_rejects_unpinned_product_or_unbounded_sync_before_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, _product = _runner(tmp_path, monkeypatch)

    with pytest.raises(AcceptanceRunnerError, match="Product commit"):
        AcceptanceRunner(replace(runner.config, product_commit="unknown"))
    with pytest.raises(AcceptanceRunnerError, match="timeout"):
        AcceptanceRunner(replace(runner.config, sync_timeout_seconds=0))


@pytest.mark.unit
def test_public_runner_pauses_for_external_review_rejects_tamper_and_seals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)

    awaiting = runner.start(bootstrap_secret="bootstrap-material", token=None)
    assert awaiting.status == "AWAITING_EXTERNAL_REVIEW"
    upload_requests = [
        body
        for method, path, _token, body in product.calls
        if method == "POST" and path.endswith("/evidence-upload-authorizations")
    ]
    assert len(upload_requests) == 2
    assert upload_requests[0] is not None and upload_requests[1] is not None
    assert upload_requests[0]["idempotency_key"] != upload_requests[1]["idempotency_key"]
    call_count = len(product.calls)
    assert runner.start(bootstrap_secret=None, token=None).status == "AWAITING_EXTERNAL_REVIEW"
    assert len(product.calls) == call_count
    assert product.manual_heads[0] != product.manual_heads[-1]
    assert any(
        path == f"/assurance-runs/{_id(36)}" for _method, path, _token, _body in product.calls
    )
    credential_bytes = (tmp_path / "credentials" / "credentials.json").read_bytes()
    state_bytes = runner.config.state_path.read_bytes()
    assert b"initiator-token-material" in credential_bytes
    assert b"reviewer-token-material" in credential_bytes
    assert b"token-material" not in state_bytes

    handoff_path = tmp_path / "handoff" / "review.json"
    runner.create_review_handoff(
        reviewer_token="reviewer-token-material",
        output=handoff_path,
    )
    original_handoff = handoff_path.read_bytes()
    tampered = json.loads(original_handoff)
    tampered["task_id"] = _id(999)
    handoff_path.write_text(json.dumps(tampered), encoding="utf-8")
    handoff_path.chmod(0o600)
    result_path = tmp_path / "external-result.json"
    result = deepcopy(EXAMPLES["evaluator-result"])
    result.update(
        {
            "request_id": product.request_id,
            "organization_id": _id(1),
            "commit_sha": product.manual_heads[0],
            "completion": "COMPLETE",
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "findings": [],
            "limitations": ["External provider launch is intentionally out of process."],
            "evaluated_at": "2026-08-07T00:00:00Z",
        }
    )
    result_path.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(AcceptanceRunnerError, match="does not match"):
        runner.submit_review(
            reviewer_token="reviewer-token-material",
            handoff_path=handoff_path,
            result_path=result_path,
        )
    handoff_path.write_bytes(original_handoff)
    handoff_path.chmod(0o600)

    submitted = runner.submit_review(
        reviewer_token="reviewer-token-material",
        handoff_path=handoff_path,
        result_path=result_path,
    )
    assert submitted.status == "EXTERNAL_REVIEW_SUBMITTED"
    assert not handoff_path.exists()
    complete = runner.finalize(token="initiator-token-material", mcp=FakeMCP())
    assert complete.status == "COMPLETE"
    assert runner.finalize(token="initiator-token-material").status == "COMPLETE"
    envelope = json.loads((runner.config.output_root / "acceptance-result.json").read_bytes())
    assert envelope["status"] == "COMPLETE"
    assert (runner.config.output_root / "results" / "canvas.json").is_file()
    all_public = b"".join(
        path.read_bytes() for path in runner.config.output_root.rglob("*") if path.is_file()
    ).lower()
    assert b"token-material" not in all_public
    assert b"private-oracle" not in all_public
    assert load_state(runner.config.state_path).hashes["sealed_manifest_sha256"]
