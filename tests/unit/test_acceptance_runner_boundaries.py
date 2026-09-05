"""Boundary-only orchestration, evaluator pause/resume, and exact-head regression tests."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from anva import __version__
from anva.acceptance.client import AcceptanceBoundaryError, APIResponse
from anva.acceptance.corpus import canonicalize_corpus
from anva.acceptance.export import AcceptanceExportError
from anva.acceptance.provenance import REQUIRED_LAUNCH_SERVICES, package_sha256
from anva.acceptance.runner import (
    AcceptanceRunner,
    AcceptanceRunnerError,
    RunnerConfig,
    _read_secret_handoff,
    _recover_secret_handoff,
    _secret_handoff_pending_path,
    _write_secret_handoff,
)
from anva.acceptance.state import ResumeState, load_state, save_state
from anva.contracts.acceptance import ACCEPTANCE_HTTP_OPERATION_IDS
from anva.contracts.bootstrap_scope import acceptance_bootstrap_scope_payload
from anva.contracts.catalog import EXAMPLES
from anva.core.services.evidence_uploads import inspect_evidence_upload

SOURCE_TEXT = "# Checkout ownership\n\nThe Payments Platform team owns checkout.\n"
SOURCE_NORMALIZED = json.dumps(
    {
        "headings": [{"level": 1, "line": 1, "text": "Checkout ownership"}],
        "links": [],
        "text": SOURCE_TEXT,
    },
    separators=(",", ":"),
    sort_keys=True,
)
SOURCE_NORMALIZED_SHA256 = hashlib.sha256(SOURCE_NORMALIZED.encode()).hexdigest()


def _id(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012d}"


def _evidence_bytes(head_commit: str, *, check_name: str = "TESTS_PASS") -> bytes:
    return (
        json.dumps(
            {
                "checks": [{"name": check_name, "status": "PASSED"}],
                "head_sha": head_commit,
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _bind_case_evidence(case: dict[str, object], head_commit: str) -> None:
    evidence = cast(dict[str, object], case["evidence"])
    evidence["content_base64"] = base64.b64encode(_evidence_bytes(head_commit)).decode()


class FakeProduct:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None, dict[str, object] | None]] = []
        self.assurance_starts = 0
        self.upload_authorization_calls = 0
        self.manual_heads: list[str] = []
        self.upload_contents: list[bytes] = []
        self.mcp_calls: list[tuple[str, dict[str, object]]] = []
        self.operation_ids: list[str] = []
        self.request_id = _id(901)
        self.evidence_manifest: dict[str, object] | None = None
        self.evidence_payload_hash = "6" * 64

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
            assert payload is not None
            request_payload = {
                key: value for key, value in payload.items() if key != "idempotency_key"
            }
            request_hash = hashlib.sha256(
                (json.dumps(request_payload, separators=(",", ":"), sort_keys=True) + "\n").encode()
            ).hexdigest()
            return APIResponse(
                201,
                {
                    "organization_id": _id(1),
                    "repository_id": _id(2),
                    "access_scope_id": _id(3),
                    "service_identity_id": _id(6),
                    "token_id": _id(7),
                    "token": "initiator-token-material",
                    "reviewer_service_identity_id": _id(8),
                    "reviewer_token_id": _id(9),
                    "reviewer_token": "reviewer-token-material",
                    "expires_at": "2026-08-04T12:00:00Z",
                    "reviewer_expires_at": "2026-08-04T12:00:00Z",
                    "bootstrap_request_sha256": request_hash,
                    "bootstrap_mode": "SCOPED" if "scope" in payload else "LEGACY",
                    "recovered": False,
                },
            )
        if token in {"wrong-token", "expired-token", "reused-token"}:
            raise AcceptanceBoundaryError("invalid_credential", "synthetic secret", status=401)
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
                    "schema_version": "1",
                    "repositories": [{"id": _id(2), "name": "acceptance"}],
                    "nodes": [
                        {
                            "id": _id(41),
                            "type": "GOAL",
                            "label": "Checkout ownership",
                            "canonical_key": "checkout",
                            "repository_ids": [_id(2)],
                            "freshness": "CURRENT",
                            "provenance": {"kind": "SOURCE_BACKED"},
                        }
                    ],
                    "edges": [],
                    "counts": {"nodes": 1, "edges": 0},
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
            self.upload_contents.append(content)
            return APIResponse(201, {"evidence_blob_id": _id(31)})
        if path.endswith("/evidence"):
            assert payload is not None
            self.evidence_manifest = deepcopy(payload)
            return APIResponse(
                201,
                {
                    "manifest_id": _id(32),
                    "payload_hash": self.evidence_payload_hash,
                    "evidence_ids": [_id(33)],
                    "created": True,
                },
            )
        if path == f"/evidence-manifests/{_id(32)}":
            assert self.evidence_manifest is not None
            return APIResponse(
                200,
                {
                    "id": _id(32),
                    "repository_id": _id(2),
                    "pull_request_number": self.evidence_manifest["pull_request_number"],
                    "commit_sha": self.evidence_manifest["commit_sha"],
                    "payload_hash": self.evidence_payload_hash,
                    "manifest": deepcopy(self.evidence_manifest),
                },
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
                    "status": "CLAIMED",
                    "task_id": _id(35),
                    "assurance_run_id": _id(34),
                    "request_id": self.request_id,
                    "input_hash": "7" * 64,
                    "head_commit": self.manual_heads[0],
                    "claimant": "independent-acceptance-evaluator",
                    "claimed_by": {
                        "actor_type": "SERVICE",
                        "actor_id": _id(8),
                        "credential_id": _id(9),
                    },
                    "attempt": 1,
                    "lease_expires_at": "2026-08-10T13:00:00Z",
                    "claim_token": "lease-bound-claim-material",
                    "replayed": False,
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
            assert payload is not None and isinstance(payload.get("result"), dict)
            result_hash = hashlib.sha256(
                json.dumps(payload["result"], separators=(",", ":"), sort_keys=True).encode()
            ).hexdigest()
            return APIResponse(
                201,
                {
                    "task_id": _id(35),
                    "assurance_run_id": _id(34),
                    "input_hash": "7" * 64,
                    "head_commit": self.manual_heads[0],
                    "result_hash": result_hash,
                    "state": "COMPLETED",
                    "readiness": "READY",
                    "reason_codes": [],
                    "report_id": _id(38),
                    "finding_ids": [],
                    "created": True,
                    "replayed": False,
                },
            )
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
        operation_id: str | None = None,
    ) -> APIResponse:
        del headers, expected
        if operation_id is not None:
            self.product.operation_ids.append(operation_id)
        return self.product.request(self.token, method, path, payload, content)


class FakeMCP:
    def __init__(self, product: FakeProduct | None = None) -> None:
        self.product = product

    def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
        if self.product is not None:
            self.product.mcp_calls.append((tool_name, dict(arguments)))
        if tool_name == "anva.search":
            return {
                "contract_version": "1",
                "tool": tool_name,
                "data": {
                    "results": [
                        {
                            "chunk_id": _id(42),
                            "content_hash": SOURCE_NORMALIZED_SHA256,
                            "pointer": "/",
                            "canonical_url": "file:///canonical/organization/decision.md",
                            "text": SOURCE_NORMALIZED,
                        }
                    ]
                },
                "next_cursor": None,
            }
        return {
            "contract_version": "1",
            "tool": tool_name,
            "data": {
                "packet_id": _id(40),
                "created": False,
                "packet": {
                    "items": [
                        {
                            "item_id": _id(43),
                            "payload": {"content_hash": SOURCE_NORMALIZED_SHA256},
                            "summary": SOURCE_NORMALIZED,
                            "anva_sources": [
                                {
                                    "canonical_url": ("file:///canonical/organization/decision.md"),
                                    "locator": "/",
                                    "source_content_hash": SOURCE_NORMALIZED_SHA256,
                                    "source_location_id": _id(44),
                                    "source_observation_id": _id(45),
                                    "access_snapshot_id": _id(46),
                                }
                            ],
                        }
                    ]
                },
            },
        }


def _runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    case_payload: dict[str, object] | None = None,
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
    fake_mcp = FakeMCP(product)
    monkeypatch.setattr(
        "anva.acceptance.runner.PublicAPI",
        lambda _url, token=None: FakeAPI(product, token),
    )
    monkeypatch.setattr(
        "anva.acceptance.runner.StreamableHTTPMCP",
        lambda _url, _token: fake_mcp,
    )
    provenance = tmp_path / "anva-build-provenance.json"
    package_digest = package_sha256(Path(__file__).resolve().parents[2] / "src" / "anva")
    provenance.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product_commit": "d" * 40,
                "build_input_sha256": "b" * 64,
                "package_sha256": package_digest,
            }
        ),
        encoding="utf-8",
    )
    provenance.chmod(0o444)
    launch_manifest = tmp_path / "launch-manifest.json"
    launch_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "anva-docker-launch",
                "product_commit": "d" * 40,
                "build_input_sha256": "b" * 64,
                "package_sha256": package_digest,
                "engine_image_id": f"sha256:{'e' * 64}",
                "image_reference": "anva:test",
                "resolved_compose_sha256": "a" * 64,
                "services": {
                    service: {
                        "config_sha256": "f" * 64,
                        "engine_image_id": f"sha256:{'e' * 64}",
                        "image_reference": "anva:test",
                    }
                    for service in REQUIRED_LAUNCH_SERVICES
                },
            }
        ),
        encoding="utf-8",
    )
    launch_manifest.chmod(0o444)
    case_path: Path | None = None
    if case_payload is not None:
        case_path = tmp_path / "acceptance-case.json"
        case_path.write_text(json.dumps(case_payload), encoding="utf-8")
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
            product_image_sha256="e" * 64,
            product_image_reference="anva:test",
            build_input_sha256="b" * 64,
            launch_service="acceptance-product-start",
            case_path=case_path,
            build_provenance_path=provenance,
            launch_manifest_path=launch_manifest,
            credential_output=tmp_path / "credentials" / "credentials.json",
            sync_timeout_seconds=1,
        )
    )
    return runner, product


@pytest.mark.unit
@pytest.mark.parametrize(
    ("case_id", "slug", "pull_request_number", "base_commit", "head_commit"),
    [
        ("tst-009.scn-synthetic", "synthetic-org", 29, "4" * 40, "5" * 40),
        ("tst-009.scn-lantern", "lantern-org", 41, "6" * 40, "7" * 40),
    ],
)
def test_case_drives_query_commits_pr_and_public_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case_id: str,
    slug: str,
    pull_request_number: int,
    base_commit: str,
    head_commit: str,
) -> None:
    case = deepcopy(EXAMPLES["acceptance-case"])
    case["case_id"] = case_id
    cast(dict[str, object], case["organization"])["slug"] = slug
    organization = cast(dict[str, object], case["organization"])
    organization["name"] = "Synthetic Org"
    organization["bootstrap_scope"] = acceptance_bootstrap_scope_payload(
        admin_email=f"operator@{slug}.invalid",
        admin_display_name=f"{slug} operator",
        repository_external_id=f"github:synthetic/{slug}",
        repository_name=f"{slug}-repository",
        initiator_name=f"{slug} acceptance runner",
        reviewer_name=f"{slug} independent reviewer",
        access_scope_name=f"{slug} exact scope",
    )
    cast(dict[str, object], case["retrieval"])["search_query"] = (
        "synthetic ownership and release policy"
    )
    change = cast(dict[str, object], case["change"])
    change.update(
        {
            "pull_request_number": pull_request_number,
            "base_commit": base_commit,
            "head_commit": head_commit,
            "stale_probe": None,
        }
    )
    _bind_case_evidence(case, head_commit)
    runner, product = _runner(tmp_path, monkeypatch, case_payload=case)

    awaiting = runner.start(bootstrap_secret="bootstrap-material", token=None)

    assert awaiting.status == "AWAITING_EXTERNAL_REVIEW"
    assert awaiting.hashes["base_commit"] == base_commit
    assert awaiting.hashes["head_commit"] == head_commit
    assert "new_head_commit" not in awaiting.hashes
    assert awaiting.hashes["case_sha256"] == runner.case.sha256
    assert awaiting.identities["reviewer_service_identity_id"] == _id(8)
    assert awaiting.identities["reviewer_token_id"] == _id(9)
    assert any(
        path == f"/repositories/{_id(2)}/pull-requests/{pull_request_number}/manual-diff"
        for _method, path, _token, _payload in product.calls
    )
    assert not any(
        "pull-requests/817/" in path for _method, path, _token, _payload in product.calls
    )
    search_arguments = next(
        arguments for tool, arguments in product.mcp_calls if tool == "anva.search"
    )
    assert search_arguments["query"] == "synthetic ownership and release policy"
    bootstrap = next(
        payload
        for method, path, _token, payload in product.calls
        if method == "POST" and path == "/bootstrap"
    )
    assert bootstrap is not None
    assert bootstrap["organization_slug"] == slug
    assert bootstrap["scope"] == organization["bootstrap_scope"]
    assert "admin_email" not in bootstrap
    identities = cast(dict[str, object], bootstrap["scope"])["service_identities"]
    assert isinstance(identities, list) and len(identities) == 2
    assurance_payload = next(
        payload
        for method, path, _token, payload in product.calls
        if method == "POST" and path.endswith("/assurance-runs")
    )
    assert assurance_payload is not None
    assert assurance_payload["reviewer_service_identity_id"] == _id(8)
    assert assurance_payload["reviewer_token_id"] == _id(9)
    assert product.upload_contents == [runner.case.evidence_bytes]
    inspected = inspect_evidence_upload(
        io.BytesIO(runner.case.evidence_bytes),
        content_length=len(runner.case.evidence_bytes),
        expected_size=len(runner.case.evidence_bytes),
        expected_sha256=hashlib.sha256(runner.case.evidence_bytes).hexdigest(),
        commit_sha=head_commit,
    )
    assert inspected.archive_summary["check_count"] == 1
    assert len(product.operation_ids) == len(product.calls)
    assert {
        "bootstrapOrganization",
        "connectFilesystemSource",
        "syncSourceConnection",
        "listSourceSyncRuns",
        "queryOrganizationalCanvas",
        "importWorkItemRevision",
        "importPolicyVersion",
        "simulatePolicy",
        "createEvidenceUploadAuthorization",
        "uploadEvidenceContent",
        "submitEvidenceManifest",
        "ingestManualPullRequestDiff",
        "startManualDiffAssurance",
    } <= set(product.operation_ids)


@pytest.mark.unit
def test_no_case_preserves_legacy_journey_golden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)
    reference = "2026-08-07T00:10:00Z"
    state = runner._new_state(reference_time=reference)

    assert runner.case.legacy_default is True
    assert state.hashes["canonical_input_sha256"] == state.hashes["canonical_manifest_sha256"]
    assert "case_sha256" not in state.hashes
    assert (
        state.hashes["base_commit"]
        == hashlib.sha256(f"{runner.corpus.source_fingerprint}:base".encode()).hexdigest()[:40]
    )
    assert (
        state.hashes["head_commit"]
        == hashlib.sha256(f"{runner.corpus.source_fingerprint}:head".encode()).hexdigest()[:40]
    )
    bootstrap = runner._bootstrap_payload(state)
    assert bootstrap == {
        "organization_slug": f"anva-acceptance-{state.hashes['reference_time_sha256'][:12]}",
        "organization_name": f"Anva Acceptance {runner.corpus.corpus_id}",
        "admin_email": (
            f"anva-acceptance-{state.hashes['reference_time_sha256'][:12]}@anva.invalid"
        ),
        "admin_display_name": "Anva acceptance operator",
        "repository_external_id": f"acceptance:{runner.corpus.source_fingerprint}",
        "repository_name": runner.corpus.corpus_id,
        "independent_reviewer_name": "Independent acceptance evaluator",
        "idempotency_key": state.hashes["bootstrap_idempotency_sha256"],
    }
    runner.start(bootstrap_secret="bootstrap-material", token=None)
    assurance_payload = next(
        payload
        for method, path, _token, payload in product.calls
        if method == "POST" and path.endswith("/assurance-runs")
    )
    assert assurance_payload is not None
    assert "reviewer_service_identity_id" not in assurance_payload
    assert "reviewer_token_id" not in assurance_payload
    assert any("pull-requests/817/" in path for _method, path, _token, _payload in product.calls)
    assert any("pull-requests/818/" in path for _method, path, _token, _payload in product.calls)
    assert json.loads(product.upload_contents[0]) == {
        "checks": [{"name": "EXACT_HEAD_PROOF", "status": "PASSED"}],
        "head_sha": product.manual_heads[0],
        "schema_version": 1,
    }
    evidence_manifests = [
        payload
        for method, path, _token, payload in product.calls
        if method == "POST" and path.endswith("/evidence")
    ]
    assert evidence_manifests
    assert evidence_manifests[0] is not None
    assert evidence_manifests[0]["producer_version"] == __version__
    entries = cast(list[dict[str, object]], evidence_manifests[0]["entries"])
    assert entries[0]["producer_version"] == __version__


@pytest.mark.unit
def test_finalize_reuses_case_retrieval_canvas_and_all_public_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = deepcopy(EXAMPLES["acceptance-case"])
    change = cast(dict[str, object], case["change"])
    change["stale_probe"] = None
    head_commit = cast(str, change["head_commit"])
    _bind_case_evidence(case, head_commit)
    retrieval = cast(dict[str, object], case["retrieval"])
    retrieval.update(
        {
            "search_query": "distinct finalize retrieval",
            "search_phase": "BUILD",
            "search_limit": 7,
            "context_task": "Distinct finalize context task",
            "context_phase": "PREFLIGHT",
            "budget": {
                "max_items": 6,
                "max_tokens": 700,
                "max_bytes": 8_000,
                "max_citations": 9,
            },
        }
    )
    canvas_case = cast(dict[str, object], case["canvas"])
    canvas_case.update(
        {
            "layers": ["governance", "provenance"],
            "depth": 2,
            "node_limit": 71,
            "edge_limit": 83,
        }
    )
    runner, product = _runner(tmp_path, monkeypatch, case_payload=case)
    runner.start(bootstrap_secret="bootstrap-material", token=None)
    handoff_path = tmp_path / "handoff" / "review.json"
    runner.create_review_handoff(
        reviewer_token="reviewer-token-material",
        output=handoff_path,
    )
    result = deepcopy(EXAMPLES["evaluator-result"])
    result.update(
        {
            "request_id": product.request_id,
            "organization_id": _id(1),
            "commit_sha": head_commit,
            "completion": "COMPLETE",
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "findings": [],
            "limitations": ["External provider launch is intentionally out of process."],
            "evaluated_at": "2026-08-07T00:00:00Z",
        }
    )
    result_path = tmp_path / "external-result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    runner.submit_review(
        reviewer_token="reviewer-token-material",
        handoff_path=handoff_path,
        result_path=result_path,
    )

    complete = runner.finalize(
        token="initiator-token-material",
        mcp=FakeMCP(product),
    )

    assert complete.status == "COMPLETE"
    search_calls = [arguments for tool, arguments in product.mcp_calls if tool == "anva.search"]
    context_calls = [
        arguments for tool, arguments in product.mcp_calls if tool == "anva.get_context_packet"
    ]
    assert search_calls[-1]["query"] == retrieval["search_query"]
    assert search_calls[-1]["phase"] == retrieval["search_phase"]
    assert search_calls[-1]["limit"] == retrieval["search_limit"]
    assert context_calls[-1]["task"] == retrieval["context_task"]
    assert context_calls[-1]["phase"] == retrieval["context_phase"]
    assert context_calls[-1]["budget"] == retrieval["budget"]
    canvas_payloads = [
        payload
        for method, path, _token, payload in product.calls
        if method == "POST" and path == "/canvas/query"
    ]
    assert canvas_payloads[-1] == {
        "repository_ids": [_id(2)],
        "layers": canvas_case["layers"],
        "depth": canvas_case["depth"],
        "node_limit": canvas_case["node_limit"],
        "edge_limit": canvas_case["edge_limit"],
    }
    assert set(product.operation_ids) == set(ACCEPTANCE_HTTP_OPERATION_IDS)


@pytest.mark.unit
def test_case_source_path_must_exist_in_pinned_canonical_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = deepcopy(EXAMPLES["acceptance-case"])
    cast(dict[str, object], case["semantic_assertions"])["source_paths"] = [
        "organization/not-in-manifest.md"
    ]

    with pytest.raises(AcceptanceRunnerError, match="absent from the canonical manifest"):
        _runner(tmp_path, monkeypatch, case_payload=case)


@pytest.mark.unit
def test_secret_handoff_publication_is_atomic_and_restart_reconciles_pending(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "handoff"
    parent.mkdir(mode=0o700)
    path = parent / "review.json"
    pending = _secret_handoff_pending_path(path)
    payload: dict[str, object] = {"schema_version": 1, "opaque": "secret-material"}

    pending.write_bytes(b'{"schema_version":')
    pending.chmod(0o600)
    assert _recover_secret_handoff(path) is None
    assert not pending.exists()

    with patch("anva.acceptance.runner.os.link", side_effect=RuntimeError("pre-publish")):
        with pytest.raises(RuntimeError, match="pre-publish"):
            _write_secret_handoff(path, payload)
    assert not path.exists()
    assert not pending.exists()

    original_unlink = Path.unlink

    def crash_after_publish(target: Path, missing_ok: bool = False) -> None:
        if target == pending and path.exists():
            raise RuntimeError("post-publish")
        original_unlink(target, missing_ok=missing_ok)

    with patch.object(Path, "unlink", crash_after_publish):
        with pytest.raises(RuntimeError, match="post-publish"):
            _write_secret_handoff(path, payload)
    assert path.stat().st_ino == pending.stat().st_ino
    assert path.stat().st_nlink == 2

    assert _read_secret_handoff(path) == payload
    assert path.stat().st_nlink == 1
    assert not pending.exists()


@pytest.mark.unit
def test_secret_handoff_recovery_rejects_links_and_handles_owned_final_files(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "handoff"
    parent.mkdir(mode=0o700)
    path = parent / "review.json"
    pending = _secret_handoff_pending_path(path)
    payload: dict[str, object] = {"schema_version": 1, "opaque": "secret-material"}

    target = parent / "target"
    target.write_text("outside", encoding="utf-8")
    pending.symlink_to(target)
    with pytest.raises(AcceptanceRunnerError, match="pending path is unsafe"):
        _recover_secret_handoff(path)
    assert pending.is_symlink()
    pending.unlink()

    target.chmod(0o600)
    os.link(target, path)
    with pytest.raises(AcceptanceRunnerError, match="unsafe"):
        _recover_secret_handoff(path)
    assert path.exists() and target.exists()
    path.unlink()
    target.unlink()

    _write_secret_handoff(path, payload)
    original = path.read_bytes()
    with pytest.raises(AcceptanceRunnerError, match="must not already exist"):
        _write_secret_handoff(path, {"replacement": True})
    assert path.read_bytes() == original
    path.unlink()

    path.write_bytes(b'{"schema_version":')
    path.chmod(0o600)
    assert _recover_secret_handoff(path) is None
    assert not path.exists()


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
def test_completed_slow_sync_resumes_without_duplicate_mutation_through_finalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)
    runner.config = replace(runner.config, sync_timeout_seconds=30)
    clock = [0.0]
    polls = 0
    original_request = product.request

    def slow_sync(
        token: str | None,
        method: str,
        path: str,
        payload: dict[str, object] | None,
        content: bytes | None,
    ) -> APIResponse:
        nonlocal polls
        if path.endswith("/sync-runs") and polls < 41:
            polls += 1
            product.calls.append((method, path, token, payload))
            return APIResponse(200, {"sync_runs": [{"id": _id(5), "state": "PROCESSING"}]})
        return original_request(token, method, path, payload, content)

    product.request = slow_sync  # type: ignore[method-assign]
    monkeypatch.setattr("anva.acceptance.runner.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "anva.acceptance.runner.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    class FailFirstSearch:
        failed = False

        def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
            del arguments
            if tool_name == "anva.search" and not self.failed:
                self.failed = True
                raise AcceptanceBoundaryError("mcp_unavailable", "CANARY-SECRET")
            return FakeMCP(product).call(tool_name, {})

    boundary = FailFirstSearch()
    monkeypatch.setattr(
        "anva.acceptance.runner.StreamableHTTPMCP",
        lambda _url, _token: boundary,
    )
    with pytest.raises(AcceptanceBoundaryError, match="CANARY"):
        runner.start(bootstrap_secret="bootstrap-material", token=None)

    checkpoint = load_state(runner.config.state_path)
    assert checkpoint.status == "PREPARING"
    assert checkpoint.identities["source_connection_id"] == _id(4)
    assert checkpoint.identities["sync_run_id"] == _id(5)
    assert clock[0] > 20
    mutations_before_resume = [
        (method, path) for method, path, _token, _payload in product.calls if method == "POST"
    ]
    assert mutations_before_resume.count(("POST", "/source-connections/filesystem")) == 1
    assert mutations_before_resume.count(("POST", f"/source-connections/{_id(4)}/sync")) == 1
    diagnostic = json.loads(
        (runner.config.state_path.parent / "operator-diagnostic.json").read_bytes()
    )
    assert diagnostic == {
        "schema_version": 1,
        "status": "FAILED",
        "run_id": checkpoint.run_id,
        "stage": "retrieval_search",
        "reason_code": "boundary_unavailable",
    }
    assert b"CANARY-SECRET" not in json.dumps(diagnostic).encode()

    awaiting = runner.start(bootstrap_secret=None, token="initiator-token-material")
    assert awaiting.status == "AWAITING_EXTERNAL_REVIEW"
    mutations_after_resume = [
        (method, path) for method, path, _token, _payload in product.calls if method == "POST"
    ]
    assert mutations_after_resume.count(("POST", "/source-connections/filesystem")) == 1
    assert mutations_after_resume.count(("POST", f"/source-connections/{_id(4)}/sync")) == 1
    assert mutations_after_resume.count(("POST", "/work-items/import")) == 1
    assert mutations_after_resume.count(("POST", "/policies/import")) == 1
    assert mutations_after_resume.count(("POST", "/policies/simulate")) == 1
    assert sum(path.endswith("/evidence") for _method, path in mutations_after_resume) == 1
    assert sum(path.endswith("/assurance-runs") for _method, path in mutations_after_resume) == 2

    handoff_path = tmp_path / "handoff" / "review.json"
    runner.create_review_handoff(
        reviewer_token="reviewer-token-material",
        output=handoff_path,
    )
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
            "limitations": [],
            "evaluated_at": "2026-08-07T00:00:00Z",
        }
    )
    result_path = tmp_path / "external-result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    runner.submit_review(
        reviewer_token="reviewer-token-material",
        handoff_path=handoff_path,
        result_path=result_path,
    )
    assert (
        runner.finalize(token="initiator-token-material", mcp=FakeMCP(product)).status == "COMPLETE"
    )


@pytest.mark.unit
@pytest.mark.parametrize("token", ["wrong-token", "expired-token", "reused-token"])
def test_preparing_resume_rejects_invalid_tokens_without_mutation_or_secret_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    token: str,
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)
    state = runner._new_state(reference_time="2026-08-07T00:10:00Z")
    state.status = "PREPARING"
    state.identities.update(
        {
            "organization_id": _id(1),
            "repository_id": _id(2),
            "access_scope_id": _id(3),
            "source_connection_id": _id(4),
            "sync_run_id": _id(5),
            "reviewer_service_identity_id": _id(8),
            "reviewer_token_id": _id(9),
        }
    )
    save_state(runner.config.state_path, state)

    with pytest.raises(AcceptanceBoundaryError):
        runner.start(bootstrap_secret=None, token=token)

    assert not [call for call in product.calls if call[0] == "POST"]
    diagnostic_bytes = (runner.config.state_path.parent / "operator-diagnostic.json").read_bytes()
    assert token.encode() not in diagnostic_bytes
    assert b"secret" not in diagnostic_bytes.lower()
    assert json.loads(diagnostic_bytes) == {
        "schema_version": 1,
        "status": "FAILED",
        "run_id": state.run_id,
        "stage": "source_sync_wait",
        "reason_code": "authorization_rejected",
        "boundary_status": 401,
    }


@pytest.mark.unit
def test_diagnostic_io_failure_preserves_original_sanitizable_boundary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, _product = _runner(tmp_path, monkeypatch)

    class UnavailableMCP:
        def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
            del tool_name, arguments
            raise AcceptanceBoundaryError("mcp_unavailable", "PRIVATE-CANARY")

    monkeypatch.setattr(
        "anva.acceptance.runner.StreamableHTTPMCP",
        lambda _url, _token: UnavailableMCP(),
    )
    with (
        patch(
            "anva.acceptance.runner._write_operator_diagnostic",
            side_effect=OSError("PRIVATE-DIAGNOSTIC-CANARY"),
        ),
        pytest.raises(AcceptanceBoundaryError, match="PRIVATE-CANARY") as captured,
    ):
        runner.start(bootstrap_secret="bootstrap-material", token=None)

    assert captured.value.code == "mcp_unavailable"


@pytest.mark.unit
def test_operator_diagnostics_distinguish_sync_timeout_and_semantic_assertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeout_root = tmp_path / "timeout"
    timeout_root.mkdir()
    timeout_runner, timeout_product = _runner(timeout_root, monkeypatch)
    original_timeout_request = timeout_product.request

    def processing(
        token: str | None,
        method: str,
        path: str,
        payload: dict[str, object] | None,
        content: bytes | None,
    ) -> APIResponse:
        if path.endswith("/sync-runs"):
            timeout_product.calls.append((method, path, token, payload))
            return APIResponse(200, {"sync_runs": [{"id": _id(5), "state": "PROCESSING"}]})
        return original_timeout_request(token, method, path, payload, content)

    timeout_product.request = processing  # type: ignore[method-assign]
    clock = [0.0]
    monkeypatch.setattr("anva.acceptance.runner.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "anva.acceptance.runner.time.sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )
    with pytest.raises(AcceptanceRunnerError, match="did not complete"):
        timeout_runner.start(bootstrap_secret="bootstrap-material", token=None)
    timeout_diagnostic = json.loads(
        (timeout_runner.config.state_path.parent / "operator-diagnostic.json").read_bytes()
    )
    assert (timeout_diagnostic["stage"], timeout_diagnostic["reason_code"]) == (
        "source_sync_wait",
        "sync_timeout",
    )

    semantic_root = tmp_path / "semantic"
    semantic_root.mkdir()
    semantic_runner, _semantic_product = _runner(semantic_root, monkeypatch)

    class EmptyMCP:
        def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
            del arguments
            if tool_name == "anva.search":
                return {
                    "contract_version": "1",
                    "tool": "anva.search",
                    "data": {"results": []},
                    "next_cursor": None,
                }
            return FakeMCP().call(tool_name, {})

    monkeypatch.setattr(
        "anva.acceptance.runner.StreamableHTTPMCP",
        lambda _url, _token: EmptyMCP(),
    )
    with pytest.raises(AcceptanceRunnerError, match="not retrievable"):
        semantic_runner.start(bootstrap_secret="bootstrap-material", token=None)
    semantic_diagnostic = json.loads(
        (semantic_runner.config.state_path.parent / "operator-diagnostic.json").read_bytes()
    )
    assert (semantic_diagnostic["stage"], semantic_diagnostic["reason_code"]) == (
        "semantic_assertions",
        "semantic_assertion_failed",
    )


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


@pytest.mark.unit
def test_bootstrap_crash_after_server_commit_recovers_exact_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)

    def leave_partial_handoff(path: Path, _payload: dict[str, object]) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b'{"schema_version":')
        path.chmod(0o600)
        raise RuntimeError("injected crash after bootstrap commit")

    with patch(
        "anva.acceptance.runner._write_secret_handoff",
        side_effect=leave_partial_handoff,
    ):
        with pytest.raises(RuntimeError, match="injected crash"):
            runner.start(bootstrap_secret="bootstrap-material", token=None)
    assert load_state(runner.config.state_path).status == "BOOTSTRAP_PREPARED"
    assert runner.config.credential_output is not None
    assert runner.config.credential_output.is_file()

    resumed = AcceptanceRunner(runner.config).start(
        bootstrap_secret="bootstrap-material", token=None
    )
    assert resumed.status == "AWAITING_EXTERNAL_REVIEW"
    assert sum(path == "/bootstrap" for _method, path, _token, _body in product.calls) == 2


@pytest.mark.unit
@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update({"bootstrap_mode": "LEGACY"}),
        lambda payload: payload.pop("reviewer_service_identity_id"),
        lambda payload: payload.pop("reviewer_token_id"),
        lambda payload: payload.pop("reviewer_token"),
        lambda payload: payload.pop("reviewer_expires_at"),
    ],
)
def test_runner_rejects_wrong_mode_or_incomplete_scoped_bootstrap_before_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: Callable[[dict[str, object]], object],
) -> None:
    runner, product = _runner(
        tmp_path,
        monkeypatch,
        case_payload=deepcopy(EXAMPLES["acceptance-case"]),
    )
    original_request = product.request

    def malformed_bootstrap(
        token: str | None,
        method: str,
        path: str,
        payload: dict[str, object] | None,
        content: bytes | None,
    ) -> APIResponse:
        response = original_request(token, method, path, payload, content)
        if path != "/bootstrap":
            return response
        malformed = deepcopy(response.payload)
        mutation(malformed)
        return APIResponse(response.status, malformed)

    monkeypatch.setattr(product, "request", malformed_bootstrap)

    with pytest.raises(AcceptanceRunnerError, match="mode|required identity"):
        runner.start(bootstrap_secret="bootstrap-material", token=None)
    assert load_state(runner.config.state_path).status == "BOOTSTRAP_PREPARED"
    assert runner.config.credential_output is not None
    assert not runner.config.credential_output.exists()


@pytest.mark.unit
def test_bootstrap_crash_after_handoff_reconciles_without_second_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)
    original_save = AcceptanceRunner._save
    crashed = False

    def crash_after_handoff(self: AcceptanceRunner, state: ResumeState) -> None:
        nonlocal crashed
        if getattr(state, "status", None) == "PREPARING" and not crashed:
            crashed = True
            raise RuntimeError("injected crash after credential handoff")
        original_save(self, state)

    with patch.object(AcceptanceRunner, "_save", crash_after_handoff):
        with pytest.raises(RuntimeError, match="injected crash"):
            runner.start(bootstrap_secret="bootstrap-material", token=None)
    assert load_state(runner.config.state_path).status == "BOOTSTRAP_PREPARED"
    assert runner.config.credential_output is not None
    assert runner.config.credential_output.is_file()

    resumed = AcceptanceRunner(runner.config).start(bootstrap_secret=None, token=None)
    assert resumed.status == "AWAITING_EXTERNAL_REVIEW"
    assert resumed.identities["reviewer_service_identity_id"] == _id(8)
    assert resumed.identities["reviewer_token_id"] == _id(9)
    assert sum(path == "/bootstrap" for _method, path, _token, _body in product.calls) == 1


@pytest.mark.unit
def test_review_and_finalize_crash_boundaries_are_restart_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, product = _runner(tmp_path, monkeypatch)
    runner.start(bootstrap_secret="bootstrap-material", token=None)
    handoff_path = tmp_path / "handoff" / "review.json"

    def leave_partial_handoff(path: Path, _payload: dict[str, object]) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b'{"schema_version":')
        path.chmod(0o600)
        raise RuntimeError("injected crash after claim")

    with patch(
        "anva.acceptance.runner._write_secret_handoff",
        side_effect=leave_partial_handoff,
    ):
        with pytest.raises(RuntimeError, match="injected crash"):
            runner.create_review_handoff(
                reviewer_token="reviewer-token-material", output=handoff_path
            )
    assert load_state(runner.config.state_path).status == "REVIEW_CLAIMING"
    assert handoff_path.is_file()
    original_save = AcceptanceRunner._save
    handoff_state_crashed = False

    def crash_after_review_handoff(self: AcceptanceRunner, state: ResumeState) -> None:
        nonlocal handoff_state_crashed
        if state.status == "REVIEW_CLAIMED" and not handoff_state_crashed:
            handoff_state_crashed = True
            raise RuntimeError("injected crash after review handoff")
        original_save(self, state)

    with patch.object(AcceptanceRunner, "_save", crash_after_review_handoff):
        with pytest.raises(RuntimeError, match="injected crash"):
            runner.create_review_handoff(
                reviewer_token="reviewer-token-material", output=handoff_path
            )
    assert handoff_path.is_file()
    assert load_state(runner.config.state_path).status == "REVIEW_CLAIMING"
    runner.create_review_handoff(reviewer_token="reviewer-token-material", output=handoff_path)
    claim_payloads = [
        body
        for _method, path, _token, body in product.calls
        if path.endswith("/evaluator-tasks/claim")
    ]
    assert len(claim_payloads) == 2
    assert claim_payloads[0] == claim_payloads[1]

    handoff = json.loads(handoff_path.read_bytes())
    assert handoff["reviewer_service_identity_id"] == _id(8)
    assert handoff["reviewer_token_id"] == _id(9)
    claimed_state = load_state(runner.config.state_path)
    assert (
        claimed_state.hashes["review_claim_idempotency_sha256"]
        == hashlib.sha256(
            (f"review-claim:{claimed_state.run_id}:{_id(35)}:{_id(8)}:{_id(9)}").encode()
        ).hexdigest()
    )
    result_path = tmp_path / "external-result.json"
    result = deepcopy(EXAMPLES["evaluator-result"])
    result.update(
        {
            "request_id": cast(dict[str, object], handoff["request"])["request_id"],
            "organization_id": _id(1),
            "commit_sha": product.manual_heads[0],
            "completion": "COMPLETE",
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "findings": [],
            "limitations": [],
            "evaluated_at": "2026-08-07T00:00:00Z",
        }
    )
    result_path.write_text(json.dumps(result), encoding="utf-8")
    original_save = AcceptanceRunner._save
    crashed = False

    def crash_after_submit(self: AcceptanceRunner, state: ResumeState) -> None:
        nonlocal crashed
        if getattr(state, "status", None) == "EXTERNAL_REVIEW_SUBMITTED" and not crashed:
            crashed = True
            raise RuntimeError("injected crash after review submission")
        original_save(self, state)

    with patch.object(AcceptanceRunner, "_save", crash_after_submit):
        with pytest.raises(RuntimeError, match="injected crash"):
            runner.submit_review(
                reviewer_token="reviewer-token-material",
                handoff_path=handoff_path,
                result_path=result_path,
            )
    assert load_state(runner.config.state_path).status == "REVIEW_SUBMITTING"
    submitted = AcceptanceRunner(runner.config).submit_review(
        reviewer_token="reviewer-token-material",
        handoff_path=handoff_path,
        result_path=result_path,
    )
    assert submitted.status == "EXTERNAL_REVIEW_SUBMITTED"

    original_save = AcceptanceRunner._save
    with patch.object(
        AcceptanceRunner,
        "_save",
        side_effect=lambda state: (
            (_ for _ in ()).throw(RuntimeError("injected crash after seal"))
            if state.status == "COMPLETE"
            else original_save(runner, state)
        ),
    ):
        with pytest.raises(RuntimeError, match="injected crash"):
            runner.finalize(token="initiator-token-material", mcp=FakeMCP())
    assert load_state(runner.config.state_path).status == "EXTERNAL_REVIEW_SUBMITTED"
    calls_before_adoption = len(product.calls)
    complete = AcceptanceRunner(runner.config).finalize(token="initiator-token-material")
    assert complete.status == "COMPLETE"
    assert len(product.calls) == calls_before_adoption
    assert len(product.operation_ids) == len(product.calls)
    assert {
        "getAssuranceRun",
        "queryOrganizationalCanvas",
        "listAssuranceFindings",
        "getAssuranceReport",
        "claimManualEvaluatorTask",
        "submitManualEvaluatorResult",
    } <= set(product.operation_ids)

    metadata = runner.config.output_root / "results" / "run-metadata.json"
    metadata.chmod(0o600)
    metadata.write_bytes(metadata.read_bytes() + b" ")
    metadata.chmod(0o400)
    with pytest.raises(AcceptanceExportError, match="checksum"):
        AcceptanceRunner(runner.config).finalize(token="initiator-token-material")
    assert load_state(runner.config.state_path).hashes["sealed_manifest_sha256"]


@pytest.mark.unit
@pytest.mark.parametrize("claimed_by_field", ["actor_id", "credential_id"])
def test_review_claim_must_match_bootstrap_reviewer_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claimed_by_field: str,
) -> None:
    runner, product = _runner(
        tmp_path,
        monkeypatch,
        case_payload=deepcopy(EXAMPLES["acceptance-case"]),
    )
    runner.start(bootstrap_secret="bootstrap-material", token=None)
    original_request = product.request

    def mismatched_claim(
        token: str | None,
        method: str,
        path: str,
        payload: dict[str, object] | None,
        content: bytes | None,
    ) -> APIResponse:
        response = original_request(token, method, path, payload, content)
        if not path.endswith("/evaluator-tasks/claim"):
            return response
        malformed = deepcopy(response.payload)
        claimed_by = cast(dict[str, object], malformed["claimed_by"])
        claimed_by[claimed_by_field] = _id(99)
        return APIResponse(response.status, malformed)

    monkeypatch.setattr(product, "request", mismatched_claim)
    handoff_path = tmp_path / "handoff" / "mismatched.json"
    with pytest.raises(AcceptanceRunnerError, match="wrong credential"):
        runner.create_review_handoff(
            reviewer_token="reviewer-token-material",
            output=handoff_path,
        )
    assert load_state(runner.config.state_path).status == "REVIEW_CLAIMING"
    assert not handoff_path.exists()
