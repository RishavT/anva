"""Externally visible HTTP contract tests."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.http import HttpRequest, JsonResponse
from django.test import Client, RequestFactory
from starlette.testclient import TestClient

from anva.contracts.acceptance import validate_acceptance_http_response
from anva.core import views as core_views
from anva.core.exceptions import AuthenticationError, IdempotencyConflictError
from anva.entrypoints.mcp import create_application
from anva.foundation.services import DependencyStatus, ReadinessStatus


@pytest.mark.contract
def test_api_liveness_contract(client: Client) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert set(response.json()) == {"status", "version"}
    assert response.json()["status"] == "alive"


@pytest.mark.contract
def test_api_readiness_contract(client: Client, ready_dependencies: None) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": [
            {"name": "database", "healthy": True, "detail": "available"},
            {"name": "migrations", "healthy": True, "detail": "current"},
            {"name": "object_storage", "healthy": True, "detail": "available"},
        ],
    }


@pytest.mark.contract
def test_api_health_endpoints_reject_unsupported_methods(client: Client) -> None:
    assert client.post("/health/live").status_code == 405
    assert client.post("/health/ready").status_code == 405


@pytest.mark.contract
def test_retention_http_uses_server_owned_reference_time(client: Client) -> None:
    organization_id = uuid.uuid4()
    actor = SimpleNamespace(organization_id=organization_id)
    completed_at = datetime(2026, 8, 4, tzinfo=UTC)
    run_record = SimpleNamespace(
        id=uuid.uuid4(),
        kind="SCHEDULED_RETENTION",
        state="COMPLETED",
        dry_run=True,
        cutoff_at=completed_at,
        summary={},
        completed_at=completed_at,
    )

    with (
        patch("anva.core.views._actor", return_value=actor),
        patch("anva.core.views.run_retention", return_value=run_record) as run_retention,
    ):
        rejected = client.post(
            f"/api/v1/organizations/{organization_id}/retention-runs",
            data=json.dumps(
                {
                    "dry_run": True,
                    "reference_time": "2099-01-01T00:00:00Z",
                }
            ),
            content_type="application/json",
        )
        accepted = client.post(
            f"/api/v1/organizations/{organization_id}/retention-runs",
            data=json.dumps({"dry_run": True}),
            content_type="application/json",
        )

    assert rejected.status_code == 400
    assert accepted.status_code == 201
    run_retention.assert_called_once_with(actor=actor, dry_run=True)


def call_mcp(path: str, method: str = "GET") -> tuple[int, dict[str, object]]:
    """Invoke the MCP ASGI contract through an in-process HTTP client."""
    with TestClient(create_application()) as client:
        response = client.request(method, path)
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.status_code, response.json()
    return response.status_code, {"detail": response.text}


@pytest.mark.contract
def test_mcp_requires_bearer_authentication_before_protocol_work() -> None:
    status, payload = call_mcp("/mcp")

    assert status == 401
    assert payload["error"] == "invalid_token"


@pytest.mark.contract
def test_mcp_liveness_contract() -> None:
    status, payload = call_mcp("/health/live")

    assert status == 200
    assert payload["service"] == "mcp"
    assert payload["status"] == "alive"


@pytest.mark.contract
@pytest.mark.parametrize(
    ("healthy", "expected_http"),
    [(True, 200), (False, 503)],
)
def test_mcp_readiness_contract(healthy: bool, expected_http: int) -> None:
    dependency = DependencyStatus("database", healthy, "available" if healthy else "unavailable")
    readiness = ReadinessStatus("ready" if healthy else "not_ready", (dependency,))

    with patch("anva.foundation.services.readiness_status", return_value=readiness):
        status, payload = call_mcp("/health/ready")

    assert status == expected_http
    assert payload["status"] == readiness.status


@pytest.mark.contract
def test_mcp_rejects_unknown_routes_and_methods() -> None:
    assert call_mcp("/missing")[0] == 404
    assert call_mcp("/health/live", "POST")[0] == 405


@pytest.mark.contract
def test_source_lifecycle_http_contracts(client: Client) -> None:
    source_id = uuid.uuid4()
    run_id = uuid.uuid4()
    repository_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    source = SimpleNamespace(id=source_id, state="ACTIVE", revision=1)
    run = SimpleNamespace(
        id=run_id,
        source_connection_id=source_id,
        access_snapshot_id=uuid.uuid4(),
        scan_mode="FULL",
        state="REQUESTED",
    )
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.views.connect_filesystem_source",
            return_value=(source, True),
        ) as connect,
        patch(
            "anva.core.views.request_ingestion_sync",
            return_value=(run, True),
        ) as sync,
        patch(
            "anva.core.views.inspect_source",
            return_value={"id": str(source_id), "state": "ACTIVE"},
        ),
        patch(
            "anva.core.views.source_sync_runs",
            return_value=[
                {
                    "id": str(run_id),
                    "state": "REQUESTED",
                    "scan_mode": "FULL",
                    "discovered_count": 0,
                    "processed_count": 0,
                    "failed_count": 0,
                    "tombstoned_count": 0,
                    "failure_code": "",
                    "started_at": "2026-08-10T12:00:00Z",
                    "completed_at": None,
                }
            ],
        ),
    ):
        connected = client.post(
            "/api/v1/source-connections/filesystem",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "access_scope_id": str(scope_id),
                    "external_key": "fixture",
                    "display_name": "Fixture",
                    "root": "/fixtures/anva-test",
                }
            ),
            content_type="application/json",
        )
        requested = client.post(
            f"/api/v1/source-connections/{source_id}/sync",
            data=json.dumps({"scan_mode": "FULL"}),
            content_type="application/json",
        )
        run.state = "PARSING"
        sync.return_value = (run, False)
        replayed = client.post(
            f"/api/v1/source-connections/{source_id}/sync",
            data=json.dumps({"scan_mode": "FULL"}),
            content_type="application/json",
        )
        inspected = client.get(f"/api/v1/source-connections/{source_id}")
        history = client.get(f"/api/v1/source-connections/{source_id}/sync-runs")
        invalid_connected = client.post(
            "/api/v1/source-connections/filesystem",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "access_scope_id": str(scope_id),
                    "external_key": "fixture",
                    "display_name": "Fixture",
                    "root": "/fixtures/anva-test",
                    "credential": "must-not-cross-boundary",
                }
            ),
            content_type="application/json",
        )
        invalid_sync = client.post(
            f"/api/v1/source-connections/{source_id}/sync",
            data=json.dumps({"scan_mode": "FULL", "unexpected": True}),
            content_type="application/json",
        )

    assert connected.status_code == 201
    assert connected.json()["created"] is True
    assert requested.status_code == 202
    assert requested.json()["access_snapshot_id"] == str(run.access_snapshot_id)
    assert replayed.status_code == 202
    assert replayed.json()["state"] == "PARSING"
    assert replayed.json()["created"] is False
    assert inspected.json() == {"id": str(source_id), "state": "ACTIVE"}
    assert history.json()["sync_runs"][0]["id"] == str(run_id)
    assert invalid_connected.status_code == invalid_sync.status_code == 400
    validate_acceptance_http_response("connectFilesystemSource", 201, connected.json())
    validate_acceptance_http_response("syncSourceConnection", 202, requested.json())
    validate_acceptance_http_response("syncSourceConnection", 202, replayed.json())
    validate_acceptance_http_response("listSourceSyncRuns", 200, history.json())
    assert connect.call_args.kwargs["root"] == "/fixtures/anva-test"
    assert connect.call_count == 1
    assert sync.call_args.kwargs["scan_mode"] == "FULL"
    assert sync.call_count == 2


@pytest.mark.contract
def test_source_lifecycle_rejects_unsupported_methods(client: Client) -> None:
    source_id = uuid.uuid4()
    assert client.get("/api/v1/source-connections/filesystem").status_code == 405
    assert client.get(f"/api/v1/source-connections/{source_id}/sync").status_code == 405
    assert client.get(f"/api/v1/source-connections/{source_id}/resync").status_code == 405


@pytest.mark.contract
def test_governance_http_creation_simulation_and_submission_contracts(
    client: Client,
) -> None:
    work_id = uuid.uuid4()
    work_revision_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    policy_version_id = uuid.uuid4()
    evaluation_id = uuid.uuid4()
    manifest_id = uuid.uuid4()
    repository_id = uuid.uuid4()
    work_result = SimpleNamespace(
        work_item=SimpleNamespace(id=work_id),
        work_item_revision=SimpleNamespace(
            id=work_revision_id,
            revision=1,
            content_hash="a" * 64,
        ),
        created=True,
    )
    policy_result = SimpleNamespace(
        policy=SimpleNamespace(id=policy_id),
        policy_version=SimpleNamespace(
            id=policy_version_id,
            version=1,
            content_hash="b" * 64,
        ),
        created=True,
    )
    evaluation = SimpleNamespace(
        id=evaluation_id,
        input_hash="c" * 64,
        output_hash="d" * 64,
        output_payload={"outcome": "CONTROLS_CALCULATED", "controls": []},
    )
    manifest_result = SimpleNamespace(
        manifest=SimpleNamespace(id=manifest_id, payload_hash="e" * 64),
        evidence=(SimpleNamespace(id=uuid.uuid4()),),
        created=True,
    )
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch("anva.core.views.import_work_item", return_value=work_result),
        patch("anva.core.views.import_policy", return_value=policy_result),
        patch("anva.core.views.evaluate_policy", return_value=(evaluation, True)),
        patch(
            "anva.core.views.submit_evidence_manifest",
            return_value=manifest_result,
        ),
    ):
        work = client.post(
            "/api/v1/work-items/import",
            data=json.dumps({"schema_version": "1.0"}),
            content_type="application/json",
        )
        policy = client.post(
            "/api/v1/policies/import",
            data=json.dumps({"schema_version": "1.0"}),
            content_type="application/json",
        )
        simulation = client.post(
            "/api/v1/policies/simulate",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "pull_request_number": 17,
                    "commit_sha": "a" * 40,
                    "policy_version_ids": [str(policy_version_id)],
                    "reference_time": "2026-07-28T00:00:00Z",
                    "affected_paths": [],
                    "affected_entities": [],
                    "target_branch": "main",
                }
            ),
            content_type="application/json",
        )
        invalid_simulation = client.post(
            "/api/v1/policies/simulate",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "pull_request_number": 17,
                    "commit_sha": "a" * 40,
                    "policy_version_ids": [str(policy_version_id)],
                    "reference_time": "2026-07-28T00:00:00Z",
                    "affected_paths": [],
                    "affected_entities": [],
                    "target_branch": "main",
                    "unexpected": "must be rejected",
                }
            ),
            content_type="application/json",
        )
        evidence = client.post(
            f"/api/v1/repositories/{repository_id}/pull-requests/17/evidence",
            data=json.dumps({"schema_version": "1.0"}),
            content_type="application/json",
        )

    assert work.status_code == policy.status_code == simulation.status_code == 201
    assert evidence.status_code == 201
    assert invalid_simulation.status_code == 400
    assert work.json()["work_item_revision_id"] == str(work_revision_id)
    assert policy.json()["policy_version_id"] == str(policy_version_id)
    assert simulation.json()["output"]["outcome"] == "CONTROLS_CALCULATED"
    assert evidence.json()["manifest_id"] == str(manifest_id)
    validate_acceptance_http_response("importWorkItemRevision", 201, work.json())
    validate_acceptance_http_response("importPolicyVersion", 201, policy.json())
    validate_acceptance_http_response("simulatePolicy", 201, simulation.json())
    validate_acceptance_http_response("submitEvidenceManifest", 201, evidence.json())


@pytest.mark.contract
def test_governance_http_rejects_oversized_body_and_unsupported_methods(
    client: Client,
) -> None:
    response = client.post(
        "/api/v1/work-items/import",
        data=json.dumps({"payload": "x" * (64 * 1024)}),
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"
    assert client.get("/api/v1/work-items/import").status_code == 405
    assert client.get("/api/v1/policies/simulate").status_code == 405


@pytest.mark.contract
def test_criterion_mapping_http_replay_status_and_closed_body(client: Client) -> None:
    revision_id = uuid.uuid4()
    repository_id = uuid.uuid4()
    payload = {
        "repository_id": str(repository_id),
        "pull_request_number": 17,
        "commit_sha": "a" * 40,
        "reference_time": "2026-07-28T00:00:00Z",
    }
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.views.map_criterion_evidence",
            return_value=SimpleNamespace(mappings=(), created=False),
        ),
    ):
        replay = client.post(
            f"/api/v1/work-item-revisions/{revision_id}/evidence-map",
            data=json.dumps(payload),
            content_type="application/json",
        )
        invalid = client.post(
            f"/api/v1/work-item-revisions/{revision_id}/evidence-map",
            data=json.dumps(payload | {"unexpected": True}),
            content_type="application/json",
        )

    assert replay.status_code == 200
    assert invalid.status_code == 400


@pytest.mark.contract
def test_governance_approval_override_and_mapping_http_responses(client: Client) -> None:
    repository_id = uuid.uuid4()
    revision_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    policy_version_id = uuid.uuid4()
    policy_evaluation_id = uuid.uuid4()
    override_id = uuid.uuid4()
    reference_time = datetime(2026, 7, 28, tzinfo=UTC)
    approval = SimpleNamespace(
        id=approval_id,
        work_item_revision_id=revision_id,
        status="APPROVED",
    )
    approval_revocation = SimpleNamespace(id=uuid.uuid4(), approval_id=approval_id)
    override = SimpleNamespace(
        id=override_id,
        policy_version_id=policy_version_id,
        commit_sha="a" * 40,
    )
    override_revocation = SimpleNamespace(
        id=uuid.uuid4(),
        policy_override_id=override_id,
    )
    mapping = SimpleNamespace(
        id=uuid.uuid4(),
        criterion_id=uuid.uuid4(),
        evidence_id=uuid.uuid4(),
        required_evidence_type="TEST_RESULT",
        pull_request_number=17,
        reference_time=reference_time,
        engine_version="criterion-evidence-v1",
        input_hash="b" * 64,
        assessment="SATISFIED",
        classification="DIRECT",
        gap_code="",
        gap_description="",
    )
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch("anva.core.views.authorize_action"),
        patch(
            "anva.core.views.approve_work_item_revision",
            return_value=(approval, True),
        ),
        patch(
            "anva.core.views.revoke_work_item_approval",
            return_value=(approval_revocation, False),
        ),
        patch(
            "anva.core.views.create_policy_override",
            return_value=(override, True),
        ),
        patch(
            "anva.core.views.revoke_policy_override",
            return_value=(override_revocation, False),
        ),
        patch(
            "anva.core.views.map_criterion_evidence",
            return_value=SimpleNamespace(mappings=(mapping,), created=True),
        ),
    ):
        approval_response = client.post(
            f"/api/v1/work-item-revisions/{revision_id}/approvals",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "status": "APPROVED",
                    "target_kind": "WORK_ITEM_REVISION",
                    "target_key": str(revision_id),
                    "reason": "Approved.",
                    "expires_at": "2026-07-29T00:00:00Z",
                }
            ),
            content_type="application/json",
        )
        approval_revoke_response = client.post(
            f"/api/v1/work-approvals/{approval_id}/revoke",
            data=json.dumps({"repository_id": str(repository_id), "reason": "Withdrawn."}),
            content_type="application/json",
        )
        override_response = client.post(
            f"/api/v1/policies/{policy_id}/override",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "policy_evaluation_id": str(policy_evaluation_id),
                    "policy_version_id": str(policy_version_id),
                    "requirement_code": "TESTS_PASS",
                    "pull_request_number": 17,
                    "commit_sha": "a" * 40,
                    "reason": "Authorized exception.",
                    "expires_at": "2026-07-29T00:00:00Z",
                }
            ),
            content_type="application/json",
        )
        override_revoke_response = client.post(
            f"/api/v1/policy-overrides/{override_id}/revoke",
            data=json.dumps({"repository_id": str(repository_id), "reason": "Withdrawn."}),
            content_type="application/json",
        )
        mapping_response = client.post(
            f"/api/v1/work-item-revisions/{revision_id}/evidence-map",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "pull_request_number": 17,
                    "commit_sha": "a" * 40,
                    "reference_time": reference_time.isoformat(),
                }
            ),
            content_type="application/json",
        )

    assert approval_response.status_code == override_response.status_code == 201
    assert approval_revoke_response.status_code == override_revoke_response.status_code == 200
    assert mapping_response.status_code == 201
    assert mapping_response.json()["mappings"][0]["evidence_id"] == str(mapping.evidence_id)


@pytest.mark.contract
def test_governance_detail_http_responses(client: Client) -> None:
    organization_id = uuid.uuid4()
    repository_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    work_id = uuid.uuid4()
    policy_id = uuid.uuid4()
    manifest_id = uuid.uuid4()
    work = SimpleNamespace(
        id=work_id,
        repository_id=repository_id,
        access_scope_id=scope_id,
        revision=2,
        status="READY",
    )
    work_revision = SimpleNamespace(
        content_hash="a" * 64,
        normalized_payload={"title": "governed"},
    )
    policy_version = SimpleNamespace(
        id=uuid.uuid4(),
        version=3,
        content_hash="b" * 64,
        definition={"status": "ACTIVE"},
    )
    policy = SimpleNamespace(
        id=policy_id,
        access_scope_id=scope_id,
        revision=3,
        status="ACTIVE",
        policyversion_set=SimpleNamespace(get=lambda **_kwargs: policy_version),
    )
    manifest = SimpleNamespace(
        id=manifest_id,
        repository_id=repository_id,
        access_scope_id=scope_id,
        pull_request_number=17,
        commit_sha="c" * 40,
        payload_hash="d" * 64,
        artifact=SimpleNamespace(payload={"schema_version": "1.0"}),
    )
    with (
        patch(
            "anva.core.views._actor",
            return_value=SimpleNamespace(organization_id=organization_id),
        ),
        patch("anva.core.views.authorize_action"),
        patch(
            "anva.core.views.get_tenant_record",
            side_effect=[work, policy, manifest],
        ),
        patch(
            "anva.core.views.WorkItemRevision.objects.get",
            return_value=work_revision,
        ),
    ):
        work_response = client.get(f"/api/v1/work-items/{work_id}")
        policy_response = client.get(f"/api/v1/policies/{policy_id}?repository_id={repository_id}")
        manifest_response = client.get(f"/api/v1/evidence-manifests/{manifest_id}")

    assert work_response.json()["intent"]["title"] == "governed"
    assert policy_response.json()["version"] == 3
    assert manifest_response.json()["manifest"]["schema_version"] == "1.0"
    validate_acceptance_http_response("getEvidenceManifest", 200, manifest_response.json())


@pytest.mark.contract
def test_http_parser_and_structured_error_branches() -> None:
    factory = RequestFactory()
    invalid_correlation = factory.get("/", HTTP_X_CORRELATION_ID="not-a-uuid")
    assert core_views._correlation_id(invalid_correlation).version == 4

    list_body = factory.post(
        "/",
        data=json.dumps(["not", "an", "object"]),
        content_type="application/json",
    )
    with pytest.raises(ValueError, match="object"):
        core_views._json_body(list_body)
    for operation in (
        lambda: core_views._string({"value": 1}, "value"),
        lambda: core_views._integer({"value": True}, "value"),
        lambda: core_views._optional_string({"value": ""}, "value"),
        lambda: core_views._optional_integer({"value": False}, "value", 1),
        lambda: core_views._date_time({"value": "2026-07-28"}, "value"),
        lambda: core_views._string_list({"value": [1]}, "value"),
        lambda: core_views._object_list({"value": "not-a-list"}, "value"),
        lambda: core_views._object_list(
            {"value": [{"id": str(uuid.uuid4()), "wrong": "SERVICE"}]},
            "value",
        ),
    ):
        with pytest.raises(ValueError):
            operation()

    def raise_authentication(_request: HttpRequest) -> JsonResponse:
        raise AuthenticationError("invalid")

    def raise_conflict(_request: HttpRequest) -> JsonResponse:
        raise IdempotencyConflictError("conflict")

    auth_response = core_views.api_errors(raise_authentication)(factory.get("/"))
    conflict_response = core_views.api_errors(raise_conflict)(factory.get("/"))
    assert auth_response.status_code == 401
    assert conflict_response.status_code == 409
