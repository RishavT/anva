"""HTTP adapter coverage for the independent manual-diff assurance lifecycle."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.test import Client

from anva.contracts.acceptance import validate_acceptance_http_response
from anva.contracts.catalog import EXAMPLES
from anva.core.models import AssuranceRun, Finding, content_hash


@pytest.mark.contract
def test_manual_diff_http_adapter_forwards_closed_exact_input(client: Client) -> None:
    repository_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    pull_request_id = uuid.uuid4()
    revision_id = uuid.uuid4()
    diff_artifact_id = uuid.uuid4()
    service_result = SimpleNamespace(
        pull_request=SimpleNamespace(id=pull_request_id),
        revision=SimpleNamespace(
            id=revision_id,
            revision=2,
            head_commit="b" * 40,
            diff_artifact_id=diff_artifact_id,
            diff_hash="d" * 64,
            changed_paths=["src/service.py"],
            classification_summary={"SOURCE": 1},
            limitations=["Manual provenance."],
        ),
        created=True,
    )
    payload = {
        "access_scope_id": str(scope_id),
        "base_commit": "a" * 40,
        "head_commit": "b" * 40,
        "title": "Change service",
        "description": "A bounded manual change.",
        "target_branch": "main",
        "is_draft": False,
        "state": "OPEN",
        "unified_diff": (
            "diff --git a/src/service.py b/src/service.py\n"
            "--- a/src/service.py\n"
            "+++ b/src/service.py\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        ),
    }
    url = f"/api/v1/repositories/{repository_id}/pull-requests/7/manual-diff"
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.views.ingest_manual_diff",
            return_value=service_result,
        ) as ingest,
    ):
        created = client.post(url, data=json.dumps(payload), content_type="application/json")
        service_result.created = False
        replayed = client.post(url, data=json.dumps(payload), content_type="application/json")

    assert created.status_code == 201
    assert replayed.status_code == 200
    assert created.json() == {
        "pull_request_id": str(pull_request_id),
        "pull_request_revision_id": str(revision_id),
        "revision": 2,
        "head_commit": "b" * 40,
        "diff_artifact_id": str(diff_artifact_id),
        "diff_hash": "d" * 64,
        "changed_paths": ["src/service.py"],
        "classification_summary": {"SOURCE": 1},
        "limitations": ["Manual provenance."],
        "created": True,
    }
    assert ingest.call_args.kwargs["repository_id"] == repository_id
    assert ingest.call_args.kwargs["pull_request_number"] == 7
    assert ingest.call_args.kwargs["access_scope_id"] == scope_id
    assert ingest.call_args.kwargs["unified_diff"] == payload["unified_diff"]
    assert client.get(url).status_code == 405
    validate_acceptance_http_response("ingestManualPullRequestDiff", 201, created.json())
    validate_acceptance_http_response("ingestManualPullRequestDiff", 200, replayed.json())


@pytest.mark.contract
def test_manual_diff_http_adapter_rejects_non_boolean_and_extra_fields(client: Client) -> None:
    repository_id = uuid.uuid4()
    url = f"/api/v1/repositories/{repository_id}/pull-requests/7/manual-diff"
    base = {
        "access_scope_id": str(uuid.uuid4()),
        "base_commit": "a" * 40,
        "head_commit": "b" * 40,
        "title": "Change",
        "description": "",
        "target_branch": "main",
        "is_draft": "false",
        "state": "OPEN",
        "unified_diff": "diff",
    }
    with patch("anva.core.views.ingest_manual_diff") as ingest:
        non_boolean = client.post(url, data=json.dumps(base), content_type="application/json")
        unknown = client.post(
            url,
            data=json.dumps({**base, "is_draft": False, "credential": "hidden"}),
            content_type="application/json",
        )

    assert non_boolean.status_code == 400
    assert unknown.status_code == 400
    ingest.assert_not_called()


@pytest.mark.contract
def test_assurance_start_http_adapter_handles_create_replay_and_invalid_checks(
    client: Client,
) -> None:
    revision_id = uuid.uuid4()
    run_id = uuid.uuid4()
    task_id = uuid.uuid4()
    policy_version_id = uuid.uuid4()
    result = SimpleNamespace(
        run=SimpleNamespace(
            id=run_id,
            state=AssuranceRun.State.MODEL_REVIEW,
            head_commit="b" * 40,
            input_hash="a" * 64,
        ),
        evaluator_task=SimpleNamespace(id=task_id),
        created=True,
    )
    payload = {
        "policy_version_ids": [str(policy_version_id)],
        "reference_time": "2026-07-28T00:00:00Z",
        "deterministic_checks": [],
        "evaluator_version": "manual-evaluator-v1",
        "prompt_version": "prompt-v1",
        "trigger_key": "manual",
    }
    url = f"/api/v1/pull-request-revisions/{revision_id}/assurance-runs"
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch("anva.core.views.start_assurance", return_value=result) as start,
    ):
        created = client.post(url, data=json.dumps(payload), content_type="application/json")
        result.created = False
        replayed = client.post(url, data=json.dumps(payload), content_type="application/json")
        invalid = client.post(
            url,
            data=json.dumps({**payload, "deterministic_checks": {}}),
            content_type="application/json",
        )

    assert created.status_code == 201
    assert replayed.status_code == 200
    assert invalid.status_code == 400
    assert created.json()["evaluator_task_id"] == str(task_id)
    validate_acceptance_http_response("startManualDiffAssurance", 201, created.json())
    validate_acceptance_http_response("startManualDiffAssurance", 200, replayed.json())
    assert start.call_args.kwargs["pull_request_revision_id"] == revision_id
    assert start.call_args.kwargs["policy_version_ids"] == [policy_version_id]
    assert start.call_args.kwargs["reference_time"] == datetime(2026, 7, 28, tzinfo=UTC)


@pytest.mark.contract
def test_manual_evaluator_claim_and_submit_http_adapters(client: Client) -> None:
    repository_id = uuid.uuid4()
    task_id = uuid.uuid4()
    run_id = uuid.uuid4()
    report_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    lease_expires = datetime.now(tz=UTC) + timedelta(minutes=5)
    request_id = uuid.uuid4()
    input_hash = "a" * 64
    head_commit = "b" * 40
    evaluator_request = deepcopy(EXAMPLES["evaluator-request"])
    evaluator_request.update(
        {
            "request_id": str(request_id),
            "assurance_run_id": str(run_id),
            "organization_id": str(uuid.uuid4()),
            "commit_sha": head_commit,
        }
    )
    claim = SimpleNamespace(
        task=SimpleNamespace(
            id=task_id,
            assurance_run_id=run_id,
            assurance_run=SimpleNamespace(input_hash=input_hash, head_commit=head_commit),
            claimant="fresh-agent",
            claimed_by_actor_type="SERVICE",
            claimed_by_actor_id="review-service",
            claimed_by_credential_id=uuid.uuid4(),
            attempt_count=2,
            lease_expires_at=lease_expires,
        ),
        claim_token="opaque-claim-token-value-0000000001",
        request=evaluator_request,
        replayed=False,
    )
    human_claim = deepcopy(claim)
    human_claim.task.claimed_by_actor_type = "USER"
    human_claim.task.claimed_by_actor_id = str(uuid.uuid4())
    human_claim.task.claimed_by_credential_id = None
    completion = SimpleNamespace(
        run=SimpleNamespace(
            id=run_id,
            state=AssuranceRun.State.COMPLETED,
            input_hash=input_hash,
            head_commit=head_commit,
        ),
        readiness=SimpleNamespace(
            status="READY_WITH_WARNINGS",
            reason_codes=["MODEL_CONCERNS"],
        ),
        report=SimpleNamespace(id=report_id),
        findings=(SimpleNamespace(id=finding_id),),
        created=True,
    )
    claim_url = f"/api/v1/repositories/{repository_id}/evaluator-tasks/claim"
    submit_url = f"/api/v1/evaluator-tasks/{task_id}/submit"
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.views.claim_evaluator_task",
            side_effect=[None, claim, human_claim],
        ) as claim_task,
        patch(
            "anva.core.views.submit_evaluator_result",
            return_value=completion,
        ) as submit,
    ):
        empty = client.post(
            claim_url,
            data=json.dumps({"claimant": "fresh-agent"}),
            content_type="application/json",
        )
        claimed = client.post(
            claim_url,
            data=json.dumps(
                {
                    "claimant": "fresh-agent",
                    "lease_seconds": 30,
                    "task_id": str(task_id),
                    "assurance_run_id": str(run_id),
                    "input_hash": input_hash,
                    "head_commit": head_commit,
                }
            ),
            content_type="application/json",
        )
        human_claimed = client.post(
            claim_url,
            data=json.dumps({"claimant": "human-reviewer"}),
            content_type="application/json",
        )
        submitted = client.post(
            submit_url,
            data=json.dumps(
                {
                    "claim_token": "opaque-claim-token",
                    "result": {"schema_version": "1.0"},
                }
            ),
            content_type="application/json",
        )
        invalid = client.post(
            submit_url,
            data=json.dumps(
                {
                    "claimant": "fresh-agent",
                    "claim_token": "opaque-claim-token",
                    "result": [],
                }
            ),
            content_type="application/json",
        )

    assert empty.json() == {"status": "EMPTY"}
    assert claimed.status_code == 200
    assert claimed.json()["task_id"] == str(task_id)
    assert claimed.json()["status"] == "CLAIMED"
    assert claimed.json()["assurance_run_id"] == str(run_id)
    assert claimed.json()["request_id"] == str(request_id)
    assert claimed.json()["input_hash"] == input_hash
    assert claimed.json()["head_commit"] == head_commit
    assert claimed.json()["claimed_by"]["actor_id"] == "review-service"
    assert claimed.json()["replayed"] is False
    assert claimed.json()["claimant"] == "fresh-agent"
    assert claimed.json()["attempt"] == 2
    assert claimed.json()["lease_expires_at"] == lease_expires.isoformat()
    assert human_claimed.json()["claimed_by"]["actor_type"] == "USER"
    assert human_claimed.json()["claimed_by"]["credential_id"] is None
    assert submitted.status_code == 201
    assert submitted.json()["readiness"] == "READY_WITH_WARNINGS"
    assert submitted.json()["finding_ids"] == [str(finding_id)]
    assert submitted.json()["task_id"] == str(task_id)
    assert submitted.json()["result_hash"] == content_hash({"schema_version": "1.0"})
    assert submitted.json()["created"] is True
    assert submitted.json()["replayed"] is False
    validate_acceptance_http_response("claimManualEvaluatorTask", 200, claimed.json())
    validate_acceptance_http_response("claimManualEvaluatorTask", 200, human_claimed.json())
    validate_acceptance_http_response("submitManualEvaluatorResult", 201, submitted.json())
    assert invalid.status_code == 400
    exact_claim_kwargs = claim_task.call_args_list[1].kwargs
    assert exact_claim_kwargs["lease_seconds"] == 30
    assert exact_claim_kwargs["task_id"] == task_id
    assert exact_claim_kwargs["assurance_run_id"] == run_id
    assert exact_claim_kwargs["input_hash"] == input_hash
    assert exact_claim_kwargs["head_commit"] == head_commit
    assert submit.call_args.kwargs["task_id"] == task_id
    assert submit.call_args.kwargs["claimant"] is None
    assert submit.call_args.kwargs["claim_token"] == "opaque-claim-token"  # noqa: S105


def _run_for_http() -> SimpleNamespace:
    context_scope_id = uuid.uuid4()
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        repository_id=uuid.uuid4(),
        context_packet_id=uuid.uuid4(),
        context_packet=SimpleNamespace(access_scope_id=context_scope_id),
        state=AssuranceRun.State.COMPLETED,
        readiness="READY_WITH_WARNINGS",
        revision=8,
        pull_request_number=7,
        pull_request_revision_id=uuid.uuid4(),
        head_commit="b" * 40,
        input_hash="a" * 64,
        requirements_hash="b" * 64,
        policy_bundle_hash="c" * 64,
        evidence_bundle_hash="d" * 64,
        evaluator_version="manual-v1",
        prompt_version="prompt-v1",
        limitations=["No code was executed."],
    )


@pytest.mark.contract
def test_assurance_read_http_adapters_return_exact_run_findings_and_report(
    client: Client,
) -> None:
    run = _run_for_http()
    finding = SimpleNamespace(
        id=uuid.uuid4(),
        fingerprint="f" * 64,
        code="REVIEW_CONCERN",
        kind=Finding.Kind.MODEL,
        severity=Finding.Severity.ADVISORY,
        confidence=Finding.Confidence.MEDIUM,
        title="Review boundary",
        explanation="Inspect the change.",
        path="src/service.py",
        line=4,
        citations=[
            {
                "type": "DIFF",
                "path": "src/service.py",
                "side": "NEW",
                "line": 4,
            }
        ],
        evidence_ids=[],
        criterion_codes=[],
        uncertainty="Bounded review.",
        suggested_resolution="Inspect.",
        state=Finding.State.OPEN,
        revision=1,
    )
    report = SimpleNamespace(
        id=uuid.uuid4(),
        renderer_version="report-v1",
        content_hash="c" * 64,
        markdown="# Assurance\n",
        html="<article>Assurance</article>\n",
    )
    actor = SimpleNamespace(organization_id=run.organization_id)
    findings_query = MagicMock()
    findings_query.order_by.return_value = [finding]
    report_query = MagicMock()
    report_query.first.return_value = report
    task_query = MagicMock()
    task_query.filter.return_value.first.return_value = SimpleNamespace(
        request_artifact=SimpleNamespace(access_scope_id=uuid.uuid4())
    )
    with (
        patch("anva.core.views._actor", return_value=actor),
        patch("anva.core.views.get_tenant_record", return_value=run),
        patch("anva.core.views.authorize_action") as authorize,
        patch(
            "anva.core.views.EvaluatorTask.objects.select_related",
            return_value=task_query,
        ),
        patch("anva.core.views.Finding.objects.filter", return_value=findings_query),
        patch("anva.core.views.AssuranceReport.objects.filter", return_value=report_query),
    ):
        detail = client.get(f"/api/v1/assurance-runs/{run.id}")
        findings = client.get(f"/api/v1/assurance-runs/{run.id}/findings")
        rendered = client.get(f"/api/v1/assurance-runs/{run.id}/report")
        report_query.first.return_value = None
        missing_report = client.get(f"/api/v1/assurance-runs/{run.id}/report")

    assert detail.status_code == 200
    assert detail.json()["input_hash"] == run.input_hash
    assert findings.status_code == 200
    assert findings.json()["findings"][0]["fingerprint"] == finding.fingerprint
    assert rendered.status_code == 200
    assert rendered.json()["markdown"] == report.markdown
    assert missing_report.status_code == 404
    validate_acceptance_http_response("getAssuranceRun", 200, detail.json())
    validate_acceptance_http_response("listAssuranceFindings", 200, findings.json())
    validate_acceptance_http_response("getAssuranceReport", 200, rendered.json())
    assert authorize.call_count == 8


@pytest.mark.contract
def test_assurance_read_fails_closed_when_run_lacks_repository(client: Client) -> None:
    run = _run_for_http()
    run.repository_id = None
    with (
        patch(
            "anva.core.views._actor",
            return_value=SimpleNamespace(organization_id=run.organization_id),
        ),
        patch("anva.core.views.get_tenant_record", return_value=run),
        patch("anva.core.views.authorize_action") as authorize,
    ):
        response = client.get(f"/api/v1/assurance-runs/{run.id}")

    assert response.status_code == 404
    authorize.assert_not_called()


@pytest.mark.contract
def test_post_merge_and_finding_decision_http_adapters_remain_review_gated(
    client: Client,
) -> None:
    run_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    repository_id = uuid.uuid4()
    link = SimpleNamespace(
        id=uuid.uuid4(),
        knowledge_proposal_id=uuid.uuid4(),
        knowledge_proposal=SimpleNamespace(state="AWAITING_REVIEW"),
        classification="INTERPRETIVE",
        confidence=0.7,
    )
    finding = SimpleNamespace(id=finding_id, state=Finding.State.DISMISSED, revision=2)
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.views.propose_post_merge_knowledge",
            return_value=(link,),
        ) as propose,
        patch("anva.core.views.authorize_sensitive_placeholder") as authorize,
        patch("anva.core.views.decide_finding", return_value=finding) as decide,
    ):
        proposed = client.post(
            f"/api/v1/assurance-runs/{run_id}/post-merge-proposals",
            data=json.dumps(
                {
                    "proposals": [
                        {
                            "summary": "Record learning",
                            "changes": [{"operation": "ADD"}],
                        }
                    ]
                }
            ),
            content_type="application/json",
        )
        invalid = client.post(
            f"/api/v1/assurance-runs/{run_id}/post-merge-proposals",
            data=json.dumps({"proposals": "not-a-list"}),
            content_type="application/json",
        )
        dismissed = client.post(
            f"/api/v1/findings/{finding_id}/dismiss",
            data=json.dumps(
                {
                    "repository_id": str(repository_id),
                    "target_state": Finding.State.DISMISSED,
                    "expected_revision": 1,
                    "reason": "False positive.",
                }
            ),
            content_type="application/json",
        )

    assert proposed.status_code == 201
    assert proposed.json()["automatic_acceptance"] is False
    assert proposed.json()["proposals"][0]["state"] == "AWAITING_REVIEW"
    assert invalid.status_code == 400
    assert dismissed.json() == {
        "id": str(finding_id),
        "state": Finding.State.DISMISSED,
        "revision": 2,
    }
    assert propose.call_args.kwargs["run_id"] == run_id
    authorize.assert_called_once()
    assert decide.call_args.kwargs["reason"] == "False positive."
