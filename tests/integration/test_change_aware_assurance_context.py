"""Broad, noisy-corpus regression for change-aware assurance retrieval."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from datetime import timedelta
from itertools import cycle, islice
from pathlib import Path
from typing import cast

import pytest
from django.utils import timezone

from anva.contracts.catalog import EXAMPLES
from anva.core.exceptions import IdempotencyConflictError, LeaseConflictError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    AccessScopeMembership,
    AssertionConflict,
    AssertionProvenance,
    AssertionValidityInterval,
    AssuranceRun,
    ContextPacketItem,
    KnowledgeAssertion,
    Membership,
    Organization,
    Repository,
    Role,
    SourceChunkVisibility,
    SourceConnection,
    User,
)
from anva.core.services.assurance import (
    REQUIRED_ASSURANCE_CONTEXT_LIMITATION_PREFIX,
    claim_evaluator_task,
    ingest_manual_diff,
    start_assurance,
    submit_evaluator_result,
)
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import invalidate_context_packets
from anva.core.services.evaluators import FakeEvaluator
from anva.core.services.evidence import submit_evidence_manifest
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.intent import import_work_item
from anva.core.services.jobs import claim_next_job, complete_job
from anva.core.services.mcp_gateway import dispatch_tool
from anva.core.services.policies import import_policy
from anva.mcp.contracts import validate_tool_output

FIXTURE = Path(__file__).parents[1] / "fixtures" / "assurance-broad-context.json"
HEAD = "d" * 40
DIFF = """diff --git a/src/support/contact_redaction.py b/src/support/contact_redaction.py
--- a/src/support/contact_redaction.py
+++ b/src/support/contact_redaction.py
@@ -1,2 +1,3 @@
 def sanitize_support_event(event):
-    return event
+    event.pop("passenger_email", None)
+    return event
"""


def _tenant() -> tuple[Organization, Repository, AccessScope, Membership, ActorContext]:
    organization = Organization.objects.create(
        slug=f"broad-assurance-{uuid.uuid4()}",
        name="Broad assurance regression",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:halcyon/support-{uuid.uuid4()}",
        name="Halcyon support platform",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="halcyon-public",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Org admin",
    )
    user = User.objects.create(
        email=f"broad-{uuid.uuid4()}@example.test",
        display_name="Broad corpus reviewer",
    )
    membership = Membership.objects.create(organization=organization, user=user, role=role)
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="untrusted-test-claim",
        request_id=uuid.uuid4(),
        source_ip_hash="a" * 64,
    )
    return organization, repository, scope, membership, actor


def _materialize_corpus(root: Path) -> None:
    fixture = cast(dict[str, object], json.loads(FIXTURE.read_text()))
    archive_templates = cast(list[str], fixture["archives"])
    archive_count = cast(int, fixture["archive_document_count"])
    for index, text in enumerate(islice(cycle(archive_templates), archive_count), start=1):
        (root / f"archive-{index:03d}.md").write_text(f"# {text}\n{text}\n")
    for name, text in cast(dict[str, str], fixture["sources"]).items():
        (root / name).write_text(text)


def _sync(
    *,
    actor: ActorContext,
    repository: Repository,
    scope: AccessScope,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected_documents: int,
) -> SourceConnection:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(root))
    source, created = connect_filesystem_source(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        external_key=f"filesystem:{uuid.uuid4()}",
        display_name="Broad Halcyon corpus",
        root=str(root),
    )
    assert created is True
    run, requested = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert requested is True
    job = claim_next_job(worker_id="issue-128-ingestion", lease_seconds=600)
    assert job is not None
    completed = execute_ingestion_job(job=job, worker_id="issue-128-ingestion")
    complete_job(
        actor=ActorContext(
            organization_id=actor.organization_id,
            actor_type="SERVICE",
            actor_id="issue-128-ingestion",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=job.id,
        worker_id="issue-128-ingestion",
        now=timezone.now(),
    )
    assert completed.id == run.id
    assert completed.processed_count == expected_documents
    assert completed.failed_count == 0
    return source


def _policy_assertion(
    *,
    organization: Organization,
    path: str,
    subject_key: str,
    value: str,
    review_state: str,
    staleness_state: str,
) -> KnowledgeAssertion:
    visibility = (
        SourceChunkVisibility.objects.filter(
            organization=organization,
            source_observation__source_document__relative_path=path,
        )
        .select_related(
            "access_snapshot",
            "source_location",
            "source_observation__source_document",
        )
        .order_by("id")
        .first()
    )
    assert visibility is not None
    assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=visibility.access_scope,
        subject_key=subject_key,
        predicate="required_policy",
        value={"claim": value},
        provenance=[{"source_id": str(visibility.source_observation_id)}],
        review_state=review_state,
        staleness_state=staleness_state,
        confidence=1.0,
    )
    AssertionProvenance.objects.create(
        organization=organization,
        assertion=assertion,
        source_location=visibility.source_location,
        source_observation=visibility.source_observation,
        access_snapshot=visibility.access_snapshot,
        extraction_class=KnowledgeAssertion.ExtractionClass.HUMAN,
        extraction_method="issue-128-regression",
        confidence=1.0,
        observed_at=visibility.observed_at,
    )
    AssertionValidityInterval.objects.create(
        organization=organization,
        assertion=assertion,
        source_document=visibility.source_observation.source_document,
        source_observation=visibility.source_observation,
        valid_from=visibility.observed_at,
        observed_from=visibility.observed_at,
    )
    return assertion


@pytest.mark.integration
@pytest.mark.django_db
def test_assurance_eval_keeps_change_context_and_conflict_ahead_of_archives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization, repository, scope, _membership, actor = _tenant()
    corpus = tmp_path / "public"
    corpus.mkdir()
    _materialize_corpus(corpus)
    source = _sync(
        actor=actor,
        repository=repository,
        scope=scope,
        root=corpus,
        monkeypatch=monkeypatch,
        expected_documents=107,
    )

    foreign_org, foreign_repository, foreign_scope, _foreign_membership, foreign_actor = _tenant()
    foreign_root = tmp_path / "foreign"
    foreign_root.mkdir()
    (foreign_root / "contact-redaction.md").write_text(
        "# Foreign contact redaction\nCANARY-FOREIGN-TENANT-ISSUE-128\n"
    )
    _sync(
        actor=foreign_actor,
        repository=foreign_repository,
        scope=foreign_scope,
        root=foreign_root,
        monkeypatch=monkeypatch,
        expected_documents=1,
    )
    assert foreign_org.id != organization.id

    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="restricted-support",
        all_memberships=False,
        all_repositories=True,
    )
    hidden_user = User.objects.create(
        email=f"hidden-{uuid.uuid4()}@example.test",
        display_name="Restricted corpus owner",
    )
    hidden_membership = Membership.objects.create(
        organization=organization,
        user=hidden_user,
        role=Role.objects.get(organization=organization, code=Role.Code.ORG_ADMIN),
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        membership=hidden_membership,
    )
    hidden_actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(hidden_user.id),
        authorization_path="untrusted-hidden-claim",
        request_id=uuid.uuid4(),
    )
    hidden_root = tmp_path / "hidden"
    hidden_root.mkdir()
    (hidden_root / "contact-redaction.md").write_text(
        "# Restricted contact redaction\nCANARY-UNAUTHORIZED-SCOPE-ISSUE-128\n"
    )
    _sync(
        actor=hidden_actor,
        repository=repository,
        scope=hidden_scope,
        root=hidden_root,
        monkeypatch=monkeypatch,
        expected_documents=1,
    )
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(corpus))

    current = _policy_assertion(
        organization=organization,
        path="current-policy.md",
        subject_key="policy:contact-redaction-current",
        value="Support contact fields must be redacted before observability export.",
        review_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
        staleness_state=KnowledgeAssertion.StalenessState.FRESH,
    )
    stale = _policy_assertion(
        organization=organization,
        path="stale-policy.md",
        subject_key="policy:contact-redaction-legacy",
        value="Support contact fields may be copied into observability logs.",
        review_state=KnowledgeAssertion.ReviewState.UNREVIEWED,
        staleness_state=KnowledgeAssertion.StalenessState.STALE,
    )
    conflict = AssertionConflict.objects.create(
        organization=organization,
        left_assertion=current,
        right_assertion=stale,
        predicate="required_policy",
    )

    work_payload = deepcopy(EXAMPLES["work-item-import"])
    work_payload.update(
        {
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_id": str(uuid.uuid4()),
            "revision": 1,
            "external_key": "HC-482",
            "title": "Redact passenger contact fields",
            "summary": "Apply contact_redaction before passenger support event export.",
        }
    )
    work_payload["requirements"][0]["normalized_text"] = (  # type: ignore[index]
        "Passenger email and telephone values are removed from support events."
    )
    work = import_work_item(actor=actor, payload=work_payload)

    policy_payload = deepcopy(EXAMPLES["policy"])
    policy_payload.update(
        {
            "organization_id": str(organization.id),
            "access_scope_id": str(scope.id),
            "policy_id": str(uuid.uuid4()),
            "version": 1,
            "name": "Current contact redaction control",
            "effective_at": "2026-07-01T00:00:00Z",
        }
    )
    policy_payload["binding"]["repository_ids"] = [str(repository.id)]  # type: ignore[index]
    policy_payload["requirements"][0].update(  # type: ignore[index]
        {
            "requirement_id": str(uuid.uuid4()),
            "code": "CONTACT_REDACTION_TEST",
            "description": "Contact redaction integration evidence must pass.",
        }
    )
    policy_version = import_policy(actor=actor, payload=policy_payload).policy_version

    evidence_payload = deepcopy(EXAMPLES["evidence-manifest"])
    evidence_payload.update(
        {
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "manifest_id": str(uuid.uuid4()),
            "pull_request_number": 41,
            "commit_sha": HEAD,
            "work_item_revision_id": str(work.work_item_revision.id),
            "created_at": timezone.now().isoformat(),
        }
    )
    evidence_payload["entries"][0].update(  # type: ignore[index]
        {
            "evidence_id": str(uuid.uuid4()),
            "name": "CONTACT_REDACTION_TEST passenger support events",
            "command": "pytest contact_redaction support_event",
            "content_hash": "e" * 64,
            "started_at": (timezone.now() - timedelta(minutes=2)).isoformat(),
            "completed_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
            "criterion_codes": ["TESTS_PASS"],
            "scenario": "passenger contact redaction",
        }
    )
    submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=41,
        payload=evidence_payload,
    ).evidence[0]

    ingested = ingest_manual_diff(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        pull_request_number=41,
        base_commit="a" * 40,
        head_commit=HEAD,
        title="Add passenger contact redaction guard",
        description="Sanitize passenger support events before observability export.",
        target_branch="main",
        is_draft=False,
        state="OPEN",
        unified_diff=DIFF,
    )
    reference_time = timezone.now() + timedelta(seconds=5)
    started = start_assurance(
        actor=actor,
        pull_request_revision_id=ingested.revision.id,
        policy_version_ids=[policy_version.id],
        reference_time=reference_time,
        deterministic_checks=[
            {
                "code": "CONTACT_REDACTION_TEST",
                "status": "PASSED",
                "blocking": True,
                "summary": "Exact-head passenger contact redaction scenario passed.",
                "evidence_ids": [],
            }
        ],
        work_item_revision_id=work.work_item_revision.id,
    )
    duplicate = start_assurance(
        actor=actor,
        pull_request_revision_id=ingested.revision.id,
        policy_version_ids=[policy_version.id],
        reference_time=reference_time,
        deterministic_checks=[
            {
                "code": "CONTACT_REDACTION_TEST",
                "status": "PASSED",
                "blocking": True,
                "summary": "Exact-head passenger contact redaction scenario passed.",
                "evidence_ids": [],
            }
        ],
        work_item_revision_id=work.work_item_revision.id,
    )
    assert duplicate.created is False
    assert duplicate.run.id == started.run.id
    assert duplicate.evaluator_task.request_artifact.content_hash == (
        started.evaluator_task.request_artifact.content_hash
    )

    packet = started.run.context_packet
    assert packet is not None
    selected_paths = {
        citation.canonical_url.rsplit("/", 1)[-1]
        for item in ContextPacketItem.objects.filter(context_packet=packet)
        for citation in item.contextpacketcitation_set.all()
    }
    assert {
        "current-policy.md",
        "stale-policy.md",
        "work.md",
        "evidence.md",
        "pull-request.md",
    } <= selected_paths
    ordered_items = list(
        ContextPacketItem.objects.filter(context_packet=packet).order_by("position")
    )
    artifact_items = cast(list[dict[str, object]], packet.artifact.payload["items"])
    assert [item.payload for item in ordered_items] == [item["payload"] for item in artifact_items]
    assert all(
        item.byte_count
        == len(
            json.dumps(
                item.payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        for item in ordered_items
    )
    relevant_names = {
        "current-policy.md",
        "stale-policy.md",
        "work.md",
        "evidence.md",
        "pull-request.md",
    }
    first_relevant_positions = {
        name: min(
            item.position
            for item in ordered_items
            if any(
                citation.canonical_url.rsplit("/", 1)[-1] == name
                for citation in item.contextpacketcitation_set.all()
            )
        )
        for name in relevant_names
    }
    archive_positions = [
        item.position
        for item in ordered_items
        if any(
            citation.canonical_url.rsplit("/", 1)[-1].startswith("archive-")
            for citation in item.contextpacketcitation_set.all()
        )
    ]
    assert set(first_relevant_positions) == relevant_names
    assert archive_positions
    assert max(first_relevant_positions.values()) < min(archive_positions)
    evidence_source_items = [
        item
        for item in ordered_items
        if any(
            citation.canonical_url.rsplit("/", 1)[-1] == "evidence.md"
            for citation in item.contextpacketcitation_set.all()
        )
    ]
    assert any(
        "evidence" in cast(list[str], item.payload.get("retrieval_facets", []))
        and "evidence" in cast(list[str], item.payload.get("required_context_facets", []))
        and "anchored" in item.selection_reason
        for item in evidence_source_items
    )
    assert ContextPacketItem.objects.filter(
        context_packet=packet,
        source_conflict=conflict,
    ).exists()
    assert not any(
        limitation.startswith(REQUIRED_ASSURANCE_CONTEXT_LIMITATION_PREFIX)
        for limitation in packet.limitations
    )

    # The packet is retrieved through the same official public MCP boundary used by
    # acceptance resume; its server-derived facet metadata must satisfy that contract.
    public_response = dispatch_tool(
        actor=actor,
        tool_name="anva.get_context_packet",
        arguments={
            "contract_version": "1",
            "repository_id": str(repository.id),
            "packet_id": str(packet.id),
        },
        transport="STREAMABLE_HTTP_MCP",
    )
    validate_tool_output("anva.get_context_packet", public_response)

    reviewer = User.objects.create(
        email=f"reviewer-{uuid.uuid4()}@example.test",
        display_name="Independent reviewer",
    )
    reviewer_role = Role.objects.create(
        organization=organization,
        code=Role.Code.REVIEWER,
        name="Reviewer",
    )
    Membership.objects.create(organization=organization, user=reviewer, role=reviewer_role)
    claim = claim_evaluator_task(
        actor=ActorContext(
            organization_id=organization.id,
            actor_type="USER",
            actor_id=str(reviewer.id),
            authorization_path="untrusted-reviewer-claim",
            request_id=uuid.uuid4(),
        ),
        repository_id=repository.id,
        claimant="issue-128-independent-reviewer",
        claim_idempotency_key="c" * 64,
        task_id=started.evaluator_task.id,
        assurance_run_id=started.run.id,
        input_hash=started.run.input_hash,
        head_commit=started.run.head_commit,
    )
    assert claim is not None
    context = cast(list[dict[str, object]], claim.request["authorized_context"])
    current_context = next(
        item
        for item in context
        if cast(dict[str, object], item["claim"]).get("assertion_id") == str(current.id)
    )
    stale_context = next(
        item
        for item in context
        if cast(dict[str, object], item["claim"]).get("assertion_id") == str(stale.id)
    )
    conflict_context = next(
        item
        for item in context
        if cast(dict[str, object], item["claim"]).get("conflict_id") == str(conflict.id)
    )
    assert current_context["freshness"] == "CURRENT"
    assert cast(dict[str, object], current_context["claim"])["review_state"] == "HUMAN_CONFIRMED"
    assert stale_context["freshness"] == "STALE"
    assert cast(dict[str, object], stale_context["claim"])["staleness_state"] == "STALE"
    assert "versus" in cast(str, conflict_context["summary"])
    assert all(cast(list[dict[str, object]], item["citations"]) for item in context)
    assert all(item["selection_reason"] for item in context)
    assert "CANARY-FOREIGN-TENANT-ISSUE-128" not in json.dumps(claim.request, sort_keys=True)
    assert "CANARY-UNAUTHORIZED-SCOPE-ISSUE-128" not in json.dumps(claim.request, sort_keys=True)
    result = FakeEvaluator().evaluate(claim.request)

    (corpus / "work.md").write_text(
        "# HC-482 redact passenger contact fields v2\n"
        "The current work now also redacts passenger postal addresses.\n"
    )
    rerun, rerun_created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert rerun_created is True
    rerun_job = claim_next_job(worker_id="issue-128-resync", lease_seconds=600)
    assert rerun_job is not None
    completed_rerun = execute_ingestion_job(job=rerun_job, worker_id="issue-128-resync")
    complete_job(
        actor=ActorContext(
            organization_id=organization.id,
            actor_type="SERVICE",
            actor_id="issue-128-resync",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=rerun_job.id,
        worker_id="issue-128-resync",
        now=timezone.now(),
    )
    assert completed_rerun.id == rerun.id
    with pytest.raises(LeaseConflictError, match="stale organizational context"):
        claim_evaluator_task(
            actor=ActorContext(
                organization_id=organization.id,
                actor_type="USER",
                actor_id=str(reviewer.id),
                authorization_path="untrusted-reviewer-replay",
                request_id=uuid.uuid4(),
            ),
            repository_id=repository.id,
            claimant="issue-128-independent-reviewer",
            claim_idempotency_key="c" * 64,
            task_id=started.evaluator_task.id,
            assurance_run_id=started.run.id,
            input_hash=started.run.input_hash,
            head_commit=started.run.head_commit,
        )
    with pytest.raises(IdempotencyConflictError, match="stale organizational context"):
        submit_evaluator_result(
            actor=ActorContext(
                organization_id=organization.id,
                actor_type="USER",
                actor_id=str(reviewer.id),
                authorization_path="untrusted-reviewer-submit",
                request_id=uuid.uuid4(),
            ),
            task_id=started.evaluator_task.id,
            claimant="issue-128-independent-reviewer",
            claim_token=claim.claim_token,
            result=result,
        )
    changed = start_assurance(
        actor=actor,
        pull_request_revision_id=ingested.revision.id,
        policy_version_ids=[policy_version.id],
        reference_time=reference_time,
        deterministic_checks=[
            {
                "code": "CONTACT_REDACTION_TEST",
                "status": "PASSED",
                "blocking": True,
                "summary": "Exact-head passenger contact redaction scenario passed.",
                "evidence_ids": [],
            }
        ],
        work_item_revision_id=work.work_item_revision.id,
    )
    started.run.refresh_from_db()
    assert started.run.state == AssuranceRun.State.STALE
    assert changed.created is True
    assert changed.run.context_artifact is not None
    assert started.run.context_artifact is not None
    assert changed.run.context_artifact.content_hash != started.run.context_artifact.content_hash
    invalidate_context_packets(
        actor=actor,
        organization_id=organization.id,
        repository_id=repository.id,
        reason="MANUAL",
        details={"test": "claim-must-fail-closed"},
    )
    with pytest.raises(ResourceNotFoundError):
        claim_evaluator_task(
            actor=ActorContext(
                organization_id=organization.id,
                actor_type="USER",
                actor_id=str(reviewer.id),
                authorization_path="untrusted-reviewer-stale-claim",
                request_id=uuid.uuid4(),
            ),
            repository_id=repository.id,
            claimant="issue-128-independent-reviewer-new",
            task_id=changed.evaluator_task.id,
            assurance_run_id=changed.run.id,
            input_hash=changed.run.input_hash,
            head_commit=changed.run.head_commit,
        )
    changed.run.refresh_from_db()
    changed.evaluator_task.refresh_from_db()
    assert changed.run.state == AssuranceRun.State.STALE
    assert changed.evaluator_task.state == changed.evaluator_task.State.CANCELLED
    assert changed.evaluator_task.failure_code == "STALE_CONTEXT"
