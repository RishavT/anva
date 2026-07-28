"""End-to-end deterministic intent, policy, evidence, and gap behavior."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from threading import Barrier
from typing import Any

import pytest
from django.db import (
    DatabaseError,
    IntegrityError,
    close_old_connections,
    connection,
    transaction,
)
from django.utils import timezone

from anva.contracts.catalog import EXAMPLES
from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AcceptanceCriterion,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    Approval,
    ApprovalRevocation,
    CriterionEvidence,
    Evidence,
    EvidenceManifest,
    EvidenceRetentionEvent,
    ImmutableArtifact,
    KnowledgeEntity,
    Membership,
    Organization,
    PolicyOverride,
    PolicyOverrideRevocation,
    Repository,
    Requirement,
    Role,
    User,
    WorkSummary,
    content_hash,
)
from anva.core.services.context import ActorContext
from anva.core.services.evidence import (
    map_criterion_evidence,
    submit_evidence_manifest,
)
from anva.core.services.intent import (
    approve_work_item_revision,
    import_work_item,
    revoke_work_item_approval,
)
from anva.core.services.policies import (
    create_policy_override,
    evaluate_policy,
    import_policy,
    revoke_policy_override,
)


def governance_tenant() -> tuple[Organization, Repository, AccessScope, ActorContext]:
    organization = Organization.objects.create(
        slug=f"governance-{uuid.uuid4()}",
        name="Governance test",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:governance/{uuid.uuid4()}",
        name="Governance repository",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="governance-visible",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Org admin",
    )
    user = User.objects.create(
        email=f"governance-{uuid.uuid4()}@example.test",
        display_name="Governance admin",
    )
    Membership.objects.create(
        organization=organization,
        user=user,
        role=role,
    )
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="untrusted",
        request_id=uuid.uuid4(),
    )
    return organization, repository, scope, actor


def work_payload(
    organization: Organization,
    repository: Repository,
    scope: AccessScope,
) -> dict[str, object]:
    payload = deepcopy(EXAMPLES["work-item-import"])
    payload.update(
        {
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_id": str(uuid.uuid4()),
            "revision": 1,
        }
    )
    return payload


def policy_payload(
    organization: Organization,
    repository: Repository,
    scope: AccessScope,
) -> dict[str, object]:
    payload = deepcopy(EXAMPLES["policy"])
    payload.update(
        {
            "organization_id": str(organization.id),
            "access_scope_id": str(scope.id),
            "policy_id": str(uuid.uuid4()),
            "version": 1,
        }
    )
    payload["binding"]["repository_ids"] = [str(repository.id)]  # type: ignore[index]
    payload["requirements"][0]["requirement_id"] = str(uuid.uuid4())  # type: ignore[index]
    return payload


def _run_identical_calls_concurrently(
    call: Callable[[], tuple[Any, bool]],
) -> list[tuple[uuid.UUID, bool]]:
    barrier = Barrier(2)

    def invoke() -> tuple[uuid.UUID, bool]:
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            record, created = call()
            return record.id, created
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        return list(executor.map(lambda _index: invoke(), range(2)))


def _install_governance_insert_pause_triggers() -> None:
    """Widen the old check/insert race while retaining real PostgreSQL writes."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            CREATE OR REPLACE FUNCTION core_test_pause_governance_insert()
            RETURNS trigger AS $$
            BEGIN
                PERFORM pg_sleep(0.5);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER test_pause_approval_insert
            BEFORE INSERT ON core_approval
            FOR EACH ROW EXECUTE FUNCTION core_test_pause_governance_insert()
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER test_pause_approval_revocation_insert
            BEFORE INSERT ON core_approvalrevocation
            FOR EACH ROW EXECUTE FUNCTION core_test_pause_governance_insert()
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER test_pause_policy_override_insert
            BEFORE INSERT ON core_policyoverride
            FOR EACH ROW EXECUTE FUNCTION core_test_pause_governance_insert()
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER test_pause_policy_override_revocation_insert
            BEFORE INSERT ON core_policyoverriderevocation
            FOR EACH ROW EXECUTE FUNCTION core_test_pause_governance_insert()
            """
        )


def _drop_governance_insert_pause_triggers() -> None:
    with connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS test_pause_approval_insert ON core_approval")
        cursor.execute(
            "DROP TRIGGER IF EXISTS test_pause_approval_revocation_insert "
            "ON core_approvalrevocation"
        )
        cursor.execute(
            "DROP TRIGGER IF EXISTS test_pause_policy_override_insert ON core_policyoverride"
        )
        cursor.execute(
            "DROP TRIGGER IF EXISTS test_pause_policy_override_revocation_insert "
            "ON core_policyoverriderevocation"
        )
        cursor.execute("DROP FUNCTION IF EXISTS core_test_pause_governance_insert()")


def _copy_evidence(source: Evidence, **changes: object) -> Evidence:
    marker = str(uuid.uuid4())
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "organization": source.organization,
        "manifest": source.manifest,
        "approval": source.approval,
        "commit_sha": source.commit_sha,
        "kind": source.kind,
        "name": f"adversarial-{marker}",
        "producer": source.producer,
        "producer_version": source.producer_version,
        "command": source.command,
        "status": source.status,
        "started_at": source.started_at,
        "completed_at": source.completed_at,
        "artifact_reference": source.artifact_reference,
        "source_url": source.source_url,
        "content_hash": content_hash({"adversarial": marker}),
        "limitations": source.limitations,
        "criterion_codes": source.criterion_codes,
        "retention_class": source.retention_class,
        "retention_expires_at": source.retention_expires_at,
        "environment": source.environment,
        "scenario": source.scenario,
    }
    values.update(changes)
    return Evidence.objects.create(**values)


def _force_satisfied_mapping(
    *,
    organization: Organization,
    scope: AccessScope,
    criterion: AcceptanceCriterion,
    evidence: Evidence,
    target_commit: str,
    pull_request_number: int,
    reference_time: datetime,
    required_evidence_type: str,
) -> CriterionEvidence:
    marker = str(uuid.uuid4())
    mapping = CriterionEvidence.objects.create(
        organization=organization,
        access_scope=scope,
        criterion=criterion,
        evidence=evidence,
        target_commit=target_commit,
        pull_request_number=pull_request_number,
        reference_time=reference_time,
        required_evidence_type=required_evidence_type,
        engine_version="criterion-evidence-v1",
        input_hash=content_hash({"input": marker}),
        classification=CriterionEvidence.Classification.DIRECT,
        assessment=CriterionEvidence.Assessment.SATISFIED,
        verifier_type="SERVICE",
        verifier_id="adversarial-test",
        limitations=[],
        confidence=1.0,
        gap_code="",
        gap_description="",
        mapping_key=content_hash({"mapping": marker}),
    )
    with connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
    return mapping


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_exact_future_draft_policy_is_simulatable_but_not_enforceable() -> None:
    organization, repository, scope, actor = governance_tenant()
    imported_work = import_work_item(
        actor=actor,
        payload=work_payload(organization, repository, scope),
    )
    reference_time = timezone.now()
    payload = policy_payload(organization, repository, scope)
    payload["status"] = "DRAFT"
    payload["effective_at"] = (reference_time + timedelta(days=7)).isoformat()
    imported_policy = import_policy(actor=actor, payload=payload)

    simulation, created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=30,
        commit_sha="3" * 40,
        policy_version_ids=[imported_policy.policy_version.id],
        reference_time=reference_time,
        affected_paths=[],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
        is_simulation=True,
    )

    assert created is True
    assert simulation.is_simulation is True
    assert simulation.input_payload["policy_versions"][0]["id"] == str(
        imported_policy.policy_version.id
    )
    with pytest.raises(ResourceNotFoundError):
        evaluate_policy(
            actor=actor,
            repository_id=repository.id,
            pull_request_number=30,
            commit_sha="3" * 40,
            policy_version_ids=[imported_policy.policy_version.id],
            reference_time=reference_time,
            affected_paths=[],
            affected_entities=[],
            target_branch="main",
            work_item_revision_id=imported_work.work_item_revision.id,
            is_simulation=False,
        )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_identical_governance_writes_replay_under_synchronized_concurrency() -> None:
    organization, repository, scope, actor = governance_tenant()
    imported_work = import_work_item(
        actor=actor,
        payload=work_payload(organization, repository, scope),
    )
    imported_policy = import_policy(
        actor=actor,
        payload=policy_payload(organization, repository, scope),
    )
    evaluation, _created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=31,
        commit_sha="4" * 40,
        policy_version_ids=[imported_policy.policy_version.id],
        reference_time=timezone.now(),
        affected_paths=[],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
    )

    _install_governance_insert_pause_triggers()
    try:
        approval_results = _run_identical_calls_concurrently(
            lambda: approve_work_item_revision(
                actor=actor,
                repository_id=repository.id,
                work_item_revision_id=imported_work.work_item_revision.id,
                status="APPROVED",
                target_kind="WORK_ITEM_REVISION",
                target_key=str(imported_work.work_item_revision.id),
                reason="Concurrent exact approval.",
            )
        )
        approval_id = approval_results[0][0]
        assert approval_results == [(approval_id, True), (approval_id, False)] or (
            approval_results == [(approval_id, False), (approval_id, True)]
        )
        assert Approval.objects.filter(id=approval_id).count() == 1

        approval_revocation_results = _run_identical_calls_concurrently(
            lambda: revoke_work_item_approval(
                actor=actor,
                repository_id=repository.id,
                approval_id=approval_id,
                reason="Concurrent exact approval revocation.",
            )
        )
        approval_revocation_id = approval_revocation_results[0][0]
        assert {item[0] for item in approval_revocation_results} == {approval_revocation_id}
        assert sorted(item[1] for item in approval_revocation_results) == [False, True]
        assert ApprovalRevocation.objects.filter(id=approval_revocation_id).count() == 1

        override_results = _run_identical_calls_concurrently(
            lambda: create_policy_override(
                actor=actor,
                repository_id=repository.id,
                policy_id=imported_policy.policy.id,
                policy_evaluation_id=evaluation.id,
                policy_version_id=imported_policy.policy_version.id,
                requirement_code="TESTS_PASS",
                pull_request_number=31,
                commit_sha="4" * 40,
                reason="Concurrent exact override.",
                expires_at=None,
            )
        )
        override_id = override_results[0][0]
        assert {item[0] for item in override_results} == {override_id}
        assert sorted(item[1] for item in override_results) == [False, True]
        assert PolicyOverride.objects.filter(id=override_id).count() == 1

        override_revocation_results = _run_identical_calls_concurrently(
            lambda: revoke_policy_override(
                actor=actor,
                repository_id=repository.id,
                policy_override_id=override_id,
                reason="Concurrent exact override revocation.",
            )
        )
        override_revocation_id = override_revocation_results[0][0]
        assert {item[0] for item in override_revocation_results} == {override_revocation_id}
        assert sorted(item[1] for item in override_revocation_results) == [False, True]
        assert PolicyOverrideRevocation.objects.filter(id=override_revocation_id).count() == 1
    finally:
        _drop_governance_insert_pause_triggers()


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_database_rejects_semantically_ineligible_satisfied_evidence() -> None:
    organization, repository, scope, actor = governance_tenant()
    imported_work = import_work_item(
        actor=actor,
        payload=work_payload(organization, repository, scope),
    )
    payload = deepcopy(EXAMPLES["evidence-manifest"])
    payload.update(
        {
            "manifest_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_revision_id": str(imported_work.work_item_revision.id),
            "pull_request_number": 32,
            "commit_sha": "5" * 40,
        }
    )
    payload["entries"][0]["evidence_id"] = str(uuid.uuid4())  # type: ignore[index]
    imported = submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=32,
        payload=payload,
    )
    source = imported.evidence[0]
    criterion = AcceptanceCriterion.objects.get(
        work_item_revision=imported_work.work_item_revision,
        code="TESTS_PASS",
    )
    reference_time = timezone.now()

    with transaction.atomic():
        valid_mapping = _force_satisfied_mapping(
            organization=organization,
            scope=scope,
            criterion=criterion,
            evidence=source,
            target_commit="5" * 40,
            pull_request_number=32,
            reference_time=reference_time,
            required_evidence_type=Evidence.Kind.TEST_RESULT,
        )
    assert valid_mapping.assessment == CriterionEvidence.Assessment.SATISFIED

    failed = _copy_evidence(source, status=Evidence.Status.FAILED)
    wrong_kind = _copy_evidence(source, kind=Evidence.Kind.LINT_RESULT)
    future = _copy_evidence(
        source,
        started_at=None,
        completed_at=reference_time + timedelta(minutes=1),
    )
    without_retention = _copy_evidence(source)
    wrong_retention = _copy_evidence(source)
    expired_retention = _copy_evidence(
        source,
        retention_expires_at=reference_time,
    )
    for retained in (failed, wrong_kind, future, expired_retention):
        EvidenceRetentionEvent.objects.create(
            organization=organization,
            evidence=retained,
            state=Evidence.RetentionState.ACTIVE,
            reason="adversarial active state",
            actor_type="SERVICE",
            actor_id="adversarial-test",
            occurred_at=reference_time - timedelta(seconds=1),
        )
    EvidenceRetentionEvent.objects.create(
        organization=organization,
        evidence=wrong_retention,
        state=Evidence.RetentionState.EXPIRED,
        reason="adversarial expired state",
        actor_type="SERVICE",
        actor_id="adversarial-test",
        occurred_at=reference_time - timedelta(seconds=1),
    )

    for invalid in (
        failed,
        wrong_kind,
        future,
        without_retention,
        wrong_retention,
        expired_retention,
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            _force_satisfied_mapping(
                organization=organization,
                scope=scope,
                criterion=criterion,
                evidence=invalid,
                target_commit="5" * 40,
                pull_request_number=32,
                reference_time=reference_time,
                required_evidence_type=Evidence.Kind.TEST_RESULT,
            )

    with pytest.raises(DatabaseError), transaction.atomic():
        _force_satisfied_mapping(
            organization=organization,
            scope=scope,
            criterion=criterion,
            evidence=source,
            target_commit="6" * 40,
            pull_request_number=32,
            reference_time=reference_time,
            required_evidence_type=Evidence.Kind.TEST_RESULT,
        )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_database_uses_mapping_reference_time_for_manual_approval_expiry() -> None:
    organization, repository, scope, actor = governance_tenant()
    work = work_payload(organization, repository, scope)
    work["acceptance_criteria"][0]["manual_approval_allowed"] = True  # type: ignore[index]
    work["acceptance_criteria"][0]["required_evidence_types"] = [  # type: ignore[index]
        "MANUAL_APPROVAL"
    ]
    imported_work = import_work_item(actor=actor, payload=work)
    expires_at = timezone.now() + timedelta(minutes=10)
    approval, _created = approve_work_item_revision(
        actor=actor,
        repository_id=repository.id,
        work_item_revision_id=imported_work.work_item_revision.id,
        status=Approval.Status.APPROVED,
        target_kind="WORK_ITEM_REVISION",
        target_key=str(imported_work.work_item_revision.id),
        reason="Approval with deterministic expiry.",
        expires_at=expires_at,
    )
    completed_at = timezone.now()
    payload = deepcopy(EXAMPLES["evidence-manifest"])
    payload.update(
        {
            "manifest_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_revision_id": str(imported_work.work_item_revision.id),
            "pull_request_number": 33,
            "commit_sha": "7" * 40,
        }
    )
    payload["entries"][0].update(  # type: ignore[index]
        {
            "evidence_id": str(uuid.uuid4()),
            "kind": "MANUAL_APPROVAL",
            "name": "manual approval",
            "status": "PASSED",
            "command": "",
            "approval_id": str(approval.id),
            "content_hash": "8" * 64,
            "started_at": None,
            "completed_at": completed_at.isoformat(),
            "retention_expires_at": (expires_at + timedelta(days=1)).isoformat(),
        }
    )
    imported = submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=33,
        payload=payload,
    )
    criterion = AcceptanceCriterion.objects.get(
        work_item_revision=imported_work.work_item_revision,
        code="TESTS_PASS",
    )

    with pytest.raises(DatabaseError), transaction.atomic():
        _force_satisfied_mapping(
            organization=organization,
            scope=scope,
            criterion=criterion,
            evidence=imported.evidence[0],
            target_commit="7" * 40,
            pull_request_number=33,
            reference_time=expires_at + timedelta(seconds=1),
            required_evidence_type=Evidence.Kind.MANUAL_APPROVAL,
        )

    future_decision_time = completed_at + timedelta(minutes=5)
    future_decision = Approval.objects.create(
        organization=organization,
        work_item_revision=imported_work.work_item_revision,
        repository=repository,
        target_kind="WORK_ITEM_REVISION",
        target_key=str(imported_work.work_item_revision.id),
        status=Approval.Status.APPROVED,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        authority_action="work.approve",
        reason="Adversarial approval decided after claimed evidence completion.",
        idempotency_key=content_hash({"future-approval": str(uuid.uuid4())}),
        decided_at=future_decision_time,
        expires_at=future_decision_time + timedelta(days=1),
    )
    future_approved_evidence = _copy_evidence(
        imported.evidence[0],
        approval=future_decision,
    )
    EvidenceRetentionEvent.objects.create(
        organization=organization,
        evidence=future_approved_evidence,
        state=Evidence.RetentionState.ACTIVE,
        reason="adversarial active state",
        actor_type="SERVICE",
        actor_id="adversarial-test",
    )
    with pytest.raises(DatabaseError), transaction.atomic():
        _force_satisfied_mapping(
            organization=organization,
            scope=scope,
            criterion=criterion,
            evidence=future_approved_evidence,
            target_commit="7" * 40,
            pull_request_number=33,
            reference_time=future_decision_time + timedelta(minutes=1),
            required_evidence_type=Evidence.Kind.MANUAL_APPROVAL,
        )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_manual_evidence_completed_before_revocation_supports_late_historical_replay() -> None:
    organization, repository, scope, actor = governance_tenant()
    work = work_payload(organization, repository, scope)
    work["acceptance_criteria"][0]["manual_approval_allowed"] = True  # type: ignore[index]
    work["acceptance_criteria"][0]["required_evidence_types"] = [  # type: ignore[index]
        "MANUAL_APPROVAL"
    ]
    imported_work = import_work_item(actor=actor, payload=work)
    approval, _created = approve_work_item_revision(
        actor=actor,
        repository_id=repository.id,
        work_item_revision_id=imported_work.work_item_revision.id,
        status=Approval.Status.APPROVED,
        target_kind="WORK_ITEM_REVISION",
        target_key=str(imported_work.work_item_revision.id),
        reason="Approval valid at historical evidence completion.",
    )
    completed_at = timezone.now()
    historical_reference_time = timezone.now()
    revocation, _created = revoke_work_item_approval(
        actor=actor,
        repository_id=repository.id,
        approval_id=approval.id,
        reason="Approval revoked after the historical reference.",
    )
    assert revocation.revoked_at > historical_reference_time >= completed_at

    payload = deepcopy(EXAMPLES["evidence-manifest"])
    payload.update(
        {
            "manifest_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_revision_id": str(imported_work.work_item_revision.id),
            "pull_request_number": 34,
            "commit_sha": "9" * 40,
        }
    )
    payload["entries"][0].update(  # type: ignore[index]
        {
            "evidence_id": str(uuid.uuid4()),
            "kind": "MANUAL_APPROVAL",
            "name": "historical manual approval",
            "status": "PASSED",
            "command": "",
            "approval_id": str(approval.id),
            "content_hash": "a" * 64,
            "started_at": None,
            "completed_at": completed_at.isoformat(),
            "retention_expires_at": (historical_reference_time + timedelta(days=1)).isoformat(),
        }
    )
    imported = submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=34,
        payload=payload,
    )
    EvidenceRetentionEvent.objects.create(
        organization=organization,
        evidence=imported.evidence[0],
        state=Evidence.RetentionState.ACTIVE,
        reason="historically observed active",
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        occurred_at=completed_at,
    )

    historical = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=34,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="9" * 40,
        reference_time=historical_reference_time,
    )
    assert historical.mappings[0].assessment == CriterionEvidence.Assessment.SATISFIED

    current = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=34,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="9" * 40,
        reference_time=timezone.now(),
    )
    assert current.mappings[0].assessment == CriterionEvidence.Assessment.GAP


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_exact_versions_produce_stable_policy_and_commit_bound_evidence() -> None:
    organization, repository, scope, actor = governance_tenant()
    imported_work = import_work_item(
        actor=actor,
        payload=work_payload(organization, repository, scope),
    )
    duplicate_work = import_work_item(
        actor=actor,
        payload=imported_work.work_item_revision.normalized_payload
        | {
            "schema_version": "1.0",
            "organization_id": str(organization.id),
        },
    )
    assert duplicate_work.created is False
    assert WorkSummary.objects.filter(work_item_revision=imported_work.work_item_revision).exists()
    approval, created = approve_work_item_revision(
        actor=actor,
        repository_id=repository.id,
        work_item_revision_id=imported_work.work_item_revision.id,
        status="APPROVED",
        target_kind="WORK_ITEM_REVISION",
        target_key=str(imported_work.work_item_revision.id),
        reason="Approved for this exact revision.",
    )
    assert created is True
    approval_revocation, created = revoke_work_item_approval(
        actor=actor,
        repository_id=repository.id,
        approval_id=approval.id,
        reason="Intent changed outside this revision.",
    )
    assert created is True
    assert approval_revocation.approval_id == approval.id
    summary_result = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="a" * 40,
        reference_time=timezone.now(),
    )
    summary_only = summary_result.mappings
    assert summary_result.created is True
    assert summary_only[0].assessment == "GAP"
    assert summary_only[0].gap_code == "NO_ELIGIBLE_EVIDENCE"

    imported_policy = import_policy(
        actor=actor,
        payload=policy_payload(organization, repository, scope),
    )
    reference_time = timezone.now()
    first_evaluation, first_created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        commit_sha="a" * 40,
        policy_version_ids=[imported_policy.policy_version.id],
        reference_time=reference_time,
        affected_paths=["src/anva/core/models.py"],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
    )
    second_evaluation, second_created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        commit_sha="a" * 40,
        policy_version_ids=[imported_policy.policy_version.id],
        reference_time=reference_time,
        affected_paths=["src/anva/core/models.py"],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
    )
    assert first_created is True
    assert second_created is False
    assert second_evaluation.id == first_evaluation.id
    assert second_evaluation.output_hash == first_evaluation.output_hash
    assert first_evaluation.output_payload["controls"][0]["code"] == "TESTS_PASS"

    manifest_payload = deepcopy(EXAMPLES["evidence-manifest"])
    manifest_payload.update(
        {
            "manifest_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_revision_id": str(imported_work.work_item_revision.id),
            "pull_request_number": 17,
            "commit_sha": "a" * 40,
        }
    )
    manifest_payload["entries"][0]["evidence_id"] = str(uuid.uuid4())  # type: ignore[index]
    imported_evidence = submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        payload=manifest_payload,
    )
    duplicate_evidence = submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        payload=manifest_payload,
    )
    assert imported_evidence.created is True
    assert duplicate_evidence.created is False
    reused_manifest_id = deepcopy(manifest_payload)
    reused_manifest_id["entries"][0]["evidence_id"] = str(uuid.uuid4())  # type: ignore[index]
    reused_manifest_id["entries"][0]["content_hash"] = "9" * 64  # type: ignore[index]
    with pytest.raises(IdempotencyConflictError, match="manifest ID"):
        submit_evidence_manifest(
            actor=actor,
            repository_id=repository.id,
            pull_request_number=17,
            payload=reused_manifest_id,
        )
    duplicate_identity = deepcopy(manifest_payload)
    duplicate_identity["manifest_id"] = str(uuid.uuid4())
    duplicate_entry = deepcopy(duplicate_identity["entries"][0])  # type: ignore[index]
    duplicate_entry["evidence_id"] = str(uuid.uuid4())
    duplicate_identity["entries"].append(duplicate_entry)  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="content/kind/name"):
        submit_evidence_manifest(
            actor=actor,
            repository_id=repository.id,
            pull_request_number=17,
            payload=duplicate_identity,
        )
    mapping_reference_time = timezone.now()

    exact_result = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="a" * 40,
        reference_time=mapping_reference_time,
    )
    stale_result = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="b" * 40,
        reference_time=mapping_reference_time,
    )
    exact = exact_result.mappings
    stale = stale_result.mappings
    assert len(exact) == len(stale) == 1
    assert exact[0].assessment == "SATISFIED"
    assert exact[0].evidence_id == imported_evidence.evidence[0].id
    assert stale[0].assessment == "GAP"
    assert stale[0].gap_code == "STALE_EVIDENCE_ONLY"

    with pytest.raises(DatabaseError), transaction.atomic():
        WorkSummary.objects.filter(work_item_revision=imported_work.work_item_revision).update(
            producer="mutated"
        )

    foreign = Organization.objects.create(slug="foreign-governance", name="Foreign")
    with pytest.raises(IntegrityError), transaction.atomic():
        Requirement.objects.create(
            organization=foreign,
            work_item_revision=imported_work.work_item_revision,
            position=99,
            code="FOREIGN_REQ",
            normalized_text="Cross-tenant graft",
            origin="test",
            status="CONFIRMED",
        )
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    second_payload = work_payload(organization, repository, scope)
    second_payload["external_key"] = "ANVA-6-SECOND"
    second_work = import_work_item(actor=actor, payload=second_payload)
    second_requirement = Requirement.objects.get(
        work_item_revision=second_work.work_item_revision,
    )
    with pytest.raises(DatabaseError, match="criterion requirement binding"), transaction.atomic():
        AcceptanceCriterion.objects.create(
            organization=organization,
            work_item_revision=imported_work.work_item_revision,
            position=99,
            requirement=second_requirement,
            code="GRAFTED_CRITERION",
            normalized_text="Must be rejected by the database.",
            required_evidence_types=["TEST_RESULT"],
        )
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    other_repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:governance/{uuid.uuid4()}",
        name="Manifest graft repository",
    )
    graft_artifact = ImmutableArtifact.objects.create(
        organization=organization,
        access_scope=scope,
        kind=ImmutableArtifact.Kind.EVIDENCE_MANIFEST,
        schema_name="evidence-manifest",
        schema_version="1.0",
        payload={"graft": str(uuid.uuid4())},
    )
    with pytest.raises(DatabaseError, match="manifest work binding"), transaction.atomic():
        EvidenceManifest.objects.create(
            organization=organization,
            repository=other_repository,
            access_scope=scope,
            artifact=graft_artifact,
            work_item_revision=imported_work.work_item_revision,
            pull_request_number=17,
            commit_sha="a" * 40,
            schema_version="1.0",
            producer="graft",
            producer_version="1",
            producer_mode="CI",
            payload_hash=graft_artifact.content_hash,
            payload_size=1,
        )
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_lower_scope_cannot_weaken_and_exact_override_is_revocable() -> None:
    organization, repository, scope, actor = governance_tenant()
    imported_work = import_work_item(
        actor=actor,
        payload=work_payload(organization, repository, scope),
    )
    required_payload = policy_payload(organization, repository, scope)
    required_policy = import_policy(actor=actor, payload=required_payload)

    lower_payload = policy_payload(organization, repository, scope)
    lower_payload["name"] = "Advisory path policy"
    lower_payload["binding"]["scope_level"] = "PATH"  # type: ignore[index]
    lower_payload["binding"]["path_patterns"] = ["src/**"]  # type: ignore[index]
    lower_payload["requirements"][0]["enforcement"] = "ADVISORY"  # type: ignore[index]
    lower_policy = import_policy(actor=actor, payload=lower_payload)

    blocked, _created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=18,
        commit_sha="c" * 40,
        policy_version_ids=[
            required_policy.policy_version.id,
            lower_policy.policy_version.id,
        ],
        reference_time=timezone.now(),
        affected_paths=["src/anva/core/models.py"],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
    )
    assert blocked.output_payload["outcome"] == "CONTROLS_CALCULATED"
    assert blocked.output_payload["controls"][0]["code"] == "TESTS_PASS"
    assert blocked.output_payload["controls"][0]["enforcement"] == "BLOCKING"

    override, created = create_policy_override(
        actor=actor,
        repository_id=repository.id,
        policy_id=required_policy.policy.id,
        policy_evaluation_id=blocked.id,
        policy_version_id=required_policy.policy_version.id,
        requirement_code="TESTS_PASS",
        pull_request_number=18,
        commit_sha="c" * 40,
        reason="Approved exception for this exact change.",
        expires_at=None,
    )
    assert created is True
    allowed, _created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=18,
        commit_sha="c" * 40,
        policy_version_ids=[
            required_policy.policy_version.id,
            lower_policy.policy_version.id,
        ],
        reference_time=timezone.now(),
        affected_paths=["src/anva/core/models.py"],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
    )
    assert allowed.output_payload["outcome"] == "CONTROLS_CALCULATED"
    assert allowed.output_payload["controls"][0]["enforcement"] == "ADVISORY"
    assert allowed.output_payload["applied_overrides"][0]["override_id"] == str(override.id)

    revocation, created = revoke_policy_override(
        actor=actor,
        repository_id=repository.id,
        policy_override_id=override.id,
        reason="Exception is no longer authorized.",
    )
    assert created is True
    after_revocation, _created = evaluate_policy(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=18,
        commit_sha="c" * 40,
        policy_version_ids=[
            required_policy.policy_version.id,
            lower_policy.policy_version.id,
        ],
        reference_time=timezone.now(),
        affected_paths=["src/anva/core/models.py"],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=imported_work.work_item_revision.id,
    )
    assert after_revocation.output_payload["controls"][0]["enforcement"] == "BLOCKING"
    assert after_revocation.input_payload["active_override_ids"] == []
    assert revocation.policy_override_id == override.id

    unrelated_policy = import_policy(
        actor=actor,
        payload=policy_payload(organization, repository, scope),
    )
    with pytest.raises(DatabaseError, match="policy override binding"), transaction.atomic():
        PolicyOverride.objects.create(
            organization=organization,
            policy_evaluation=blocked,
            policy_version=unrelated_policy.policy_version,
            repository=repository,
            pull_request_number=18,
            requirement_code="TESTS_PASS",
            commit_sha="c" * 40,
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
            authority_path="direct-graft",
            reason="Must be rejected.",
            idempotency_key=content_hash({"graft": str(uuid.uuid4())}),
        )
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_repository_bound_actor_cannot_import_cross_repository_policy() -> None:
    organization, repository, scope, actor = governance_tenant()
    other_repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:governance/{uuid.uuid4()}",
        name="Other repository",
    )
    payload = policy_payload(organization, repository, scope)
    payload["binding"]["repository_ids"] = [  # type: ignore[index]
        str(repository.id),
        str(other_repository.id),
    ]

    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        import_policy(
            actor=replace(actor, repository_id=repository.id),
            payload=payload,
        )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_every_required_evidence_type_gets_a_mapping_and_required_approval_is_enforced() -> None:
    organization, repository, scope, actor = governance_tenant()
    payload = work_payload(organization, repository, scope)
    payload["requirements"][0]["requires_approval"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="MANUAL_APPROVAL"):
        import_work_item(actor=actor, payload=payload)

    payload["acceptance_criteria"][0]["manual_approval_allowed"] = True  # type: ignore[index]
    payload["acceptance_criteria"][0]["required_evidence_types"] = [  # type: ignore[index]
        "TEST_RESULT",
        "MANUAL_APPROVAL",
    ]
    imported_work = import_work_item(actor=actor, payload=payload)

    approval, _created = approve_work_item_revision(
        actor=actor,
        repository_id=repository.id,
        work_item_revision_id=imported_work.work_item_revision.id,
        status="APPROVED",
        target_kind="REQUIREMENT",
        target_key="REQ_VERSION_INTENT",
        reason="The exact requirement is approved.",
    )
    manifest_payload = deepcopy(EXAMPLES["evidence-manifest"])
    manifest_payload.update(
        {
            "manifest_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_revision_id": str(imported_work.work_item_revision.id),
            "pull_request_number": 19,
            "commit_sha": "d" * 40,
        }
    )
    manifest_payload["entries"][0]["evidence_id"] = str(uuid.uuid4())  # type: ignore[index]
    manual_entry = deepcopy(manifest_payload["entries"][0])  # type: ignore[index]
    manual_completed_at = timezone.now()
    manual_entry.update(
        {
            "evidence_id": str(uuid.uuid4()),
            "kind": "MANUAL_APPROVAL",
            "name": "requirement approval",
            "command": "",
            "approval_id": str(approval.id),
            "content_hash": "e" * 64,
            "started_at": None,
            "completed_at": manual_completed_at.isoformat(),
            "retention_expires_at": (manual_completed_at + timedelta(days=1)).isoformat(),
        }
    )
    manifest_payload["entries"].append(manual_entry)  # type: ignore[attr-defined]
    submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=19,
        payload=manifest_payload,
    )

    mapping_result = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=19,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="d" * 40,
        reference_time=timezone.now(),
    )
    mappings = mapping_result.mappings
    assert [(item.required_evidence_type, item.assessment) for item in mappings] == [
        ("MANUAL_APPROVAL", "SATISFIED"),
        ("TEST_RESULT", "SATISFIED"),
    ]
    assert all(item.pull_request_number == 19 for item in mappings)
    assert all(
        item.input_hash and item.engine_version == "criterion-evidence-v1" for item in mappings
    )
    late_historical_reference_time = timezone.now()
    revoke_work_item_approval(
        actor=actor,
        repository_id=repository.id,
        approval_id=approval.id,
        reason="Approval withdrawn.",
    )
    historical_after_revocation = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=19,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="d" * 40,
        reference_time=late_historical_reference_time,
    )
    assert all(item.assessment == "SATISFIED" for item in historical_after_revocation.mappings)
    after_revocation = map_criterion_evidence(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=19,
        work_item_revision_id=imported_work.work_item_revision.id,
        commit_sha="d" * 40,
        reference_time=timezone.now(),
    )
    assert [
        (item.required_evidence_type, item.assessment) for item in after_revocation.mappings
    ] == [
        ("MANUAL_APPROVAL", "GAP"),
        ("TEST_RESULT", "SATISFIED"),
    ]


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_governance_mutations_require_write_authority_and_scope_membership() -> None:
    organization, repository, scope, admin = governance_tenant()
    imported_work = import_work_item(
        actor=admin,
        payload=work_payload(organization, repository, scope),
    )
    imported_policy = import_policy(
        actor=admin,
        payload=policy_payload(organization, repository, scope),
    )
    viewer_role = Role.objects.create(
        organization=organization,
        code=Role.Code.VIEWER,
        name="Viewer",
    )
    viewer_user = User.objects.create(
        email=f"viewer-{uuid.uuid4()}@example.test",
        display_name="Viewer",
    )
    Membership.objects.create(
        organization=organization,
        user=viewer_user,
        role=viewer_role,
    )
    viewer = replace(admin, actor_id=str(viewer_user.id))
    with pytest.raises(ResourceNotFoundError):
        map_criterion_evidence(
            actor=viewer,
            repository_id=repository.id,
            pull_request_number=20,
            work_item_revision_id=imported_work.work_item_revision.id,
            commit_sha="f" * 40,
            reference_time=timezone.now(),
        )
    with pytest.raises(ResourceNotFoundError):
        evaluate_policy(
            actor=viewer,
            repository_id=repository.id,
            pull_request_number=20,
            commit_sha="f" * 40,
            policy_version_ids=[imported_policy.policy_version.id],
            reference_time=timezone.now(),
            affected_paths=[],
            affected_entities=[],
            target_branch="main",
            work_item_revision_id=imported_work.work_item_revision.id,
        )

    manager_role = Role.objects.create(
        organization=organization,
        code=Role.Code.KNOWLEDGE_ADMIN,
        name="Knowledge admin",
    )
    manager_user = User.objects.create(
        email=f"manager-{uuid.uuid4()}@example.test",
        display_name="Manager",
    )
    Membership.objects.create(
        organization=organization,
        user=manager_user,
        role=manager_role,
    )
    approved_payload = work_payload(organization, repository, scope)
    approved_payload["status"] = "APPROVED"
    with pytest.raises(ResourceNotFoundError):
        import_work_item(
            actor=replace(admin, actor_id=str(manager_user.id)),
            payload=approved_payload,
        )

    admin_membership = Membership.objects.get(
        organization=organization,
        user_id=uuid.UUID(admin.actor_id),
    )
    restricted_scope = AccessScope.objects.create(
        organization=organization,
        name="admin-only",
        all_repositories=True,
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=restricted_scope,
        membership=admin_membership,
    )
    restricted_work_payload = work_payload(organization, repository, restricted_scope)
    restricted_work_payload["external_key"] = "ANVA-6-RESTRICTED"
    restricted_work = import_work_item(actor=admin, payload=restricted_work_payload)
    restricted_policy = import_policy(
        actor=admin,
        payload=policy_payload(organization, repository, restricted_scope),
    )
    evaluation, _created = evaluate_policy(
        actor=admin,
        repository_id=repository.id,
        pull_request_number=22,
        commit_sha="2" * 40,
        policy_version_ids=[restricted_policy.policy_version.id],
        reference_time=timezone.now(),
        affected_paths=[],
        affected_entities=[],
        target_branch="main",
        work_item_revision_id=restricted_work.work_item_revision.id,
    )
    security_role = Role.objects.create(
        organization=organization,
        code=Role.Code.SECURITY_REVIEWER,
        name="Security reviewer",
    )
    security_user = User.objects.create(
        email=f"security-{uuid.uuid4()}@example.test",
        display_name="Security",
    )
    Membership.objects.create(
        organization=organization,
        user=security_user,
        role=security_role,
    )
    with pytest.raises(ResourceNotFoundError):
        create_policy_override(
            actor=replace(admin, actor_id=str(security_user.id)),
            repository_id=repository.id,
            policy_id=restricted_policy.policy.id,
            policy_evaluation_id=evaluation.id,
            policy_version_id=restricted_policy.policy_version.id,
            requirement_code="TESTS_PASS",
            pull_request_number=22,
            commit_sha="2" * 40,
            reason="Caller lacks the evaluation scope.",
            expires_at=None,
        )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_policy_entity_types_and_every_bound_repository_are_authoritative() -> None:
    organization, repository, _scope, actor = governance_tenant()
    admin_membership = Membership.objects.get(
        organization=organization,
        user_id=uuid.UUID(actor.actor_id),
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="restricted repositories",
        all_memberships=False,
        all_repositories=False,
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=scope,
        membership=admin_membership,
    )
    AccessScopeRepository.objects.create(
        organization=organization,
        access_scope=scope,
        repository=repository,
    )
    other_repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:governance/{uuid.uuid4()}",
        name="Unauthorized binding target",
    )
    cross_repository = policy_payload(organization, repository, scope)
    cross_repository["binding"]["repository_ids"] = [  # type: ignore[index]
        str(repository.id),
        str(other_repository.id),
    ]
    with pytest.raises(ResourceNotFoundError):
        import_policy(actor=actor, payload=cross_repository)

    duplicate_requirements = policy_payload(organization, repository, scope)
    duplicate_requirements["requirements"].append(  # type: ignore[attr-defined]
        deepcopy(duplicate_requirements["requirements"][0])  # type: ignore[index]
    )
    with pytest.raises(ValueError, match="requirement IDs"):
        import_policy(actor=actor, payload=duplicate_requirements)

    entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:checkout",
        display_name="Checkout",
        access_scope=scope,
    )
    payload = policy_payload(organization, repository, scope)
    payload["binding"]["entity_ids"] = [str(entity.id)]  # type: ignore[index]
    payload["binding"]["entity_types"] = ["SERVICE"]  # type: ignore[index]
    imported = import_policy(actor=actor, payload=payload)
    with pytest.raises(ResourceNotFoundError):
        evaluate_policy(
            actor=actor,
            repository_id=repository.id,
            pull_request_number=21,
            commit_sha="1" * 40,
            policy_version_ids=[imported.policy_version.id],
            reference_time=timezone.now(),
            affected_paths=[],
            affected_entities=[{"id": str(entity.id), "type": "COMPONENT"}],
            target_branch="main",
        )
