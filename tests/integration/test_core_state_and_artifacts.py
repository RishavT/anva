"""PostgreSQL integration tests for tenant, transition, and artifact invariants."""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from django.db import DatabaseError, IntegrityError, connection, transaction

from anva.contracts.catalog import EXAMPLES
from anva.core.exceptions import (
    InvalidStateTransitionError,
    OptimisticConcurrencyError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AccessScope,
    ArtifactImmutableError,
    AssuranceRun,
    AuditEvent,
    ImmutableArtifact,
    KnowledgeAssertion,
    Membership,
    Organization,
    OutboxEvent,
    Repository,
    Role,
    SourceConnection,
    SyncRun,
    User,
)
from anva.core.services.artifacts import create_artifact, require_artifact_organization
from anva.core.services.authorization import NOT_FOUND_MESSAGE
from anva.core.services.context import ActorContext
from anva.core.services.creation import (
    create_assertion,
    request_assurance_run,
    request_sync_run,
    submit_knowledge_proposal,
)
from anva.core.services.transitions import (
    transition_assertion_review,
    transition_assurance_run,
    transition_knowledge_proposal,
    transition_sync_run,
)


def actor_for(organization: Organization) -> ActorContext:
    role, _ = Role.objects.get_or_create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        defaults={"name": "Organization administrator"},
    )
    user = User.objects.create(
        email=f"{uuid.uuid4()}@example.test",
        display_name="Test administrator",
    )
    Membership.objects.create(organization=organization, user=user, role=role)
    return ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="untrusted-test-claim",
        request_id=uuid.uuid4(),
        source_ip_hash="a" * 64,
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_cross_organization_foreign_keys_fail_in_postgresql() -> None:
    first = Organization.objects.create(slug="first", name="First")
    second = Organization.objects.create(slug="second", name="Second")
    foreign_connection = SourceConnection.objects.create(
        organization=second,
        external_key="github:second/repository",
    )
    foreign_artifact = ImmutableArtifact.objects.create(
        organization=second,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload=EXAMPLES["context-packet"],
    )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            SyncRun.objects.create(
                organization=first,
                source_connection=foreign_connection,
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS core_sync_org_connection_fk IMMEDIATE")

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            AssuranceRun.objects.create(
                organization=first,
                repository_external_id="github:first/repository",
                pull_request_number=1,
                head_commit="a" * 40,
                policy_version=1,
                context_artifact=foreign_artifact,
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS core_assurance_org_artifact_fk IMMEDIATE")


@pytest.mark.integration
@pytest.mark.django_db
def test_content_addressed_artifacts_are_idempotent_and_database_immutable() -> None:
    organization = Organization.objects.create(slug="artifacts", name="Artifacts")
    actor = actor_for(organization)
    repository = Repository.objects.create(
        organization=organization,
        external_id="github:artifacts/repository",
        name="Artifacts",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="artifact authors",
        all_memberships=True,
        all_repositories=True,
    )

    artifact, created = create_artifact(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload=EXAMPLES["context-packet"],
    )
    predecessor, created_again = create_artifact(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload=EXAMPLES["context-packet"],
    )

    assert created
    assert not created_again
    assert predecessor.id == artifact.id
    assert len(artifact.content_hash) == 64
    artifact.payload = {"changed": True}
    with pytest.raises(ArtifactImmutableError):
        artifact.save()
    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            ImmutableArtifact.objects.filter(id=artifact.id).update(payload={"changed": True})
    with pytest.raises(ValueError, match="metadata must match"):
        create_artifact(
            actor=actor,
            repository_id=repository.id,
            access_scope_id=scope.id,
            kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
            schema_name="context-packet",
            schema_version="2.0",
            payload=EXAMPLES["context-packet"],
        )


@pytest.mark.integration
@pytest.mark.django_db
def test_artifact_lookup_hides_foreign_or_missing_ids() -> None:
    owner = Organization.objects.create(slug="artifact-owner", name="Artifact Owner")
    caller = Organization.objects.create(slug="artifact-caller", name="Artifact Caller")
    foreign = ImmutableArtifact.objects.create(
        organization=owner,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload=EXAMPLES["context-packet"],
    )

    errors: list[tuple[str, str]] = []
    for artifact_id in (foreign.id, uuid.uuid4()):
        with pytest.raises(ResourceNotFoundError) as captured:
            require_artifact_organization(artifact_id, caller.id)
        errors.append((captured.value.code, str(captured.value)))

    assert set(errors) == {("resource_not_found", NOT_FOUND_MESSAGE)}


@pytest.mark.integration
@pytest.mark.django_db
def test_audit_rows_cannot_be_updated_or_deleted() -> None:
    organization = Organization.objects.create(slug="audit", name="Audit")
    actor = actor_for(organization)
    connection_record = SourceConnection.objects.create(
        organization=organization,
        external_key="github:audit/repository",
    )
    run, _ = request_sync_run(actor=actor, source_connection_id=connection_record.id)
    event = AuditEvent.objects.get(target_id=run.id)

    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            AuditEvent.objects.filter(id=event.id).update(actor_id="rewritten")
    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            AuditEvent.objects.filter(id=event.id).delete()


@pytest.mark.integration
@pytest.mark.django_db
def test_authoritative_transition_audits_and_enforces_revision() -> None:
    organization = Organization.objects.create(slug="states", name="States")
    actor = actor_for(organization)
    repository = Repository.objects.create(
        organization=organization,
        external_id="github:states/repository",
        name="States",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="knowledge authors",
        all_memberships=True,
        all_repositories=True,
    )
    assertion = create_assertion(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        subject_key="service:checkout",
        predicate="owned_by",
        value={"team": "payments"},
        provenance=[{"source_id": str(uuid.uuid4())}],
    )

    reviewed = transition_assertion_review(
        actor=actor,
        assertion_id=assertion.id,
        target_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
        expected_revision=1,
    )

    assert reviewed.revision == 2
    assert AuditEvent.objects.filter(target_id=assertion.id).count() == 2
    assert OutboxEvent.objects.filter(aggregate_id=assertion.id).count() == 2
    with pytest.raises(OptimisticConcurrencyError):
        transition_assertion_review(
            actor=actor,
            assertion_id=assertion.id,
            target_state=KnowledgeAssertion.ReviewState.DISPUTED,
            expected_revision=1,
        )
    with pytest.raises(InvalidStateTransitionError):
        transition_assertion_review(
            actor=actor,
            assertion_id=assertion.id,
            target_state=KnowledgeAssertion.ReviewState.REJECTED,
            expected_revision=2,
        )


@pytest.mark.integration
@pytest.mark.django_db
def test_transition_and_audit_roll_back_together() -> None:
    organization = Organization.objects.create(slug="rollback", name="Rollback")
    actor = actor_for(organization)
    connection_record = SourceConnection.objects.create(
        organization=organization,
        external_key="github:rollback/repository",
    )
    run, _ = request_sync_run(actor=actor, source_connection_id=connection_record.id)
    initial_audits = AuditEvent.objects.count()
    initial_outbox = OutboxEvent.objects.count()

    with (
        patch(
            "anva.core.services.transitions.record_transition",
            side_effect=RuntimeError("outbox unavailable"),
        ),
        pytest.raises(RuntimeError, match="outbox unavailable"),
    ):
        transition_sync_run(
            actor=actor,
            run_id=run.id,
            target_state=SyncRun.State.DISCOVERING,
            expected_revision=1,
        )

    run.refresh_from_db()
    assert run.state == SyncRun.State.REQUESTED
    assert run.revision == 1
    assert AuditEvent.objects.count() == initial_audits
    assert OutboxEvent.objects.count() == initial_outbox


@pytest.mark.integration
@pytest.mark.django_db
def test_sync_request_is_idempotent_and_tenant_scoped() -> None:
    organization = Organization.objects.create(slug="sync", name="Sync")
    other = Organization.objects.create(slug="sync-other", name="Sync Other")
    actor = actor_for(organization)
    connection_record = SourceConnection.objects.create(
        organization=organization,
        external_key="github:sync/repository",
    )

    first, created = request_sync_run(actor=actor, source_connection_id=connection_record.id)
    second, created_again = request_sync_run(actor=actor, source_connection_id=connection_record.id)

    assert created
    assert not created_again
    assert first.id == second.id
    with pytest.raises(ResourceNotFoundError, match=NOT_FOUND_MESSAGE):
        request_sync_run(actor=actor_for(other), source_connection_id=connection_record.id)


@pytest.mark.integration
@pytest.mark.django_db
def test_new_assurance_head_stales_older_run_and_completion_is_commit_pinned() -> None:
    organization = Organization.objects.create(slug="assurance", name="Assurance")
    actor = actor_for(organization)
    repository = Repository.objects.create(
        organization=organization,
        external_id="github:anva/repository",
        name="Anva",
    )
    older, _ = request_assurance_run(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=42,
        head_commit="a" * 40,
        policy_version=2,
    )
    newer, created = request_assurance_run(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=42,
        head_commit="b" * 40,
        policy_version=2,
    )

    older.refresh_from_db()
    assert created
    assert older.state == AssuranceRun.State.STALE
    assert older.completed_at is not None
    assert newer.state == AssuranceRun.State.REQUESTED

    newer.state = AssuranceRun.State.PUBLISHING
    newer.revision = 10
    newer.save(update_fields=["state", "revision", "updated_at"])
    with pytest.raises(InvalidStateTransitionError):
        transition_assurance_run(
            actor=actor,
            run_id=newer.id,
            target_state=AssuranceRun.State.COMPLETED,
            expected_revision=10,
            evaluated_commit=newer.head_commit,
            report_commit="c" * 40,
        )

    completed = transition_assurance_run(
        actor=actor,
        run_id=newer.id,
        target_state=AssuranceRun.State.COMPLETED,
        expected_revision=10,
        evaluated_commit=newer.head_commit,
        report_commit=newer.head_commit,
    )
    assert completed.completed_at is not None


@pytest.mark.integration
@pytest.mark.django_db
def test_proposal_cannot_be_accepted_before_review() -> None:
    organization = Organization.objects.create(slug="proposal", name="Proposal")
    actor = actor_for(organization)
    proposal = submit_knowledge_proposal(
        actor=actor,
        summary="Correct ownership",
        proposed_changes=[{"operation": "CORRECT"}],
        anva_sources=[{"source_id": str(uuid.uuid4())}],
    )

    with pytest.raises(InvalidStateTransitionError):
        transition_knowledge_proposal(
            actor=actor,
            proposal_id=proposal.id,
            target_state="ACCEPTED",
            expected_revision=1,
        )
