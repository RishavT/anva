"""End-to-end durable ingestion behavior through the leased job boundary."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from django.db import DatabaseError, transaction
from django.utils import timezone

from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    AssertionConflict,
    BackgroundJob,
    IngestionFailure,
    IngestionStageResult,
    KnowledgeAssertion,
    KnowledgeRelationship,
    Membership,
    Organization,
    ParsedSource,
    Repository,
    Role,
    SourceChunk,
    SourceChunkVisibility,
    SourceConnection,
    SourceDocument,
    SourceObservation,
    SourceRevision,
    SyncRun,
    User,
)
from anva.core.services.context import ActorContext
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.jobs import cancel_job, claim_next_job, complete_job, enqueue_job
from anva.core.services.retrieval import (
    authorized_relationships,
    authorized_source_chunks,
)
from anva.core.services.scopes import revoke_source_connection


def _actor(
    organization: Organization,
    repository: Repository,
    role_code: str,
    label: str,
) -> ActorContext:
    role, _created = Role.objects.get_or_create(
        organization=organization,
        code=role_code,
        defaults={"name": role_code},
    )
    user = User.objects.create(
        email=f"{label}-{uuid.uuid4()}@example.test",
        display_name=label,
    )
    Membership.objects.create(
        organization=organization,
        user=user,
        role=role,
    )
    return ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="untrusted-test-claim",
        request_id=uuid.uuid4(),
        repository_id=repository.id,
    )


def _source_setup(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    slug: str,
) -> tuple[ActorContext, SourceConnection]:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(root))
    organization = Organization.objects.create(slug=slug, name=slug)
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"filesystem:{slug}",
        name=slug,
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="visible",
        all_memberships=True,
        all_repositories=True,
    )
    actor = _actor(organization, repository, Role.Code.ORG_ADMIN, f"{slug}-admin")
    source, created = connect_filesystem_source(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        external_key=f"filesystem:{slug}",
        display_name=slug,
        root=str(root),
    )
    assert created
    return actor, source


def _execute_requested(actor: ActorContext, source: SourceConnection) -> SyncRun:
    run, created = request_ingestion_sync(
        actor=actor,
        source_connection_id=source.id,
    )
    assert created
    claimed = claim_next_job(worker_id="ingestion-test", lease_seconds=600)
    assert claimed is not None
    assert claimed.kind == "ingestion.sync"
    completed_run = execute_ingestion_job(job=claimed, worker_id="ingestion-test")
    complete_job(
        actor=ActorContext(
            organization_id=actor.organization_id,
            actor_type="SERVICE",
            actor_id="ingestion-test",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=claimed.id,
        worker_id="ingestion-test",
        now=timezone.now(),
    )
    return completed_run


@pytest.mark.integration
@pytest.mark.django_db
def test_unchanged_changed_and_a_to_b_to_a_sync_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_file = tmp_path / "service.json"
    source_file.write_text(json.dumps({"service": "api", "owner": "team-a"}))
    actor, source = _source_setup(tmp_path, monkeypatch, slug="history")

    first = _execute_requested(actor, source)
    second = _execute_requested(actor, source)
    source_file.write_text(json.dumps({"service": "api", "owner": "team-b"}))
    third = _execute_requested(actor, source)
    source_file.write_text(json.dumps({"service": "api", "owner": "team-a"}))
    fourth = _execute_requested(actor, source)

    document = SourceDocument.objects.get(source_container__source_connection=source)
    assert [first.state, second.state, third.state, fourth.state] == [
        SyncRun.State.COMPLETED,
        SyncRun.State.COMPLETED,
        SyncRun.State.COMPLETED,
        SyncRun.State.COMPLETED,
    ]
    assert SourceRevision.objects.filter(source_document=document).count() == 2
    assert SourceObservation.objects.filter(source_document=document).count() == 4
    assert ParsedSource.objects.filter(source_revision__source_document=document).count() == 2
    current_revision = document.current_revision
    first_observation_revision = (
        SourceObservation.objects.filter(sync_run=first).get().source_revision
    )
    assert current_revision is not None
    assert first_observation_revision is not None
    assert current_revision.content_hash == first_observation_revision.content_hash
    current_owner = KnowledgeAssertion.objects.get(
        organization=source.organization,
        subject_key="service:api",
        predicate="owned_by",
        valid_until__isnull=True,
    )
    assert current_owner.value == "team-a"


@pytest.mark.integration
@pytest.mark.django_db
def test_full_sync_tombstones_and_reappearance_preserve_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_file = tmp_path / "service.json"
    source_file.write_text('{"service":"api","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="tombstone")
    _execute_requested(actor, source)
    document = SourceDocument.objects.get(source_container__source_connection=source)
    repository = source.repository
    assert repository is not None
    original_revision_id = document.current_revision_id
    assert (
        authorized_source_chunks(
            actor=actor,
            repository_id=repository.id,
        ).count()
        == 1
    )
    assert (
        authorized_relationships(
            actor=actor,
            repository_id=repository.id,
        ).count()
        == 1
    )

    source_file.unlink()
    removed = _execute_requested(actor, source)
    document.refresh_from_db()
    assert removed.tombstoned_count == 1
    assert document.state == SourceDocument.State.TOMBSTONED
    assert SourceChunkVisibility.objects.filter(
        source_location__source_observation__source_document=document,
        state=SourceChunkVisibility.State.SOURCE_UNAVAILABLE,
    ).exists()
    assert not KnowledgeAssertion.objects.filter(
        organization=source.organization,
        valid_until__isnull=True,
    ).exists()
    assert not authorized_source_chunks(
        actor=actor,
        repository_id=repository.id,
    ).exists()
    assert not authorized_relationships(
        actor=actor,
        repository_id=repository.id,
    ).exists()

    source_file.write_text('{"service":"api","owner":"platform"}')
    restored = _execute_requested(actor, source)
    document.refresh_from_db()
    assert restored.processed_count == 1
    assert document.state == SourceDocument.State.PRESENT
    assert document.current_revision_id == original_revision_id
    assert SourceRevision.objects.filter(source_document=document).count() == 1
    assert SourceChunkVisibility.objects.filter(
        source_location__source_observation__source_document=document,
        state=SourceChunkVisibility.State.AVAILABLE,
    ).exists()
    assert (
        authorized_source_chunks(
            actor=actor,
            repository_id=repository.id,
        ).count()
        == 1
    )
    assert (
        authorized_relationships(
            actor=actor,
            repository_id=repository.id,
        ).count()
        == 1
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_malformed_items_are_isolated_and_conflicting_sources_are_retained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.json").write_text('{"service":"api","owner":"team-a"}')
    (tmp_path / "b.json").write_text('{"service":"api","owner":"team-b"}')
    (tmp_path / "bad.json").write_text("{not-json")
    actor, source = _source_setup(tmp_path, monkeypatch, slug="partial")

    run = _execute_requested(actor, source)

    assert run.state == SyncRun.State.PARTIALLY_COMPLETED
    assert run.discovered_count == 3
    assert run.processed_count == 2
    assert run.failed_count == 1
    assert IngestionFailure.objects.get(sync_run=run).error_code == "malformed_json"
    owners = KnowledgeAssertion.objects.filter(
        organization=source.organization,
        subject_key="service:api",
        predicate="owned_by",
        valid_until__isnull=True,
    )
    assert {item.value for item in owners} == {"team-a", "team-b"}
    assert (
        AssertionConflict.objects.filter(
            organization=source.organization,
            status=AssertionConflict.Status.OPEN,
        ).count()
        == 1
    )
    assert (
        SourceChunk.objects.filter(
            organization=source.organization,
        ).count()
        == 2
    )
    assert (
        SourceChunkVisibility.objects.filter(
            organization=source.organization,
            state=SourceChunkVisibility.State.AVAILABLE,
        ).count()
        == 2
    )
    relationships = list(
        KnowledgeRelationship.objects.filter(
            organization=source.organization,
            relationship_type=KnowledgeRelationship.RelationshipType.OWNED_BY,
        )
    )
    assert len(relationships) == 2
    assert {
        (relationship.source_entity_type, relationship.target_entity_type)
        for relationship in relationships
    } == {
        (
            "SERVICE",
            "TEAM",
        )
    }
    relationship = relationships[0]
    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            KnowledgeRelationship.objects.filter(id=relationship.id).update(confidence=0.5)
    with pytest.raises(DatabaseError, match="endpoint types"):
        with transaction.atomic():
            KnowledgeRelationship.objects.create(
                organization=relationship.organization,
                relationship_type=relationship.relationship_type,
                source_entity=relationship.target_entity,
                target_entity=relationship.source_entity,
                source_entity_type="SERVICE",
                target_entity_type="TEAM",
                assertion=relationship.assertion,
                source_location=relationship.source_location,
                source_observation=relationship.source_observation,
                access_snapshot=relationship.access_snapshot,
                access_scope=relationship.access_scope,
                extraction_class=relationship.extraction_class,
                confidence=relationship.confidence,
                observed_at=relationship.observed_at,
            )
    chunk = SourceChunk.objects.filter(organization=source.organization).first()
    assert chunk is not None
    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            SourceChunk.objects.filter(id=chunk.id).update(text="rewritten")


@pytest.mark.integration
@pytest.mark.django_db
def test_authorization_precedes_idempotency_and_claimed_jobs_revalidate_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "service.json").write_text('{"service":"api","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="revalidation")
    repository = source.repository
    assert repository is not None
    run, created = request_ingestion_sync(
        actor=actor,
        source_connection_id=source.id,
    )
    assert created
    viewer = _actor(
        source.organization,
        repository,
        Role.Code.VIEWER,
        "viewer",
    )
    with pytest.raises(ResourceNotFoundError):
        request_ingestion_sync(actor=viewer, source_connection_id=source.id)

    claimed = claim_next_job(worker_id="revoked-worker", lease_seconds=600)
    assert claimed is not None
    queued, _created = enqueue_job(
        actor=actor,
        kind="ingestion.sync",
        payload={
            "sync_run_id": str(run.id),
            "source_connection_id": str(source.id),
            "access_snapshot_id": str(run.access_snapshot_id),
        },
        idempotency_key=f"queued-revalidation:{run.id}",
    )
    revoke_source_connection(
        actor=actor,
        source_connection_id=source.id,
        expected_revision=source.revision,
    )
    with pytest.raises(Exception, match="no longer active"):
        execute_ingestion_job(job=claimed, worker_id="revoked-worker")
    cancel_job(
        actor=ActorContext(
            organization_id=actor.organization_id,
            actor_type="SERVICE",
            actor_id="revoked-worker",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=claimed.id,
        worker_id="revoked-worker",
        error_code="source_revoked",
    )
    run.refresh_from_db()
    assert run.state == SyncRun.State.CANCELLED
    assert BackgroundJob.objects.get(id=claimed.id).state == BackgroundJob.State.CANCELLED
    assert BackgroundJob.objects.get(id=queued.id).state == BackgroundJob.State.CANCELLED
    assert not authorized_source_chunks(
        actor=actor,
        repository_id=repository.id,
    ).exists()
    assert not authorized_relationships(
        actor=actor,
        repository_id=repository.id,
    ).exists()


@pytest.mark.integration
@pytest.mark.django_db
def test_whole_run_failure_is_observable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "service.json").write_text('{"service":"api","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="failed-run")
    run, created = request_ingestion_sync(
        actor=actor,
        source_connection_id=source.id,
    )
    assert created
    source.configuration = {"root": 42}
    source.save(update_fields=["configuration", "updated_at"])
    claimed = claim_next_job(worker_id="failed-worker", lease_seconds=600)
    assert claimed is not None

    with pytest.raises(Exception, match="configuration is invalid"):
        execute_ingestion_job(job=claimed, worker_id="failed-worker")

    run.refresh_from_db()
    source.refresh_from_db()
    stage = IngestionStageResult.objects.get(sync_run=run, stage="INGEST")
    assert run.state == SyncRun.State.FAILED
    assert run.failure_code == "invalid_source_configuration"
    assert source.last_error_code == "invalid_source_configuration"
    assert stage.status == IngestionStageResult.Status.FAILED
    assert stage.error_code == "invalid_source_configuration"
    assert stage.completed_at is not None
