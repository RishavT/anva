"""Authorized source lifecycle and idempotent filesystem ingestion orchestration."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path

from django.db import connection, transaction
from django.db.models import QuerySet
from django.utils import timezone

from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    AccessScopeSource,
    AccessSnapshot,
    AssertionConflict,
    AssertionProvenance,
    AssertionValidityInterval,
    BackgroundJob,
    ContextPacketInvalidation,
    EntityAlias,
    EntityResolution,
    IngestionFailure,
    IngestionStageResult,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeRelationship,
    Organization,
    ParsedSource,
    Repository,
    SourceChunk,
    SourceChunkVisibility,
    SourceConnection,
    SourceContainer,
    SourceContentArtifact,
    SourceDocument,
    SourceLocation,
    SourceObservation,
    SourceRevision,
    SyncCursor,
    SyncRun,
)
from anva.core.models import (
    ExtractionResult as StoredExtractionResult,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.jobs import enqueue_job, require_current_lease
from anva.core.services.scopes import create_access_snapshot
from anva.core.services.search_index import index_source_chunk
from anva.ingestion.errors import IngestionError
from anva.ingestion.extractors import MechanicalExtractor
from anva.ingestion.filesystem import FilesystemConnector
from anva.ingestion.interfaces import (
    DiscoveryFailure,
    DocumentDescriptor,
    ExtractedClaim,
    JSONValue,
    ParsedDocument,
    choose_parser,
)
from anva.ingestion.limits import IngestionLimits
from anva.ingestion.parsers import default_parsers

INGESTION_JOB_KIND = "ingestion.sync"
INGESTION_IMPLEMENTATION_VERSION = "1"
MAX_SYNC_PAGES = 10_000
SOURCE_CHUNK_CHARS = 4_000
TERMINAL_SYNC_STATES = {
    SyncRun.State.COMPLETED,
    SyncRun.State.PARTIALLY_COMPLETED,
    SyncRun.State.FAILED,
    SyncRun.State.CANCELLED,
}


def _organization(actor: ActorContext) -> Organization:
    return Organization.objects.get(id=actor.organization_id)


def _validated_source_root(raw_root: str) -> Path:
    candidate = Path(raw_root)
    if not candidate.is_absolute():
        raise ValueError("Filesystem source root must be absolute")
    allowed_raw = os.getenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", "/fixtures")
    allowed_roots: list[Path] = []
    for value in allowed_raw.split(os.pathsep):
        if value.strip():
            allowed_roots.append(Path(value).resolve(strict=False))
    resolved = candidate.resolve(strict=True)
    if not any(resolved == root or resolved.is_relative_to(root) for root in allowed_roots):
        raise ValueError("Filesystem source root is outside configured read-only roots")
    return resolved


def connect_filesystem_source(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    external_key: str,
    display_name: str,
    root: str,
) -> tuple[SourceConnection, bool]:
    """Authorize before creating an idempotent read-only filesystem connection."""
    decision = authorize_action(
        actor=actor,
        action=Action.SOURCE_SYNC,
        repository_id=repository_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    if not external_key.strip() or not display_name.strip():
        raise ValueError("external_key and display_name are required")
    source_root = _validated_source_root(root)
    FilesystemConnector(source_root)
    with transaction.atomic():
        organization = _organization(actor)
        repository = get_tenant_record(
            queryset=Repository.objects.filter(is_active=True),
            record_id=repository_id,
            organization_id=actor.organization_id,
        )
        scope = get_tenant_record(
            queryset=AccessScope.objects.filter(is_active=True),
            record_id=access_scope_id,
            organization_id=actor.organization_id,
        )
        existing = SourceConnection.objects.filter(
            organization=organization,
            external_key=external_key,
        ).first()
        expected_configuration = {"root": str(source_root)}
        if existing is not None:
            if (
                existing.repository_id != repository.id
                or existing.access_scope_id != scope.id
                or existing.configuration != expected_configuration
                or existing.connector_kind != SourceConnection.ConnectorKind.FILESYSTEM
            ):
                raise IdempotencyConflictError(
                    "Source external key was already used for different configuration"
                )
            return existing, False
        source = SourceConnection.objects.create(
            organization=organization,
            external_key=external_key,
            display_name=display_name,
            connector_kind=SourceConnection.ConnectorKind.FILESYSTEM,
            configuration=expected_configuration,
            repository=repository,
            access_scope=scope,
            state=SourceConnection.State.ACTIVE,
        )
        AccessScopeSource.objects.create(
            organization=organization,
            access_scope=scope,
            source_connection=source,
        )
        record_transition(
            organization=organization,
            actor=actor,
            target_type="sourceconnection",
            target_id=source.id,
            from_state="",
            to_state=SourceConnection.State.ACTIVE,
            revision=source.revision,
        )
        return source, True


def request_ingestion_sync(
    *,
    actor: ActorContext,
    source_connection_id: uuid.UUID,
    scan_mode: str = SyncRun.ScanMode.FULL,
) -> tuple[SyncRun, bool]:
    """Authorize before idempotency lookup, capture visibility, and enqueue one run."""
    decision = authorize_action(
        actor=actor,
        action=Action.SOURCE_SYNC,
        repository_id=actor.repository_id,
        source_connection_id=source_connection_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    if scan_mode not in SyncRun.ScanMode.values:
        raise ValueError("scan_mode is invalid")
    with transaction.atomic():
        source = get_tenant_record_for_update(
            queryset=SourceConnection.objects.select_related("organization"),
            record_id=source_connection_id,
            organization_id=actor.organization_id,
        )
        if source.access_scope_id is None or source.repository_id is None:
            raise ValueError("Source connection is missing scope or repository")
        existing = (
            SyncRun.objects.select_for_update()
            .filter(
                organization_id=actor.organization_id,
                source_connection=source,
                state__in=[
                    SyncRun.State.REQUESTED,
                    SyncRun.State.DISCOVERING,
                    SyncRun.State.FETCHING,
                    SyncRun.State.PARSING,
                    SyncRun.State.INDEXING,
                    SyncRun.State.EXTRACTING,
                    SyncRun.State.RESOLVING,
                    SyncRun.State.PUBLISHING,
                ],
            )
            .first()
        )
        if existing is not None:
            return existing, False
        snapshot = create_access_snapshot(
            actor=actor,
            source_connection_id=source.id,
            access_scope_id=source.access_scope_id,
            action=Action.SOURCE_SYNC,
        )
        run = SyncRun.objects.create(
            organization=source.organization,
            source_connection=source,
            access_snapshot=snapshot,
            scan_mode=scan_mode,
        )
        record_transition(
            organization=source.organization,
            actor=actor,
            target_type="syncrun",
            target_id=run.id,
            from_state="",
            to_state=run.state,
            revision=run.revision,
        )
        enqueue_job(
            actor=actor,
            kind=INGESTION_JOB_KIND,
            payload={
                "sync_run_id": str(run.id),
                "source_connection_id": str(source.id),
                "access_snapshot_id": str(snapshot.id),
            },
            idempotency_key=f"ingestion-sync:{run.id}",
            max_attempts=3,
        )
        return run, True


def inspect_source(
    *,
    actor: ActorContext,
    source_connection_id: uuid.UUID,
) -> dict[str, object]:
    """Return bounded operational status only after source-view authorization."""
    decision = authorize_action(
        actor=actor,
        action=Action.SOURCE_VIEW,
        repository_id=actor.repository_id,
        source_connection_id=source_connection_id,
        allow_revoked_source=True,
    )
    source = get_tenant_record(
        queryset=SourceConnection.objects.all(),
        record_id=source_connection_id,
        organization_id=actor.organization_id,
    )
    latest = (
        SyncRun.objects.filter(
            organization_id=actor.organization_id,
            source_connection=source,
        )
        .order_by("-started_at")
        .first()
    )
    return {
        "id": str(source.id),
        "display_name": source.display_name,
        "connector_kind": source.connector_kind,
        "state": source.state,
        "revision": source.revision,
        "authorization_path": decision.authorization_path,
        "last_successful_sync_at": (
            source.last_successful_sync_at.isoformat()
            if source.last_successful_sync_at is not None
            else None
        ),
        "latest_sync": _sync_status(latest) if latest is not None else None,
    }


def _sync_status(run: SyncRun) -> dict[str, object]:
    return {
        "id": str(run.id),
        "state": run.state,
        "scan_mode": run.scan_mode,
        "discovered_count": run.discovered_count,
        "processed_count": run.processed_count,
        "failed_count": run.failed_count,
        "tombstoned_count": run.tombstoned_count,
        "failure_code": run.failure_code,
        "started_at": run.started_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


def _worker_actor(organization_id: uuid.UUID, worker_id: str) -> ActorContext:
    return ActorContext(
        organization_id=organization_id,
        actor_type="SERVICE",
        actor_id=worker_id,
        authorization_path="internal:ingestion-worker",
        request_id=uuid.uuid4(),
    )


def _transition_run(run: SyncRun, actor: ActorContext, state: str) -> None:
    run.refresh_from_db(fields=["state", "revision", "completed_at"])
    if run.state == state:
        return
    if run.state in TERMINAL_SYNC_STATES:
        raise IngestionError(
            "sync_run_terminal",
            "A terminal sync run cannot transition to another state",
        )
    previous = str(run.state)
    run.state = state
    run.revision += 1
    terminal = state in {
        SyncRun.State.COMPLETED,
        SyncRun.State.PARTIALLY_COMPLETED,
        SyncRun.State.FAILED,
        SyncRun.State.CANCELLED,
    }
    run.completed_at = timezone.now() if terminal else None
    run.save(update_fields=["state", "revision", "completed_at", "updated_at"])
    record_transition(
        organization=run.organization,
        actor=actor,
        target_type="syncrun",
        target_id=run.id,
        from_state=previous,
        to_state=state,
        revision=run.revision,
    )


def _stage(
    *,
    run: SyncRun,
    job: BackgroundJob,
    stage: str,
    status: str,
    started_at: datetime,
    duration_ms: int = 0,
    error_code: str = "",
) -> IngestionStageResult:
    result, _created = IngestionStageResult.objects.update_or_create(
        organization=run.organization,
        sync_run=run,
        stage=stage,
        implementation_version=INGESTION_IMPLEMENTATION_VERSION,
        defaults={
            "background_job": job,
            "input_version": str(run.access_snapshot_id),
            "output_version": str(run.revision),
            "status": status,
            "duration_ms": duration_ms,
            "error_code": error_code,
            "started_at": started_at,
            "completed_at": None
            if status == IngestionStageResult.Status.RUNNING
            else timezone.now(),
        },
    )
    return result


def _source_document_kind(descriptor: DocumentDescriptor) -> str:
    return SourceDocument.Kind(descriptor.document_format.value)


def _location_defaults(
    parsed: ParsedDocument,
    pointer: str,
    revision: SourceRevision,
) -> dict[str, object]:
    location = next(
        (
            item
            for item in parsed.locations
            if item.get("pointer") == pointer and isinstance(item.get("pointer"), str)
        ),
        {},
    )
    start_line = location.get("start_line")
    end_line = location.get("end_line")
    return {
        "start_line": start_line if isinstance(start_line, int) else None,
        "end_line": end_line if isinstance(end_line, int) else None,
        "excerpt_hash": hashlib.sha256(f"{revision.content_hash}:{pointer}".encode()).hexdigest(),
    }


def _database_jsonb_hash(payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    with connection.cursor() as cursor:
        cursor.execute("SELECT core_ingestion_jsonb_sha256(%s::jsonb)", [serialized])
        row = cursor.fetchone()
    if row is None or not isinstance(row[0], str):
        raise IngestionError("digest_unavailable", "Payload identity could not be computed")
    return row[0]


def _persist_location(
    *,
    organization: Organization,
    stored_parsed: ParsedSource,
    observation: SourceObservation,
    revision: SourceRevision,
    parsed: ParsedDocument,
    pointer: str,
) -> SourceLocation:
    location, _created = SourceLocation.objects.get_or_create(
        organization=organization,
        parsed_source=stored_parsed,
        source_observation=observation,
        pointer=pointer,
        defaults=_location_defaults(parsed, pointer, revision),
    )
    return location


def _assertion_id(
    organization: Organization,
    scope: AccessScope,
    extraction: StoredExtractionResult,
    claim_index: int,
) -> uuid.UUID:
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"anva:{organization.id}:{scope.id}:{extraction.id}:{claim_index}",
    )


def _entity_resolution(
    *,
    organization: Organization,
    scope: AccessScope,
    location: SourceLocation,
    subject_key: str,
    entity_type: str,
) -> KnowledgeEntity | None:
    alias = subject_key.casefold().strip()
    matches = list(
        KnowledgeEntity.objects.filter(
            organization=organization,
            access_scope=scope,
            entityalias__normalized_alias=alias,
            is_active=True,
        )
        .distinct()
        .order_by("id")[:11]
    )
    outcome = EntityResolution.Outcome.MATCHED
    entity: KnowledgeEntity | None = None
    if not matches:
        entity, created = KnowledgeEntity.objects.get_or_create(
            organization=organization,
            entity_type=entity_type,
            canonical_key=subject_key,
            defaults={
                "display_name": subject_key,
                "access_scope": scope,
            },
        )
        outcome = EntityResolution.Outcome.CREATED if created else EntityResolution.Outcome.MATCHED
        EntityAlias.objects.get_or_create(
            organization=organization,
            entity=entity,
            normalized_alias=alias,
            defaults={"source_location": location},
        )
        candidate_ids = [str(entity.id)]
    elif len(matches) == 1:
        entity = matches[0]
        candidate_ids = [str(entity.id)]
    else:
        outcome = EntityResolution.Outcome.AMBIGUOUS
        candidate_ids = [str(item.id) for item in matches]
    EntityResolution.objects.get_or_create(
        organization=organization,
        source_location=location,
        candidate_key=subject_key,
        resolver_version=INGESTION_IMPLEMENTATION_VERSION,
        defaults={
            "outcome": outcome,
            "entity": entity,
            "candidate_ids": candidate_ids,
        },
    )
    return entity


def _entity_type_for_subject(subject_key: str) -> str:
    if subject_key.startswith("service:"):
        return KnowledgeEntity.EntityType.SERVICE
    if subject_key.startswith("component:"):
        return KnowledgeEntity.EntityType.COMPONENT
    if subject_key.startswith("team:"):
        return KnowledgeEntity.EntityType.TEAM
    return KnowledgeEntity.EntityType.UNKNOWN


def _relationship_targets(claim: ExtractedClaim) -> list[str]:
    if isinstance(claim.value, str):
        return [claim.value]
    if isinstance(claim.value, list):
        return [item for item in claim.value if isinstance(item, str)]
    return []


def _persist_relationships(
    *,
    organization: Organization,
    scope: AccessScope,
    assertion: KnowledgeAssertion,
    location: SourceLocation,
    observation: SourceObservation,
    claim: ExtractedClaim,
    source_entity: KnowledgeEntity | None,
) -> None:
    relationship_types = {
        "owned_by": KnowledgeRelationship.RelationshipType.OWNED_BY,
        "maintained_by": KnowledgeRelationship.RelationshipType.MAINTAINED_BY,
        "depends_on": KnowledgeRelationship.RelationshipType.DEPENDS_ON,
    }
    relationship_type = relationship_types.get(claim.predicate)
    if relationship_type is None or source_entity is None:
        return
    target_type = (
        KnowledgeEntity.EntityType.TEAM
        if relationship_type
        in {
            KnowledgeRelationship.RelationshipType.OWNED_BY,
            KnowledgeRelationship.RelationshipType.MAINTAINED_BY,
        }
        else KnowledgeEntity.EntityType.UNKNOWN
    )
    for target_value in _relationship_targets(claim):
        target_prefix = "team" if target_type == KnowledgeEntity.EntityType.TEAM else "source"
        target_key = f"{target_prefix}:{target_value}"
        target_entity, _created = KnowledgeEntity.objects.get_or_create(
            organization=organization,
            entity_type=target_type,
            canonical_key=target_key,
            defaults={
                "display_name": target_value,
                "access_scope": scope,
            },
        )
        EntityAlias.objects.get_or_create(
            organization=organization,
            entity=target_entity,
            normalized_alias=target_key.casefold(),
            defaults={"source_location": location},
        )
        if source_entity.id == target_entity.id:
            continue
        KnowledgeRelationship.objects.get_or_create(
            organization=organization,
            relationship_type=relationship_type,
            source_entity=source_entity,
            target_entity=target_entity,
            assertion=assertion,
            defaults={
                "source_entity_type": source_entity.entity_type,
                "target_entity_type": target_entity.entity_type,
                "source_location": location,
                "source_observation": observation,
                "access_snapshot": observation.access_snapshot,
                "access_scope": scope,
                "extraction_class": claim.extraction_class.value,
                "confidence": claim.confidence,
                "observed_at": observation.observed_at,
            },
        )


def _retain_conflicts(assertion: KnowledgeAssertion) -> None:
    contradictory = KnowledgeAssertion.objects.filter(
        organization=assertion.organization,
        access_scope=assertion.access_scope,
        subject_key=assertion.subject_key,
        predicate=assertion.predicate,
        valid_until__isnull=True,
    ).exclude(id=assertion.id)
    for candidate in contradictory:
        if candidate.value == assertion.value:
            continue
        left, right = sorted((candidate, assertion), key=lambda item: str(item.id))
        AssertionConflict.objects.get_or_create(
            organization=assertion.organization,
            left_assertion=left,
            right_assertion=right,
            defaults={"predicate": assertion.predicate},
        )


def _persist_claim(
    *,
    organization: Organization,
    scope: AccessScope,
    document: SourceDocument,
    observation: SourceObservation,
    revision: SourceRevision,
    parsed: ParsedDocument,
    stored_parsed: ParsedSource,
    stored_extraction: StoredExtractionResult,
    claim: ExtractedClaim,
    claim_index: int,
) -> KnowledgeAssertion:
    location = _persist_location(
        organization=organization,
        stored_parsed=stored_parsed,
        observation=observation,
        revision=revision,
        parsed=parsed,
        pointer=claim.location_pointer,
    )
    subject_key = (
        f"document:{document.external_id}"
        if claim.subject_key == "source:document"
        else claim.subject_key
    )
    now = observation.observed_at
    assertion, created = KnowledgeAssertion.objects.get_or_create(
        id=_assertion_id(organization, scope, stored_extraction, claim_index),
        defaults={
            "organization": organization,
            "subject_key": subject_key,
            "predicate": claim.predicate,
            "value": claim.value,
            "is_inferred": claim.is_inferred,
            "extraction_class": claim.extraction_class.value,
            "extraction_method": claim.extraction_method,
            "confidence": claim.confidence,
            "valid_from": now,
            "observed_at": now,
            "provenance": [{"location_id": str(location.id)}],
            "access_scope": scope,
        },
    )
    if not created and assertion.valid_until is not None:
        assertion.valid_from = now
        assertion.valid_until = None
        assertion.observed_at = now
        assertion.staleness_state = KnowledgeAssertion.StalenessState.FRESH
        assertion.revision += 1
        assertion.save(
            update_fields=[
                "valid_from",
                "valid_until",
                "observed_at",
                "staleness_state",
                "revision",
                "updated_at",
            ]
        )
    AssertionProvenance.objects.get_or_create(
        organization=organization,
        assertion=assertion,
        source_location=location,
        defaults={
            "source_observation": observation,
            "access_snapshot": observation.access_snapshot,
            "extraction_class": claim.extraction_class.value,
            "extraction_method": claim.extraction_method,
            "confidence": claim.confidence,
            "is_inferred": claim.is_inferred,
            "observed_at": observation.observed_at,
        },
    )
    AssertionValidityInterval.objects.get_or_create(
        organization=organization,
        assertion=assertion,
        source_document=document,
        valid_until__isnull=True,
        defaults={
            "source_observation": observation,
            "valid_from": now,
            "observed_from": now,
        },
    )
    source_entity = _entity_resolution(
        organization=organization,
        scope=scope,
        location=location,
        subject_key=subject_key,
        entity_type=_entity_type_for_subject(subject_key),
    )
    _persist_relationships(
        organization=organization,
        scope=scope,
        assertion=assertion,
        location=location,
        observation=observation,
        claim=claim,
        source_entity=source_entity,
    )
    _retain_conflicts(assertion)
    return assertion


def _close_absent_assertions(
    *,
    document: SourceDocument,
    current_assertion_ids: set[uuid.UUID],
    at: datetime,
    unavailable: bool = False,
) -> None:
    intervals: QuerySet[AssertionValidityInterval] = (
        AssertionValidityInterval.objects.select_related("assertion")
        .filter(
            organization=document.organization,
            source_document=document,
            valid_until__isnull=True,
        )
        .exclude(assertion_id__in=current_assertion_ids)
    )
    for interval in intervals:
        interval.valid_until = at
        interval.observed_until = at
        interval.save(update_fields=["valid_until", "observed_until"])
        assertion = interval.assertion
        if not AssertionValidityInterval.objects.filter(
            organization=document.organization,
            assertion=assertion,
            valid_until__isnull=True,
        ).exists():
            assertion.valid_until = at
            assertion.staleness_state = (
                KnowledgeAssertion.StalenessState.SOURCE_UNAVAILABLE
                if unavailable
                else KnowledgeAssertion.StalenessState.CONTRADICTED
            )
            assertion.revision += 1
            assertion.save(
                update_fields=[
                    "valid_until",
                    "staleness_state",
                    "revision",
                    "updated_at",
                ]
            )


def _persist_chunks(
    *,
    organization: Organization,
    stored_parsed: ParsedSource,
    parsed: ParsedDocument,
    observation: SourceObservation,
    revision: SourceRevision,
) -> None:
    root_location = _persist_location(
        organization=organization,
        stored_parsed=stored_parsed,
        observation=observation,
        revision=revision,
        parsed=parsed,
        pointer="/",
    )
    rendered = json.dumps(
        dict(parsed.normalized),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )
    segments = [
        rendered[index : index + SOURCE_CHUNK_CHARS]
        for index in range(0, len(rendered), SOURCE_CHUNK_CHARS)
    ] or [""]
    for chunk_index, text in enumerate(segments):
        chunk, _created = SourceChunk.objects.get_or_create(
            organization=organization,
            parsed_source=stored_parsed,
            chunk_index=chunk_index,
            defaults={
                "pointer": "/",
                "text": text,
                "content_hash": hashlib.sha256(text.encode()).hexdigest(),
                "char_count": len(text),
            },
        )
        index_source_chunk(chunk)
        SourceChunkVisibility.objects.get_or_create(
            organization=organization,
            source_chunk=chunk,
            source_observation=observation,
            defaults={
                "source_location": root_location,
                "access_snapshot": observation.access_snapshot,
                "access_scope": observation.access_snapshot.access_scope,
                "state": SourceChunkVisibility.State.AVAILABLE,
                "observed_at": observation.observed_at,
            },
        )


def _process_document(
    *,
    run: SyncRun,
    container: SourceContainer,
    connector: FilesystemConnector,
    descriptor: DocumentDescriptor,
    extractor: MechanicalExtractor,
    worker_actor: ActorContext,
) -> None:
    if run.access_snapshot is None:
        raise IngestionError("missing_access_snapshot", "Sync access snapshot is missing")
    scope = run.access_snapshot.access_scope
    fetched = connector.fetch(descriptor, max_bytes=connector.limits.max_file_bytes)
    _require_active_run_source(run, worker_actor)
    parser = choose_parser(descriptor, default_parsers(limits=connector.limits))
    parsed = parser.parse(fetched)
    extracted = extractor.extract(parsed)
    _require_active_run_source(run, worker_actor)
    now = timezone.now()
    raw_hash = hashlib.sha256(fetched.content).hexdigest()
    with transaction.atomic():
        _lock_active_run_source(run)
        document, _created = SourceDocument.objects.get_or_create(
            organization=run.organization,
            source_container=container,
            external_id=descriptor.external_id,
            defaults={
                "relative_path": descriptor.relative_path.as_posix(),
                "canonical_url": descriptor.canonical_url,
                "document_kind": _source_document_kind(descriptor),
                "media_type": descriptor.media_type,
            },
        )
        artifact, _artifact_created = SourceContentArtifact.objects.get_or_create(
            organization=run.organization,
            content_hash=raw_hash,
            defaults={
                "byte_size": len(fetched.content),
                "media_type": descriptor.media_type,
                "content": fetched.content,
            },
        )
        revision, _revision_created = SourceRevision.objects.get_or_create(
            organization=run.organization,
            source_document=document,
            content_hash=raw_hash,
            defaults={
                "content_artifact": artifact,
                "canonical_url": descriptor.canonical_url,
                "source_modified_at": descriptor.source_modified_at,
                "observed_at": now,
            },
        )
        observation, _observation_created = SourceObservation.objects.get_or_create(
            organization=run.organization,
            sync_run=run,
            source_document=document,
            defaults={
                "source_revision": revision,
                "access_snapshot": run.access_snapshot,
                "status": SourceObservation.Status.PRESENT,
                "observed_at": now,
            },
        )
        document.relative_path = descriptor.relative_path.as_posix()
        document.canonical_url = descriptor.canonical_url
        document.document_kind = _source_document_kind(descriptor)
        document.media_type = descriptor.media_type
        document.state = SourceDocument.State.PRESENT
        document.current_revision = revision
        document.last_seen_run = run
        document.last_observed_at = observation.observed_at
        document.tombstoned_at = None
        document.save()
        normalized = dict(parsed.normalized)
        stored_parsed, _parsed_created = ParsedSource.objects.get_or_create(
            organization=run.organization,
            source_revision=revision,
            parser_name=parsed.parser_name,
            parser_version=parsed.parser_version,
            defaults={
                "document_kind": _source_document_kind(descriptor),
                "normalized": normalized,
                "output_hash": _database_jsonb_hash(normalized),
                "duration_ms": 0,
            },
        )
        _persist_chunks(
            organization=run.organization,
            stored_parsed=stored_parsed,
            parsed=parsed,
            observation=observation,
            revision=revision,
        )
        for location_data in parsed.locations:
            pointer = location_data.get("pointer")
            if isinstance(pointer, str):
                _persist_location(
                    organization=run.organization,
                    stored_parsed=stored_parsed,
                    observation=observation,
                    revision=revision,
                    parsed=parsed,
                    pointer=pointer,
                )
        serialized_claims = [asdict(claim) for claim in extracted.claims]
        stored_extraction, _extraction_created = StoredExtractionResult.objects.get_or_create(
            organization=run.organization,
            parsed_source=stored_parsed,
            extractor_name=extracted.extractor_name,
            extractor_version=extracted.extractor_version,
            defaults={
                "claims": serialized_claims,
                "output_hash": _database_jsonb_hash(serialized_claims),
                "duration_ms": 0,
            },
        )
        current_ids = {
            _persist_claim(
                organization=run.organization,
                scope=scope,
                document=document,
                observation=observation,
                revision=revision,
                parsed=parsed,
                stored_parsed=stored_parsed,
                stored_extraction=stored_extraction,
                claim=claim,
                claim_index=index,
            ).id
            for index, claim in enumerate(extracted.claims)
        }
        _close_absent_assertions(
            document=document,
            current_assertion_ids=current_ids,
            at=observation.observed_at,
        )


def _record_item_failure(
    *,
    run: SyncRun,
    descriptor: DocumentDescriptor,
    error: Exception,
) -> None:
    if isinstance(error, IngestionError):
        code = error.code
        message = error.safe_message
        transient = error.is_transient
    else:
        code = "internal_item_failure"
        message = "Source item could not be processed"
        transient = False
    IngestionFailure.objects.get_or_create(
        organization=run.organization,
        sync_run=run,
        stage="PROCESS",
        item_key=descriptor.external_id,
        error_code=code,
        defaults={
            "safe_message": message,
            "is_transient": transient,
        },
    )
    document = SourceDocument.objects.filter(
        organization=run.organization,
        source_container__source_connection=run.source_connection,
        external_id=descriptor.external_id,
    ).first()
    if document is not None:
        SourceObservation.objects.get_or_create(
            organization=run.organization,
            sync_run=run,
            source_document=document,
            defaults={
                "source_revision": None,
                "access_snapshot": run.access_snapshot,
                "status": SourceObservation.Status.FAILED,
                "observed_at": timezone.now(),
                "error_code": code,
            },
        )


def _record_discovery_failure(*, run: SyncRun, failure: DiscoveryFailure) -> None:
    IngestionFailure.objects.get_or_create(
        organization=run.organization,
        sync_run=run,
        stage="DISCOVER",
        item_key=failure.item_key,
        error_code=failure.error_code,
        defaults={
            "safe_message": failure.safe_message,
            "is_transient": failure.is_transient,
        },
    )


def _write_cursor(
    *,
    run: SyncRun,
    cursor_value: dict[str, JSONValue],
) -> None:
    with transaction.atomic():
        cursor = (
            SyncCursor.objects.select_for_update()
            .filter(
                organization=run.organization,
                source_connection=run.source_connection,
                cursor_key="filesystem-discovery",
            )
            .first()
        )
        if cursor is None:
            SyncCursor.objects.create(
                organization=run.organization,
                source_connection=run.source_connection,
                cursor_key="filesystem-discovery",
                cursor_value=cursor_value,
            )
            return
        cursor.cursor_value = cursor_value
        cursor.revision += 1
        cursor.save(update_fields=["cursor_value", "revision", "updated_at"])


def _read_cursor(run: SyncRun) -> dict[str, JSONValue] | None:
    stored = SyncCursor.objects.filter(
        organization=run.organization,
        source_connection=run.source_connection,
        cursor_key="filesystem-discovery",
    ).first()
    if stored is None or not isinstance(stored.cursor_value, dict):
        return None
    value = stored.cursor_value
    if value.get("sync_run_id") != str(run.id) or value.get("complete") is not False:
        return None
    connector_cursor = value.get("cursor")
    if not isinstance(connector_cursor, dict):
        return None
    return dict(connector_cursor)


def _write_discovery_cursor(
    *,
    run: SyncRun,
    connector_cursor: dict[str, JSONValue],
) -> None:
    _write_cursor(
        run=run,
        cursor_value={
            "sync_run_id": str(run.id),
            "complete": False,
            "cursor": connector_cursor,
        },
    )


def _require_active_run_source(run: SyncRun, worker_actor: ActorContext) -> None:
    active = SourceConnection.objects.filter(
        id=run.source_connection_id,
        organization=run.organization,
        state=SourceConnection.State.ACTIVE,
    ).exists()
    snapshot_active = (
        run.access_snapshot_id is not None
        and AccessSnapshot.objects.filter(
            id=run.access_snapshot_id,
            organization=run.organization,
            revoked_at__isnull=True,
        ).exists()
    )
    if active and snapshot_active:
        return
    run.refresh_from_db()
    if run.state not in TERMINAL_SYNC_STATES:
        _transition_run(run, worker_actor, SyncRun.State.CANCELLED)
    raise IngestionError("source_revoked", "Source authorization is no longer active")


def _lock_active_run_source(run: SyncRun) -> None:
    if run.access_snapshot_id is None:
        raise IngestionError("source_revoked", "Source authorization is no longer active")
    source = (
        SourceConnection.objects.select_for_update()
        .filter(
            id=run.source_connection_id,
            organization=run.organization,
        )
        .first()
    )
    snapshot = (
        AccessSnapshot.objects.select_for_update()
        .select_related("access_scope")
        .filter(
            id=run.access_snapshot_id,
            organization=run.organization,
        )
        .first()
    )
    if (
        source is None
        or source.state != SourceConnection.State.ACTIVE
        or snapshot is None
        or snapshot.revoked_at is not None
    ):
        raise IngestionError("source_revoked", "Source authorization is no longer active")
    run.source_connection = source
    run.access_snapshot = snapshot


def _tombstone_missing(
    *,
    run: SyncRun,
    container: SourceContainer,
    discovered_ids: set[str],
) -> int:
    if run.scan_mode != SyncRun.ScanMode.FULL:
        return 0
    count = 0
    for document in SourceDocument.objects.filter(
        organization=run.organization,
        source_container=container,
        state=SourceDocument.State.PRESENT,
    ).exclude(external_id__in=discovered_ids):
        observed_at = timezone.now()
        observation, created = SourceObservation.objects.get_or_create(
            organization=run.organization,
            sync_run=run,
            source_document=document,
            defaults={
                "source_revision": None,
                "access_snapshot": run.access_snapshot,
                "status": SourceObservation.Status.TOMBSTONED,
                "observed_at": observed_at,
            },
        )
        if not created:
            continue
        document.state = SourceDocument.State.TOMBSTONED
        document.tombstoned_at = observed_at
        document.last_observed_at = observed_at
        document.last_seen_run = run
        document.save()
        for visibility in SourceChunkVisibility.objects.filter(
            organization=run.organization,
            source_location__source_observation__source_document=document,
            state=SourceChunkVisibility.State.AVAILABLE,
        ):
            visibility.state = SourceChunkVisibility.State.SOURCE_UNAVAILABLE
            visibility.revoked_at = observed_at
            visibility.save(update_fields=["state", "revoked_at"])
        _close_absent_assertions(
            document=document,
            current_assertion_ids=set(),
            at=observation.observed_at,
            unavailable=True,
        )
        count += 1
    return count


def _execute_ingestion_job(
    *,
    job: BackgroundJob,
    worker_id: str,
    limits: IngestionLimits | None = None,
) -> SyncRun:
    """Execute a claimed job with lease and revocation checks before idempotent returns."""
    now = timezone.now()
    require_current_lease(job=job, worker_id=worker_id, now=now)
    try:
        run_id = uuid.UUID(str(job.payload["sync_run_id"]))
        source_id = uuid.UUID(str(job.payload["source_connection_id"]))
        snapshot_id = uuid.UUID(str(job.payload["access_snapshot_id"]))
    except (KeyError, TypeError, ValueError) as error:
        raise IngestionError("invalid_job_payload", "Ingestion job payload is invalid") from error
    run = get_tenant_record(
        queryset=SyncRun.objects.select_related(
            "organization",
            "source_connection",
            "access_snapshot",
            "access_snapshot__access_scope",
        ),
        record_id=run_id,
        organization_id=job.organization_id,
    )
    snapshot = run.access_snapshot
    if (
        run.source_connection_id != source_id
        or run.access_snapshot_id != snapshot_id
        or snapshot is None
        or run.source_connection.state != SourceConnection.State.ACTIVE
        or snapshot.revoked_at is not None
    ):
        if run.state not in {
            SyncRun.State.COMPLETED,
            SyncRun.State.PARTIALLY_COMPLETED,
            SyncRun.State.FAILED,
            SyncRun.State.CANCELLED,
        }:
            _transition_run(
                run,
                _worker_actor(run.organization_id, worker_id),
                SyncRun.State.CANCELLED,
            )
        raise IngestionError("source_revoked", "Source authorization is no longer active")
    if run.state in {SyncRun.State.COMPLETED, SyncRun.State.PARTIALLY_COMPLETED}:
        return run
    configuration_root = run.source_connection.configuration.get("root")
    if not isinstance(configuration_root, str):
        raise IngestionError("invalid_source_configuration", "Source configuration is invalid")
    connector = FilesystemConnector(
        _validated_source_root(configuration_root),
        limits=limits,
    )
    worker_actor = _worker_actor(run.organization_id, worker_id)
    started = timezone.now()
    started_monotonic = time.monotonic()
    _stage(
        run=run,
        job=job,
        stage="INGEST",
        status=IngestionStageResult.Status.RUNNING,
        started_at=started,
    )
    _transition_run(run, worker_actor, SyncRun.State.DISCOVERING)
    container, _created = SourceContainer.objects.get_or_create(
        organization=run.organization,
        source_connection=run.source_connection,
        external_id=connector.container.external_id,
        defaults={
            "name": connector.container.name,
            "canonical_url": connector.container.canonical_url,
        },
    )
    cursor = _read_cursor(run)
    previous_observations = SourceObservation.objects.filter(
        organization=run.organization,
        sync_run=run,
    )
    discovered = set(previous_observations.values_list("source_document__external_id", flat=True))
    previous_failures = IngestionFailure.objects.filter(
        organization=run.organization,
        sync_run=run,
        stage__in=["DISCOVER", "PROCESS"],
    )
    discovered.update(previous_failures.values_list("item_key", flat=True))
    processed = previous_observations.filter(status=SourceObservation.Status.PRESENT).count()
    failed = previous_failures.count()
    page_count = 0
    extractor = MechanicalExtractor()
    while True:
        require_current_lease(job=job, worker_id=worker_id, now=timezone.now())
        _require_active_run_source(run, worker_actor)
        page_count += 1
        if page_count > MAX_SYNC_PAGES:
            raise IngestionError("page_limit_exceeded", "Source page limit exceeded")
        page = connector.discover(cursor=cursor, limit=connector.limits.max_discovery_page)
        for failure in page.failures:
            discovered.add(failure.item_key)
            _record_discovery_failure(run=run, failure=failure)
            failed += 1
        for descriptor in page.documents:
            require_current_lease(job=job, worker_id=worker_id, now=timezone.now())
            _require_active_run_source(run, worker_actor)
            discovered.add(descriptor.external_id)
            try:
                _transition_run(run, worker_actor, SyncRun.State.FETCHING)
                _process_document(
                    run=run,
                    container=container,
                    connector=connector,
                    descriptor=descriptor,
                    extractor=extractor,
                    worker_actor=worker_actor,
                )
                _require_active_run_source(run, worker_actor)
                processed += 1
            except Exception as error:
                if isinstance(error, IngestionError) and error.code == "source_revoked":
                    raise
                _record_item_failure(run=run, descriptor=descriptor, error=error)
                failed += 1
        if page.next_cursor is None:
            break
        cursor = dict(page.next_cursor)
        _write_discovery_cursor(run=run, connector_cursor=cursor)
    processed = SourceObservation.objects.filter(
        organization=run.organization,
        sync_run=run,
        status=SourceObservation.Status.PRESENT,
    ).count()
    failed = IngestionFailure.objects.filter(
        organization=run.organization,
        sync_run=run,
        stage__in=["DISCOVER", "PROCESS"],
    ).count()
    _require_active_run_source(run, worker_actor)
    with transaction.atomic():
        _lock_active_run_source(run)
        tombstoned = _tombstone_missing(
            run=run,
            container=container,
            discovered_ids=discovered,
        )
        _write_cursor(
            run=run,
            cursor_value={
                "sync_run_id": str(run.id),
                "complete": True,
                "cursor": {},
            },
        )
        run.discovered_count = len(discovered)
        run.processed_count = processed
        run.failed_count = failed
        run.tombstoned_count = tombstoned
        run.save(
            update_fields=[
                "discovered_count",
                "processed_count",
                "failed_count",
                "tombstoned_count",
                "updated_at",
            ]
        )
        _transition_run(run, worker_actor, SyncRun.State.PUBLISHING)
        terminal = SyncRun.State.PARTIALLY_COMPLETED if failed else SyncRun.State.COMPLETED
        _transition_run(run, worker_actor, terminal)
        run.source_connection.last_successful_sync_at = run.completed_at
        run.source_connection.last_error_code = ""
        run.source_connection.save(
            update_fields=["last_successful_sync_at", "last_error_code", "updated_at"]
        )
        _stage(
            run=run,
            job=job,
            stage="INGEST",
            status=(
                IngestionStageResult.Status.PARTIAL
                if failed
                else IngestionStageResult.Status.SUCCEEDED
            ),
            started_at=started,
            duration_ms=max(0, int((time.monotonic() - started_monotonic) * 1_000)),
        )
        if run.source_connection.repository_id is not None:
            from anva.core.services.context_packets import invalidate_context_packets

            invalidate_context_packets(
                organization_id=run.organization_id,
                repository_id=run.source_connection.repository_id,
                reason=ContextPacketInvalidation.Reason.INGESTION,
                details={"sync_run_id": str(run.id)},
            )
    return run


def _record_ingestion_job_failure(
    *,
    job: BackgroundJob,
    worker_id: str,
    error_code: str,
    terminal: bool,
) -> None:
    """Persist bounded operational failure state when a whole run cannot continue."""
    try:
        run_id = uuid.UUID(str(job.payload["sync_run_id"]))
    except (KeyError, TypeError, ValueError):
        return
    run = (
        SyncRun.objects.select_related("organization", "source_connection")
        .filter(
            id=run_id,
            organization_id=job.organization_id,
        )
        .first()
    )
    if run is None:
        return
    run.failure_code = error_code
    run.save(update_fields=["failure_code", "updated_at"])
    terminal_states = {
        SyncRun.State.COMPLETED,
        SyncRun.State.PARTIALLY_COMPLETED,
        SyncRun.State.FAILED,
        SyncRun.State.CANCELLED,
    }
    if terminal and run.state not in terminal_states:
        _transition_run(
            run,
            _worker_actor(run.organization_id, worker_id),
            SyncRun.State.FAILED,
        )
    run.source_connection.last_error_code = error_code
    run.source_connection.save(update_fields=["last_error_code", "updated_at"])
    existing = IngestionStageResult.objects.filter(
        organization=run.organization,
        sync_run=run,
        stage="INGEST",
        implementation_version=INGESTION_IMPLEMENTATION_VERSION,
    ).first()
    _stage(
        run=run,
        job=job,
        stage="INGEST",
        status=IngestionStageResult.Status.FAILED,
        started_at=existing.started_at if existing is not None else run.started_at,
        error_code=error_code,
    )


def execute_ingestion_job(
    *,
    job: BackgroundJob,
    worker_id: str,
    limits: IngestionLimits | None = None,
) -> SyncRun:
    """Run ingestion while making whole-run failures observable and retry-safe."""
    try:
        return _execute_ingestion_job(
            job=job,
            worker_id=worker_id,
            limits=limits,
        )
    except IngestionError as error:
        _record_ingestion_job_failure(
            job=job,
            worker_id=worker_id,
            error_code=error.code,
            terminal=not error.is_transient or job.attempt_count >= job.max_attempts,
        )
        raise
    except Exception:
        _record_ingestion_job_failure(
            job=job,
            worker_id=worker_id,
            error_code="internal_ingestion_failure",
            terminal=job.attempt_count >= job.max_attempts,
        )
        raise


def source_sync_runs(
    *,
    actor: ActorContext,
    source_connection_id: uuid.UUID,
) -> list[dict[str, object]]:
    """List bounded sync history after source-view authorization."""
    authorize_action(
        actor=actor,
        action=Action.SOURCE_VIEW,
        repository_id=actor.repository_id,
        source_connection_id=source_connection_id,
        allow_revoked_source=True,
    )
    if not SourceConnection.objects.filter(
        id=source_connection_id,
        organization_id=actor.organization_id,
    ).exists():
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    return [
        _sync_status(run)
        for run in SyncRun.objects.filter(
            organization_id=actor.organization_id,
            source_connection_id=source_connection_id,
        ).order_by("-started_at")[:50]
    ]
