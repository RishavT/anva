"""PostgreSQL invariants for immutable, access-aware source provenance."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest
from django.core.exceptions import FieldDoesNotExist
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.utils import timezone

from anva.core.models import (
    AccessScope,
    AccessSnapshot,
    AssertionProvenance,
    AssertionValidityInterval,
    KnowledgeAssertion,
    Organization,
    ParsedSource,
    Repository,
    SourceConnection,
    SourceContainer,
    SourceContentArtifact,
    SourceDocument,
    SourceLocation,
    SourceObservation,
    SourceRevision,
    SyncRun,
    content_hash,
)


@dataclass(frozen=True)
class ProvenanceGraph:
    organization: Organization
    connection: SourceConnection
    snapshots: tuple[AccessSnapshot, AccessSnapshot]
    document: SourceDocument
    revisions: tuple[SourceRevision, SourceRevision]
    observations: tuple[SourceObservation, SourceObservation, SourceObservation]
    parsed: tuple[ParsedSource, ParsedSource]


def _completed_run(
    organization: Organization,
    source: SourceConnection,
    snapshot: AccessSnapshot,
) -> SyncRun:
    now = timezone.now()
    return SyncRun.objects.create(
        organization=organization,
        source_connection=source,
        access_snapshot=snapshot,
        state=SyncRun.State.COMPLETED,
        started_at=now,
        completed_at=now,
    )


def _artifact(organization: Organization, value: bytes) -> SourceContentArtifact:
    return SourceContentArtifact.objects.create(
        organization=organization,
        content_hash="",
        byte_size=len(value),
        media_type="application/json",
        content=value,
    )


def _build_graph(slug: str = "provenance") -> ProvenanceGraph:
    organization = Organization.objects.create(slug=slug, name="Provenance")
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"filesystem:{slug}",
        name="Fixture",
    )
    first_scope = AccessScope.objects.create(
        organization=organization,
        name="Engineering",
        all_repositories=True,
    )
    second_scope = AccessScope.objects.create(
        organization=organization,
        name="Leadership",
        all_repositories=True,
    )
    source = SourceConnection.objects.create(
        organization=organization,
        external_key=f"filesystem:{slug}",
        display_name="Fixture",
        repository=repository,
        access_scope=first_scope,
        state=SourceConnection.State.ACTIVE,
    )
    first_snapshot = AccessSnapshot.objects.create(
        organization=organization,
        source_connection=source,
        access_scope=first_scope,
        scope_revision=first_scope.revision,
        payload={"scope_id": str(first_scope.id), "revision": first_scope.revision},
    )
    second_snapshot = AccessSnapshot.objects.create(
        organization=organization,
        source_connection=source,
        access_scope=second_scope,
        scope_revision=second_scope.revision,
        payload={"scope_id": str(second_scope.id), "revision": second_scope.revision},
    )
    container = SourceContainer.objects.create(
        organization=organization,
        source_connection=source,
        external_id="root",
        name="root",
        canonical_url="file:///fixtures",
    )
    document = SourceDocument.objects.create(
        organization=organization,
        source_container=container,
        external_id="service.json",
        relative_path="service.json",
        canonical_url="file:///fixtures/service.json",
        document_kind=SourceDocument.Kind.JSON,
        media_type="application/json",
    )
    artifact_a = _artifact(organization, b'{"owner":"team-a"}')
    revision_a = SourceRevision.objects.create(
        organization=organization,
        source_document=document,
        content_artifact=artifact_a,
        content_hash=artifact_a.content_hash,
        canonical_url=document.canonical_url,
    )
    artifact_b = _artifact(organization, b'{"owner":"team-b"}')
    revision_b = SourceRevision.objects.create(
        organization=organization,
        source_document=document,
        content_artifact=artifact_b,
        content_hash=artifact_b.content_hash,
        canonical_url=document.canonical_url,
    )

    first_run = _completed_run(organization, source, first_snapshot)
    second_run = _completed_run(organization, source, first_snapshot)
    third_run = _completed_run(organization, source, second_snapshot)
    first_observation = SourceObservation.objects.create(
        organization=organization,
        sync_run=first_run,
        source_document=document,
        source_revision=revision_a,
        access_snapshot=first_snapshot,
        status=SourceObservation.Status.PRESENT,
    )
    second_observation = SourceObservation.objects.create(
        organization=organization,
        sync_run=second_run,
        source_document=document,
        source_revision=revision_b,
        access_snapshot=first_snapshot,
        status=SourceObservation.Status.PRESENT,
    )
    third_observation = SourceObservation.objects.create(
        organization=organization,
        sync_run=third_run,
        source_document=document,
        source_revision=revision_a,
        access_snapshot=second_snapshot,
        status=SourceObservation.Status.PRESENT,
    )
    document.current_revision = revision_a
    document.last_seen_run = third_run
    document.last_observed_at = third_observation.observed_at
    document.save()

    parsed_v1 = ParsedSource.objects.create(
        organization=organization,
        source_revision=revision_a,
        parser_name="json",
        parser_version="1",
        document_kind=SourceDocument.Kind.JSON,
        normalized={"owner": "team-a"},
        output_hash=content_hash({"owner": "team-a"}),
        duration_ms=1,
    )
    parsed_v2 = ParsedSource.objects.create(
        organization=organization,
        source_revision=revision_a,
        parser_name="json",
        parser_version="2",
        document_kind=SourceDocument.Kind.JSON,
        normalized={"owner": {"name": "team-a"}},
        output_hash=content_hash({"owner": {"name": "team-a"}}),
        duration_ms=1,
    )
    return ProvenanceGraph(
        organization=organization,
        connection=source,
        snapshots=(first_snapshot, second_snapshot),
        document=document,
        revisions=(revision_a, revision_b),
        observations=(first_observation, second_observation, third_observation),
        parsed=(parsed_v1, parsed_v2),
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_a_to_b_to_a_reuses_revision_and_retains_observations_and_parser_derivations() -> None:
    graph = _build_graph()

    assert list(
        SourceObservation.objects.order_by("observed_at").values_list(
            "source_revision__content_hash",
            flat=True,
        )
    ) == [
        graph.revisions[0].content_hash,
        graph.revisions[1].content_hash,
        graph.revisions[0].content_hash,
    ]
    assert SourceRevision.objects.filter(source_document=graph.document).count() == 2
    assert graph.observations[0].access_snapshot_id != graph.observations[2].access_snapshot_id
    assert graph.observations[0].source_revision_id == graph.observations[2].source_revision_id
    assert {item.parser_version for item in graph.parsed} == {"1", "2"}
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            ParsedSource.objects.create(
                organization=graph.organization,
                source_revision=graph.revisions[0],
                parser_name="json",
                parser_version="1",
                document_kind=SourceDocument.Kind.JSON,
                normalized={"duplicate": True},
                output_hash=content_hash({"duplicate": True}),
                duration_ms=1,
            )

    artifact_meta: Any = SourceContentArtifact._meta
    revision_meta: Any = SourceRevision._meta
    with pytest.raises(FieldDoesNotExist):
        artifact_meta.get_field("access_scope")
    with pytest.raises(FieldDoesNotExist):
        revision_meta.get_field("access_snapshot")


@pytest.mark.integration
@pytest.mark.django_db
def test_database_rejects_cross_tenant_and_immutable_provenance_changes() -> None:
    graph = _build_graph("immutable")
    foreign = Organization.objects.create(slug="foreign", name="Foreign")

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            SourceContainer.objects.create(
                organization=foreign,
                source_connection=graph.connection,
                external_id="foreign",
                name="foreign",
                canonical_url="file:///foreign",
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS srccontainer_conn_tenant_fk IMMEDIATE")

    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            SourceRevision.objects.filter(id=graph.revisions[0].id).update(content_hash="f" * 64)
    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            SourceObservation.objects.filter(id=graph.observations[0].id).delete()

    malformed = SourceContentArtifact(
        organization=graph.organization,
        content_hash=hashlib.sha256(b"short").hexdigest(),
        byte_size=500,
        media_type="text/plain",
        content=b"short",
    )
    with pytest.raises(DatabaseError, match="byte size"):
        with transaction.atomic():
            SourceContentArtifact.objects.bulk_create([malformed])


@pytest.mark.integration
@pytest.mark.django_db
def test_locations_provenance_and_temporal_intervals_are_aligned_and_append_only() -> None:
    graph = _build_graph("lineage")
    location = SourceLocation.objects.create(
        organization=graph.organization,
        parsed_source=graph.parsed[0],
        source_observation=graph.observations[0],
        pointer="/owner",
        start_line=1,
        end_line=1,
        excerpt_hash=hashlib.sha256(b"team-a").hexdigest(),
    )
    with pytest.raises(DatabaseError, match="inconsistent"):
        with transaction.atomic():
            SourceLocation.objects.create(
                organization=graph.organization,
                parsed_source=graph.parsed[0],
                source_observation=graph.observations[1],
                pointer="/owner",
                excerpt_hash=hashlib.sha256(b"team-b").hexdigest(),
            )

    assertion = KnowledgeAssertion.objects.create(
        organization=graph.organization,
        subject_key="service:api",
        predicate="owned_by",
        value="team-a",
        extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
        extraction_method="json-pointer",
        confidence=1.0,
        provenance=[{"location_id": str(location.id)}],
        access_scope=graph.snapshots[0].access_scope,
    )
    provenance = AssertionProvenance.objects.create(
        organization=graph.organization,
        assertion=assertion,
        source_location=location,
        source_observation=graph.observations[0],
        access_snapshot=graph.snapshots[0],
        extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
        extraction_method="json-pointer",
        confidence=1.0,
        observed_at=graph.observations[0].observed_at,
    )
    with pytest.raises(DatabaseError, match="inconsistent"):
        with transaction.atomic():
            AssertionProvenance.objects.create(
                organization=graph.organization,
                assertion=assertion,
                source_location=location,
                source_observation=graph.observations[0],
                access_snapshot=graph.snapshots[1],
                extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
                extraction_method="json-pointer",
                confidence=1.0,
                observed_at=graph.observations[0].observed_at,
            )
    with pytest.raises(DatabaseError, match="immutable"):
        with transaction.atomic():
            AssertionProvenance.objects.filter(id=provenance.id).update(confidence=0.5)

    interval = AssertionValidityInterval.objects.create(
        organization=graph.organization,
        assertion=assertion,
        source_document=graph.document,
        source_observation=graph.observations[0],
        valid_from=graph.observations[0].observed_at,
        observed_from=graph.observations[0].observed_at,
    )
    closed_at = timezone.now() + timedelta(seconds=1)
    assert AssertionValidityInterval.objects.filter(id=interval.id).update(
        valid_until=closed_at,
        observed_until=closed_at,
    )
    with pytest.raises(DatabaseError, match="closed once"):
        with transaction.atomic():
            AssertionValidityInterval.objects.filter(id=interval.id).update(
                valid_until=closed_at + timedelta(seconds=1),
                observed_until=closed_at + timedelta(seconds=1),
            )
    with pytest.raises(DatabaseError, match="cannot be deleted"):
        with transaction.atomic():
            AssertionValidityInterval.objects.filter(id=interval.id).delete()
