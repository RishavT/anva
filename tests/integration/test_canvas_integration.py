"""Database-backed authorization and mutation coverage for Organizational Canvas."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import time
import uuid
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.models import F
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from anva.core.exceptions import (
    IdempotencyConflictError,
    OptimisticConcurrencyError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    AccessSnapshot,
    AssertionProvenance,
    AssertionRevision,
    AssertionValidityInterval,
    CanvasNodePlacement,
    CanvasShare,
    CanvasView,
    CanvasViewRevision,
    EntityResolution,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeRelationship,
    Membership,
    Organization,
    ParsedSource,
    Repository,
    Role,
    ServiceIdentity,
    SourceChunkVisibility,
    SourceConnection,
    SourceContainer,
    SourceContentArtifact,
    SourceDocument,
    SourceLocation,
    SourceObservation,
    SourceRevision,
    SyncRun,
    User,
    content_hash,
)
from anva.core.services.authorization import (
    Action,
    AuthorizedRepositoryScopes,
    resolve_authorized_repository_scopes,
)
from anva.core.services.canvas import (
    CanvasQuery,
    _batch_authorized_assertions,
    _batch_authorized_entities,
    _canvas_payload_size,
    canvas_entity_detail,
    canvas_path,
    canvas_projection,
    canvas_selection_scope,
    create_canvas_share,
    create_canvas_view,
    list_canvas_views,
    propose_canvas_relationship,
    resolve_canvas_share,
    revoke_canvas_share,
    save_canvas_revision,
)
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import authorized_assertion_citations_batch
from anva.core.services.graph import (
    _AUTHORIZED_INCIDENT_EDGE_BATCH_SELECT,
    authorized_graph_edges,
    authorized_incident_graph_edges_batch,
)
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.jobs import claim_next_job, complete_job
from anva.core.services.tokens import issue_bootstrap_repository_token

PERFORMANCE_ROOT = Path("docs/evidence/issue-012/performance")


def _metric_summary(samples: list[float]) -> dict[str, object]:
    ordered = sorted(samples)
    percentile_95 = ordered[math.ceil(len(ordered) * 0.95) - 1]
    middle = len(ordered) // 2
    percentile_50 = (ordered[middle - 1] + ordered[middle]) / 2
    return {
        "raw": [round(value, 3) for value in samples],
        "p50": round(percentile_50, 3),
        "p95": round(percentile_95, 3),
        "max": round(max(samples), 3),
        "sample_count": len(samples),
    }


def _cpu_model() -> str:
    for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("model name"):
            return line.partition(":")[2].strip()
    return "unavailable"


def _tenant(*, slug: str = "canvas") -> tuple[Organization, Repository, ActorContext, User]:
    organization = Organization.objects.create(slug=slug, name=f"{slug} organization")
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"filesystem:{slug}:one",
        name=f"{slug}-one",
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Organization administrator",
    )
    user = User.objects.create(
        email=f"admin-{slug}@example.test",
        display_name="Canvas Administrator",
    )
    Membership.objects.create(organization=organization, user=user, role=role)
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="test:canvas",
        request_id=uuid.uuid4(),
    )
    return organization, repository, actor, user


def _viewer(
    *, organization: Organization, membership_scope: AccessScope, label: str
) -> ActorContext:
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.VIEWER,
        name="Viewer",
    )
    user = User.objects.create(
        email=f"{label}@example.test",
        display_name=label,
    )
    membership = Membership.objects.create(organization=organization, user=user, role=role)
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=membership_scope,
        membership=membership,
    )
    return ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="test:canvas-viewer",
        request_id=uuid.uuid4(),
    )


def _ingest(
    *,
    actor: ActorContext,
    repository: Repository,
    scope: AccessScope,
    root: Path,
    key: str,
) -> SourceConnection:
    source, created = connect_filesystem_source(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        external_key=f"filesystem:{key}",
        display_name=key,
        root=str(root),
    )
    assert created
    _run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    job = claim_next_job(worker_id=f"canvas-{key}", lease_seconds=600)
    assert job is not None
    completed = execute_ingestion_job(job=job, worker_id=f"canvas-{key}")
    complete_job(
        actor=ActorContext(
            organization_id=actor.organization_id,
            actor_type="SERVICE",
            actor_id=f"canvas-{key}",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=job.id,
        worker_id=f"canvas-{key}",
    )
    assert completed.state in {completed.State.COMPLETED, completed.State.PARTIALLY_COMPLETED}
    source.refresh_from_db()
    return source


def _relationship_from_provenance(
    *,
    seed: KnowledgeRelationship,
    source: KnowledgeEntity,
    target: KnowledgeEntity,
    relationship_type: str,
    observed_at: Any | None = None,
) -> KnowledgeRelationship:
    """Create a semantic test edge using a real authorized ingestion lineage."""
    return KnowledgeRelationship.objects.create(
        organization=seed.organization,
        relationship_type=relationship_type,
        source_entity=source,
        target_entity=target,
        source_entity_type=source.entity_type,
        target_entity_type=target.entity_type,
        assertion=seed.assertion,
        source_location=seed.source_location,
        source_observation=seed.source_observation,
        access_snapshot=seed.access_snapshot,
        access_scope=seed.access_scope,
        extraction_class=seed.extraction_class,
        confidence=seed.confidence,
        observed_at=observed_at or seed.observed_at,
        review_state=seed.review_state,
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_unions_only_strict_per_repository_authorized_graphs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository_one, admin, _user = _tenant(slug="canvas-union")
    repository_two = Repository.objects.create(
        organization=organization,
        external_id="filesystem:canvas-union:two",
        name="canvas-two",
    )
    public_scope = AccessScope.objects.create(
        organization=organization,
        name="public canvas",
        all_repositories=True,
    )
    viewer = _viewer(
        organization=organization,
        membership_scope=public_scope,
        label="canvas-limited-viewer",
    )
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    hidden_root = tmp_path / "hidden"
    first_root.mkdir()
    second_root.mkdir()
    hidden_root.mkdir()
    (first_root / "service.json").write_text(
        json.dumps({"service": "payments", "owner": "platform"})
    )
    (second_root / "service.json").write_text(
        json.dumps({"service": "catalog", "owner": "commerce"})
    )
    (hidden_root / "service.json").write_text(
        json.dumps(
            {
                "service": "CANARY-HIDDEN-ACQUISITION",
                "owner": "CANARY-HIDDEN-EXECUTIVE",
            }
        )
    )
    _ingest(
        actor=admin,
        repository=repository_one,
        scope=public_scope,
        root=first_root,
        key="canvas-public-one",
    )
    _ingest(
        actor=admin,
        repository=repository_two,
        scope=public_scope,
        root=second_root,
        key="canvas-public-two",
    )

    before = canvas_projection(actor=viewer, query=CanvasQuery())
    repositories = cast(list[dict[str, object]], before["repositories"])
    assert {row["name"] for row in repositories} == {
        "canvas-union-one",
        "canvas-two",
    }
    assert before["nodes"]
    assert before["edges"]

    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="hidden executive canvas",
        all_repositories=True,
    )
    _ingest(
        actor=admin,
        repository=repository_one,
        scope=hidden_scope,
        root=hidden_root,
        key="canvas-hidden",
    )
    after = canvas_projection(actor=viewer, query=CanvasQuery())

    for key in ("nodes", "edges", "counts", "truncated", "limitations", "layout"):
        assert after[key] == before[key]
    assert "CANARY" not in json.dumps(after, sort_keys=True)
    hidden_id = KnowledgeEntity.objects.get(
        organization=organization,
        canonical_key__contains="CANARY-HIDDEN-ACQUISITION",
    ).id
    nodes = cast(list[dict[str, object]], before["nodes"])
    public_id = uuid.UUID(str(nodes[0]["id"]))
    with pytest.raises(ResourceNotFoundError):
        canvas_path(actor=viewer, source_id=public_id, target_id=hidden_id)

    provenance_only = canvas_projection(
        actor=viewer,
        query=CanvasQuery(layers=("provenance",)),
    )
    assert provenance_only["edges"] == []


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_detail_and_as_of_use_only_bounded_authorized_graph_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository, actor, _user = _tenant(slug="canvas-context")
    scope = AccessScope.objects.create(
        organization=organization,
        name="context scope",
        all_memberships=True,
        all_repositories=True,
    )
    root = tmp_path / "context"
    root.mkdir()
    (root / "system.json").write_text(
        json.dumps({"service": "checkout", "owner": "commerce", "status": "ACTIVE"})
    )
    _ingest(actor=actor, repository=repository, scope=scope, root=root, key="context")
    seed = KnowledgeRelationship.objects.filter(organization=organization).first()
    assert seed is not None
    AssertionRevision.objects.create(
        organization=organization,
        assertion=seed.assertion,
        revision=seed.assertion.revision,
        snapshot={"predicate": seed.assertion.predicate},
    )
    subject = seed.source_entity
    related: dict[str, KnowledgeEntity] = {}
    for entity_type, key, status in (
        (KnowledgeEntity.EntityType.DECISION, "decision", "ACCEPTED"),
        (KnowledgeEntity.EntityType.POLICY, "policy", "ACTIVE"),
        (KnowledgeEntity.EntityType.RISK, "risk", "OPEN"),
        (KnowledgeEntity.EntityType.INCIDENT, "incident", "RESOLVED"),
        (KnowledgeEntity.EntityType.TASK, "task", "IN_PROGRESS"),
        (KnowledgeEntity.EntityType.PULL_REQUEST, "pull-request", "MERGED"),
    ):
        related[key] = KnowledgeEntity.objects.create(
            organization=organization,
            entity_type=entity_type,
            canonical_key=f"{key}:checkout",
            display_name=f"Checkout {key}",
            attributes={"status": status},
            access_scope=scope,
        )
    relationship_types = {
        "decision": KnowledgeRelationship.RelationshipType.DECISION_APPLIES_TO_ENTITY,
        "policy": KnowledgeRelationship.RelationshipType.POLICY_APPLIES_TO_ENTITY,
        "risk": KnowledgeRelationship.RelationshipType.RISK_AFFECTS_ENTITY,
        "incident": KnowledgeRelationship.RelationshipType.INCIDENT_AFFECTED_ENTITY,
        "task": KnowledgeRelationship.RelationshipType.TASK_CHANGES_ENTITY,
        "pull-request": KnowledgeRelationship.RelationshipType.PULL_REQUEST_CHANGES_ENTITY,
    }
    boundary = timezone.now() + timedelta(minutes=1)
    late_relationship: KnowledgeRelationship | None = None
    for key, relationship_type in relationship_types.items():
        relationship = _relationship_from_provenance(
            seed=seed,
            source=related[key],
            target=subject,
            relationship_type=relationship_type,
            observed_at=(boundary + timedelta(hours=1) if key == "pull-request" else boundary),
        )
        if key == "pull-request":
            late_relationship = relationship
    assert late_relationship is not None

    detail = canvas_entity_detail(
        actor=actor,
        entity_id=subject.id,
        repository_ids=(repository.id,),
    )
    assert len(cast(list[object], detail["relationships"])) >= 6
    assert {
        item["type"] for item in cast(list[dict[str, object]], detail["decisions_policies"])
    } == {
        KnowledgeEntity.EntityType.DECISION,
        KnowledgeEntity.EntityType.POLICY,
    }
    assert {item["type"] for item in cast(list[dict[str, object]], detail["risks_incidents"])} == {
        KnowledgeEntity.EntityType.RISK,
        KnowledgeEntity.EntityType.INCIDENT,
    }
    assert [item["type"] for item in cast(list[dict[str, object]], detail["active_work"])] == [
        KnowledgeEntity.EntityType.TASK
    ]
    assert [
        item["type"] for item in cast(list[dict[str, object]], detail["recent_pull_requests"])
    ] == [KnowledgeEntity.EntityType.PULL_REQUEST]
    assert AssertionRevision.objects.filter(assertion=seed.assertion).exists()
    assert cast(list[dict[str, object]], detail["history"])[0]["predicate"] == (
        seed.assertion.predicate
    )

    current = canvas_projection(
        actor=actor,
        query=CanvasQuery(repository_ids=(repository.id,)),
    )
    historical = canvas_projection(
        actor=actor,
        query=CanvasQuery(repository_ids=(repository.id,), as_of=boundary),
    )
    current_edges = cast(list[dict[str, object]], current["edges"])
    historical_edges = cast(list[dict[str, object]], historical["edges"])
    assert str(late_relationship.id) in {edge["id"] for edge in current_edges}
    assert str(late_relationship.id) not in {edge["id"] for edge in historical_edges}
    assert historical["as_of"] == boundary.isoformat()


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_detail_batches_authorization_provenance_and_related_context_queries() -> None:
    organization, first_repository, _admin, admin_user = _tenant(slug="canvas-detail-batch")
    repositories = [first_repository]
    repositories.extend(
        Repository.objects.create(
            organization=organization,
            external_id=f"filesystem:canvas-detail-batch:{index}",
            name=f"detail-batch-{index}",
        )
        for index in range(1, 10)
    )
    visible_scope = AccessScope.objects.create(
        organization=organization,
        name="detail batch visible",
    )
    AccessScopeRepository.objects.bulk_create(
        [
            AccessScopeRepository(
                organization=organization,
                access_scope=visible_scope,
                repository=repository,
            )
            for repository in repositories
        ]
    )
    viewer = _viewer(
        organization=organization,
        membership_scope=visible_scope,
        label="canvas-detail-batch-viewer",
    )

    def create_seed_provenance(
        *,
        repository: Repository,
        scope: AccessScope,
        index: int,
        label: str,
    ) -> AssertionProvenance:
        observed_at = timezone.now() + timedelta(seconds=index)
        source = SourceConnection.objects.create(
            organization=organization,
            external_key=f"filesystem:detail-batch:{label}:{index}",
            display_name=f"Detail batch {label} {index}",
            repository=repository,
            access_scope=scope,
            state=SourceConnection.State.ACTIVE,
        )
        AccessScopeSource.objects.create(
            organization=organization,
            access_scope=scope,
            source_connection=source,
        )
        snapshot = AccessSnapshot.objects.create(
            organization=organization,
            source_connection=source,
            access_scope=scope,
            scope_revision=scope.revision,
            payload={"scope_id": str(scope.id), "repository_id": str(repository.id)},
        )
        sync_run = SyncRun.objects.create(
            organization=organization,
            source_connection=source,
            access_snapshot=snapshot,
            state=SyncRun.State.COMPLETED,
            started_at=observed_at,
            completed_at=observed_at,
            discovered_count=1,
            processed_count=1,
        )
        container = SourceContainer.objects.create(
            organization=organization,
            source_connection=source,
            external_id=f"root-{label}-{index}",
            name=f"root-{label}-{index}",
            canonical_url=f"file:///detail-batch/{label}/{index}",
        )
        document = SourceDocument.objects.create(
            organization=organization,
            source_container=container,
            external_id="service.json",
            relative_path="service.json",
            canonical_url=f"file:///detail-batch/{label}/{index}/service.json",
            document_kind=SourceDocument.Kind.JSON,
            media_type="application/json",
        )
        raw_content = json.dumps({"label": label, "index": index}).encode()
        digest = hashlib.sha256(raw_content).hexdigest()
        artifact = SourceContentArtifact.objects.create(
            organization=organization,
            content_hash=digest,
            byte_size=len(raw_content),
            media_type="application/json",
            content=raw_content,
        )
        revision = SourceRevision.objects.create(
            organization=organization,
            source_document=document,
            content_artifact=artifact,
            content_hash=digest,
            canonical_url=document.canonical_url,
            observed_at=observed_at,
        )
        observation = SourceObservation.objects.create(
            organization=organization,
            sync_run=sync_run,
            source_document=document,
            source_revision=revision,
            access_snapshot=snapshot,
            status=SourceObservation.Status.PRESENT,
            observed_at=observed_at,
        )
        document.current_revision = revision
        document.last_seen_run = sync_run
        document.last_observed_at = observed_at
        document.save(update_fields=["current_revision", "last_seen_run", "last_observed_at"])
        normalized = {"label": label, "index": index}
        parsed = ParsedSource.objects.create(
            organization=organization,
            source_revision=revision,
            parser_name="json",
            parser_version="detail-batch-v1",
            document_kind=SourceDocument.Kind.JSON,
            normalized=normalized,
            output_hash=content_hash(normalized),
            duration_ms=1,
        )
        location = SourceLocation.objects.create(
            organization=organization,
            parsed_source=parsed,
            source_observation=observation,
            pointer=f"/{label}/{index}",
            excerpt_hash=digest,
        )
        seed_assertion = KnowledgeAssertion.objects.create(
            organization=organization,
            subject_key=f"seed:{label}:{index}",
            predicate="detail.batch.seed",
            value=normalized,
            extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
            extraction_method="test:detail-batch-seed",
            confidence=1.0,
            valid_from=observed_at,
            observed_at=observed_at,
            provenance=[{"source_location_id": str(location.id)}],
            access_scope=scope,
        )
        provenance = AssertionProvenance.objects.create(
            organization=organization,
            assertion=seed_assertion,
            source_location=location,
            source_observation=observation,
            access_snapshot=snapshot,
            extraction_class=seed_assertion.extraction_class,
            extraction_method=seed_assertion.extraction_method,
            confidence=seed_assertion.confidence,
            observed_at=observed_at,
        )
        AssertionValidityInterval.objects.create(
            organization=organization,
            assertion=seed_assertion,
            source_document=document,
            source_observation=observation,
            valid_from=observed_at,
            observed_from=observed_at,
        )
        return provenance

    seed_provenance: list[AssertionProvenance] = []
    for index, repository in enumerate(repositories):
        seed_provenance.append(
            create_seed_provenance(
                repository=repository,
                scope=visible_scope,
                index=index,
                label="visible",
            )
        )

    selected = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:detail-batch-selected",
        display_name="Detail batch selected",
        attributes={"status": "ACTIVE", "owner": "platform"},
        access_scope=visible_scope,
    )
    related_entities = [
        KnowledgeEntity.objects.create(
            organization=organization,
            entity_type=KnowledgeEntity.EntityType.SERVICE,
            canonical_key=f"service:detail-batch-related-{index}",
            display_name=f"Detail batch related {index}",
            attributes={"status": "ACTIVE"},
            access_scope=visible_scope,
        )
        for index in range(10)
    ]
    assertions: list[KnowledgeAssertion] = []
    provenance_by_assertion: dict[uuid.UUID, list[AssertionProvenance]] = {}

    def create_assertion(index: int) -> KnowledgeAssertion:
        observed_at = timezone.now() + timedelta(minutes=index)
        assertion = KnowledgeAssertion.objects.create(
            organization=organization,
            subject_key=selected.canonical_key,
            predicate=f"detail.batch.predicate.{index:02d}",
            value={"index": index},
            extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
            extraction_method="test:detail-batch",
            confidence=0.99,
            valid_from=observed_at,
            observed_at=observed_at,
            staleness_state=KnowledgeAssertion.StalenessState.FRESH,
            provenance=[{"fixture": "detail-batch", "index": index}],
            review_state=KnowledgeAssertion.ReviewState.AUTO_ACCEPTED,
            access_scope=visible_scope,
        )
        assertion_provenance: list[AssertionProvenance] = []
        for repository_index, seed in enumerate(seed_provenance):
            citation_time = observed_at + timedelta(seconds=repository_index)
            assertion_provenance.append(
                AssertionProvenance.objects.create(
                    organization=organization,
                    assertion=assertion,
                    source_location=seed.source_location,
                    source_observation=seed.source_observation,
                    access_snapshot=seed.access_snapshot,
                    extraction_class=seed.extraction_class,
                    extraction_method=seed.extraction_method,
                    confidence=seed.confidence,
                    is_inferred=False,
                    observed_at=citation_time,
                )
            )
            AssertionValidityInterval.objects.create(
                organization=organization,
                assertion=assertion,
                source_document=seed.source_observation.source_document,
                source_observation=seed.source_observation,
                valid_from=citation_time,
                observed_from=citation_time,
            )
        provenance_by_assertion[assertion.id] = assertion_provenance
        return assertion

    query_counts: dict[str, int] = {}
    shapes = ((1, 1), (2, 2), (5, 4), (20, 10))
    for assertion_count, repository_count in shapes:
        while len(assertions) < assertion_count:
            assertions.append(create_assertion(len(assertions)))
        if assertion_count == 1:
            for repository_index, related in enumerate(related_entities):
                provenance = provenance_by_assertion[assertions[0].id][repository_index]
                KnowledgeRelationship.objects.create(
                    organization=organization,
                    relationship_type=(
                        KnowledgeRelationship.RelationshipType.SERVICE_DEPENDS_ON_SERVICE
                    ),
                    source_entity=selected,
                    target_entity=related,
                    source_entity_type=selected.entity_type,
                    target_entity_type=related.entity_type,
                    assertion=assertions[0],
                    source_location=provenance.source_location,
                    source_observation=provenance.source_observation,
                    access_snapshot=provenance.access_snapshot,
                    access_scope=visible_scope,
                    extraction_class=provenance.extraction_class,
                    confidence=provenance.confidence,
                    observed_at=provenance.observed_at,
                    review_state=KnowledgeRelationship.ReviewState.UNREVIEWED,
                )
        requested_ids = tuple(repository.id for repository in repositories[:repository_count])
        with CaptureQueriesContext(connection) as captured:
            detail = canvas_entity_detail(
                actor=viewer,
                entity_id=selected.id,
                repository_ids=requested_ids,
            )
        query_counts[f"{assertion_count}x{repository_count}"] = len(captured)
        sources = cast(list[dict[str, object]], detail["sources"])
        relationships = cast(list[dict[str, object]], detail["relationships"])
        assert len(sources) == assertion_count
        assert all(
            len(cast(list[dict[str, object]], source["citations"])) == repository_count
            for source in sources
        )
        for source in sources:
            citations = cast(list[dict[str, object]], source["citations"])
            observed_values = [str(citation["observed_at"]) for citation in citations]
            assert observed_values == sorted(observed_values)
        assert {relationship["repository_id"] for relationship in relationships} == {
            str(repository_id) for repository_id in requested_ids
        }
        assert len(relationships) == repository_count

    # Principal/grants/repositories, two scope-map statements, eight detail-data
    # statements, and four organization-action checks are exactly 17 statements.
    assert query_counts == {"1x1": 17, "2x2": 17, "5x4": 17, "20x10": 17}
    assert max(query_counts.values()) <= 22, query_counts
    assert max(query_counts.values()) - min(query_counts.values()) <= 2, query_counts
    materialized_cte = _AUTHORIZED_INCIDENT_EDGE_BATCH_SELECT.partition(")\nSELECT")[0]
    assert "relationship.source_entity_id = %(entity_id)s" in materialized_cte
    assert "relationship.target_entity_id = %(entity_id)s" in materialized_cte
    assert "FROM authorized_edges\nWHERE" not in _AUTHORIZED_INCIDENT_EDGE_BATCH_SELECT

    with CaptureQueriesContext(connection) as before_queries:
        before_hidden = canvas_entity_detail(actor=viewer, entity_id=selected.id)
    hidden_repository = Repository.objects.create(
        organization=organization,
        external_id="filesystem:canvas-detail-batch:hidden",
        name="detail-batch-hidden",
    )
    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="detail batch hidden",
    )
    AccessScopeRepository.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        repository=hidden_repository,
    )
    admin_membership = Membership.objects.get(organization=organization, user=admin_user)
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        membership=admin_membership,
    )
    hidden_seed = create_seed_provenance(
        repository=hidden_repository,
        scope=hidden_scope,
        index=10,
        label="hidden",
    )
    hidden_time = timezone.now() + timedelta(hours=1)
    hidden_assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        subject_key=selected.canonical_key,
        predicate="CANARY-HIDDEN-DETAIL-BATCH",
        value={"hidden": True},
        extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
        extraction_method="test:hidden-detail-batch",
        confidence=1.0,
        valid_from=hidden_time,
        observed_at=hidden_time,
        provenance=[{"fixture": "hidden-detail-batch"}],
        access_scope=hidden_scope,
    )
    hidden_provenance = AssertionProvenance.objects.create(
        organization=organization,
        assertion=hidden_assertion,
        source_location=hidden_seed.source_location,
        source_observation=hidden_seed.source_observation,
        access_snapshot=hidden_seed.access_snapshot,
        extraction_class=hidden_seed.extraction_class,
        extraction_method=hidden_seed.extraction_method,
        confidence=hidden_seed.confidence,
        observed_at=hidden_time,
    )
    AssertionValidityInterval.objects.create(
        organization=organization,
        assertion=hidden_assertion,
        source_document=hidden_seed.source_observation.source_document,
        source_observation=hidden_seed.source_observation,
        valid_from=hidden_time,
        observed_from=hidden_time,
    )
    hidden_related = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:CANARY-HIDDEN-DETAIL-BATCH-RELATED",
        display_name="CANARY-HIDDEN-DETAIL-BATCH",
        access_scope=hidden_scope,
    )
    KnowledgeRelationship.objects.create(
        organization=organization,
        relationship_type=KnowledgeRelationship.RelationshipType.SERVICE_DEPENDS_ON_SERVICE,
        source_entity=selected,
        target_entity=hidden_related,
        source_entity_type=selected.entity_type,
        target_entity_type=hidden_related.entity_type,
        assertion=hidden_assertion,
        source_location=hidden_provenance.source_location,
        source_observation=hidden_provenance.source_observation,
        access_snapshot=hidden_provenance.access_snapshot,
        access_scope=hidden_scope,
        extraction_class=hidden_provenance.extraction_class,
        confidence=hidden_provenance.confidence,
        observed_at=hidden_provenance.observed_at,
        review_state=KnowledgeRelationship.ReviewState.UNREVIEWED,
    )
    with CaptureQueriesContext(connection) as after_queries:
        after_hidden = canvas_entity_detail(actor=viewer, entity_id=selected.id)
    assert after_hidden == before_hidden
    assert "CANARY-HIDDEN-DETAIL-BATCH" not in json.dumps(after_hidden, sort_keys=True)
    assert len(after_queries) == len(before_queries)

    citation_boundary = resolve_authorized_repository_scopes(
        actor=viewer,
        actions=(Action.CANVAS_VIEW, Action.SEARCH),
        required_action=Action.SEARCH,
        repository_ids=tuple(repository.id for repository in repositories),
    )
    assert isinstance(citation_boundary.repository_ids_by_action, tuple)
    assert isinstance(citation_boundary.scope_ids_by_repository, tuple)
    with pytest.raises(TypeError):
        AuthorizedRepositoryScopes()
    with pytest.raises(ValueError, match="repository authorization budget"):
        resolve_authorized_repository_scopes(
            actor=viewer,
            actions=(Action.SEARCH,),
            required_action=Action.SEARCH,
            repository_ids=(repositories[0].id,) * 101,
        )
    with pytest.raises(ValueError, match="assertion citation batch budget"):
        authorized_assertion_citations_batch(
            actor=viewer,
            authorization=citation_boundary,
            assertion_ids=(assertions[0].id,) * 501,
            per_assertion_limit=20,
        )
    with pytest.raises(ResourceNotFoundError):
        authorized_incident_graph_edges_batch(
            actor=replace(
                viewer,
                credential_actions=frozenset({Action.SEARCH.value}),
            ),
            authorization=citation_boundary,
            entity_id=selected.id,
        )

    citation_seed = seed_provenance[0]
    citation_revision = citation_seed.source_observation.source_revision
    assert citation_revision is not None
    duplicate_observed_at = assertions[0].observed_at - timedelta(hours=1)
    for index in range(45):
        normalized = {"citation_dedupe": index}
        parsed = ParsedSource.objects.create(
            organization=organization,
            source_revision=citation_revision,
            parser_name=f"detail-batch-citation-{index}",
            parser_version="v1",
            document_kind=SourceDocument.Kind.JSON,
            normalized=normalized,
            output_hash=content_hash(normalized),
            duration_ms=1,
        )
        pointer = "/duplicate-display-key" if index < 25 else f"/unique-display-key/{index}"
        location = SourceLocation.objects.create(
            organization=organization,
            parsed_source=parsed,
            source_observation=citation_seed.source_observation,
            pointer=pointer,
            excerpt_hash=citation_seed.source_location.excerpt_hash,
        )
        AssertionProvenance.objects.create(
            organization=organization,
            assertion=assertions[0],
            source_location=location,
            source_observation=citation_seed.source_observation,
            access_snapshot=citation_seed.access_snapshot,
            extraction_class=citation_seed.extraction_class,
            extraction_method=citation_seed.extraction_method,
            confidence=citation_seed.confidence,
            observed_at=(
                duplicate_observed_at
                if index < 25
                else duplicate_observed_at + timedelta(seconds=index)
            ),
        )
    deduplicated_citations = authorized_assertion_citations_batch(
        actor=viewer,
        authorization=citation_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    )[assertions[0].id]
    display_keys = [
        (str(citation["locator"]), str(citation["observed_at"]))
        for citation in deduplicated_citations
    ]
    assert len(display_keys) == 20
    assert len(set(display_keys)) == 20
    assert sum(locator == "/duplicate-display-key" for locator, _observed_at in display_keys) == 1

    extra_repositories = Repository.objects.bulk_create(
        [
            Repository(
                organization=organization,
                external_id=f"filesystem:canvas-detail-batch:high-cardinality:{index}",
                name=f"detail-batch-high-cardinality-{index}",
            )
            for index in range(90)
        ]
    )
    repositories.extend(extra_repositories)
    AccessScopeRepository.objects.bulk_create(
        [
            AccessScopeRepository(
                organization=organization,
                access_scope=visible_scope,
                repository=repository,
            )
            for repository in extra_repositories
        ]
    )
    AccessScope.objects.bulk_create(
        [
            AccessScope(
                organization=organization,
                name=f"detail batch high cardinality scope {index}",
                all_memberships=True,
                all_repositories=True,
            )
            for index in range(99)
        ]
    )
    high_cardinality_boundary = resolve_authorized_repository_scopes(
        actor=viewer,
        actions=(Action.CANVAS_VIEW, Action.SEARCH),
        required_action=Action.CANVAS_VIEW,
        repository_ids=tuple(repository.id for repository in repositories),
        repository_limit=100,
    )
    assert len(high_cardinality_boundary.repositories) == 100
    assert len(high_cardinality_boundary.scope_ids_for(Action.SEARCH)) == 100
    high_cardinality_started = time.perf_counter()
    with CaptureQueriesContext(connection) as high_cardinality_queries:
        high_cardinality_detail = canvas_entity_detail(
            actor=viewer,
            entity_id=selected.id,
            repository_ids=tuple(repository.id for repository in repositories),
        )
    high_cardinality_wall_seconds = time.perf_counter() - high_cardinality_started
    high_cardinality_query_seconds = [
        float(query["time"]) for query in high_cardinality_queries.captured_queries
    ]
    assert high_cardinality_detail["id"] == str(selected.id)
    assert len(high_cardinality_queries) <= 22
    assert high_cardinality_wall_seconds < 1.0, high_cardinality_wall_seconds
    assert max(high_cardinality_query_seconds, default=0.0) < 1.0, high_cardinality_query_seconds

    tied_observed_at = timezone.now() + timedelta(hours=2)
    tied_assertions = KnowledgeAssertion.objects.bulk_create(
        [
            KnowledgeAssertion(
                organization=organization,
                subject_key=selected.canonical_key,
                predicate=f"detail.batch.tied.{index:02d}",
                value={"tied": index},
                extraction_class=KnowledgeAssertion.ExtractionClass.HUMAN,
                extraction_method="test:detail-batch-tied",
                confidence=1.0,
                valid_from=tied_observed_at,
                observed_at=tied_observed_at,
                provenance=[{"fixture": "detail-batch-tied", "index": index}],
                access_scope=visible_scope,
            )
            for index in range(22)
        ]
    )
    expected_tied_ids = [
        str(assertion.id)
        for assertion in sorted(
            tied_assertions, key=lambda assertion: str(assertion.id), reverse=True
        )[:21]
    ]
    first_tied_assertions = _batch_authorized_assertions(
        actor=viewer,
        authorization=citation_boundary,
        subject_keys={selected.canonical_key},
        limit=21,
    )
    second_tied_assertions = _batch_authorized_assertions(
        actor=viewer,
        authorization=citation_boundary,
        subject_keys={selected.canonical_key},
        limit=21,
    )
    first_tied_ids = [str(assertion.id) for assertion in first_tied_assertions]
    second_tied_ids = [str(assertion.id) for assertion in second_tied_assertions]
    assert first_tied_ids == expected_tied_ids
    assert first_tied_ids == second_tied_ids
    assert len(first_tied_ids[:20]) == 20
    assert len(first_tied_ids) == 21

    with connection.cursor() as cursor:
        cursor.execute("ANALYZE core_knowledgeassertion, core_assertionprovenance")
        cursor.execute("SET LOCAL enable_seqscan = off")
        cursor.execute(
            """
            EXPLAIN (FORMAT JSON)
            SELECT id
            FROM core_knowledgeassertion
            WHERE organization_id = %s
              AND subject_key = %s
              AND valid_until IS NULL
            ORDER BY observed_at DESC, id DESC
            LIMIT 21
            """,
            (organization.id, selected.canonical_key),
        )
        assertion_plan = json.dumps(cursor.fetchone()[0])
        cursor.execute("SET LOCAL enable_bitmapscan = off")
        cursor.execute("SET LOCAL enable_sort = off")
        cursor.execute(
            """
            EXPLAIN (FORMAT JSON)
            SELECT id
            FROM core_assertionprovenance
            WHERE organization_id = %s
              AND assertion_id = %s
            ORDER BY observed_at, id
            LIMIT 20
            """,
            (organization.id, assertions[0].id),
        )
        provenance_plan = json.dumps(cursor.fetchone()[0])
    assert "core_assert_current_subj_idx" in assertion_plan
    assert "core_assertprov_order_idx" in provenance_plan

    viewer_membership = Membership.objects.get(
        organization=organization,
        user_id=uuid.UUID(viewer.actor_id),
    )
    AccessScopeMembership.objects.filter(
        access_scope=visible_scope,
        membership=viewer_membership,
    ).delete()
    assert authorized_assertion_citations_batch(
        actor=viewer,
        authorization=citation_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    ) == {assertions[0].id: ()}
    assert (
        _batch_authorized_entities(
            actor=viewer,
            authorization=citation_boundary,
            entity_ids={selected.id},
        )
        == []
    )
    assert (
        _batch_authorized_assertions(
            actor=viewer,
            authorization=citation_boundary,
            subject_keys={selected.canonical_key},
            limit=21,
        )
        == []
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=visible_scope,
        membership=viewer_membership,
    )

    AccessScopeRepository.objects.filter(
        access_scope=visible_scope,
        repository=repositories[0],
    ).delete()
    binding_revoked_citations = authorized_assertion_citations_batch(
        actor=viewer,
        authorization=citation_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    )[assertions[0].id]
    assert len(binding_revoked_citations) == 9
    assert not any(citation["locator"] == "/visible/0" for citation in binding_revoked_citations)
    AccessScopeRepository.objects.create(
        organization=organization,
        access_scope=visible_scope,
        repository=repositories[0],
    )

    service_identity = ServiceIdentity.objects.create(
        organization=organization,
        name="canvas detail stale-boundary service",
        issuer="anva-test",
        audience="anva-test-api",
    )
    scope_service_binding = AccessScopeServiceIdentity.objects.create(
        organization=organization,
        access_scope=visible_scope,
        service_identity=service_identity,
    )
    service_grants = [
        AccessGrant.objects.create(
            organization=organization,
            service_identity=service_identity,
            repository=repositories[0],
            action=action.value,
        )
        for action in (Action.CANVAS_VIEW, Action.SEARCH)
    ]
    issued = issue_bootstrap_repository_token(
        organization=organization,
        repository=repositories[0],
        service_identity=service_identity,
        actions=frozenset({Action.CANVAS_VIEW, Action.SEARCH}),
        expires_at=timezone.now() + timedelta(days=1),
    )
    service_actor = ActorContext(
        organization_id=organization.id,
        actor_type="SERVICE",
        actor_id=str(service_identity.id),
        authorization_path="test:canvas-detail-stale-boundary",
        request_id=uuid.uuid4(),
        repository_id=repositories[0].id,
        credential_id=issued.record.id,
        credential_actions=frozenset({Action.CANVAS_VIEW.value, Action.SEARCH.value}),
    )
    service_boundary = resolve_authorized_repository_scopes(
        actor=service_actor,
        actions=(Action.CANVAS_VIEW, Action.SEARCH),
        required_action=Action.CANVAS_VIEW,
        repository_ids=(repositories[0].id,),
        repository_limit=1,
    )
    assert authorized_assertion_citations_batch(
        actor=service_actor,
        authorization=service_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    )[assertions[0].id]

    issued.record.revoked_at = timezone.now()
    issued.record.save(update_fields=["revoked_at"])
    assert authorized_assertion_citations_batch(
        actor=service_actor,
        authorization=service_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    ) == {assertions[0].id: ()}
    issued.record.revoked_at = None
    issued.record.save(update_fields=["revoked_at"])

    for grant in service_grants:
        grant.revoked_at = timezone.now()
        grant.save(update_fields=["revoked_at"])
    assert authorized_assertion_citations_batch(
        actor=service_actor,
        authorization=service_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    ) == {assertions[0].id: ()}
    assert (
        _batch_authorized_entities(
            actor=service_actor,
            authorization=service_boundary,
            entity_ids={selected.id},
        )
        == []
    )
    for grant in service_grants:
        grant.revoked_at = None
        grant.save(update_fields=["revoked_at"])

    scope_service_binding.delete()
    assert authorized_assertion_citations_batch(
        actor=service_actor,
        authorization=service_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    ) == {assertions[0].id: ()}
    scope_service_binding = AccessScopeServiceIdentity.objects.create(
        organization=organization,
        access_scope=visible_scope,
        service_identity=service_identity,
    )

    repositories[0].is_active = False
    repositories[0].save(update_fields=["is_active"])
    assert authorized_assertion_citations_batch(
        actor=service_actor,
        authorization=service_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    ) == {assertions[0].id: ()}
    assert (
        _batch_authorized_entities(
            actor=service_actor,
            authorization=service_boundary,
            entity_ids={selected.id},
        )
        == []
    )
    repositories[0].is_active = True
    repositories[0].save(update_fields=["is_active"])
    scope_service_binding.delete()

    visible_scope.is_active = False
    visible_scope.save(update_fields=["is_active"])
    assert authorized_assertion_citations_batch(
        actor=viewer,
        authorization=citation_boundary,
        assertion_ids=(assertions[0].id,),
        per_assertion_limit=20,
    ) == {assertions[0].id: ()}
    with pytest.raises(ResourceNotFoundError):
        canvas_entity_detail(actor=viewer, entity_id=selected.id)


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_selected_question_and_no_js_explorer_exclude_same_repository_decoy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository, actor, user = _tenant(slug="canvas-selection-evidence")
    scope = AccessScope.objects.create(
        organization=organization,
        name="selection evidence scope",
        all_memberships=True,
        all_repositories=True,
    )
    root = tmp_path / "selection-evidence"
    root.mkdir()
    relevant_file = root / "relevant.json"
    relevant_file.write_text(
        json.dumps(
            {
                "service": "scopefixture-relevant",
                "owner": "selection-team",
                "evidence": "STALE-SELECTION-EVIDENCE",
            }
        )
    )
    (root / "decoy.json").write_text(
        json.dumps(
            {
                "service": "scopefixture-decoy",
                "owner": "decoy-team",
                "evidence": "DECOY-REPOSITORY-EVIDENCE",
            }
        )
    )
    source = _ingest(
        actor=actor,
        repository=repository,
        scope=scope,
        root=root,
        key="selection-evidence",
    )
    relevant_file.write_text(
        json.dumps(
            {
                "service": "scopefixture-relevant",
                "owner": "selection-team",
                "evidence": "RELEVANT-SCOPED-EVIDENCE",
                "filler": "x" * 4_500,
            }
        )
    )
    _run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    job = claim_next_job(worker_id="canvas-selection-evidence-resync", lease_seconds=600)
    assert job is not None
    completed = execute_ingestion_job(
        job=job,
        worker_id="canvas-selection-evidence-resync",
    )
    complete_job(
        actor=ActorContext(
            organization_id=actor.organization_id,
            actor_type="SERVICE",
            actor_id="canvas-selection-evidence-resync",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=job.id,
        worker_id="canvas-selection-evidence-resync",
    )
    assert completed.state in {completed.State.COMPLETED, completed.State.PARTIALLY_COMPLETED}
    selected = KnowledgeEntity.objects.get(
        organization=organization,
        canonical_key="service:scopefixture-relevant",
    )
    selected_assertion = KnowledgeAssertion.objects.get(
        organization=organization,
        subject_key=selected.canonical_key,
        predicate="declares_service",
        valid_until__isnull=True,
    )
    selected_provenance = AssertionProvenance.objects.get(assertion=selected_assertion)
    assert selected_provenance.source_location.pointer == "/service"
    selected_resolution = EntityResolution.objects.get(
        organization=organization,
        entity=selected,
        source_location=selected_provenance.source_location,
    )
    assert selected_resolution.source_location.pointer == "/service"
    relevant_root = SourceChunkVisibility.objects.get(
        organization=organization,
        source_observation_id=selected_provenance.source_observation_id,
        source_chunk__text__contains="RELEVANT-SCOPED-EVIDENCE",
    )
    assert relevant_root.source_location.pointer == "/"
    assert "RELEVANT-SCOPED-EVIDENCE" in relevant_root.source_chunk.text
    decoy_root = SourceChunkVisibility.objects.get(
        organization=organization,
        source_chunk__text__contains="DECOY-REPOSITORY-EVIDENCE",
        source_observation__sync_run_id=F("source_observation__source_document__last_seen_run_id"),
    )
    assert decoy_root.source_location.pointer == "/"
    assert decoy_root.source_observation_id != relevant_root.source_observation_id
    relevant_document_id = relevant_root.source_observation.source_document_id
    current_relevant_visibilities = SourceChunkVisibility.objects.filter(
        organization=organization,
        source_observation__source_document_id=relevant_document_id,
        source_observation__sync_run_id=F("source_observation__source_document__last_seen_run_id"),
    )
    assert current_relevant_visibilities.count() >= 2
    assert current_relevant_visibilities.values("source_location_id").distinct().count() == 1
    stale_relevant_location_ids = set(
        SourceChunkVisibility.objects.filter(
            organization=organization,
            source_observation__source_document_id=relevant_document_id,
        )
        .exclude(source_observation_id=relevant_root.source_observation_id)
        .values_list("source_location_id", flat=True)
    )
    assert stale_relevant_location_ids
    selection_scope = canvas_selection_scope(
        actor=actor,
        entity_id=selected.id,
        repository_id=repository.id,
    )
    scoped_source_location_ids = cast(tuple[uuid.UUID, ...], selection_scope["source_location_ids"])
    assert scoped_source_location_ids == (relevant_root.source_location_id,)
    assert not stale_relevant_location_ids.intersection(scoped_source_location_ids)

    client = Client(enforce_csrf_checks=True)
    session = client.session
    session["anva_web_user_id"] = str(user.id)
    session["anva_web_organization_id"] = str(organization.id)
    session.save()
    page = client.get("/app/canvas")
    assert page.status_code == 200
    csrf = client.cookies["csrftoken"].value

    question = client.post(
        "/app/canvas/question",
        data=json.dumps(
            {
                "entity_id": str(selected.id),
                "repository_id": str(repository.id),
                "question": "scopefixture",
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert question.status_code == 200
    assert question.json()["entity"]["id"] == str(selected.id)
    assert {item["source_location_id"] for item in question.json()["results"]} == {
        str(relevant_root.source_location_id)
    }
    rendered_question = json.dumps(question.json(), sort_keys=True)
    assert "RELEVANT-SCOPED-EVIDENCE" in rendered_question
    assert "DECOY-REPOSITORY-EVIDENCE" not in rendered_question

    explorer = client.get(
        "/app/explorer",
        {
            "repository": str(repository.id),
            "start_entity": str(selected.id),
            "q": "scopefixture",
            "type": KnowledgeEntity.EntityType.SERVICE,
            "freshness": KnowledgeAssertion.StalenessState.FRESH,
        },
    )
    assert explorer.status_code == 200
    rendered_explorer = explorer.content.decode()
    assert "currently authorized one-hop context" in rendered_explorer
    assert (
        f'href="/app/explorer/entities/{selected.id}?repository={repository.id}"'
        in rendered_explorer
    )
    assert "service:scopefixture-relevant" in rendered_explorer
    assert "service:scopefixture-decoy" not in rendered_explorer
    assert "Assertions by freshness" in rendered_explorer
    assert "RELEVANT-SCOPED-EVIDENCE" in rendered_explorer
    assert "DECOY-REPOSITORY-EVIDENCE" not in rendered_explorer


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_detail_filters_incident_edges_before_global_six_hundred_edge_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository, actor, _user = _tenant(slug="canvas-detail-starvation")
    scope = AccessScope.objects.create(
        organization=organization,
        name="detail starvation scope",
        all_memberships=True,
        all_repositories=True,
    )
    root = tmp_path / "detail-starvation"
    root.mkdir()
    (root / "seed.json").write_text(json.dumps({"service": "seed"}))
    _ingest(actor=actor, repository=repository, scope=scope, root=root, key="detail-starvation")
    seed_assertion = KnowledgeAssertion.objects.get(
        organization=organization,
        predicate="declares_service",
    )
    seed_provenance = AssertionProvenance.objects.get(assertion=seed_assertion)
    assert not KnowledgeRelationship.objects.filter(organization=organization).exists()
    selected = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:selected-after-global-cap",
        display_name="Selected after global cap",
        access_scope=scope,
    )
    incident_target = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:selected-incident-target",
        display_name="Selected incident target",
        access_scope=scope,
    )
    unrelated_source = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:unrelated-source",
        display_name="Unrelated source",
        access_scope=scope,
    )
    unrelated_targets = [
        KnowledgeEntity(
            organization=organization,
            entity_type=KnowledgeEntity.EntityType.SERVICE,
            canonical_key=f"service:unrelated-target-{index:03d}",
            display_name=f"Unrelated target {index:03d}",
            access_scope=scope,
        )
        for index in range(600)
    ]
    KnowledgeEntity.objects.bulk_create(unrelated_targets)

    common = {
        "organization": organization,
        "relationship_type": (KnowledgeRelationship.RelationshipType.SERVICE_DEPENDS_ON_SERVICE),
        "source_entity_type": KnowledgeEntity.EntityType.SERVICE,
        "target_entity_type": KnowledgeEntity.EntityType.SERVICE,
        "assertion": seed_assertion,
        "source_location": seed_provenance.source_location,
        "source_observation": seed_provenance.source_observation,
        "access_snapshot": seed_provenance.access_snapshot,
        "access_scope": seed_assertion.access_scope,
        "extraction_class": seed_provenance.extraction_class,
        "confidence": seed_provenance.confidence,
        "observed_at": seed_provenance.observed_at,
        "review_state": KnowledgeRelationship.ReviewState.UNREVIEWED,
    }
    KnowledgeRelationship.objects.bulk_create(
        [
            KnowledgeRelationship(
                id=uuid.UUID(int=index + 1),
                source_entity=unrelated_source,
                target_entity=target,
                **common,
            )
            for index, target in enumerate(unrelated_targets)
        ]
    )
    incident_id = uuid.UUID(int=(1 << 128) - 1)
    KnowledgeRelationship.objects.create(
        id=incident_id,
        source_entity=selected,
        target_entity=incident_target,
        **common,
    )

    globally_capped, globally_truncated = authorized_graph_edges(
        actor=actor,
        repository_id=repository.id,
        edge_limit=600,
    )
    low_ids = {uuid.UUID(int=index + 1) for index in range(600)}
    assert globally_truncated is True
    assert len(globally_capped) == 600
    assert {edge.relationship_id for edge in globally_capped} == low_ids
    assert incident_id not in {edge.relationship_id for edge in globally_capped}

    detail = canvas_entity_detail(
        actor=actor,
        entity_id=selected.id,
        repository_ids=(repository.id,),
    )
    relationships = cast(list[dict[str, object]], detail["relationships"])
    assert [item["id"] for item in relationships] == [str(incident_id)]
    assert [item["type"] for item in relationships] == [
        KnowledgeRelationship.RelationshipType.SERVICE_DEPENDS_ON_SERVICE
    ]
    assert [item["target_id"] for item in relationships] == [str(incident_target.id)]


@pytest.mark.integration
@pytest.mark.django_db
def test_saved_canvas_boundaries_are_reauthorized_before_persist_or_exposure() -> None:
    organization, repository, admin, _user = _tenant(slug="canvas-reauthorize")
    hidden_repository = Repository.objects.create(
        organization=organization,
        external_id="filesystem:canvas-reauthorize:hidden",
        name="hidden repository",
    )
    foreign = Organization.objects.create(slug="canvas-reauthorize-foreign", name="Foreign")
    foreign_repository = Repository.objects.create(
        organization=foreign,
        external_id="filesystem:foreign:repo",
        name="foreign repository",
    )
    before = CanvasView.objects.count()
    with pytest.raises(ResourceNotFoundError):
        create_canvas_view(
            actor=admin,
            name="Foreign semantic boundary",
            description="must not persist",
            view_type=CanvasView.ViewType.CUSTOM,
            semantic_query={"repository_ids": [str(foreign_repository.id)]},
            repository_id=repository.id,
            access_scope_id=None,
            idempotency_key="foreign-semantic-boundary",
        )
    assert CanvasView.objects.count() == before

    view, _created = create_canvas_view(
        actor=admin,
        name="Visible service boundary",
        description="",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={"repository_ids": [str(repository.id)]},
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="visible-service-boundary",
    )
    hidden_view, _created = create_canvas_view(
        actor=admin,
        name="Hidden semantic boundary",
        description="",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={"repository_ids": [str(hidden_repository.id)]},
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="hidden-service-boundary",
    )
    share, _created = create_canvas_share(
        actor=admin,
        view_id=hidden_view.id,
        idempotency_key="hidden-service-share",
    )
    service = ServiceIdentity.objects.create(
        organization=organization,
        name="limited canvas service",
        issuer="anva-test",
        audience="anva-test-api",
    )
    for action in (Action.CANVAS_VIEW, Action.CANVAS_MANAGE):
        AccessGrant.objects.create(
            organization=organization,
            service_identity=service,
            repository=repository,
            action=action.value,
        )
    service_actor = ActorContext(
        organization_id=organization.id,
        actor_type="SERVICE",
        actor_id=str(service.id),
        authorization_path="test:limited-canvas-service",
        request_id=uuid.uuid4(),
    )
    Repository.objects.bulk_create(
        [
            Repository(
                id=uuid.UUID(int=index),
                organization=organization,
                external_id=f"filesystem:canvas-reauthorize:unavailable-{index:03d}",
                name=f"Unavailable repository {index:03d}",
            )
            for index in range(1, 102)
        ]
    )
    default_projection = canvas_projection(actor=service_actor, query=CanvasQuery())
    assert [
        item["id"] for item in cast(list[dict[str, object]], default_projection["repositories"])
    ] == [str(repository.id)]
    assert [item.id for item in list_canvas_views(actor=service_actor)] == [view.id]
    with pytest.raises(ResourceNotFoundError):
        canvas_projection(actor=service_actor, query=CanvasQuery(view_id=hidden_view.id))
    with pytest.raises(ResourceNotFoundError):
        resolve_canvas_share(actor=service_actor, share_id=share.id)
    with pytest.raises(ResourceNotFoundError):
        save_canvas_revision(
            actor=service_actor,
            view_id=view.id,
            expected_revision=1,
            semantic_query={"repository_ids": [str(hidden_repository.id)]},
            placements=[],
            filters=[],
            layers=[],
            groups=[],
            annotations=[],
            idempotency_key="inaccessible-save-boundary",
        )
    assert CanvasViewRevision.objects.filter(canvas_view=view).count() == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_is_deterministic_and_hard_caps_authorized_nodes() -> None:
    organization, repository, actor, _user = _tenant(slug="canvas-cap")
    scope = AccessScope.objects.create(
        organization=organization,
        name="all canvas nodes",
        all_memberships=True,
        all_repositories=True,
    )
    KnowledgeEntity.objects.bulk_create(
        [
            KnowledgeEntity(
                organization=organization,
                entity_type=KnowledgeEntity.EntityType.COMPONENT,
                canonical_key=f"component:{index:03d}",
                display_name=f"Component {index:03d}",
                access_scope=scope,
            )
            for index in reversed(range(305))
        ]
    )

    started = time.perf_counter()
    first = canvas_projection(
        actor=actor,
        query=CanvasQuery(repository_ids=(repository.id,)),
    )
    elapsed = time.perf_counter() - started
    second = canvas_projection(
        actor=actor,
        query=CanvasQuery(repository_ids=(repository.id,)),
    )

    assert first["counts"] == {"nodes": 300, "edges": 0}
    assert first["truncated"] is True
    assert first["nodes"] == second["nodes"]
    assert first["layout"] == second["layout"]
    assert any("capped at 300" in message for message in cast(list[str], first["limitations"]))
    assert _canvas_payload_size(first) <= 750 * 1024
    assert elapsed < 5


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_http_wire_budget_is_compact_utf8_and_deterministically_trimmed() -> None:
    organization, repository, _actor, user = _tenant(slug="canvas-wire-budget")
    scope = AccessScope.objects.create(
        organization=organization,
        name="wire budget scope",
        all_memberships=True,
        all_repositories=True,
    )
    KnowledgeEntity.objects.bulk_create(
        [
            KnowledgeEntity(
                organization=organization,
                entity_type=KnowledgeEntity.EntityType.COMPONENT,
                canonical_key=f"component:wire:{index:03d}",
                display_name=f"{index:03d}" + "界" * 497,
                attributes={"owner": "فريق" * 75, "status": "ACTIVE", "risk": "界" * 100},
                access_scope=scope,
            )
            for index in range(300)
        ]
    )
    client = Client()
    session = client.session
    session["anva_web_user_id"] = str(user.id)
    session["anva_web_organization_id"] = str(organization.id)
    session.save()
    request = {
        "repository_ids": [str(repository.id)],
        "node_limit": 300,
        "edge_limit": 600,
    }
    first = client.post(
        "/app/canvas/query",
        data=json.dumps(request),
        content_type="application/json",
    )
    second = client.post(
        "/app/canvas/query",
        data=json.dumps(request),
        content_type="application/json",
    )
    assert first.status_code == second.status_code == 200
    assert len(first.content) <= 750 * 1024
    assert len(second.content) <= 750 * 1024
    assert "界".encode() in first.content
    assert b"\\u754c" not in first.content
    first_payload = first.json()
    second_payload = second.json()
    assert first_payload["truncated"] is True
    assert first_payload["counts"]["nodes"] < 300
    for key in ("nodes", "edges", "counts", "layout", "limitations", "truncated"):
        assert first_payload[key] == second_payload[key]


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_performance_report_has_30_warm_strict_samples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository, actor, _user = _tenant(slug="canvas-performance")
    scope = AccessScope.objects.create(
        organization=organization,
        name="performance scope",
        all_memberships=True,
        all_repositories=True,
    )
    source_root = tmp_path / "strict-source"
    source_root.mkdir()
    (source_root / "service.json").write_text(
        json.dumps({"service": "performance-runtime", "owner": "platform"}),
        encoding="utf-8",
    )
    _ingest(
        actor=actor,
        repository=repository,
        scope=scope,
        root=source_root,
        key="canvas-performance-source",
    )
    remaining = 300 - KnowledgeEntity.objects.filter(organization=organization).count()
    KnowledgeEntity.objects.bulk_create(
        [
            KnowledgeEntity(
                organization=organization,
                entity_type=KnowledgeEntity.EntityType.COMPONENT,
                canonical_key=f"component:performance:{index:03d}",
                display_name=f"Performance component {index:03d}",
                attributes={"owner": "Performance", "status": "ACTIVE", "risk": "LOW"},
                access_scope=scope,
            )
            for index in range(remaining)
        ]
    )
    relationship = KnowledgeRelationship.objects.get(organization=organization)
    query = CanvasQuery(repository_ids=(repository.id,))

    warm_projection = canvas_projection(actor=actor, query=query)
    warm_path = canvas_path(
        actor=actor,
        source_id=relationship.source_entity_id,
        target_id=relationship.target_entity_id,
        repository_ids=(repository.id,),
    )
    assert warm_projection["counts"] == {"nodes": 300, "edges": 1}
    assert warm_path["found"] is True

    projection_ms: list[float] = []
    projection_queries: list[int] = []
    path_ms: list[float] = []
    path_queries: list[int] = []
    last_projection = warm_projection
    for _sample in range(30):
        with CaptureQueriesContext(connection) as captured:
            started = time.perf_counter()
            last_projection = canvas_projection(actor=actor, query=query)
            projection_ms.append((time.perf_counter() - started) * 1_000)
        projection_queries.append(len(captured))
        with CaptureQueriesContext(connection) as captured:
            started = time.perf_counter()
            path = canvas_path(
                actor=actor,
                source_id=relationship.source_entity_id,
                target_id=relationship.target_entity_id,
                repository_ids=(repository.id,),
            )
            path_ms.append((time.perf_counter() - started) * 1_000)
        path_queries.append(len(captured))
        assert path["found"] is True

    projection_summary = _metric_summary(projection_ms)
    path_summary = _metric_summary(path_ms)
    assert cast(float, projection_summary["p95"]) <= 400
    assert cast(float, path_summary["p95"]) <= 1_000
    assert max(projection_queries) == min(projection_queries)
    assert max(path_queries) == min(path_queries)
    assert max(projection_queries) <= 30
    assert max(path_queries) <= 30
    payload_bytes = _canvas_payload_size(last_projection)
    assert payload_bytes <= 750 * 1024

    report = {
        "schema_version": "1",
        "metadata": {
            "commit": os.environ.get(
                "ANVA_PERFORMANCE_COMMIT",
                "fbb79960f96518a51cc8cf0e4f3ffb3090798378+working-tree",
            ),
            "environment": "Docker Compose test profile",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_model": _cpu_model(),
            "cpu_count": os.cpu_count(),
            "postgres_server_version": cast(Any, connection).pg_version,
            "fixture": {
                "visible_nodes": 300,
                "strict_source_relationships": 1,
                "repositories": 1,
                "semantic_depth": 2,
                "fixture_key": "canvas-performance-v1",
            },
        },
        "targets": {
            "strict_query_hydration_p95_ms": 400,
            "path_p95_ms": 1_000,
            "payload_bytes": 750 * 1024,
        },
        "metrics": {
            "strict_query_hydration_ms": projection_summary,
            "strict_query_hydration_query_count": {
                **_metric_summary([float(value) for value in projection_queries]),
                "bounded_and_constant": True,
            },
            "path_round_trip_service_ms": path_summary,
            "path_query_count": {
                **_metric_summary([float(value) for value in path_queries]),
                "bounded_and_constant": True,
            },
            "payload_bytes": payload_bytes,
        },
        "notes": [
            "Each metric contains 30 samples after one discarded warm call.",
            (
                "Strict query/hydration includes authorization, strict provenance CTE, "
                "ORM hydration, deterministic layout, and payload construction in-process."
            ),
            (
                "Query-count equality across all samples is the N+1 regression gate; "
                "the fixture contains a real ingested strict relationship."
            ),
        ],
    }
    PERFORMANCE_ROOT.mkdir(parents=True, exist_ok=True)
    (PERFORMANCE_ROOT / "database.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_canvas_revisions_are_append_only_idempotent_and_tenant_safe() -> None:
    organization, repository, actor, _user = _tenant(slug="canvas-revision")
    scope = AccessScope.objects.create(
        organization=organization,
        name="canvas revision scope",
        all_memberships=True,
        all_repositories=True,
    )
    product = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.PRODUCT,
        canonical_key="product:storefront",
        display_name="Storefront",
        access_scope=scope,
    )
    repository_entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.REPOSITORY,
        canonical_key="repository:storefront",
        display_name="Storefront repository",
        access_scope=scope,
    )
    view, created = create_canvas_view(
        actor=actor,
        name="Storefront system",
        description="A semantic system view",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={"repository_ids": [str(repository.id)]},
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="create-storefront-view",
    )
    assert created is True
    initial_hash = CanvasViewRevision.objects.get(canvas_view=view, revision=1).content_hash
    canonical_revision = product.revision
    assert [item.id for item in list_canvas_views(actor=actor)] == [view.id]
    detail = canvas_entity_detail(
        actor=actor,
        entity_id=product.id,
        repository_ids=(repository.id,),
    )
    assert detail["id"] == str(product.id)
    assert detail["summary"] == "No governed summary is available."
    assert detail["sources"] == []
    assert detail["permitted_actions"] == {
        "view": True,
        "move_in_view": True,
        "propose_relationship": True,
        "delete_canonical": False,
    }

    owner_membership = Membership.objects.get(organization=organization, user_id=actor.actor_id)
    with pytest.raises(ValueError, match="expiry must be in the future"):
        create_canvas_share(
            actor=actor,
            view_id=view.id,
            recipient_membership_id=owner_membership.id,
            expires_at=timezone.now() - timedelta(seconds=1),
            idempotency_key="expired-storefront-share",
        )
    share, created = create_canvas_share(
        actor=actor,
        view_id=view.id,
        recipient_membership_id=owner_membership.id,
        expires_at=timezone.now() + timedelta(hours=1),
        idempotency_key="storefront-share",
    )
    assert created is True
    retry_share, created = create_canvas_share(
        actor=actor,
        view_id=view.id,
        recipient_membership_id=owner_membership.id,
        expires_at=share.expires_at,
        idempotency_key="storefront-share",
    )
    assert created is False
    assert retry_share.id == share.id
    shared_view, shared_revision = resolve_canvas_share(actor=actor, share_id=share.id)
    assert shared_view.id == view.id
    assert shared_revision.revision == 1

    presentation = [
        {
            "entity_id": str(product.id),
            "x": 160.5,
            "y": 80.25,
            "is_pinned": True,
            "is_hidden": False,
            "group_index": 0,
        }
    ]
    filters: list[dict[str, object]] = [
        {"field": "status", "operator": "EQUALS", "value": "ACTIVE"}
    ]
    layers = [
        {"key": "execution", "label": "Execution", "is_visible": True},
        {"key": "ownership", "label": "Ownership", "is_visible": False},
    ]
    groups = [
        {
            "label": "Storefront group",
            "x": 20,
            "y": 30,
            "width": 600,
            "height": 400,
        }
    ]
    annotations = [
        {
            "entity_id": str(product.id),
            "body": "Presentation-only note",
            "x": 180,
            "y": 110,
        }
    ]
    revision, created = save_canvas_revision(
        actor=actor,
        view_id=view.id,
        expected_revision=1,
        semantic_query={"repository_ids": [str(repository.id)]},
        placements=presentation,
        filters=filters,
        layers=layers,
        groups=groups,
        annotations=annotations,
        idempotency_key="save-storefront-layout",
    )
    assert created is True
    retry, created = save_canvas_revision(
        actor=actor,
        view_id=view.id,
        expected_revision=1,
        semantic_query={"repository_ids": [str(repository.id)]},
        placements=presentation,
        filters=filters,
        layers=layers,
        groups=groups,
        annotations=annotations,
        idempotency_key="save-storefront-layout",
    )
    assert created is False
    assert retry.id == revision.id
    product.refresh_from_db()
    assert product.revision == canonical_revision
    assert CanvasViewRevision.objects.get(canvas_view=view, revision=1).content_hash == initial_hash
    _shared_view, exact_shared_revision = resolve_canvas_share(actor=actor, share_id=share.id)
    assert exact_shared_revision.revision == 1
    shared_projection = canvas_projection(
        actor=actor,
        query=CanvasQuery(view_id=view.id, view_revision=exact_shared_revision.revision),
    )
    assert shared_projection["view"] == {
        "id": str(view.id),
        "name": view.name,
        "type": view.view_type,
        "revision": 1,
        "content_hash": exact_shared_revision.content_hash,
    }
    with pytest.raises(OptimisticConcurrencyError):
        revoke_canvas_share(
            actor=actor,
            share_id=share.id,
            expected_view_revision=2,
            idempotency_key="revoke-storefront-share-stale",
        )
    revoked_share, revoked = revoke_canvas_share(
        actor=actor,
        share_id=share.id,
        expected_view_revision=1,
        idempotency_key="revoke-storefront-share",
    )
    assert revoked is True
    assert revoked_share.revoked_at is not None
    replayed_revocation, revoked = revoke_canvas_share(
        actor=actor,
        share_id=share.id,
        expected_view_revision=1,
        idempotency_key="revoke-storefront-share",
    )
    assert revoked is False
    assert replayed_revocation.revoked_at == revoked_share.revoked_at
    with pytest.raises(ResourceNotFoundError):
        resolve_canvas_share(actor=actor, share_id=share.id)
    assert CanvasShare.objects.filter(id=share.id).exists()
    assert CanvasViewRevision.objects.filter(canvas_view=view).count() == 2

    with pytest.raises(IdempotencyConflictError):
        save_canvas_revision(
            actor=actor,
            view_id=view.id,
            expected_revision=1,
            semantic_query={"search": "different"},
            placements=presentation,
            filters=filters,
            layers=layers,
            groups=groups,
            annotations=annotations,
            idempotency_key="save-storefront-layout",
        )
    with pytest.raises(OptimisticConcurrencyError):
        save_canvas_revision(
            actor=actor,
            view_id=view.id,
            expected_revision=1,
            semantic_query={},
            placements=[],
            filters=[],
            layers=[],
            groups=[],
            annotations=[],
            idempotency_key="stale-storefront-layout",
        )

    with pytest.raises(DatabaseError):
        with transaction.atomic():
            CanvasViewRevision.objects.filter(id=revision.id).update(layout_version="changed")
    placement = CanvasNodePlacement.objects.get(view_revision=revision)
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            CanvasNodePlacement.objects.filter(id=placement.id).update(x=999)

    foreign = Organization.objects.create(slug="canvas-foreign", name="Foreign")
    foreign_scope = AccessScope.objects.create(
        organization=foreign,
        name="foreign",
        all_memberships=True,
        all_repositories=True,
    )
    foreign_entity = KnowledgeEntity.objects.create(
        organization=foreign,
        entity_type=KnowledgeEntity.EntityType.COMPONENT,
        canonical_key="component:foreign",
        display_name="Foreign",
        access_scope=foreign_scope,
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            CanvasNodePlacement.objects.create(
                organization=foreign,
                view_revision=revision,
                entity=foreign_entity,
                x=0,
                y=0,
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    relationship_count = KnowledgeRelationship.objects.count()
    proposal, created = propose_canvas_relationship(
        actor=actor,
        source_id=product.id,
        target_id=repository_entity.id,
        relationship_type=KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY,
        repository_id=repository.id,
        expected_source_revision=product.revision,
        expected_target_revision=repository_entity.revision,
        rationale="The storefront is implemented in this governed repository.",
        idempotency_key="storefront-relationship",
    )
    assert created is True
    retry_proposal, created = propose_canvas_relationship(
        actor=actor,
        source_id=product.id,
        target_id=repository_entity.id,
        relationship_type=KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY,
        repository_id=repository.id,
        expected_source_revision=product.revision,
        expected_target_revision=repository_entity.revision,
        rationale="The storefront is implemented in this governed repository.",
        idempotency_key="storefront-relationship",
    )
    assert created is False
    assert retry_proposal.id == proposal.id
    assert proposal.state == KnowledgeProposal.State.PROPOSED
    assert KnowledgeRelationship.objects.count() == relationship_count
    with pytest.raises(OptimisticConcurrencyError):
        propose_canvas_relationship(
            actor=actor,
            source_id=product.id,
            target_id=repository_entity.id,
            relationship_type=(
                KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY
            ),
            repository_id=repository.id,
            expected_source_revision=product.revision + 1,
            expected_target_revision=repository_entity.revision,
            rationale="A stale retry must not create canonical or proposed state.",
            idempotency_key="stale-storefront-relationship",
        )


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_http_query_requires_csrf_and_never_requires_javascript() -> None:
    organization, repository, _actor, user = _tenant(slug="canvas-http")
    scope = AccessScope.objects.create(
        organization=organization,
        name="http scope",
        all_memberships=True,
        all_repositories=True,
    )
    product = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.PRODUCT,
        canonical_key="product:http-storefront",
        display_name="HTTP storefront",
        attributes={"owner": "Product", "status": "ACTIVE", "risk": "HIGH"},
        access_scope=scope,
    )
    repository_entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.REPOSITORY,
        canonical_key="repository:http-storefront",
        display_name="HTTP storefront repository",
        access_scope=scope,
    )
    client = Client(enforce_csrf_checks=True)
    session = client.session
    session["anva_web_user_id"] = str(user.id)
    session["anva_web_organization_id"] = str(organization.id)
    session.save()

    page = client.get("/app/canvas")
    assert page.status_code == 200
    rendered = page.content.decode()
    assert "Keyboard and no-JS equivalent" in rendered
    assert "Permitted nodes" in rendered
    assert "HTTP storefront" in rendered
    assert "HTTP storefront repository" in rendered

    missing = client.post(
        "/app/canvas/query",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert missing.status_code == 403
    csrf = client.cookies["csrftoken"].value
    allowed = client.post(
        "/app/canvas/query",
        data=json.dumps({}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert allowed.status_code == 200
    assert allowed.json()["schema_version"] == "1"
    invalid_query_payloads: tuple[dict[str, object], ...] = (
        {"node_limit": "300"},
        {"depth": None},
        {"depth": True},
        {"view_id": None},
        {"view_id": {}},
        {"view_revision": None},
        {"repository_ids": [True]},
        {"owner": []},
        {"anchor_id": False},
        {"as_of": {}},
        {"entity_types": "PRODUCT"},
        {"layers": [1]},
    )
    for invalid_payload in invalid_query_payloads:
        invalid_query = client.post(
            "/app/canvas/query",
            data=json.dumps(invalid_payload),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        assert invalid_query.status_code == 400, invalid_payload
    strict_valid_query = client.post(
        "/app/canvas/query",
        data=json.dumps(
            {
                "repository_ids": [str(repository.id)],
                "node_limit": 300,
                "edge_limit": 600,
                "owner": "",
                "entity_types": [],
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert strict_valid_query.status_code == 200
    assert strict_valid_query.json()["counts"] == allowed.json()["counts"]

    detail = client.get(
        f"/app/canvas/entities/{product.id}",
        {"repository": str(repository.id)},
    )
    assert detail.status_code == 200
    assert detail.json()["id"] == str(product.id)
    scoped_question = client.post(
        "/app/canvas/question",
        data=json.dumps(
            {
                "entity_id": str(product.id),
                "repository_id": str(repository.id),
                "question": "What implements this product?",
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert scoped_question.status_code == 200
    assert scoped_question.json()["entity"]["id"] == str(product.id)
    assert scoped_question.json()["selection_context"]["depth"] == 1
    assert {node["id"] for node in scoped_question.json()["selection_context"]["nodes"]} == {
        str(product.id)
    }
    path_payload = {
        "source_id": str(product.id),
        "target_id": str(repository_entity.id),
        "repository_ids": [str(repository.id)],
        "max_depth": 3,
    }
    for field, invalid_value in (
        ("source_id", True),
        ("repository_ids", [False]),
        ("max_depth", "3"),
    ):
        invalid_path = client.post(
            "/app/canvas/path",
            data=json.dumps({**path_payload, field: invalid_value}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=csrf,
        )
        assert invalid_path.status_code == 400, field
    no_path = client.post(
        "/app/canvas/path",
        data=json.dumps(path_payload),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert no_path.status_code == 200
    assert no_path.json()["found"] is False

    created_view = client.post(
        "/app/canvas/views",
        data={
            "name": "HTTP storefront map",
            "description": "Saved without requiring client-side JavaScript",
            "view_type": CanvasView.ViewType.PRODUCT_SYSTEM,
            "repository_id": str(repository.id),
            "entity_type": [KnowledgeEntity.EntityType.PRODUCT],
            "idempotency_key": "http-storefront-view",
        },
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert created_view.status_code == 302
    view = CanvasView.objects.get(name="HTTP storefront map")
    saved_as_of = (timezone.now() + timedelta(hours=1)).isoformat()
    invalid_saved_revision = client.post(
        f"/app/canvas/views/{view.id}/revisions",
        data=json.dumps(
            {
                "expected_revision": True,
                "semantic_query": {},
                "presentation": {
                    "placements": [],
                    "filters": [],
                    "layers": [],
                    "groups": [],
                    "annotations": [],
                },
                "idempotency_key": "invalid-boolean-revision",
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert invalid_saved_revision.status_code == 400
    saved_revision = client.post(
        f"/app/canvas/views/{view.id}/revisions",
        data=json.dumps(
            {
                "expected_revision": 1,
                "semantic_query": {
                    "repository_ids": [str(repository.id)],
                    "root_entity_id": str(product.id),
                    "entity_types": [KnowledgeEntity.EntityType.PRODUCT],
                    "owner": "Product",
                    "status": "ACTIVE",
                    "risk": "HIGH",
                    "freshness": "UNKNOWN",
                    "layers": ["provenance"],
                    "as_of": saved_as_of,
                    "search": "HTTP storefront",
                    "depth": 3,
                },
                "presentation": {
                    "placements": [
                        {
                            "entity_id": str(product.id),
                            "x": 10,
                            "y": 20,
                            "is_pinned": True,
                            "is_hidden": False,
                            "group_index": None,
                        }
                    ],
                    "filters": [],
                    "layers": [],
                    "groups": [],
                    "annotations": [],
                },
                "idempotency_key": "http-storefront-revision",
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert saved_revision.status_code == 201
    assert saved_revision.json()["revision"] == 2
    saved_page = client.get(f"/app/canvas?view={view.id}")
    saved_html = saved_page.content.decode()
    assert saved_page.status_code == 200
    assert 'value="Product"' in saved_html
    assert 'value="ACTIVE"' in saved_html
    assert saved_as_of[:16] in saved_html
    assert 'value="provenance" checked' in saved_html
    assert 'value="3" selected' in saved_html
    focused_page = client.get(f"/app/canvas?view={view.id}&focus={product.id}&depth=1")
    assert focused_page.status_code == 200
    assert f'value="{product.id}" selected' in focused_page.content.decode()
    cleared_query = client.post(
        "/app/canvas/query",
        data=json.dumps(
            {
                "view_id": str(view.id),
                "anchor_id": None,
                "entity_types": [],
                "owner": "",
                "status": "",
                "risk": "",
                "freshness": "",
                "as_of": None,
                "search": "",
                "layers": [],
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert cleared_query.status_code == 200
    assert cleared_query.json()["semantic_query"] == {
        "repository_ids": [str(repository.id)],
        "depth": 3,
    }
    cleared_page = client.get(
        "/app/canvas",
        {
            "view": str(view.id),
            "semantic_controls": "1",
            "q": "",
            "freshness": "",
            "owner": "",
            "status": "",
            "risk": "",
            "as_of": "",
            "focus": "",
            "depth": "3",
        },
    )
    assert cleared_page.status_code == 200
    cleared_html = cleared_page.content.decode()
    assert 'name="q" type="search" maxlength="500" value=""' in cleared_html
    assert 'name="owner" maxlength="300" value=""' in cleared_html
    assert 'name="status" maxlength="100" value=""' in cleared_html
    assert 'name="risk" maxlength="100" value=""' in cleared_html
    assert 'name="as_of" type="datetime-local" value=""' in cleared_html
    assert 'value="PRODUCT" selected' not in cleared_html
    assert 'value="FRESH" selected' not in cleared_html
    assert f'value="{product.id}" selected' not in cleared_html
    assert 'value="execution" checked' in cleared_html
    invalid_share = client.post(
        f"/app/canvas/views/{view.id}/shares",
        data=json.dumps({"idempotency_key": {"not": "a string"}}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert invalid_share.status_code == 400
    shared = client.post(
        f"/app/canvas/views/{view.id}/shares",
        data=json.dumps({"idempotency_key": "http-storefront-share"}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert shared.status_code == 201
    assert shared.json()["authorization_required"] is True
    shared_page = client.get(shared.json()["deep_link"])
    assert shared_page.status_code == 200
    assert "HTTP storefront map" in shared_page.content.decode()
    assert "Revoke this share" in shared_page.content.decode()
    revoked = client.post(
        f"/app/canvas/shares/{shared.json()['share_id']}/revoke",
        data={
            "expected_view_revision": 2,
            "idempotency_key": "http-storefront-revoke",
        },
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert revoked.status_code == 302
    closed_share = client.get(shared.json()["deep_link"])
    assert closed_share.status_code == 404

    proposed = client.post(
        "/app/canvas/relationship-proposals",
        data={
            "source_id": str(product.id),
            "target_id": str(repository_entity.id),
            "relationship_type": (
                KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY
            ),
            "repository_id": str(repository.id),
            "expected_source_revision": product.revision,
            "expected_target_revision": repository_entity.revision,
            "rationale": "The product is implemented by this repository.",
            "idempotency_key": "http-storefront-proposal",
        },
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert proposed.status_code == 302
    assert KnowledgeProposal.objects.filter(organization=organization).count() == 1
    for response in (allowed, detail, scoped_question, no_path, saved_revision, shared):
        assert len(response.content) <= 750 * 1024
        assert b'": "' not in response.content


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_api_is_bearer_authenticated_and_closed() -> None:
    organization, repository, admin, _user = _tenant(slug="canvas-api")
    scope = AccessScope.objects.create(
        organization=organization,
        name="service canvas scope",
        all_memberships=True,
        all_service_identities=True,
        all_repositories=True,
    )
    entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.PRODUCT,
        canonical_key="product:api-visible",
        display_name="API visible product",
        attributes={"owner": "API", "status": "ACTIVE", "risk": "LOW"},
        access_scope=scope,
    )
    target = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.REPOSITORY,
        canonical_key="repository:api-visible",
        display_name="API visible repository",
        access_scope=scope,
    )
    view, created = create_canvas_view(
        actor=admin,
        name="Bearer API view",
        description="A service-readable and manageable view",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={
            "repository_ids": [str(repository.id)],
            "root_entity_id": str(entity.id),
            "entity_types": [KnowledgeEntity.EntityType.PRODUCT],
            "owner": "API",
            "status": "ACTIVE",
            "risk": "LOW",
            "freshness": "UNKNOWN",
            "as_of": (timezone.now() + timedelta(hours=1)).isoformat(),
            "search": "API visible",
            "layers": ["provenance"],
            "depth": 4,
        },
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="bearer-api-view",
    )
    assert created is True
    service = ServiceIdentity.objects.create(
        organization=organization,
        name="canvas-api-client",
        issuer="anva-test",
        audience="anva-test-api",
    )
    AccessGrant.objects.create(
        organization=organization,
        service_identity=service,
        repository=repository,
        action=Action.CANVAS_VIEW.value,
    )
    AccessGrant.objects.create(
        organization=organization,
        service_identity=service,
        repository=repository,
        action=Action.CANVAS_MANAGE.value,
    )
    AccessGrant.objects.create(
        organization=organization,
        service_identity=service,
        repository=repository,
        action=Action.KNOWLEDGE_PROPOSE.value,
    )
    issued = issue_bootstrap_repository_token(
        organization=organization,
        repository=repository,
        service_identity=service,
        actions=frozenset({Action.CANVAS_VIEW, Action.CANVAS_MANAGE, Action.KNOWLEDGE_PROPOSE}),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    client = Client()

    unauthenticated = client.post(
        "/api/v1/canvas/query",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert unauthenticated.status_code == 401
    invalid = client.post(
        "/api/v1/canvas/query",
        data=json.dumps({"unknown": True}),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {issued.plaintext}",
    )
    assert invalid.status_code == 400
    invalid_api_query_payloads: tuple[dict[str, object], ...] = (
        {"node_limit": "300"},
        {"depth": None},
        {"anchor_id": True},
        {"view_id": None},
        {"view_revision": None},
        {"repository_ids": [False]},
        {"owner": {}},
        {"layers": "execution"},
    )
    for invalid_payload in invalid_api_query_payloads:
        invalid_typed = client.post(
            "/api/v1/canvas/query",
            data=json.dumps(invalid_payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {issued.plaintext}",
        )
        assert invalid_typed.status_code == 400, invalid_payload
    allowed = client.post(
        "/api/v1/canvas/query",
        data=json.dumps({"repository_ids": [str(repository.id)]}),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {issued.plaintext}",
    )
    assert allowed.status_code == 200
    assert {node["id"] for node in allowed.json()["nodes"]} == {
        str(entity.id),
        str(target.id),
    }

    authorization = f"Bearer {issued.plaintext}"
    cleared_api = client.post(
        "/api/v1/canvas/query",
        data=json.dumps(
            {
                "view_id": str(view.id),
                "anchor_id": None,
                "entity_types": [],
                "owner": "",
                "status": "",
                "risk": "",
                "freshness": "",
                "as_of": None,
                "search": "",
                "layers": [],
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert cleared_api.status_code == 200
    assert cleared_api.json()["semantic_query"] == {
        "repository_ids": [str(repository.id)],
        "depth": 4,
    }
    listed = client.get(
        "/api/v1/canvas/views",
        HTTP_AUTHORIZATION=authorization,
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["views"]] == [str(view.id)]
    service_create = client.post(
        "/api/v1/canvas/views",
        data=json.dumps(
            {
                "name": "Service-owned views are unsupported",
                "view_type": CanvasView.ViewType.CUSTOM,
                "semantic_query": {},
                "idempotency_key": "service-owned-view",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert service_create.status_code == 404

    detail = client.get(
        f"/api/v1/canvas/entities/{entity.id}",
        {"repository_id": str(repository.id)},
        HTTP_AUTHORIZATION=authorization,
    )
    assert detail.status_code == 200
    assert detail.json()["id"] == str(entity.id)
    no_path = client.post(
        "/api/v1/canvas/path",
        data=json.dumps(
            {
                "source_id": str(entity.id),
                "target_id": str(target.id),
                "repository_ids": [str(repository.id)],
                "max_depth": 4,
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert no_path.status_code == 200
    assert no_path.json()["found"] is False

    revision = client.post(
        f"/api/v1/canvas/views/{view.id}/revisions",
        data=json.dumps(
            {
                "expected_revision": 1,
                "semantic_query": {"repository_ids": [str(repository.id)]},
                "presentation": {
                    "placements": [],
                    "filters": [],
                    "layers": [],
                    "groups": [],
                    "annotations": [],
                },
                "idempotency_key": "bearer-api-revision",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert revision.status_code == 201
    assert revision.json()["revision"] == 2
    expires_at = (timezone.now() + timedelta(hours=1)).isoformat()
    shared = client.post(
        f"/api/v1/canvas/views/{view.id}/shares",
        data=json.dumps(
            {
                "expires_at": expires_at,
                "idempotency_key": "bearer-api-share",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert shared.status_code == 201
    assert shared.json()["view_revision"] == 2
    stale_revoke = client.post(
        f"/api/v1/canvas/shares/{shared.json()['id']}/revoke",
        data=json.dumps(
            {"expected_view_revision": 1, "idempotency_key": "bearer-api-revoke-stale"}
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert stale_revoke.status_code == 409
    revoked = client.post(
        f"/api/v1/canvas/shares/{shared.json()['id']}/revoke",
        data=json.dumps({"expected_view_revision": 2, "idempotency_key": "bearer-api-revoke"}),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True
    replayed_revoke = client.post(
        f"/api/v1/canvas/shares/{shared.json()['id']}/revoke",
        data=json.dumps({"expected_view_revision": 2, "idempotency_key": "bearer-api-revoke"}),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert replayed_revoke.status_code == 200
    assert replayed_revoke.json()["revoked"] is False
    proposed = client.post(
        "/api/v1/canvas/relationship-proposals",
        data=json.dumps(
            {
                "source_id": str(entity.id),
                "target_id": str(target.id),
                "relationship_type": (
                    KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY
                ),
                "repository_id": str(repository.id),
                "expected_source_revision": entity.revision,
                "expected_target_revision": target.revision,
                "rationale": "The API product is implemented by the API repository.",
                "idempotency_key": "bearer-api-proposal",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert proposed.status_code == 201
    assert proposed.json()["state"] == KnowledgeProposal.State.PROPOSED
    for response in (
        allowed,
        listed,
        detail,
        no_path,
        revision,
        shared,
        revoked,
        replayed_revoke,
        proposed,
    ):
        assert len(response.content) <= 750 * 1024
        assert b'": "' not in response.content
