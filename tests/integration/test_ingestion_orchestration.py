"""End-to-end durable ingestion behavior through the leased job boundary."""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from django.db import DatabaseError, connection, transaction
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from anva.core import views as core_views
from anva.core.exceptions import (
    RequiredContextBudgetError,
    RequiredPolicyBudgetError,
    RequiredSearchAnchorUnavailableError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AccessScope,
    AccessScopeMembership,
    AccessScopeSource,
    AssertionConflict,
    AssertionProvenance,
    AssertionValidityInterval,
    AuditEvent,
    BackgroundJob,
    ContextPacketInvalidation,
    ContextPacketItem,
    ContextPacketRecord,
    IngestionFailure,
    IngestionStageResult,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeRelationship,
    Membership,
    Organization,
    ParsedSource,
    Repository,
    Role,
    SourceChunk,
    SourceChunkSearchIndex,
    SourceChunkVisibility,
    SourceConnection,
    SourceContentArtifact,
    SourceDocument,
    SourceLocation,
    SourceObservation,
    SourceRevision,
    SyncCursor,
    SyncRun,
    User,
)
from anva.core.services.authorization import Action
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import (
    PacketBudget,
    RequiredSearchAnchor,
    RetrievalFacet,
    _chunk_candidate,
    _merge_candidates,
    _required_search_anchor_candidates,
    build_context_packet,
    get_context_packet,
)
from anva.core.services.graph import traverse_graph
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.jobs import cancel_job, claim_next_job, complete_job, enqueue_job
from anva.core.services.mcp_gateway import _context_packet
from anva.core.services.retrieval import (
    authorized_assertions,
    authorized_relationships,
    authorized_source_chunks,
)
from anva.core.services.scopes import revoke_source_connection
from anva.core.services.search import search_chunks
from anva.ingestion.errors import IngestionError
from anva.ingestion.filesystem import FilesystemConnector
from anva.ingestion.limits import IngestionLimits
from anva.ingestion.parsers import JsonParser


class _SqlCapture:
    """Capture one emitted retrieval statement for a real PostgreSQL EXPLAIN."""

    def __init__(self, marker: str) -> None:
        self.marker = marker
        self.sql: str | None = None
        self.parameters: Any = None

    def __call__(
        self,
        execute: Any,
        sql: str,
        parameters: Any,
        many: bool,
        context: Any,
    ) -> Any:
        if self.marker in sql:
            self.sql = sql
            self.parameters = parameters
        return execute(sql, parameters, many, context)


def _assert_explainable(capture: _SqlCapture) -> None:
    assert capture.sql is not None
    with connection.cursor() as cursor:
        cursor.execute(f"EXPLAIN (FORMAT JSON) {capture.sql}", capture.parameters)
        row = cursor.fetchone()
    assert row is not None
    assert row[0]


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


def _required_anchor(result: Any) -> RequiredSearchAnchor:
    return RequiredSearchAnchor(
        chunk_id=result.chunk_id,
        content_hash=result.content_hash,
        access_scope_id=result.access_scope_id,
        source_location_id=result.source_location_id,
        source_observation_id=result.source_observation_id,
        access_snapshot_id=result.access_snapshot_id,
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_ingestion_builds_versioned_indexes_and_hybrid_search_is_reproducible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "policy.json").write_text(
        json.dumps(
            {
                "policy": "deployments require two reviewers",
                "service": "payments",
            }
        )
    )
    actor, source = _source_setup(tmp_path, monkeypatch, slug="retrieval-index")
    _execute_requested(actor, source)
    repository_id = source.repository_id
    assert repository_id is not None

    chunks = SourceChunk.objects.filter(organization=source.organization)
    indexes = SourceChunkSearchIndex.objects.filter(organization=source.organization)
    assert indexes.count() == chunks.count() == 1
    assert indexes.get().indexed_text_hash == chunks.get().content_hash
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT extname FROM pg_extension WHERE extname IN ('pg_trgm', 'vector') "
            "ORDER BY extname"
        )
        assert [row[0] for row in cursor.fetchall()] == ["pg_trgm", "vector"]
        cursor.execute(
            "SELECT indexname FROM pg_indexes "
            "WHERE indexname IN ('core_chunk_search_fts_gin', "
            "'core_chunk_embedding_hnsw') ORDER BY indexname"
        )
        assert [row[0] for row in cursor.fetchall()] == [
            "core_chunk_embedding_hnsw",
            "core_chunk_search_fts_gin",
        ]
    with pytest.raises(DatabaseError), transaction.atomic():
        indexes.update(index_version="rewritten")

    first = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query="two reviewers",
        phase="PREFLIGHT",
    )
    second = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query="two reviewers",
        phase="PREFLIGHT",
    )

    assert first.as_dict() == second.as_dict()
    assert len(first.results) == 1
    assert first.results[0].content_hash == chunks.get().content_hash
    assert first.results[0].explanation.lexical_rank == 1


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_required_search_anchor_survives_dense_context_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(55):
        payload = {"topic": "dense common retry context", "index": index}
        if index == 37:
            payload["decision"] = "distinctive capped retry anchor six attempts"
        (tmp_path / f"document-{index:02d}.json").write_text(json.dumps(payload))
    actor, source = _source_setup(tmp_path, monkeypatch, slug="required-search-anchor")
    _execute_requested(actor, source)
    repository_id = source.repository_id
    assert repository_id is not None
    search = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query="distinctive capped retry anchor six attempts",
        phase="ASSURANCE",
        limit=50,
    )
    assert search.results
    target = search.results[0]
    anchor = _required_anchor(target)
    budget = PacketBudget(max_items=1, max_tokens=8_000, max_bytes=100_000, max_citations=1)

    with CaptureQueriesContext(connection) as resolver_queries:
        resolved_anchors = _required_search_anchor_candidates(
            actor=actor,
            repository_id=repository_id,
            anchors=(anchor,),
            visible_scope_ids=(anchor.access_scope_id,),
        )
    assert len(resolver_queries) == 1
    assert len(resolved_anchors) == 1
    assert len(resolved_anchors) <= 50

    with CaptureQueriesContext(connection) as anchor_queries:
        packet, created = build_context_packet(
            actor=actor,
            repository_id=repository_id,
            task="dense common retry context",
            phase=ContextPacketRecord.Phase.ASSURANCE,
            budget=budget,
            required_search_anchors=(anchor,),
        )
    assert len(anchor_queries) <= 80
    cached, cached_created = build_context_packet(
        actor=actor,
        repository_id=repository_id,
        task="dense   common retry context",
        phase=ContextPacketRecord.Phase.ASSURANCE,
        budget=budget,
        required_search_anchors=(anchor, anchor),
    )

    assert created is True
    assert cached_created is False
    assert cached.id == packet.id
    assert packet.normalized_request["required_search_anchors"] == [anchor.as_dict()]
    selected = cast(list[dict[str, Any]], packet.artifact.payload["items"])
    assert len(selected) == 1
    assert selected[0]["item_key"] == f"chunk:{target.chunk_id}"
    assert cast(dict[str, object], selected[0]["payload"])["required_search_anchor"] is True
    citations = cast(list[dict[str, object]], selected[0]["anva_sources"])
    assert citations[0]["access_snapshot_id"] == str(target.access_snapshot_id)
    assert citations[0]["source_content_hash"] == target.content_hash
    assert packet.artifact.payload["limitations"]

    adapter_payload: dict[str, object] = {
        "repository_id": str(repository_id),
        "task": "adapter parity exact anchor",
        "phase": "ASSURANCE",
        "budget": budget.as_dict(),
        "required_search_anchors": [anchor.as_dict()],
    }
    mcp_data = _context_packet(actor, adapter_payload)
    monkeypatch.setattr(core_views, "_actor", lambda _request: actor)
    request = RequestFactory().post(
        "/api/v1/context-packets",
        data=json.dumps(adapter_payload),
        content_type="application/json",
    )
    rest_response = core_views.context_packets(request)
    rest_data = json.loads(rest_response.content)
    assert rest_response.status_code == 200
    assert mcp_data["created"] is True
    assert rest_data["created"] is False
    assert rest_data["packet_id"] == mcp_data["packet_id"]
    assert rest_data["packet"] == mcp_data["packet"]

    failures = (
        replace(anchor, content_hash="f" * 64),
        replace(anchor, access_scope_id=uuid.uuid4()),
        replace(anchor, source_location_id=uuid.uuid4()),
        replace(anchor, source_observation_id=uuid.uuid4()),
        replace(anchor, access_snapshot_id=uuid.uuid4()),
    )
    for index, unavailable in enumerate(failures):
        with pytest.raises(
            RequiredSearchAnchorUnavailableError,
            match=r"^One or more required search anchors are unavailable$",
        ):
            build_context_packet(
                actor=actor,
                repository_id=repository_id,
                task=f"unavailable anchor {index}",
                phase=ContextPacketRecord.Phase.ASSURANCE,
                required_search_anchors=(unavailable,),
            )

    other_repository = Repository.objects.create(
        organization=source.organization,
        external_id="filesystem:required-search-anchor-other",
        name="required-search-anchor-other",
    )
    with pytest.raises(
        RequiredSearchAnchorUnavailableError,
        match=r"^One or more required search anchors are unavailable$",
    ):
        build_context_packet(
            actor=replace(actor, repository_id=other_repository.id),
            repository_id=other_repository.id,
            task="cross repository anchor",
            phase=ContextPacketRecord.Phase.ASSURANCE,
            required_search_anchors=(anchor,),
        )

    target_scope = AccessScope.objects.get(id=anchor.access_scope_id)
    target_scope.all_memberships = False
    target_scope.save(update_fields=["all_memberships", "updated_at"])
    original_membership = Membership.objects.get(user_id=uuid.UUID(actor.actor_id))
    AccessScopeMembership.objects.create(
        organization=source.organization,
        access_scope=target_scope,
        membership=original_membership,
    )
    unauthorized_actor = _actor(
        source.organization,
        cast(Repository, source.repository),
        Role.Code.ORG_ADMIN,
        "anchor-outsider",
    )
    outsider_scope = AccessScope.objects.create(
        organization=source.organization,
        name="anchor-outsider-visible",
        all_repositories=True,
    )
    AccessScopeMembership.objects.create(
        organization=source.organization,
        access_scope=outsider_scope,
        membership=Membership.objects.get(user_id=uuid.UUID(unauthorized_actor.actor_id)),
    )
    with pytest.raises(
        RequiredSearchAnchorUnavailableError,
        match=r"^One or more required search anchors are unavailable$",
    ):
        build_context_packet(
            actor=unauthorized_actor,
            repository_id=repository_id,
            task="unauthorized anchor",
            phase=ContextPacketRecord.Phase.ASSURANCE,
            required_search_anchors=(anchor,),
        )

    second = search.results[1]
    second_anchor = _required_anchor(second)
    cross_product_anchor = replace(
        anchor,
        access_scope_id=second_anchor.access_scope_id,
        source_location_id=second_anchor.source_location_id,
        source_observation_id=second_anchor.source_observation_id,
        access_snapshot_id=second_anchor.access_snapshot_id,
    )
    cross_product_second = replace(
        second_anchor,
        access_scope_id=anchor.access_scope_id,
        source_location_id=anchor.source_location_id,
        source_observation_id=anchor.source_observation_id,
        access_snapshot_id=anchor.access_snapshot_id,
    )
    with pytest.raises(
        RequiredSearchAnchorUnavailableError,
        match=r"^One or more required search anchors are unavailable$",
    ):
        build_context_packet(
            actor=actor,
            repository_id=repository_id,
            task="cross product identity must not resolve",
            phase=ContextPacketRecord.Phase.ASSURANCE,
            required_search_anchors=(cross_product_anchor, cross_product_second),
        )
    with pytest.raises(RequiredContextBudgetError, match="required search anchor"):
        build_context_packet(
            actor=actor,
            repository_id=repository_id,
            task="two anchors cannot fit one item",
            phase=ContextPacketRecord.Phase.ASSURANCE,
            budget=budget,
            required_search_anchors=(anchor, second_anchor),
        )

    SourceChunkVisibility.objects.filter(
        organization=source.organization,
        source_chunk_id=anchor.chunk_id,
        access_snapshot_id=anchor.access_snapshot_id,
    ).update(state=SourceChunkVisibility.State.REVOKED, revoked_at=timezone.now())
    with pytest.raises(
        RequiredSearchAnchorUnavailableError,
        match=r"^One or more required search anchors are unavailable$",
    ):
        build_context_packet(
            actor=actor,
            repository_id=repository_id,
            task="revoked anchor",
            phase=ContextPacketRecord.Phase.ASSURANCE,
            required_search_anchors=(anchor,),
        )

    zero_anchor_packet, _ = build_context_packet(
        actor=actor,
        repository_id=repository_id,
        task="zero anchors retain legacy behavior",
        phase=ContextPacketRecord.Phase.ASSURANCE,
        required_search_anchors=(),
    )
    assert "required_search_anchors" not in zero_anchor_packet.normalized_request


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_required_anchor_provenance_wins_concurrent_unchanged_reobservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phrase = "checkout ownership remains payments platform"
    (tmp_path / "ownership.json").write_text(json.dumps({"decision": phrase}))
    actor, source = _source_setup(tmp_path, monkeypatch, slug="anchor-a-to-a")
    _execute_requested(actor, source)
    repository_id = cast(uuid.UUID, source.repository_id)
    first = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query=phrase,
        phase="ASSURANCE",
    ).results[0]
    anchor = _required_anchor(first)
    anchored_candidate = _required_search_anchor_candidates(
        actor=actor,
        repository_id=repository_id,
        anchors=(anchor,),
        visible_scope_ids=(anchor.access_scope_id,),
    )[0]

    _execute_requested(actor, source)
    current = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query=phrase,
        phase="ASSURANCE",
    ).results[0]
    assert current.chunk_id == first.chunk_id
    assert current.source_observation_id != first.source_observation_id
    facet_candidate = _chunk_candidate(
        current,
        1,
        facet=RetrievalFacet(
            label="changed_paths",
            query=phrase,
            anchors=(phrase,),
            required_if_matched=True,
        ),
        facet_position=0,
        change_aware=True,
    )
    assert facet_candidate.citations != anchored_candidate.citations

    forward = _merge_candidates([facet_candidate, anchored_candidate])[0]
    reverse = _merge_candidates([anchored_candidate, facet_candidate])[0]

    assert forward.as_dict() == reverse.as_dict()
    assert forward.payload == anchored_candidate.payload
    assert forward.citations == anchored_candidate.citations
    assert forward.contributing_scope_ids == anchored_candidate.contributing_scope_ids
    assert forward.required_search_anchor is True
    assert forward.required_context_facets == ("changed_paths",)


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_context_packet_is_budgeted_reconstructable_cached_and_invalidated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "policy.json").write_text(json.dumps({"service": "payments", "owner": "platform"}))
    actor, source = _source_setup(tmp_path, monkeypatch, slug="context-packet")
    _execute_requested(actor, source)
    repository_id = source.repository_id
    assert repository_id is not None
    visibility = (
        SourceChunkVisibility.objects.filter(organization=source.organization)
        .select_related(
            "source_location",
            "source_observation__source_document",
        )
        .get()
    )
    policy = KnowledgeAssertion.objects.create(
        organization=source.organization,
        access_scope=visibility.access_scope,
        subject_key="policy:deploy-review",
        predicate="required_policy",
        value={"rule": "deployments must have two reviewers"},
        provenance=[{"source_id": str(visibility.source_observation_id)}],
        review_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
    )
    AssertionProvenance.objects.create(
        organization=source.organization,
        assertion=policy,
        source_location=visibility.source_location,
        source_observation=visibility.source_observation,
        access_snapshot=visibility.access_snapshot,
        extraction_class=KnowledgeAssertion.ExtractionClass.HUMAN,
        extraction_method="test",
        confidence=1.0,
        observed_at=visibility.observed_at,
    )
    AssertionValidityInterval.objects.create(
        organization=source.organization,
        assertion=policy,
        source_document=visibility.source_observation.source_document,
        source_observation=visibility.source_observation,
        valid_from=visibility.observed_at,
        observed_from=visibility.observed_at,
    )
    stale_policy = KnowledgeAssertion.objects.create(
        organization=source.organization,
        access_scope=visibility.access_scope,
        subject_key="policy:legacy-deploy-review",
        predicate="required_policy",
        value={"rule": "deployments must follow the retired process"},
        provenance=[{"source_id": str(visibility.source_observation_id)}],
        staleness_state=KnowledgeAssertion.StalenessState.STALE,
    )
    AssertionProvenance.objects.create(
        organization=source.organization,
        assertion=stale_policy,
        source_location=visibility.source_location,
        source_observation=visibility.source_observation,
        access_snapshot=visibility.access_snapshot,
        extraction_class=KnowledgeAssertion.ExtractionClass.HUMAN,
        extraction_method="test",
        confidence=1.0,
        observed_at=visibility.observed_at,
    )
    AssertionValidityInterval.objects.create(
        organization=source.organization,
        assertion=stale_policy,
        source_document=visibility.source_observation.source_document,
        source_observation=visibility.source_observation,
        valid_from=visibility.observed_at,
        observed_from=visibility.observed_at,
    )

    packet, created = build_context_packet(
        actor=actor,
        repository_id=repository_id,
        task="prepare the payments deployment",
        phase=ContextPacketRecord.Phase.PREFLIGHT,
    )
    cached, cached_created = build_context_packet(
        actor=actor,
        repository_id=repository_id,
        task="prepare   the payments deployment",
        phase=ContextPacketRecord.Phase.PREFLIGHT,
    )

    assert created is True
    assert cached_created is False
    assert cached.id == packet.id
    assert (
        get_context_packet(
            actor=actor,
            repository_id=repository_id,
            packet_id=packet.id,
        )
        == packet.artifact.payload
    )
    first_item = ContextPacketItem.objects.filter(context_packet=packet).order_by("position")[0]
    assert first_item.kind == ContextPacketItem.Kind.POLICY
    assert first_item.selection_reason == "Applicable required current policy"
    assert first_item.contextpacketcitation_set.count() >= 1
    assert packet.selected_items <= packet.budget_max_items
    assert packet.selected_bytes <= packet.budget_max_bytes
    with pytest.raises(DatabaseError), transaction.atomic():
        ContextPacketItem.objects.filter(id=first_item.id).update(summary="rewritten")

    with pytest.raises(RequiredPolicyBudgetError):
        build_context_packet(
            actor=actor,
            repository_id=repository_id,
            task="prepare the payments deployment with two reviewers",
            phase=ContextPacketRecord.Phase.PREFLIGHT,
            budget=PacketBudget(
                max_items=1,
                max_tokens=1,
                max_bytes=1,
                max_citations=1,
            ),
        )

    _execute_requested(actor, source)
    assert ContextPacketInvalidation.objects.filter(context_packet=packet).exists()
    rebuilt, rebuilt_created = build_context_packet(
        actor=actor,
        repository_id=repository_id,
        task="prepare the payments deployment",
        phase=ContextPacketRecord.Phase.PREFLIGHT,
    )
    assert rebuilt_created is True
    assert rebuilt.id != packet.id
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        get_context_packet(
            actor=actor,
            repository_id=repository_id,
            packet_id=packet.id,
        )
    assert ContextPacketRecord.objects.filter(id=packet.id).exists()
    assert packet.artifact.payload["packet_id"] == str(packet.id)


@pytest.mark.integration
@pytest.mark.django_db
def test_graph_traversal_is_typed_reproducible_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "service.json").write_text(json.dumps({"service": "payments", "owner": "platform"}))
    actor, source = _source_setup(tmp_path, monkeypatch, slug="retrieval-graph")
    _execute_requested(actor, source)
    repository_id = source.repository_id
    assert repository_id is not None
    relationship = KnowledgeRelationship.objects.get(organization=source.organization)

    first = traverse_graph(
        actor=actor,
        repository_id=repository_id,
        start_entity_id=relationship.source_entity_id,
        depth=4,
        degree=1,
        edge_limit=1,
    )
    second = traverse_graph(
        actor=actor,
        repository_id=repository_id,
        start_entity_id=relationship.source_entity_id,
        depth=4,
        degree=1,
        edge_limit=1,
    )

    assert first.as_dict() == second.as_dict()
    assert len(first.edges) == 1
    assert first.edges[0].source_entity_type
    assert first.edges[0].target_entity_type
    assert first.depth_limit <= 4
    assert first.degree_limit <= 100
    assert first.edge_limit <= 500


@pytest.mark.integration
@pytest.mark.django_db
def test_hidden_chunks_never_enter_ranking_or_leak_canary_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public_root = tmp_path / "public"
    hidden_root = tmp_path / "hidden"
    cross_repository_root = tmp_path / "cross-repository"
    public_root.mkdir()
    hidden_root.mkdir()
    cross_repository_root.mkdir()
    (public_root / "service.json").write_text(
        json.dumps(
            {
                "service": "payments",
                "owner": "platform",
                "deployment": "reviewed",
            }
        )
    )
    (hidden_root / "secret.json").write_text(
        json.dumps(
            {
                "title": "CANARY-HIDDEN-EXECUTIVE-PLAN",
                "service": "payments",
                "owner": "CANARY-HIDDEN-OWNER",
                "deployment": "CANARY-SECRET",
            }
        )
    )
    (cross_repository_root / "cross-repository.json").write_text(
        json.dumps(
            {
                "service": "CANARY-CROSS-REPOSITORY-SERVICE",
                "owner": "CANARY-CROSS-REPOSITORY-OWNER",
            }
        )
    )
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization = Organization.objects.create(slug="ranking-canary", name="ranking-canary")
    repository = Repository.objects.create(
        organization=organization,
        external_id="filesystem:ranking-canary",
        name="ranking-canary",
    )
    admin = _actor(organization, repository, Role.Code.ORG_ADMIN, "ranking-admin")
    viewer = _actor(organization, repository, Role.Code.DEVELOPER, "ranking-viewer")
    viewer_membership = Membership.objects.get(user_id=viewer.actor_id)
    public_scope = AccessScope.objects.create(
        organization=organization,
        name="viewer-visible",
        all_repositories=True,
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=public_scope,
        membership=viewer_membership,
    )
    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="viewer-hidden",
        all_repositories=True,
    )
    public_source, _created = connect_filesystem_source(
        actor=admin,
        repository_id=repository.id,
        access_scope_id=public_scope.id,
        external_key="filesystem:ranking-public",
        display_name="ranking-public",
        root=str(public_root),
    )
    hidden_source, _created = connect_filesystem_source(
        actor=admin,
        repository_id=repository.id,
        access_scope_id=hidden_scope.id,
        external_key="filesystem:ranking-hidden",
        display_name="ranking-hidden",
        root=str(hidden_root),
    )
    _execute_requested(admin, public_source)
    before = search_chunks(
        actor=viewer,
        repository_id=repository.id,
        query="deployment",
    )
    public_relationship = KnowledgeRelationship.objects.get(
        access_scope=public_scope,
    )
    graph_before = traverse_graph(
        actor=viewer,
        repository_id=repository.id,
        start_entity_id=public_relationship.source_entity_id,
    )
    _execute_requested(admin, hidden_source)
    cross_repository = Repository.objects.create(
        organization=organization,
        external_id="filesystem:ranking-cross-repository",
        name="ranking-cross-repository",
    )
    cross_repository_admin = _actor(
        organization,
        cross_repository,
        Role.Code.ORG_ADMIN,
        "ranking-cross-repository-admin",
    )
    cross_repository_source, _created = connect_filesystem_source(
        actor=cross_repository_admin,
        repository_id=cross_repository.id,
        access_scope_id=public_scope.id,
        external_key="filesystem:ranking-cross-repository",
        display_name="ranking-cross-repository",
        root=str(cross_repository_root),
    )
    _execute_requested(cross_repository_admin, cross_repository_source)
    cross_repository_packet, cross_repository_created = build_context_packet(
        actor=viewer,
        repository_id=repository.id,
        task="CANARY-CROSS-REPOSITORY-SERVICE",
        phase=ContextPacketRecord.Phase.PREPARE,
    )
    assert cross_repository_created is True
    assert not ContextPacketItem.objects.filter(
        context_packet=cross_repository_packet,
        source_relationship__source_observation__source_document__source_container__source_connection=(
            cross_repository_source
        ),
    ).exists()
    assert "CANARY-CROSS-REPOSITORY-OWNER" not in json.dumps(
        cross_repository_packet.artifact.payload["items"],
        sort_keys=True,
    )

    search_capture = _SqlCapture("authorized_chunks AS MATERIALIZED")
    with connection.execute_wrapper(search_capture):
        after = search_chunks(
            actor=viewer,
            repository_id=repository.id,
            query="deployment",
        )
    canary_query = search_chunks(
        actor=viewer,
        repository_id=repository.id,
        query="CANARY-HIDDEN-EXECUTIVE-PLAN",
    )
    hidden_endpoint = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.COMPONENT,
        canonical_key="component:CANARY-HIDDEN-ENDPOINT",
        display_name="CANARY-HIDDEN-ENDPOINT",
        access_scope=hidden_scope,
    )
    public_terminal = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.COMPONENT,
        canonical_key="component:public-terminal",
        display_name="public-terminal",
        access_scope=public_scope,
    )
    for source_entity, target_entity in (
        (public_relationship.source_entity, hidden_endpoint),
        (hidden_endpoint, public_terminal),
    ):
        KnowledgeRelationship.objects.create(
            organization=organization,
            relationship_type=KnowledgeRelationship.RelationshipType.DEPENDS_ON,
            source_entity=source_entity,
            target_entity=target_entity,
            source_entity_type=source_entity.entity_type,
            target_entity_type=target_entity.entity_type,
            assertion=public_relationship.assertion,
            source_location=public_relationship.source_location,
            source_observation=public_relationship.source_observation,
            access_snapshot=public_relationship.access_snapshot,
            access_scope=public_scope,
            extraction_class=KnowledgeAssertion.ExtractionClass.MECHANICAL,
            confidence=1.0,
            observed_at=public_relationship.observed_at,
        )
    graph_capture = _SqlCapture("authorized_edges AS MATERIALIZED")
    with connection.execute_wrapper(graph_capture):
        graph_after = traverse_graph(
            actor=viewer,
            repository_id=repository.id,
            start_entity_id=public_relationship.source_entity_id,
        )
    hidden_hash = SourceChunk.objects.get(
        parsed_source__source_revision__source_document__source_container__source_connection=(
            hidden_source
        )
    ).content_hash

    assert before.as_dict() == after.as_dict()
    assert graph_before.as_dict() == graph_after.as_dict()
    assert all(result.content_hash != hidden_hash for result in canary_query.results)
    assert "CANARY" not in json.dumps([result.as_dict() for result in canary_query.results])
    assert "CANARY" not in json.dumps(graph_after.as_dict())
    _assert_explainable(search_capture)
    _assert_explainable(graph_capture)

    public_visibility = SourceChunkVisibility.objects.select_related(
        "source_location",
        "source_observation__source_document",
    ).get(
        access_scope=public_scope,
        source_observation__source_document__source_container__source_connection=public_source,
    )
    hidden_visibility = SourceChunkVisibility.objects.select_related(
        "source_observation__source_document",
        "source_chunk__parsed_source",
    ).get(access_scope=hidden_scope)
    hidden_location = SourceLocation.objects.create(
        organization=organization,
        parsed_source=hidden_visibility.source_chunk.parsed_source,
        source_observation=hidden_visibility.source_observation,
        pointer="/CANARY-HIDDEN-LOCATOR",
        excerpt_hash="e" * 64,
    )
    mixed_assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=public_scope,
        subject_key="policy:release-requirement",
        predicate="required_policy",
        value={"rule": "release requires review"},
        provenance=[
            {"source_id": str(public_visibility.source_observation_id)},
            {"source_id": str(hidden_visibility.source_observation_id)},
        ],
    )
    for visibility, location in (
        (public_visibility, public_visibility.source_location),
        (hidden_visibility, hidden_location),
    ):
        AssertionProvenance.objects.create(
            organization=organization,
            assertion=mixed_assertion,
            source_location=location,
            source_observation=visibility.source_observation,
            access_snapshot=visibility.access_snapshot,
            extraction_class=KnowledgeAssertion.ExtractionClass.HUMAN,
            extraction_method="test",
            confidence=1.0,
            observed_at=visibility.observed_at,
        )
        AssertionValidityInterval.objects.create(
            organization=organization,
            assertion=mixed_assertion,
            source_document=visibility.source_observation.source_document,
            source_observation=visibility.source_observation,
            valid_from=visibility.observed_at,
            observed_from=visibility.observed_at,
        )
    secondary_scope = AccessScope.objects.create(
        organization=organization,
        name="viewer-visible-secondary",
        all_repositories=True,
    )
    secondary_membership = AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=secondary_scope,
        membership=viewer_membership,
    )
    AccessScopeSource.objects.create(
        organization=organization,
        access_scope=secondary_scope,
        source_connection=public_source,
    )
    right_assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=secondary_scope,
        subject_key="policy:release-requirement-alternative",
        predicate="required_policy",
        value={"rule": "CANARY-RIGHT-SIDE-CLAIM"},
        provenance=[{"source_id": str(public_visibility.source_observation_id)}],
    )
    AssertionProvenance.objects.create(
        organization=organization,
        assertion=right_assertion,
        source_location=public_visibility.source_location,
        source_observation=public_visibility.source_observation,
        access_snapshot=public_visibility.access_snapshot,
        extraction_class=KnowledgeAssertion.ExtractionClass.HUMAN,
        extraction_method="test",
        confidence=1.0,
        observed_at=public_visibility.observed_at,
    )
    AssertionValidityInterval.objects.create(
        organization=organization,
        assertion=right_assertion,
        source_document=public_visibility.source_observation.source_document,
        source_observation=public_visibility.source_observation,
        valid_from=public_visibility.observed_at,
        observed_from=public_visibility.observed_at,
    )
    conflict = AssertionConflict.objects.create(
        organization=organization,
        left_assertion=mixed_assertion,
        right_assertion=right_assertion,
        predicate="required_policy",
    )
    packet, created = build_context_packet(
        actor=viewer,
        repository_id=repository.id,
        task="release requirement",
        phase=ContextPacketRecord.Phase.PREFLIGHT,
    )
    assert created is True
    mixed_item = ContextPacketItem.objects.get(
        context_packet=packet,
        source_assertion=mixed_assertion,
    )
    packet_text = json.dumps(packet.artifact.payload, sort_keys=True)
    hidden_revision = hidden_visibility.source_observation.source_revision
    assert hidden_revision is not None
    assert str(hidden_visibility.access_snapshot_id) not in packet_text
    assert hidden_revision.content_hash not in packet_text
    assert hidden_visibility.source_observation.source_document.canonical_url not in packet_text
    assert "CANARY-HIDDEN-LOCATOR" not in packet_text
    assert "CANARY-HIDDEN-EXECUTIVE-PLAN" not in packet_text
    assert mixed_item.contextpacketcitation_set.count() == 1
    assert set(mixed_item.access_scope.derived_from.values_list("id", flat=True)) == {
        public_scope.id
    }
    conflict_item = ContextPacketItem.objects.get(
        context_packet=packet,
        source_conflict=conflict,
    )
    assert set(conflict_item.access_scope.derived_from.values_list("id", flat=True)) == {
        public_scope.id,
        secondary_scope.id,
    }
    assert conflict_item.contextpacketcitation_set.count() == 2

    secondary_membership.delete()
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        get_context_packet(
            actor=viewer,
            repository_id=repository.id,
            packet_id=packet.id,
        )
    narrowed_packet, narrowed_created = build_context_packet(
        actor=viewer,
        repository_id=repository.id,
        task="release requirement",
        phase=ContextPacketRecord.Phase.PREFLIGHT,
    )
    assert narrowed_created is True
    assert narrowed_packet.id != packet.id
    assert "CANARY-RIGHT-SIDE-CLAIM" not in json.dumps(
        narrowed_packet.artifact.payload["items"],
        sort_keys=True,
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=secondary_scope,
        membership=viewer_membership,
    )

    AccessScopeMembership.objects.filter(
        access_scope__in=[public_scope, secondary_scope],
        membership=viewer_membership,
    ).delete()
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        get_context_packet(
            actor=viewer,
            repository_id=repository.id,
            packet_id=packet.id,
        )
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        build_context_packet(
            actor=viewer,
            repository_id=repository.id,
            task="release requirement",
            phase=ContextPacketRecord.Phase.PREFLIGHT,
        )
    assert ContextPacketRecord.objects.filter(id=packet.id).exists()

    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=public_scope,
        membership=viewer_membership,
    )
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=secondary_scope,
        membership=viewer_membership,
    )
    scope_packet, scope_created = build_context_packet(
        actor=viewer,
        repository_id=repository.id,
        task="second release requirement",
        phase=ContextPacketRecord.Phase.PREFLIGHT,
    )
    assert scope_created is True
    AccessScopeSource.objects.filter(
        access_scope=public_scope,
        source_connection=public_source,
    ).delete()
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        get_context_packet(
            actor=viewer,
            repository_id=repository.id,
            packet_id=scope_packet.id,
        )
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        build_context_packet(
            actor=viewer,
            repository_id=repository.id,
            task="second release requirement",
            phase=ContextPacketRecord.Phase.PREFLIGHT,
        )
    AccessScopeSource.objects.create(
        organization=organization,
        access_scope=public_scope,
        source_connection=public_source,
    )
    assert (
        get_context_packet(
            actor=viewer,
            repository_id=repository.id,
            packet_id=scope_packet.id,
        )
        == scope_packet.artifact.payload
    )
    public_scope.is_active = False
    public_scope.revision += 1
    public_scope.save(update_fields=["is_active", "revision", "updated_at"])
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        get_context_packet(
            actor=viewer,
            repository_id=repository.id,
            packet_id=scope_packet.id,
        )
    assert ContextPacketRecord.objects.filter(id=scope_packet.id).exists()


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


@pytest.mark.integration
@pytest.mark.django_db
def test_acl_only_reobservation_versions_assertions_and_relationship_visibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "service.json").write_text('{"service":"api","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="acl-reobservation")
    first = _execute_requested(actor, source)
    old_scope = source.access_scope
    assert old_scope is not None
    old_assertion = KnowledgeAssertion.objects.get(
        organization=source.organization,
        predicate="owned_by",
        valid_until__isnull=True,
    )
    old_relationship = KnowledgeRelationship.objects.get(
        organization=source.organization,
    )

    old_scope.all_memberships = False
    old_scope.save(update_fields=["all_memberships", "updated_at"])
    new_scope = AccessScope.objects.create(
        organization=source.organization,
        name="new-visible-scope",
        all_memberships=True,
        all_repositories=True,
    )
    AccessScopeSource.objects.create(
        organization=source.organization,
        access_scope=new_scope,
        source_connection=source,
    )
    source.access_scope = new_scope
    source.save(update_fields=["access_scope", "updated_at"])

    second = _execute_requested(actor, source)
    old_assertion.refresh_from_db()
    current_assertion = KnowledgeAssertion.objects.get(
        organization=source.organization,
        predicate="owned_by",
        valid_until__isnull=True,
    )
    repository = source.repository
    assert repository is not None
    assert first.access_snapshot_id != second.access_snapshot_id
    assert SourceRevision.objects.filter(organization=source.organization).count() == 1
    assert old_assertion.valid_until is not None
    assert current_assertion.id != old_assertion.id
    assert current_assertion.access_scope_id == new_scope.id
    assert list(
        authorized_assertions(
            actor=actor,
            repository_id=repository.id,
            action=Action.KNOWLEDGE_VIEW,
        )
        .filter(predicate="owned_by")
        .values_list("id", flat=True)
    ) == [current_assertion.id]
    assert list(
        authorized_relationships(
            actor=actor,
            repository_id=repository.id,
        ).values_list("id", flat=True)
    ) != [old_relationship.id]
    assert KnowledgeRelationship.objects.filter(organization=source.organization).count() == 2


@pytest.mark.integration
@pytest.mark.django_db
def test_revocation_during_fetch_cancels_without_derived_writes_or_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "service.json").write_text('{"service":"api","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="mid-fetch-revocation")
    run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    claimed = claim_next_job(worker_id="mid-fetch-worker", lease_seconds=600)
    assert claimed is not None
    original_fetch = FilesystemConnector.fetch

    def revoking_fetch(
        connector: FilesystemConnector,
        document: object,
        *,
        max_bytes: int,
    ) -> object:
        fetched = original_fetch(connector, document, max_bytes=max_bytes)  # type: ignore[arg-type]
        revoke_source_connection(
            actor=actor,
            source_connection_id=source.id,
            expected_revision=source.revision,
        )
        return fetched

    monkeypatch.setattr(FilesystemConnector, "fetch", revoking_fetch)
    with pytest.raises(IngestionError, match="no longer active"):
        execute_ingestion_job(job=claimed, worker_id="mid-fetch-worker")

    run.refresh_from_db()
    claimed.refresh_from_db()
    assert run.state == SyncRun.State.CANCELLED
    assert claimed.state != BackgroundJob.State.SUCCEEDED
    assert not SourceContentArtifact.objects.filter(organization=source.organization).exists()
    assert not ParsedSource.objects.filter(organization=source.organization).exists()
    assert not KnowledgeAssertion.objects.filter(organization=source.organization).exists()
    assert not AuditEvent.objects.filter(
        organization=source.organization,
        target_type="syncrun",
        target_id=run.id,
        to_state=SyncRun.State.COMPLETED,
    ).exists()


@pytest.mark.integration
@pytest.mark.django_db
def test_retry_resumes_from_the_persisted_connector_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "a.json").write_text('{"service":"a","owner":"platform"}')
    (tmp_path / "b.json").write_text('{"service":"b","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="cursor-resume")
    run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    claimed = claim_next_job(worker_id="cursor-worker", lease_seconds=600)
    assert claimed is not None
    original_discover = FilesystemConnector.discover
    seen_cursors: list[object] = []
    interrupted = False

    def interrupted_discover(
        connector: FilesystemConnector,
        *,
        cursor: object,
        limit: int,
    ) -> object:
        nonlocal interrupted
        seen_cursors.append(cursor)
        if cursor is not None and not interrupted:
            interrupted = True
            raise IngestionError(
                "temporary_discovery_failure",
                "Source discovery is temporarily unavailable",
                is_transient=True,
            )
        return original_discover(connector, cursor=cursor, limit=limit)  # type: ignore[arg-type]

    monkeypatch.setattr(FilesystemConnector, "discover", interrupted_discover)
    limits = IngestionLimits(max_discovery_page=1)
    with pytest.raises(IngestionError, match="temporarily unavailable"):
        execute_ingestion_job(job=claimed, worker_id="cursor-worker", limits=limits)
    stored = SyncCursor.objects.get(source_connection=source)
    persisted_connector_cursor = stored.cursor_value["cursor"]

    completed = execute_ingestion_job(
        job=claimed,
        worker_id="cursor-worker",
        limits=limits,
    )

    assert seen_cursors[:3] == [None, persisted_connector_cursor, persisted_connector_cursor]
    assert completed.state == SyncRun.State.COMPLETED
    assert completed.processed_count == 2
    assert SourceObservation.objects.filter(sync_run=run).count() == 2


@pytest.mark.integration
@pytest.mark.django_db
def test_parser_upgrade_exposes_only_current_assertions_and_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "service.json").write_text('{"service":"api","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="parser-upgrade")
    _execute_requested(actor, source)
    monkeypatch.setattr(JsonParser, "implementation_version", "2")

    _execute_requested(actor, source)

    repository = source.repository
    assert repository is not None
    assertions = authorized_assertions(
        actor=actor,
        repository_id=repository.id,
        action=Action.KNOWLEDGE_VIEW,
    )
    chunks = authorized_source_chunks(actor=actor, repository_id=repository.id)
    assert assertions.count() == 2
    assert KnowledgeAssertion.objects.filter(
        organization=source.organization,
        valid_until__isnull=False,
    ).exists()
    assert chunks.count() == 1
    assert chunks.get().parsed_source.parser_version == "2"
    assert ParsedSource.objects.filter(organization=source.organization).count() == 2


@pytest.mark.integration
@pytest.mark.django_db
def test_hostile_discovery_entry_is_partial_while_safe_sibling_ingests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "safe.json").write_text('{"service":"safe","owner":"platform"}')
    (tmp_path / "this-path-is-too-long.json").write_text('{"service":"unsafe","owner":"platform"}')
    actor, source = _source_setup(tmp_path, monkeypatch, slug="hostile-discovery")
    run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    claimed = claim_next_job(worker_id="hostile-path-worker", lease_seconds=600)
    assert claimed is not None

    completed = execute_ingestion_job(
        job=claimed,
        worker_id="hostile-path-worker",
        limits=IngestionLimits(max_relative_path_bytes=12),
    )

    assert completed.state == SyncRun.State.PARTIALLY_COMPLETED
    assert completed.processed_count == 1
    assert completed.failed_count == 1
    assert (
        SourceDocument.objects.get(
            source_container__source_connection=source,
        ).external_id
        == "safe.json"
    )
    assert IngestionFailure.objects.get(sync_run=run).error_code == "path_limit_exceeded"
