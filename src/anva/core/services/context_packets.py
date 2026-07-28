"""Deterministic, immutable, permission-safe context packet assembly."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, NoReturn, cast

from django.db import transaction
from django.db.models import F, QuerySet
from django.utils import timezone

from anva.core.exceptions import RequiredPolicyBudgetError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    AccessSnapshot,
    AssertionConflict,
    AssertionProvenance,
    ContextPacketCitation,
    ContextPacketInvalidation,
    ContextPacketItem,
    ContextPacketRecord,
    ImmutableArtifact,
    KnowledgeAssertion,
    KnowledgeRelationship,
    Organization,
    Repository,
    RetrievalWatermark,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    resolve_principal,
)
from anva.core.services.context import ActorContext
from anva.core.services.ranking import RETRIEVAL_ALGORITHM_VERSION
from anva.core.services.retrieval import (
    authorized_assertions,
    authorized_relationships,
    authorized_scope_ids,
    authorized_source_chunks,
    get_authorized_artifact,
)
from anva.core.services.search import SearchResult, search_chunks
from anva.core.services.search_index import EMBEDDING_VERSION, INDEX_VERSION

MAX_ASSERTION_CANDIDATES = 500
MAX_RELATIONSHIP_CANDIDATES = 200


@dataclass(frozen=True, slots=True)
class PacketBudget:
    max_items: int = 50
    max_tokens: int = 8_000
    max_bytes: int = 100_000
    max_citations: int = 100

    def __post_init__(self) -> None:
        limits = (
            self.max_items,
            self.max_tokens,
            self.max_bytes,
            self.max_citations,
        )
        if any(limit < 1 for limit in limits):
            raise ValueError("all packet budgets must be positive")
        if self.max_items > 500:
            raise ValueError("max_items cannot exceed 500")
        if self.max_tokens > 100_000 or self.max_bytes > 1_000_000:
            raise ValueError("packet token or byte budget is too large")
        if self.max_citations > 1_000:
            raise ValueError("max_citations cannot exceed 1000")

    def as_dict(self) -> dict[str, int]:
        return {
            "max_items": self.max_items,
            "max_tokens": self.max_tokens,
            "max_bytes": self.max_bytes,
            "max_citations": self.max_citations,
        }


@dataclass(frozen=True, slots=True)
class CitationCandidate:
    access_scope_id: uuid.UUID
    source_location_id: uuid.UUID
    source_observation_id: uuid.UUID
    access_snapshot_id: uuid.UUID
    canonical_url: str
    locator: str
    source_content_hash: str
    observed_at: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "source_location_id": str(self.source_location_id),
            "source_observation_id": str(self.source_observation_id),
            "access_snapshot_id": str(self.access_snapshot_id),
            "canonical_url": self.canonical_url,
            "locator": self.locator,
            "source_content_hash": self.source_content_hash,
            "observed_at": self.observed_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class PacketCandidate:
    item_id: uuid.UUID
    kind: str
    item_key: str
    summary: str
    freshness: str
    is_inferred: bool
    selection_reason: str
    rank_score: float
    tier: int
    required_policy: bool
    payload: dict[str, object]
    contributing_scope_ids: tuple[uuid.UUID, ...]
    citations: tuple[CitationCandidate, ...]
    source_assertion_id: uuid.UUID | None = None
    source_relationship_id: uuid.UUID | None = None
    source_chunk_id: uuid.UUID | None = None
    source_conflict_id: uuid.UUID | None = None

    @property
    def token_count(self) -> int:
        return max(1, math.ceil(len(self.summary) / 4))

    @property
    def byte_count(self) -> int:
        return len(
            json.dumps(
                self.payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "item_id": str(self.item_id),
            "kind": self.kind,
            "item_key": self.item_key,
            "summary": self.summary,
            "freshness": self.freshness,
            "is_inferred": self.is_inferred,
            "selection_reason": self.selection_reason,
            "rank_score": self.rank_score,
            "payload": self.payload,
            "anva_sources": [citation.as_dict() for citation in self.citations],
        }


@dataclass(frozen=True, slots=True)
class PacketSelection:
    candidates: tuple[PacketCandidate, ...]
    selected_tokens: int
    selected_bytes: int
    selected_citations: int
    limitations: tuple[str, ...]


def _json_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _freshness(assertion: KnowledgeAssertion) -> str:
    if assertion.staleness_state == KnowledgeAssertion.StalenessState.FRESH:
        return ContextPacketItem.Freshness.CURRENT
    if assertion.staleness_state in {
        KnowledgeAssertion.StalenessState.STALE,
        KnowledgeAssertion.StalenessState.CONTRADICTED,
        KnowledgeAssertion.StalenessState.SOURCE_UNAVAILABLE,
    }:
        return ContextPacketItem.Freshness.STALE
    return ContextPacketItem.Freshness.UNKNOWN


def _assertion_kind(assertion: KnowledgeAssertion) -> str:
    normalized = f"{assertion.subject_key} {assertion.predicate}".casefold()
    if "policy" in normalized:
        return ContextPacketItem.Kind.POLICY
    if "decision" in normalized or "adr" in normalized:
        return ContextPacketItem.Kind.DECISION
    if "incident" in normalized or "risk" in normalized:
        return ContextPacketItem.Kind.INCIDENT
    return ContextPacketItem.Kind.ASSERTION


def _required_policy(assertion: KnowledgeAssertion) -> bool:
    if _assertion_kind(assertion) != ContextPacketItem.Kind.POLICY:
        return False
    rendered = json.dumps(assertion.value, sort_keys=True).casefold()
    normalized = f"{assertion.subject_key} {assertion.predicate} {rendered}".casefold()
    return any(term in normalized for term in ("required", "requires", "must", "shall"))


def _assertion_summary(assertion: KnowledgeAssertion) -> str:
    rendered = json.dumps(
        assertion.value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"{assertion.subject_key} {assertion.predicate} {rendered}"


def _authorized_provenance(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    assertion_ids: list[uuid.UUID] | set[uuid.UUID],
) -> QuerySet[AssertionProvenance]:
    """Filter every provenance row through its current source authorization lineage."""
    visible_scope_ids = authorized_scope_ids(
        actor=actor,
        repository_id=repository_id,
        action=Action.SEARCH,
    )
    return (
        AssertionProvenance.objects.filter(
            organization_id=actor.organization_id,
            assertion_id__in=assertion_ids,
            access_snapshot__access_scope_id__in=visible_scope_ids,
            access_snapshot__revoked_at__isnull=True,
            access_snapshot__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            access_snapshot__access_scope__accessscopesource__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            source_observation__status="PRESENT",
            source_observation__source_document__state="PRESENT",
            source_observation__source_document__source_container__source_connection__repository_id=(
                repository_id
            ),
            source_observation__source_document__source_container__source_connection__state__in=(
                "ACTIVE",
                "DEGRADED",
            ),
            source_observation__source_revision_id=F(
                "source_observation__source_document__current_revision_id"
            ),
            source_observation__sync_run_id=F(
                "source_observation__source_document__last_seen_run_id"
            ),
            source_location__source_observation_id=F("source_observation_id"),
            source_location__parsed_source__source_revision_id=F(
                "source_observation__source_revision_id"
            ),
            assertion__assertionvalidityinterval__valid_until__isnull=True,
            assertion__assertionvalidityinterval__source_observation_id=F("source_observation_id"),
        )
        .select_related(
            "source_location",
            "source_observation__source_document",
            "source_observation__source_revision",
            "access_snapshot",
        )
        .order_by("assertion_id", "observed_at", "id")
        .distinct()
    )


def _citation_from_provenance(
    provenance: AssertionProvenance,
) -> CitationCandidate:
    location = provenance.source_location
    observation = provenance.source_observation
    revision = observation.source_revision
    if revision is None:
        raise ValueError("citation observation must have a source revision")
    locator = location.pointer
    if location.start_line is not None:
        locator = f"{locator}#L{location.start_line}-L{location.end_line}"
    return CitationCandidate(
        access_scope_id=provenance.access_snapshot.access_scope_id,
        source_location_id=location.id,
        source_observation_id=observation.id,
        access_snapshot_id=provenance.access_snapshot_id,
        canonical_url=observation.source_document.canonical_url,
        locator=locator,
        source_content_hash=revision.content_hash,
        observed_at=provenance.observed_at,
    )


def _assertion_candidates(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    query: str,
) -> list[PacketCandidate]:
    query_terms = tuple(term.casefold() for term in query.split() if len(term) > 1)
    assertions = list(
        authorized_assertions(
            actor=actor,
            repository_id=repository_id,
            action=Action.SEARCH,
        )
        .select_related("access_scope")
        .order_by("id")[:MAX_ASSERTION_CANDIDATES]
    )
    provenance_by_assertion: dict[uuid.UUID, tuple[CitationCandidate, ...]] = {}
    provenance_rows = _authorized_provenance(
        actor=actor,
        repository_id=repository_id,
        assertion_ids=[assertion.id for assertion in assertions],
    )
    for provenance in provenance_rows:
        existing = provenance_by_assertion.get(provenance.assertion_id, ())
        provenance_by_assertion[provenance.assertion_id] = (
            *existing,
            _citation_from_provenance(provenance),
        )

    candidates: list[PacketCandidate] = []
    for assertion in assertions:
        citations = provenance_by_assertion.get(assertion.id, ())
        if not citations or assertion.access_scope_id is None:
            continue
        summary = _assertion_summary(assertion)
        required = _required_policy(assertion)
        matches = not query_terms or any(term in summary.casefold() for term in query_terms)
        kind = _assertion_kind(assertion)
        if not matches and kind not in {
            ContextPacketItem.Kind.POLICY,
            ContextPacketItem.Kind.DECISION,
            ContextPacketItem.Kind.INCIDENT,
        }:
            continue
        if required and _freshness(assertion) == ContextPacketItem.Freshness.CURRENT:
            tier = 0
            reason = "Applicable required current policy"
        elif kind == ContextPacketItem.Kind.POLICY:
            tier = 3
            reason = "Applicable policy"
        elif kind == ContextPacketItem.Kind.DECISION:
            tier = 5
            reason = "Relevant decision"
        elif kind == ContextPacketItem.Kind.INCIDENT:
            tier = 6
            reason = "Relevant risk or incident"
        else:
            tier = 2
            reason = "Phase-relevant governed assertion"
        payload = {
            "assertion_id": str(assertion.id),
            "subject_key": assertion.subject_key,
            "predicate": assertion.predicate,
            "value": assertion.value,
            "review_state": assertion.review_state,
            "staleness_state": assertion.staleness_state,
            "confidence": assertion.confidence,
        }
        candidates.append(
            PacketCandidate(
                item_id=uuid.uuid4(),
                kind=kind,
                item_key=f"assertion:{assertion.id}",
                summary=summary,
                freshness=_freshness(assertion),
                is_inferred=assertion.is_inferred,
                selection_reason=reason,
                rank_score=max(0.0, assertion.confidence),
                tier=tier,
                required_policy=required,
                payload=payload,
                contributing_scope_ids=tuple(
                    sorted(
                        {
                            assertion.access_scope_id,
                            *(citation.access_scope_id for citation in citations),
                        }
                    )
                ),
                citations=citations,
                source_assertion_id=assertion.id,
            )
        )
    return candidates


def _authorized_packet_relationships(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
) -> QuerySet[KnowledgeRelationship]:
    """Apply current endpoint, provenance, repository, and source lineage to packet edges."""
    visible_scope_ids = authorized_scope_ids(
        actor=actor,
        repository_id=repository_id,
        action=Action.KNOWLEDGE_VIEW,
    )
    return (
        authorized_relationships(actor=actor, repository_id=repository_id)
        .filter(
            access_scope_id__in=visible_scope_ids,
            assertion__access_scope_id__in=visible_scope_ids,
            source_entity__access_scope_id__in=visible_scope_ids,
            target_entity__access_scope_id__in=visible_scope_ids,
            access_snapshot__access_scope_id__in=visible_scope_ids,
            access_snapshot__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            access_snapshot__access_scope__accessscopesource__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            source_observation__status="PRESENT",
            source_observation__source_document__state="PRESENT",
            source_observation__source_document__source_container__source_connection__repository_id=(
                repository_id
            ),
            source_observation__source_document__source_container__source_connection__state__in=(
                "ACTIVE",
                "DEGRADED",
            ),
            source_observation__sync_run_id=F(
                "source_observation__source_document__last_seen_run_id"
            ),
            source_location__source_observation_id=F("source_observation_id"),
            source_location__parsed_source__source_revision_id=F(
                "source_observation__source_revision_id"
            ),
            source_entity__is_active=True,
            target_entity__is_active=True,
        )
        .exclude(review_state=KnowledgeRelationship.ReviewState.REJECTED)
        .distinct()
    )


def _relationship_candidates(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    query: str,
) -> list[PacketCandidate]:
    query_terms = tuple(term.casefold() for term in query.split() if len(term) > 1)
    relationships = (
        _authorized_packet_relationships(
            actor=actor,
            repository_id=repository_id,
        )
        .select_related(
            "source_entity",
            "target_entity",
            "assertion",
            "source_location",
            "source_observation__source_document",
            "source_observation__source_revision",
        )
        .order_by("id")[:MAX_RELATIONSHIP_CANDIDATES]
    )
    candidates: list[PacketCandidate] = []
    for relationship in relationships:
        revision = relationship.source_observation.source_revision
        if revision is None or relationship.assertion.access_scope_id is None:
            continue
        summary = (
            f"{relationship.source_entity.display_name} "
            f"{relationship.relationship_type} {relationship.target_entity.display_name}"
        )
        if query_terms and not any(term in summary.casefold() for term in query_terms):
            continue
        citation = CitationCandidate(
            access_scope_id=relationship.access_snapshot.access_scope_id,
            source_location_id=relationship.source_location_id,
            source_observation_id=relationship.source_observation_id,
            access_snapshot_id=relationship.access_snapshot_id,
            canonical_url=relationship.source_observation.source_document.canonical_url,
            locator=relationship.source_location.pointer,
            source_content_hash=revision.content_hash,
            observed_at=relationship.observed_at,
        )
        candidates.append(
            PacketCandidate(
                item_id=uuid.uuid4(),
                kind=ContextPacketItem.Kind.RELATIONSHIP,
                item_key=f"relationship:{relationship.id}",
                summary=summary,
                freshness=ContextPacketItem.Freshness.CURRENT,
                is_inferred=(
                    relationship.extraction_class == KnowledgeAssertion.ExtractionClass.INTERPRETIVE
                ),
                selection_reason="Direct authorized entity relationship",
                rank_score=max(0.0, relationship.confidence),
                tier=1,
                required_policy=False,
                payload={
                    "relationship_id": str(relationship.id),
                    "relationship_type": relationship.relationship_type,
                    "source_entity_id": str(relationship.source_entity_id),
                    "target_entity_id": str(relationship.target_entity_id),
                    "review_state": relationship.review_state,
                    "confidence": relationship.confidence,
                },
                contributing_scope_ids=tuple(
                    sorted(
                        {
                            relationship.access_scope_id,
                            relationship.assertion.access_scope_id,
                            relationship.source_entity.access_scope_id,
                            relationship.target_entity.access_scope_id,
                            citation.access_scope_id,
                        }
                    )
                ),
                citations=(citation,),
                source_relationship_id=relationship.id,
            )
        )
    return candidates


def _chunk_candidate(result: SearchResult, position: int) -> PacketCandidate:
    citation = CitationCandidate(
        access_scope_id=result.access_scope_id,
        source_location_id=result.source_location_id,
        source_observation_id=result.source_observation_id,
        access_snapshot_id=result.access_snapshot_id,
        canonical_url=result.canonical_url,
        locator=result.pointer,
        source_content_hash=result.content_hash,
        observed_at=result.observed_at,
    )
    summary = result.text[:10_000]
    return PacketCandidate(
        item_id=uuid.uuid4(),
        kind=ContextPacketItem.Kind.SOURCE_EXCERPT,
        item_key=f"chunk:{result.chunk_id}",
        summary=summary,
        freshness=ContextPacketItem.Freshness.CURRENT,
        is_inferred=False,
        selection_reason="Permission-filtered hybrid source match",
        rank_score=max(0.0, result.explanation.reciprocal_rank_score),
        tier=4,
        required_policy=False,
        payload={
            "chunk_id": str(result.chunk_id),
            "content_hash": result.content_hash,
            "ranking": result.explanation.as_dict(),
            "search_position": position,
        },
        contributing_scope_ids=(result.access_scope_id,),
        citations=(citation,),
        source_chunk_id=result.chunk_id,
    )


def _conflict_candidates(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    selected_assertion_ids: set[uuid.UUID],
) -> list[PacketCandidate]:
    if not selected_assertion_ids:
        return []
    conflicts = (
        AssertionConflict.objects.filter(
            organization_id=actor.organization_id,
            status=AssertionConflict.Status.OPEN,
            left_assertion_id__in=selected_assertion_ids,
            right_assertion_id__in=selected_assertion_ids,
        )
        .select_related("left_assertion", "right_assertion")
        .order_by("id")
    )
    candidates: list[PacketCandidate] = []
    provenance_by_assertion: dict[uuid.UUID, AssertionProvenance] = {}
    for provenance in _authorized_provenance(
        actor=actor,
        repository_id=repository_id,
        assertion_ids=selected_assertion_ids,
    ):
        provenance_by_assertion.setdefault(provenance.assertion_id, provenance)
    for conflict in conflicts:
        left_provenance = provenance_by_assertion.get(conflict.left_assertion_id)
        right_provenance = provenance_by_assertion.get(conflict.right_assertion_id)
        if (
            left_provenance is None
            or right_provenance is None
            or conflict.left_assertion.access_scope_id is None
            or conflict.right_assertion.access_scope_id is None
        ):
            continue
        citations = (
            _citation_from_provenance(left_provenance),
            _citation_from_provenance(right_provenance),
        )
        candidates.append(
            PacketCandidate(
                item_id=uuid.uuid4(),
                kind=ContextPacketItem.Kind.CONFLICT,
                item_key=f"conflict:{conflict.id}",
                summary=(
                    f"Conflict for {conflict.predicate}: "
                    f"{conflict.left_assertion.value!r} versus "
                    f"{conflict.right_assertion.value!r}"
                ),
                freshness=ContextPacketItem.Freshness.CURRENT,
                is_inferred=False,
                selection_reason="Authorized contradiction among selected assertions",
                rank_score=0.0,
                tier=7,
                required_policy=False,
                payload={
                    "conflict_id": str(conflict.id),
                    "left_assertion_id": str(conflict.left_assertion_id),
                    "right_assertion_id": str(conflict.right_assertion_id),
                    "predicate": conflict.predicate,
                },
                contributing_scope_ids=tuple(
                    sorted(
                        {
                            conflict.left_assertion.access_scope_id,
                            conflict.right_assertion.access_scope_id,
                            *(citation.access_scope_id for citation in citations),
                        }
                    )
                ),
                citations=citations,
                source_conflict_id=conflict.id,
            )
        )
    return candidates


def _select(
    candidates: list[PacketCandidate],
    budget: PacketBudget,
) -> PacketSelection:
    deduplicated = {candidate.item_key: candidate for candidate in candidates}
    ordered = sorted(
        deduplicated.values(),
        key=lambda candidate: (
            candidate.tier,
            candidate.freshness != ContextPacketItem.Freshness.CURRENT,
            -candidate.rank_score,
            candidate.item_key,
        ),
    )
    selected: list[PacketCandidate] = []
    tokens = 0
    byte_count = 0
    citations = 0
    omitted = 0
    for candidate in ordered:
        next_items = len(selected) + 1
        next_tokens = tokens + candidate.token_count
        next_bytes = byte_count + candidate.byte_count
        next_citations = citations + len(candidate.citations)
        fits = (
            next_items <= budget.max_items
            and next_tokens <= budget.max_tokens
            and next_bytes <= budget.max_bytes
            and next_citations <= budget.max_citations
        )
        if not fits:
            if candidate.required_policy and (
                candidate.freshness == ContextPacketItem.Freshness.CURRENT
            ):
                raise RequiredPolicyBudgetError(
                    "Packet budget cannot contain every applicable required current policy"
                )
            omitted += 1
            continue
        selected.append(candidate)
        tokens = next_tokens
        byte_count = next_bytes
        citations = next_citations
    limitations: tuple[str, ...] = ()
    if omitted:
        limitations = (f"{omitted} lower-priority candidates omitted by budget",)
    return PacketSelection(tuple(selected), tokens, byte_count, citations, limitations)


def _seal_actor_scope(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    source_scope_ids: set[uuid.UUID],
    scope_key: uuid.UUID,
) -> AccessScope:
    """Create an actor-and-repository-only scope narrower than every input scope."""
    principal = resolve_principal(actor)
    scopes = list(
        AccessScope.objects.select_for_update()
        .filter(
            organization_id=actor.organization_id,
            id__in=source_scope_ids,
            is_active=True,
        )
        .order_by("id")
    )
    if len(scopes) != len(source_scope_ids):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    organization = Organization.objects.get(id=actor.organization_id)
    derived = AccessScope.objects.create(
        organization=organization,
        name=f"context-packet:{scope_key}",
    )
    derived.derived_from.set(scopes)
    if principal.membership is not None:
        AccessScopeMembership.objects.create(
            organization=organization,
            access_scope=derived,
            membership=principal.membership,
        )
    else:
        if principal.service_identity is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        AccessScopeServiceIdentity.objects.create(
            organization=organization,
            access_scope=derived,
            service_identity=principal.service_identity,
        )
    AccessScopeRepository.objects.create(
        organization=organization,
        access_scope=derived,
        repository_id=repository_id,
    )
    source_ids = AccessScopeSource.objects.filter(access_scope_id__in=source_scope_ids).values_list(
        "source_connection_id", flat=True
    )
    AccessScopeSource.objects.bulk_create(
        [
            AccessScopeSource(
                organization=organization,
                access_scope=derived,
                source_connection_id=source_id,
            )
            for source_id in sorted(set(source_ids))
        ]
    )
    derived.is_derived = True
    derived.boundary_sealed_at = timezone.now()
    derived.save(
        update_fields=["is_derived", "boundary_sealed_at", "updated_at"],
    )
    return derived


def _authorization_snapshot(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
) -> tuple[list[uuid.UUID], str]:
    authorized_ids = list(
        authorized_scope_ids(
            actor=actor,
            repository_id=repository_id,
            action=Action.SEARCH,
        )
    )
    scope_ids = list(
        AccessScope.objects.filter(
            id__in=authorized_ids,
            organization_id=actor.organization_id,
        )
        .exclude(name__startswith="context-packet:")
        .order_by("id")
        .values_list("id", flat=True)
    )
    if not scope_ids:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    scopes = list(
        AccessScope.objects.filter(id__in=scope_ids).order_by("id").values("id", "revision")
    )
    snapshots = list(
        AccessSnapshot.objects.filter(
            organization_id=actor.organization_id,
            access_scope_id__in=scope_ids,
            revoked_at__isnull=True,
        )
        .order_by("id")
        .values("id", "content_hash")
    )
    payload = {
        "actor_type": actor.actor_type,
        "actor_id": actor.actor_id,
        "repository_id": str(repository_id),
        "scopes": [{"id": str(scope["id"]), "revision": scope["revision"]} for scope in scopes],
        "snapshots": [
            {"id": str(snapshot["id"]), "content_hash": snapshot["content_hash"]}
            for snapshot in snapshots
        ],
    }
    return scope_ids, _json_hash(payload)


def _watermark(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
) -> RetrievalWatermark:
    repository = Repository.objects.get(
        id=repository_id,
        organization_id=actor.organization_id,
    )
    watermark, _created = RetrievalWatermark.objects.get_or_create(
        organization_id=actor.organization_id,
        repository=repository,
    )
    return watermark


def _deny_packet() -> NoReturn:
    raise ResourceNotFoundError(NOT_FOUND_MESSAGE)


def _reauthorize_packet_current(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    packet: ContextPacketRecord,
) -> ImmutableArtifact:
    """Recheck every parent scope and citation against current source lineage."""
    if ContextPacketInvalidation.objects.filter(context_packet=packet).exists():
        _deny_packet()
    artifact = get_authorized_artifact(
        actor=actor,
        repository_id=repository_id,
        artifact_id=packet.artifact_id,
    )
    visible_scope_ids = set(
        authorized_scope_ids(
            actor=actor,
            repository_id=repository_id,
            action=Action.ARTIFACT_VIEW,
        )
    )
    if packet.access_scope_id not in visible_scope_ids:
        _deny_packet()
    items = list(
        ContextPacketItem.objects.filter(
            organization_id=actor.organization_id,
            context_packet=packet,
        )
        .select_related("access_scope")
        .prefetch_related("access_scope__derived_from")
        .order_by("position")
    )
    packet_parent_ids = set(packet.access_scope.derived_from.values_list("id", flat=True))
    expected_packet_parents = {item.access_scope_id for item in items}
    if items:
        if packet_parent_ids != expected_packet_parents:
            _deny_packet()
    elif not packet_parent_ids or not packet_parent_ids <= visible_scope_ids:
        _deny_packet()

    visible_assertion_ids = set(
        authorized_assertions(
            actor=actor,
            repository_id=repository_id,
            action=Action.ARTIFACT_VIEW,
        ).values_list("id", flat=True)
    )
    visible_relationship_ids = set(
        _authorized_packet_relationships(
            actor=actor,
            repository_id=repository_id,
        ).values_list("id", flat=True)
    )
    visible_chunk_ids = set(
        authorized_source_chunks(
            actor=actor,
            repository_id=repository_id,
        ).values_list("id", flat=True)
    )
    visible_conflict_ids = set(
        AssertionConflict.objects.filter(
            organization_id=actor.organization_id,
            status=AssertionConflict.Status.OPEN,
            left_assertion_id__in=visible_assertion_ids,
            right_assertion_id__in=visible_assertion_ids,
        ).values_list("id", flat=True)
    )
    citations_by_item: dict[uuid.UUID, list[ContextPacketCitation]] = {}
    citations = (
        ContextPacketCitation.objects.filter(
            organization_id=actor.organization_id,
            context_packet=packet,
        )
        .select_related(
            "access_snapshot__access_scope",
            "access_snapshot__source_connection",
            "source_location__parsed_source",
            "source_observation__source_revision",
            "source_observation__source_document__source_container__source_connection",
        )
        .order_by("context_item_id", "position")
    )
    for citation in citations:
        citations_by_item.setdefault(citation.context_item_id, []).append(citation)

    for item in items:
        if item.access_scope_id not in visible_scope_ids:
            _deny_packet()
        item_parent_ids = set(item.access_scope.derived_from.values_list("id", flat=True))
        if not item_parent_ids or not item_parent_ids <= visible_scope_ids:
            _deny_packet()
        item_citations = citations_by_item.get(item.id, [])
        if not item_citations:
            _deny_packet()
        citation_scope_ids: set[uuid.UUID] = set()
        for citation in item_citations:
            if citation.access_snapshot is None:
                _deny_packet()
            citation_scope_ids.add(citation.access_snapshot.access_scope_id)
        if not citation_scope_ids <= item_parent_ids:
            _deny_packet()
        if (
            item.source_assertion_id is not None
            and item.source_assertion_id not in visible_assertion_ids
        ):
            _deny_packet()
        if (
            item.source_relationship_id is not None
            and item.source_relationship_id not in visible_relationship_ids
        ):
            _deny_packet()
        if item.source_chunk_id is not None and item.source_chunk_id not in visible_chunk_ids:
            _deny_packet()
        if (
            item.source_conflict_id is not None
            and item.source_conflict_id not in visible_conflict_ids
        ):
            _deny_packet()

        for citation in item_citations:
            snapshot = citation.access_snapshot
            location = citation.source_location
            observation = citation.source_observation
            if location is None or observation is None or snapshot is None:
                _deny_packet()
            document = observation.source_document
            source_connection = document.source_container.source_connection
            revision = observation.source_revision
            if (
                snapshot.revoked_at is not None
                or snapshot.access_scope_id not in item_parent_ids
                or snapshot.source_connection_id != source_connection.id
                or not AccessScopeSource.objects.filter(
                    organization_id=actor.organization_id,
                    access_scope_id=snapshot.access_scope_id,
                    source_connection_id=source_connection.id,
                ).exists()
                or source_connection.repository_id != repository_id
                or source_connection.state not in {"ACTIVE", "DEGRADED"}
                or document.state != "PRESENT"
                or observation.status != "PRESENT"
                or revision is None
                or observation.source_revision_id != document.current_revision_id
                or observation.sync_run_id != document.last_seen_run_id
                or location.source_observation_id != observation.id
                or location.parsed_source.source_revision_id != revision.id
                or citation.canonical_url != document.canonical_url
            ):
                _deny_packet()
            expected_hash = revision.content_hash
            if item.source_chunk_id is not None:
                if item.source_chunk is None:
                    _deny_packet()
                expected_hash = item.source_chunk.content_hash
            if citation.source_content_hash != expected_hash:
                _deny_packet()
    return artifact


@transaction.atomic
def build_context_packet(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    task: str,
    phase: str,
    budget: PacketBudget | None = None,
) -> tuple[ContextPacketRecord, bool]:
    """Build or reuse an exact immutable packet for one actor/repository snapshot."""
    normalized_task = " ".join(task.split())
    if not normalized_task or len(normalized_task) > 2_000:
        raise ValueError("task must contain between 1 and 2000 characters")
    normalized_phase = phase.upper()
    if normalized_phase not in ContextPacketRecord.Phase.values:
        raise ValueError("phase is invalid")
    budget = budget or PacketBudget()
    authorize_action(
        actor=actor,
        action=Action.ARTIFACT_CREATE,
        repository_id=repository_id,
    )
    visible_scopes, authorization_hash = _authorization_snapshot(
        actor=actor,
        repository_id=repository_id,
    )
    watermark = _watermark(actor=actor, repository_id=repository_id)
    normalized_request = {
        "task": normalized_task,
        "phase": normalized_phase,
        "budget": budget.as_dict(),
    }
    request_hash = _json_hash(normalized_request)
    cache_key = _json_hash(
        {
            "request": normalized_request,
            "actor_type": actor.actor_type,
            "actor_id": actor.actor_id,
            "repository_id": str(repository_id),
            "authorization_hash": authorization_hash,
            "watermark": watermark.value,
            "retrieval_algorithm_version": RETRIEVAL_ALGORITHM_VERSION,
            "index_version": INDEX_VERSION,
            "embedding_version": EMBEDDING_VERSION,
        }
    )
    cached = (
        ContextPacketRecord.objects.filter(
            organization_id=actor.organization_id,
            repository_id=repository_id,
            cache_key=cache_key,
            contextpacketinvalidation__isnull=True,
        )
        .order_by("generated_at")
        .first()
    )
    if cached is not None:
        _reauthorize_packet_current(
            actor=actor,
            repository_id=repository_id,
            packet=cached,
        )
        return cached, False

    assertions = _assertion_candidates(
        actor=actor,
        repository_id=repository_id,
        query=normalized_task,
    )
    relationships = _relationship_candidates(
        actor=actor,
        repository_id=repository_id,
        query=normalized_task,
    )
    search_response = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query=normalized_task,
        phase=normalized_phase,
        limit=min(100, budget.max_items),
    )
    chunks = [
        _chunk_candidate(result, position)
        for position, result in enumerate(search_response.results, start=1)
    ]
    selected_assertions = {
        candidate.source_assertion_id
        for candidate in assertions
        if candidate.source_assertion_id is not None
    }
    conflicts = _conflict_candidates(
        actor=actor,
        repository_id=repository_id,
        selected_assertion_ids=selected_assertions,
    )
    selection = _select(
        [*assertions, *relationships, *chunks, *conflicts],
        budget,
    )
    selection_hash = _json_hash([candidate.as_dict() for candidate in selection.candidates])
    packet_id = uuid.uuid4()
    generated_at = timezone.now()
    packet_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "packet_id": str(packet_id),
        "organization_id": str(actor.organization_id),
        "repository_id": str(repository_id),
        "work_item_id": None,
        "revision": 1,
        "generated_at": generated_at.isoformat(),
        "content_hash": selection_hash,
        "phase": normalized_phase,
        "request": normalized_request,
        "authorization_hash": authorization_hash,
        "selection_hash": selection_hash,
        "retrieval_watermark": watermark.value,
        "retrieval_algorithm_version": RETRIEVAL_ALGORITHM_VERSION,
        "index_version": INDEX_VERSION,
        "embedding_version": EMBEDDING_VERSION,
        "budget": {
            **budget.as_dict(),
            "selected_items": len(selection.candidates),
            "selected_tokens": selection.selected_tokens,
            "selected_bytes": selection.selected_bytes,
            "selected_citations": selection.selected_citations,
        },
        "items": [candidate.as_dict() for candidate in selection.candidates],
        "limitations": list(selection.limitations),
    }
    item_scopes = {
        candidate.item_id: _seal_actor_scope(
            actor=actor,
            repository_id=repository_id,
            source_scope_ids=set(candidate.contributing_scope_ids),
            scope_key=candidate.item_id,
        )
        for candidate in selection.candidates
    }
    selected_scope_ids = {scope.id for scope in item_scopes.values()} or {visible_scopes[0]}
    sealed_scope = _seal_actor_scope(
        actor=actor,
        repository_id=repository_id,
        source_scope_ids=selected_scope_ids,
        scope_key=packet_id,
    )
    organization = Organization.objects.get(id=actor.organization_id)
    artifact = ImmutableArtifact.objects.create(
        organization=organization,
        access_scope=sealed_scope,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload=packet_payload,
    )
    packet = ContextPacketRecord.objects.create(
        id=packet_id,
        organization=organization,
        artifact=artifact,
        repository_id=repository_id,
        access_scope=sealed_scope,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        phase=normalized_phase,
        normalized_request=normalized_request,
        request_hash=request_hash,
        authorization_hash=authorization_hash,
        selection_hash=selection_hash,
        retrieval_watermark=watermark.value,
        retrieval_algorithm_version=RETRIEVAL_ALGORITHM_VERSION,
        index_version=INDEX_VERSION,
        embedding_version=EMBEDDING_VERSION,
        budget_max_items=budget.max_items,
        budget_max_tokens=budget.max_tokens,
        budget_max_bytes=budget.max_bytes,
        budget_max_citations=budget.max_citations,
        selected_items=len(selection.candidates),
        selected_tokens=selection.selected_tokens,
        selected_bytes=selection.selected_bytes,
        selected_citations=selection.selected_citations,
        limitations=list(selection.limitations),
        cache_key=cache_key,
        generated_at=generated_at,
    )
    for position, candidate in enumerate(selection.candidates, start=1):
        item = ContextPacketItem.objects.create(
            id=candidate.item_id,
            organization=organization,
            context_packet=packet,
            access_scope=item_scopes[candidate.item_id],
            position=position,
            kind=candidate.kind,
            item_key=candidate.item_key,
            summary=candidate.summary,
            freshness=candidate.freshness,
            is_inferred=candidate.is_inferred,
            selection_reason=candidate.selection_reason,
            rank_score=candidate.rank_score,
            token_count=candidate.token_count,
            byte_count=candidate.byte_count,
            payload=candidate.payload,
            source_assertion_id=candidate.source_assertion_id,
            source_relationship_id=candidate.source_relationship_id,
            source_chunk_id=candidate.source_chunk_id,
            source_conflict_id=candidate.source_conflict_id,
        )
        ContextPacketCitation.objects.bulk_create(
            [
                ContextPacketCitation(
                    organization=organization,
                    context_packet=packet,
                    context_item=item,
                    position=citation_position,
                    source_location_id=citation.source_location_id,
                    source_observation_id=citation.source_observation_id,
                    access_snapshot_id=citation.access_snapshot_id,
                    canonical_url=citation.canonical_url,
                    locator=citation.locator,
                    source_content_hash=citation.source_content_hash,
                    observed_at=citation.observed_at,
                )
                for citation_position, citation in enumerate(
                    candidate.citations,
                    start=1,
                )
            ]
        )
    return packet, True


def get_context_packet(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    packet_id: uuid.UUID,
) -> dict[str, object]:
    """Reconstruct the exact original packet via its authorized immutable artifact."""
    packet = ContextPacketRecord.objects.filter(
        id=packet_id,
        organization_id=actor.organization_id,
        repository_id=repository_id,
    ).first()
    if packet is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    artifact = _reauthorize_packet_current(
        actor=actor,
        repository_id=repository_id,
        packet=packet,
    )
    return cast(dict[str, object], artifact.payload)


@transaction.atomic
def invalidate_context_packets(
    *,
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    reason: str,
    details: dict[str, object] | None = None,
) -> int:
    """Advance a repository watermark and append invalidations without deletion."""
    if reason not in ContextPacketInvalidation.Reason.values:
        raise ValueError("invalidation reason is invalid")
    repository = Repository.objects.get(
        id=repository_id,
        organization_id=organization_id,
    )
    watermark, _created = RetrievalWatermark.objects.select_for_update().get_or_create(
        organization_id=organization_id,
        repository=repository,
    )
    watermark.value += 1
    watermark.revision += 1
    watermark.reason = reason
    watermark.save(
        update_fields=["value", "revision", "reason", "updated_at"],
    )
    packets = ContextPacketRecord.objects.filter(
        organization_id=organization_id,
        repository=repository,
        contextpacketinvalidation__isnull=True,
    ).order_by("id")
    invalidations = [
        ContextPacketInvalidation(
            organization_id=organization_id,
            context_packet=packet,
            repository=repository,
            reason=reason,
            watermark=watermark.value,
            details=details or {},
        )
        for packet in packets
    ]
    ContextPacketInvalidation.objects.bulk_create(invalidations)
    return len(invalidations)
