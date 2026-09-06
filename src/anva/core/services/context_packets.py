"""Deterministic, immutable, permission-safe context packet assembly."""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from time import monotonic
from typing import Any, NoReturn, cast

from django.db import connection, transaction
from django.db.models import Case, F, Q, QuerySet, Subquery, TextField, Value, When
from django.db.models.functions import Cast, Concat
from django.utils import timezone

from anva.core.exceptions import (
    RequiredContextBudgetError,
    RequiredPolicyBudgetError,
    RequiredSearchAnchorUnavailableError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    AccessSnapshot,
    AssertionConflict,
    AssertionProvenance,
    AssuranceRun,
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
    SourceChunkVisibility,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    AuthorizedRepositoryScopes,
    authorize_action,
    current_authorized_scope_filter,
    resolve_authorized_repository_scopes,
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
CONTEXT_SCAN_VERSION = "authorized-conflict-scan-v1"
CONTEXT_SCAN_PAGE_SIZE = 200
CONTEXT_SCAN_MAX_ROWS = 50_000
CONTEXT_SCAN_MAX_OPERATIONS = 100_000
# Leave one second of the v3 five-second context target for ranking, sealing,
# and publication reauthorization around this internal database scan.
CONTEXT_SCAN_MAX_SECONDS = 4.0
MAX_RETRIEVAL_FACETS = 8
MAX_REQUIRED_SEARCH_ANCHORS = 50
# One closed anchor is 373 canonical ASCII JSON bytes. The array adds 49 commas
# and two brackets, so this is the smallest ceiling that admits 50 maximum values.
MAX_REQUIRED_SEARCH_ANCHORS_BYTES = 18_701
MAX_REQUIRED_PACKING_CANDIDATES = 10_000
MAX_REQUIRED_PACKING_STATES = 50_000
MAX_REQUIRED_PACKING_OPERATIONS = 1_000_000
_FACET_LABEL = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_QUERY_TERM = re.compile(r"[a-z0-9][a-z0-9_.:/-]*")


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
class RetrievalFacet:
    """One bounded, server-derived aspect of the change under review."""

    label: str
    query: str
    anchors: tuple[str, ...] = ()
    required_if_matched: bool = True
    coverage_incomplete: bool = False


@dataclass(frozen=True, slots=True)
class RequiredSearchAnchor:
    """Exact public search identity that must survive into the context packet."""

    chunk_id: uuid.UUID
    content_hash: str
    access_scope_id: uuid.UUID
    source_location_id: uuid.UUID
    source_observation_id: uuid.UUID
    access_snapshot_id: uuid.UUID

    def as_dict(self) -> dict[str, str]:
        return {
            "chunk_id": str(self.chunk_id),
            "content_hash": self.content_hash,
            "access_scope_id": str(self.access_scope_id),
            "source_location_id": str(self.source_location_id),
            "source_observation_id": str(self.source_observation_id),
            "access_snapshot_id": str(self.access_snapshot_id),
        }

    @property
    def canonical_key(self) -> tuple[str, ...]:
        payload = self.as_dict()
        return tuple(payload[key] for key in sorted(payload))


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
    matched_facets: tuple[str, ...] = ()
    required_context_facets: tuple[str, ...] = ()
    required_search_anchor: bool = False
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
                self.effective_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )

    @property
    def effective_payload(self) -> dict[str, object]:
        payload = dict(self.payload)
        if self.required_search_anchor:
            payload["required_search_anchor"] = True
        if self.matched_facets:
            payload["retrieval_facets"] = list(self.matched_facets)
        if self.required_context_facets:
            payload["required_context_facets"] = list(self.required_context_facets)
        return payload

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
            "payload": self.effective_payload,
            "anva_sources": [citation.as_dict() for citation in self.citations],
        }


@dataclass(frozen=True, slots=True)
class PacketSelection:
    candidates: tuple[PacketCandidate, ...]
    selected_tokens: int
    selected_bytes: int
    selected_citations: int
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContextCompleteness:
    """Bounded internal scan accounting; never a public continuation cursor."""

    assertion_count: int
    conflict_count: int
    processed_count: int
    digest: str
    complete: bool = True

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "version": CONTEXT_SCAN_VERSION,
            "ordering": "kind,id",
            "processed_rows": self.processed_count,
            "digest": self.digest,
            "complete": self.complete,
            "page_size": CONTEXT_SCAN_PAGE_SIZE,
        }
        if self.complete:
            payload.update(
                exact_eligible_assertions=self.assertion_count,
                exact_eligible_conflicts=self.conflict_count,
                exact_digest=self.digest,
            )
        else:
            payload.update(
                partial_retained_assertions=self.assertion_count,
                partial_retained_conflicts=self.conflict_count,
                partial_digest=self.digest,
            )
        return payload


class ScannedCandidates(list[PacketCandidate]):
    """Candidate list carrying internal completeness without changing public models."""

    def __init__(self) -> None:
        super().__init__()
        self.complete = True
        self.eligible_assertion_ids: set[uuid.UUID] = set()
        self.processed_count = 0


def normalize_required_search_anchors(
    anchors: tuple[RequiredSearchAnchor, ...] | None,
) -> tuple[RequiredSearchAnchor, ...]:
    """Bound, deduplicate, and canonically order caller-required search identities."""
    raw = anchors or ()
    if len(raw) > MAX_REQUIRED_SEARCH_ANCHORS:
        raise ValueError(
            f"required_search_anchors cannot exceed {MAX_REQUIRED_SEARCH_ANCHORS} entries"
        )
    for anchor in raw:
        if not isinstance(anchor, RequiredSearchAnchor):
            raise ValueError("required_search_anchors is invalid")
        if (
            any(
                not isinstance(value, uuid.UUID)
                for value in (
                    anchor.chunk_id,
                    anchor.access_scope_id,
                    anchor.source_location_id,
                    anchor.source_observation_id,
                    anchor.access_snapshot_id,
                )
            )
            or re.fullmatch(r"[a-f0-9]{64}", anchor.content_hash) is None
        ):
            raise ValueError("required_search_anchors is invalid")
    normalized = tuple(sorted(set(raw), key=lambda anchor: anchor.canonical_key))
    if len({anchor.chunk_id for anchor in normalized}) != len(normalized):
        raise ValueError("required_search_anchors must identify distinct chunks")
    serialized = json.dumps(
        [anchor.as_dict() for anchor in normalized],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    if len(serialized) > MAX_REQUIRED_SEARCH_ANCHORS_BYTES:
        raise ValueError("required_search_anchors exceeds its serialized byte bound")
    return normalized


def parse_required_search_anchors(value: object) -> tuple[RequiredSearchAnchor, ...]:
    """Parse the shared MCP/REST representation before any database work."""
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_REQUIRED_SEARCH_ANCHORS:
        raise ValueError("required_search_anchors is invalid")
    expected = {
        "chunk_id",
        "content_hash",
        "access_scope_id",
        "source_location_id",
        "source_observation_id",
        "access_snapshot_id",
    }
    anchors: list[RequiredSearchAnchor] = []
    try:
        for item in value:
            if not isinstance(item, dict) or set(item) != expected:
                raise ValueError("required_search_anchors is invalid")
            content_hash = item["content_hash"]
            identity_values = [item[key] for key in expected if key != "content_hash"]
            if not isinstance(content_hash, str) or not all(
                isinstance(identity, str) for identity in identity_values
            ):
                raise ValueError("required_search_anchors is invalid")
            anchors.append(
                RequiredSearchAnchor(
                    chunk_id=uuid.UUID(cast(str, item["chunk_id"])),
                    content_hash=content_hash,
                    access_scope_id=uuid.UUID(cast(str, item["access_scope_id"])),
                    source_location_id=uuid.UUID(cast(str, item["source_location_id"])),
                    source_observation_id=uuid.UUID(cast(str, item["source_observation_id"])),
                    access_snapshot_id=uuid.UUID(cast(str, item["access_snapshot_id"])),
                )
            )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("required_search_anchors is invalid") from error
    return normalize_required_search_anchors(tuple(anchors))


def _normalized_facets(
    *,
    task: str,
    retrieval_facets: tuple[RetrievalFacet, ...] | None,
) -> tuple[RetrievalFacet, ...]:
    if retrieval_facets is None:
        return (RetrievalFacet(label="task", query=task[:500], required_if_matched=False),)
    if not retrieval_facets or len(retrieval_facets) > MAX_RETRIEVAL_FACETS:
        raise ValueError("retrieval_facets must contain between 1 and 8 entries")
    normalized: list[RetrievalFacet] = []
    labels: set[str] = set()
    for facet in retrieval_facets:
        label = facet.label.strip().casefold()
        query = " ".join(facet.query.split())
        if _FACET_LABEL.fullmatch(label) is None or label in labels:
            raise ValueError("retrieval facet labels must be unique lowercase identifiers")
        if not query or len(query) > 500:
            raise ValueError("retrieval facet queries must contain between 1 and 500 characters")
        labels.add(label)
        anchors = tuple(dict.fromkeys(" ".join(anchor.split()) for anchor in facet.anchors))
        if len(anchors) > 16 or any(not anchor or len(anchor) > 200 for anchor in anchors):
            raise ValueError("retrieval facet anchors must contain up to 16 bounded values")
        if facet.required_if_matched and not anchors:
            raise ValueError("required retrieval facets must include exact anchors")
        normalized.append(
            RetrievalFacet(
                label,
                query,
                anchors,
                facet.required_if_matched,
                facet.coverage_incomplete,
            )
        )
    return tuple(normalized)


def _query_terms(query: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            term
            for term in _QUERY_TERM.findall(query.casefold())
            if len(term) > 1 and term not in {"and", "or", "not"}
        )
    )


def _matching_facets(summary: str, facets: tuple[RetrievalFacet, ...]) -> tuple[str, ...]:
    normalized = summary.casefold()
    return tuple(
        facet.label
        for facet in facets
        if any(term in normalized for term in _query_terms(facet.query))
    )


def _required_matching_facets(
    summary: str,
    matched: tuple[str, ...],
    facets: tuple[RetrievalFacet, ...],
) -> tuple[str, ...]:
    normalized = " ".join(summary.casefold().split())
    required = {
        facet.label
        for facet in facets
        if facet.required_if_matched
        and any(" ".join(anchor.casefold().split()) in normalized for anchor in facet.anchors)
    }
    return tuple(label for label in matched if label in required)


def _candidate_order(candidate: PacketCandidate) -> tuple[object, ...]:
    return (
        candidate.tier,
        candidate.freshness != ContextPacketItem.Freshness.CURRENT,
        -candidate.rank_score,
        candidate.item_key,
    )


def _merge_candidates(candidates: list[PacketCandidate]) -> list[PacketCandidate]:
    """Deduplicate a source while preserving every facet it substantively matched."""
    grouped: dict[str, list[PacketCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.item_key, []).append(candidate)
    merged: list[PacketCandidate] = []
    for item_key in sorted(grouped):
        variants = grouped[item_key]
        anchored = [item for item in variants if item.required_search_anchor]
        best = min(anchored or variants, key=_candidate_order)
        matched = tuple(sorted({label for item in variants for label in item.matched_facets}))
        required = tuple(
            sorted({label for item in variants for label in item.required_context_facets})
        )
        merged.append(
            replace(
                best,
                matched_facets=matched,
                required_context_facets=required,
                required_search_anchor=bool(anchored),
            )
        )
    return merged


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


def _authorized_provenance_for_authorization(
    *,
    actor: ActorContext,
    authorization: AuthorizedRepositoryScopes,
    assertion_ids: list[uuid.UUID] | set[uuid.UUID] | None,
) -> QuerySet[AssertionProvenance]:
    """Apply the relational repository/scope boundary to current provenance."""
    if not authorization.repository_ids_for(Action.SEARCH) or not authorization.scope_ids_for(
        Action.SEARCH
    ):
        return AssertionProvenance.objects.none()
    queryset = (
        AssertionProvenance.objects.filter(
            organization_id=actor.organization_id,
            access_snapshot__revoked_at__isnull=True,
            access_snapshot__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            access_snapshot__access_scope__accessscopesource__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            source_observation__status="PRESENT",
            source_observation__source_document__state="PRESENT",
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
        .filter(
            current_authorized_scope_filter(
                actor=actor,
                authorization=authorization,
                action=Action.SEARCH,
                scope_id_path="assertion__access_scope_id",
            )
        )
        .filter(
            current_authorized_scope_filter(
                actor=actor,
                authorization=authorization,
                action=Action.SEARCH,
                scope_id_path="access_snapshot__access_scope_id",
                repository_id_path=(
                    "source_observation__source_document__source_container__"
                    "source_connection__repository_id"
                ),
                repository_relation_path=(
                    "source_observation__source_document__source_container__"
                    "source_connection__repository"
                ),
            )
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
    if assertion_ids is not None:
        queryset = queryset.filter(assertion_id__in=assertion_ids)
    return queryset


def _authorized_provenance(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    assertion_ids: list[uuid.UUID] | set[uuid.UUID],
) -> QuerySet[AssertionProvenance]:
    """Filter every provenance row through its current source authorization lineage."""
    authorization = resolve_authorized_repository_scopes(
        actor=actor,
        actions=(Action.SEARCH,),
        required_action=Action.SEARCH,
        repository_ids=(repository_id,),
        repository_limit=1,
    )
    return _authorized_provenance_for_authorization(
        actor=actor,
        authorization=authorization,
        assertion_ids=assertion_ids,
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


def authorized_assertion_citations(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    assertion_id: uuid.UUID,
) -> tuple[dict[str, object], ...]:
    """Expose current normalized assertion lineage for API/MCP explanations."""
    provenance_rows = _authorized_provenance(
        actor=actor,
        repository_id=repository_id,
        assertion_ids=[assertion_id],
    )
    return tuple(_citation_from_provenance(provenance).as_dict() for provenance in provenance_rows)


def authorized_assertion_citations_batch(
    *,
    actor: ActorContext,
    authorization: AuthorizedRepositoryScopes,
    assertion_ids: tuple[uuid.UUID, ...],
    per_assertion_limit: int,
) -> dict[uuid.UUID, tuple[dict[str, object], ...]]:
    """Group bounded current citations for many assertions and repositories."""
    if not 1 <= per_assertion_limit <= 100:
        raise ValueError("per_assertion_limit must be between 1 and 100")
    if len(assertion_ids) > MAX_ASSERTION_CANDIDATES:
        raise ValueError("assertion citation batch budget exceeded")
    ordered_assertion_ids = tuple(sorted(set(assertion_ids), key=str))
    if not authorization.is_bound_to(actor):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    grouped: dict[uuid.UUID, list[dict[str, object]]] = {
        assertion_id: [] for assertion_id in ordered_assertion_ids
    }
    if not ordered_assertion_ids:
        return {assertion_id: tuple(items) for assertion_id, items in grouped.items()}
    authorized_candidates = _authorized_provenance_for_authorization(
        actor=actor,
        authorization=authorization,
        assertion_ids=set(ordered_assertion_ids),
    )
    candidate_rows = (
        authorized_candidates.annotate(
            citation_locator=Case(
                When(
                    source_location__start_line__isnull=False,
                    then=Concat(
                        F("source_location__pointer"),
                        Value("#L"),
                        Cast("source_location__start_line", output_field=TextField()),
                        Value("-L"),
                        Cast("source_location__end_line", output_field=TextField()),
                        output_field=TextField(),
                    ),
                ),
                default=F("source_location__pointer"),
                output_field=TextField(),
            )
        )
        .order_by()
        .values("id", "assertion_id", "observed_at", "citation_locator")
        .distinct()
    )
    candidate_sql, candidate_params = candidate_rows.query.sql_with_params()
    # ``candidate_sql`` is generated exclusively by Django's compiler; all
    # dynamic values remain in ``candidate_params`` below.
    bounded_sql = "\n".join(
        (
            "WITH authorized AS MATERIALIZED (",
            candidate_sql,
            """),
deduplicated AS MATERIALIZED (
    SELECT DISTINCT ON (assertion_id, citation_locator, observed_at)
        id AS provenance_id,
        assertion_id,
        observed_at
    FROM authorized
    ORDER BY assertion_id, citation_locator, observed_at, id
),
ranked AS (
    SELECT
        provenance_id,
        assertion_id,
        ROW_NUMBER() OVER (
            PARTITION BY assertion_id
            ORDER BY observed_at, provenance_id
        ) AS citation_rank
    FROM deduplicated
)
SELECT provenance_id
FROM ranked
WHERE citation_rank <= %s
ORDER BY assertion_id, citation_rank
""",
        )
    )
    with connection.cursor() as cursor:
        cursor.execute(bounded_sql, (*candidate_params, per_assertion_limit))
        selected_ids = tuple(row[0] for row in cursor.fetchall())

    # Rebuild the authorization predicate so revocation or expiry between the
    # candidate and hydration statements fails closed.
    current_rows_by_id = {
        provenance.id: provenance
        for provenance in _authorized_provenance_for_authorization(
            actor=actor,
            authorization=authorization,
            assertion_ids=set(ordered_assertion_ids),
        ).filter(id__in=selected_ids)
    }
    for provenance_id in selected_ids:
        provenance = current_rows_by_id.get(provenance_id)
        if provenance is None:
            continue
        grouped[provenance.assertion_id].append(_citation_from_provenance(provenance).as_dict())
    return {assertion_id: tuple(grouped[assertion_id]) for assertion_id in ordered_assertion_ids}


def _assertion_candidates(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    facets: tuple[RetrievalFacet, ...],
    change_aware: bool,
) -> list[PacketCandidate]:
    authorization = resolve_authorized_repository_scopes(
        actor=actor,
        actions=(Action.SEARCH,),
        required_action=Action.SEARCH,
        repository_ids=(repository_id,),
        repository_limit=1,
    )
    current_provenance = _authorized_provenance_for_authorization(
        actor=actor,
        authorization=authorization,
        assertion_ids=None,
    )
    eligible = (
        authorized_assertions(
            actor=actor,
            repository_id=repository_id,
            action=Action.SEARCH,
        )
        .filter(id__in=Subquery(current_provenance.order_by().values("assertion_id")))
        .select_related("access_scope")
        .order_by("id")
        .distinct()
    )

    candidates = ScannedCandidates()
    last_id: uuid.UUID | None = None
    scanned = 0
    started = monotonic()
    candidate_capacity = min(CONTEXT_SCAN_MAX_ROWS, CONTEXT_SCAN_MAX_OPERATIONS // 2)
    while True:
        page_query = eligible
        if last_id is not None:
            page_query = page_query.filter(id__gt=last_id)
        remaining = candidate_capacity - scanned
        if remaining <= 0:
            candidates.complete = not page_query.exists()
            break
        assertions = list(page_query[: min(CONTEXT_SCAN_PAGE_SIZE, remaining)])
        if not assertions:
            break
        scanned += len(assertions)
        candidates.processed_count = scanned
        if monotonic() - started > CONTEXT_SCAN_MAX_SECONDS:
            candidates.complete = False
            break
        last_id = assertions[-1].id
        provenance_by_assertion: dict[uuid.UUID, tuple[CitationCandidate, ...]] = {}
        provenance_rows = (
            _authorized_provenance_for_authorization(
                actor=actor,
                authorization=authorization,
                assertion_ids={assertion.id for assertion in assertions},
            )
            .order_by("assertion_id", "observed_at", "id")
            .distinct("assertion_id")
        )
        for provenance in provenance_rows:
            existing = provenance_by_assertion.get(provenance.assertion_id, ())
            provenance_by_assertion[provenance.assertion_id] = (
                *existing,
                _citation_from_provenance(provenance),
            )
        for assertion in assertions:
            citations = provenance_by_assertion.get(assertion.id, ())
            if not citations or assertion.access_scope_id is None:
                continue
            candidates.eligible_assertion_ids.add(assertion.id)
            summary = _assertion_summary(assertion)
            required = _required_policy(assertion)
            matched_facets = _matching_facets(summary, facets)
            required_facets = _required_matching_facets(summary, matched_facets, facets)
            matches = bool(matched_facets)
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
            elif change_aware and required_facets:
                tier = 1
                reason = f"Change-aware assurance anchored match: {', '.join(required_facets)}"
            elif change_aware and matches:
                tier = 3
                reason = f"Change-aware assurance lexical fallback: {', '.join(matched_facets)}"
            elif kind == ContextPacketItem.Kind.POLICY:
                tier = 6 if change_aware else 3
                reason = "Governed policy fallback"
            elif kind == ContextPacketItem.Kind.DECISION:
                tier = 7 if change_aware else 5
                reason = "Relevant decision"
            elif kind == ContextPacketItem.Kind.INCIDENT:
                tier = 8 if change_aware else 6
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
                    matched_facets=matched_facets,
                    required_context_facets=required_facets,
                    source_assertion_id=assertion.id,
                )
            )
        if len(assertions) == remaining:
            candidates.complete = not eligible.filter(id__gt=last_id).exists()
            break
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
    facets: tuple[RetrievalFacet, ...],
    change_aware: bool,
) -> list[PacketCandidate]:
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
        matched_facets = _matching_facets(summary, facets)
        if not matched_facets:
            continue
        required_facets = _required_matching_facets(summary, matched_facets, facets)
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
                selection_reason=(
                    f"Change-aware assurance relationship: {', '.join(matched_facets)}"
                    if change_aware
                    else "Direct authorized entity relationship"
                ),
                rank_score=max(0.0, relationship.confidence),
                tier=1 if required_facets or not change_aware else 3,
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
                matched_facets=matched_facets,
                required_context_facets=required_facets,
                source_relationship_id=relationship.id,
            )
        )
    return candidates


def _chunk_candidate(
    result: SearchResult,
    position: int,
    *,
    facet: RetrievalFacet,
    facet_position: int,
    change_aware: bool,
) -> PacketCandidate:
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
    lexical_match = result.explanation.lexical_rank is not None
    matched_facets = (facet.label,) if lexical_match else ()
    required_facets = _required_matching_facets(summary, matched_facets, (facet,))
    tier = 1 if change_aware and required_facets else 4
    if change_aware and lexical_match and not required_facets:
        tier = 3
    reason = "Permission-filtered hybrid source match"
    if change_aware:
        mode = (
            "anchored lexical"
            if required_facets
            else "lexical fallback"
            if lexical_match
            else "semantic fallback"
        )
        reason = f"Change-aware assurance {facet.label} {mode} match"
    return PacketCandidate(
        item_id=uuid.uuid4(),
        kind=ContextPacketItem.Kind.SOURCE_EXCERPT,
        item_key=f"chunk:{result.chunk_id}",
        summary=summary,
        freshness=ContextPacketItem.Freshness.CURRENT,
        is_inferred=False,
        selection_reason=reason,
        rank_score=max(
            0.0,
            result.explanation.reciprocal_rank_score
            + ((MAX_RETRIEVAL_FACETS - facet_position) if lexical_match else 0),
        ),
        tier=tier,
        required_policy=False,
        payload={
            "chunk_id": str(result.chunk_id),
            "content_hash": result.content_hash,
            "ranking": result.explanation.as_dict(),
            "search_position": position,
            "retrieval_facet": facet.label,
            "retrieval_facet_position": facet_position,
            "retrieval_match": "LEXICAL" if lexical_match else "SEMANTIC_FALLBACK",
        },
        contributing_scope_ids=(result.access_scope_id,),
        citations=(citation,),
        matched_facets=matched_facets,
        required_context_facets=required_facets,
        source_chunk_id=result.chunk_id,
    )


def _required_search_anchor_candidates(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    anchors: tuple[RequiredSearchAnchor, ...],
    visible_scope_ids: tuple[uuid.UUID, ...] | list[uuid.UUID],
) -> list[PacketCandidate]:
    """Resolve exact search identities in one permission-first, current-lineage query."""
    if not anchors:
        return []
    anchor_scope_ids = {anchor.access_scope_id for anchor in anchors} & set(visible_scope_ids)
    exact_identity = Q()
    for anchor in anchors:
        exact_identity |= Q(
            source_chunk_id=anchor.chunk_id,
            source_chunk__content_hash=anchor.content_hash,
            access_scope_id=anchor.access_scope_id,
            source_location_id=anchor.source_location_id,
            source_observation_id=anchor.source_observation_id,
            access_snapshot_id=anchor.access_snapshot_id,
        )
    rows = (
        SourceChunkVisibility.objects.filter(
            exact_identity,
            organization_id=actor.organization_id,
            access_scope_id__in=anchor_scope_ids,
            state=SourceChunkVisibility.State.AVAILABLE,
            revoked_at__isnull=True,
            access_scope__is_active=True,
            access_snapshot__revoked_at__isnull=True,
            access_snapshot__access_scope_id=F("access_scope_id"),
            access_snapshot__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
            source_observation__access_snapshot_id=F("access_snapshot_id"),
            source_observation__status="PRESENT",
            source_observation__source_document__state="PRESENT",
            source_observation__source_revision_id=F(
                "source_observation__source_document__current_revision_id"
            ),
            source_observation__sync_run_id=F(
                "source_observation__source_document__last_seen_run_id"
            ),
            source_location__source_observation_id=F("source_observation_id"),
            source_location__parsed_source_id=F("source_chunk__parsed_source_id"),
            source_location__parsed_source__source_revision_id=F(
                "source_observation__source_revision_id"
            ),
            source_observation__source_document__source_container__source_connection__repository_id=(
                repository_id
            ),
            source_observation__source_document__source_container__source_connection__state__in=(
                "ACTIVE",
                "DEGRADED",
            ),
            access_scope__accessscopesource__source_connection_id=F(
                "source_observation__source_document__source_container__source_connection_id"
            ),
        )
        .select_related(
            "source_chunk",
            "source_location",
            "source_observation__source_document",
        )
        .order_by("source_chunk_id", "access_scope_id", "id")
        .distinct()
    )
    resolved_by_key: dict[tuple[object, ...], SourceChunkVisibility] = {}
    ambiguous_keys: set[tuple[object, ...]] = set()
    for row in rows:
        key = (
            row.source_chunk_id,
            row.source_chunk.content_hash,
            row.access_scope_id,
            row.source_location_id,
            row.source_observation_id,
            row.access_snapshot_id,
        )
        if key in resolved_by_key:
            ambiguous_keys.add(key)
        resolved_by_key[key] = row
    requested_keys = {
        (
            anchor.chunk_id,
            anchor.content_hash,
            anchor.access_scope_id,
            anchor.source_location_id,
            anchor.source_observation_id,
            anchor.access_snapshot_id,
        )
        for anchor in anchors
    }
    by_key = {key: row for key, row in resolved_by_key.items() if key in requested_keys}
    if set(by_key) != requested_keys or ambiguous_keys & requested_keys:
        raise RequiredSearchAnchorUnavailableError(
            "One or more required search anchors are unavailable"
        )
    candidates: list[PacketCandidate] = []
    for anchor in anchors:
        row = by_key[
            (
                anchor.chunk_id,
                anchor.content_hash,
                anchor.access_scope_id,
                anchor.source_location_id,
                anchor.source_observation_id,
                anchor.access_snapshot_id,
            )
        ]
        document = row.source_observation.source_document
        citation = CitationCandidate(
            access_scope_id=row.access_scope_id,
            source_location_id=row.source_location_id,
            source_observation_id=row.source_observation_id,
            access_snapshot_id=row.access_snapshot_id,
            canonical_url=document.canonical_url,
            locator=row.source_location.pointer,
            source_content_hash=row.source_chunk.content_hash,
            observed_at=row.observed_at,
        )
        candidates.append(
            PacketCandidate(
                item_id=uuid.uuid4(),
                kind=ContextPacketItem.Kind.SOURCE_EXCERPT,
                item_key=f"chunk:{row.source_chunk_id}",
                summary=row.source_chunk.text[:10_000],
                freshness=ContextPacketItem.Freshness.CURRENT,
                is_inferred=False,
                selection_reason="Caller-required authorized search anchor",
                rank_score=0.0,
                tier=1,
                required_policy=False,
                payload={
                    "chunk_id": str(row.source_chunk_id),
                    "content_hash": row.source_chunk.content_hash,
                },
                contributing_scope_ids=(row.access_scope_id,),
                citations=(citation,),
                required_search_anchor=True,
                source_chunk_id=row.source_chunk_id,
            )
        )
    return candidates


def _conflict_candidates(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    selected_assertion_ids: set[uuid.UUID],
    relevant_assertion_facets: dict[uuid.UUID, tuple[str, ...]],
    change_aware: bool,
) -> list[PacketCandidate]:
    if not selected_assertion_ids:
        return []
    conflict_queryset = AssertionConflict.objects.filter(
        organization_id=actor.organization_id,
        status=AssertionConflict.Status.OPEN,
        left_assertion_id__in=selected_assertion_ids,
        right_assertion_id__in=selected_assertion_ids,
    )
    if change_aware:
        relevant_assertion_ids = set(relevant_assertion_facets)
        conflict_queryset = conflict_queryset.filter(
            Q(left_assertion_id__in=relevant_assertion_ids)
            | Q(right_assertion_id__in=relevant_assertion_ids)
        )
    ordered_conflicts = conflict_queryset.select_related(
        "left_assertion", "right_assertion"
    ).order_by("id")
    bounded_conflicts: list[AssertionConflict] = []
    scan_complete = True
    last_id: uuid.UUID | None = None
    started = monotonic()
    candidate_capacity = min(CONTEXT_SCAN_MAX_ROWS, CONTEXT_SCAN_MAX_OPERATIONS // 2)
    while True:
        page_query = ordered_conflicts
        if last_id is not None:
            page_query = page_query.filter(id__gt=last_id)
        remaining = candidate_capacity - len(selected_assertion_ids) - len(bounded_conflicts)
        if remaining <= 0:
            scan_complete = not page_query.exists()
            break
        page = list(page_query[: min(CONTEXT_SCAN_PAGE_SIZE, remaining)])
        if not page:
            break
        bounded_conflicts.extend(page)
        if monotonic() - started > CONTEXT_SCAN_MAX_SECONDS:
            scan_complete = False
            break
        last_id = page[-1].id
        if len(page) == remaining:
            scan_complete = not conflict_queryset.filter(id__gt=last_id).exists()
            break
    candidates = ScannedCandidates()
    candidates.complete = scan_complete
    candidates.processed_count = len(bounded_conflicts)
    provenance_by_assertion: dict[uuid.UUID, AssertionProvenance] = {}
    conflict_endpoint_ids = {
        assertion_id
        for conflict in bounded_conflicts
        for assertion_id in (conflict.left_assertion_id, conflict.right_assertion_id)
    }
    ordered_endpoint_ids = sorted(conflict_endpoint_ids, key=str)
    for offset in range(0, len(ordered_endpoint_ids), CONTEXT_SCAN_PAGE_SIZE * 2):
        endpoint_page = set(ordered_endpoint_ids[offset : offset + CONTEXT_SCAN_PAGE_SIZE * 2])
        provenance_rows = (
            _authorized_provenance(
                actor=actor,
                repository_id=repository_id,
                assertion_ids=endpoint_page,
            )
            .order_by("assertion_id", "observed_at", "id")
            .distinct("assertion_id")
        )
        for provenance in provenance_rows:
            provenance_by_assertion.setdefault(provenance.assertion_id, provenance)
    for conflict in bounded_conflicts:
        matched_facets = tuple(
            sorted(
                {
                    *relevant_assertion_facets.get(conflict.left_assertion_id, ()),
                    *relevant_assertion_facets.get(conflict.right_assertion_id, ()),
                }
            )
        )
        if change_aware and not matched_facets:
            continue
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
                selection_reason=(
                    f"Change-aware contradiction: {', '.join(matched_facets)}"
                    if change_aware
                    else "Authorized contradiction among selected assertions"
                ),
                rank_score=0.0,
                tier=2 if change_aware else 7,
                required_policy=False,
                payload={
                    "conflict_id": str(conflict.id),
                    "left_assertion_id": str(conflict.left_assertion_id),
                    "right_assertion_id": str(conflict.right_assertion_id),
                    "predicate": conflict.predicate,
                    "left": {
                        "value": conflict.left_assertion.value,
                        "review_state": conflict.left_assertion.review_state,
                        "staleness_state": conflict.left_assertion.staleness_state,
                    },
                    "right": {
                        "value": conflict.right_assertion.value,
                        "review_state": conflict.right_assertion.review_state,
                        "staleness_state": conflict.right_assertion.staleness_state,
                    },
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
                matched_facets=matched_facets,
                required_context_facets=(*matched_facets, "conflict"),
                source_conflict_id=conflict.id,
            )
        )
    return candidates


def _select(
    candidates: list[PacketCandidate],
    budget: PacketBudget,
    *,
    required_context_overflow: tuple[str, ...] = (),
) -> PacketSelection:
    ordered = sorted(_merge_candidates(candidates), key=_candidate_order)
    selected: list[PacketCandidate] = []
    selected_keys: set[str] = set()
    tokens = 0
    byte_count = 0
    citations = 0

    def add_if_fits(candidate: PacketCandidate) -> bool:
        nonlocal tokens, byte_count, citations
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
            return False
        selected.append(candidate)
        selected_keys.add(candidate.item_key)
        tokens = next_tokens
        byte_count = next_bytes
        citations = next_citations
        return True

    # Required policy and discovered-facet representatives are selected before optional
    # material.  This prevents an otherwise valid packet from spending its final bound on
    # lower-priority content.  The final packet is sorted canonically below, so reservation
    # order cannot leak caller or retrieval ordering.
    for candidate in ordered:
        if candidate.required_policy and candidate.freshness == ContextPacketItem.Freshness.CURRENT:
            if not add_if_fits(candidate):
                raise RequiredPolicyBudgetError(
                    "Packet budget cannot contain every applicable required current policy"
                )

    for candidate in ordered:
        if candidate.required_search_anchor and candidate.item_key not in selected_keys:
            if not add_if_fits(candidate):
                raise RequiredContextBudgetError(
                    "Packet budget cannot contain every required search anchor"
                )

    discovered_required = {
        label for candidate in ordered for label in candidate.required_context_facets
    } | set(required_context_overflow)
    covered_required = {
        label for candidate in selected for label in candidate.required_context_facets
    }
    required_labels = tuple(sorted(discovered_required))
    label_bits = {label: 1 << position for position, label in enumerate(required_labels)}
    full_mask = (1 << len(required_labels)) - 1
    initial_mask = sum(label_bits[label] for label in covered_required)
    # Each mask retains only resource-Pareto-optimal deterministic selections.  With at
    # most eight required facets this finds a feasible packing without greedy dead ends,
    # while bounding the state space independently of retrieval order.
    states: dict[
        int,
        list[tuple[tuple[PacketCandidate, ...], int, int, int]],
    ] = {initial_mask: [((), tokens, byte_count, citations)]}
    representatives = [
        candidate
        for candidate in ordered
        if candidate.item_key not in selected_keys and candidate.required_context_facets
    ]
    if len(representatives) > MAX_REQUIRED_PACKING_CANDIDATES:
        raise RequiredContextBudgetError(
            "Required context packing exceeded its deterministic candidate bound"
        )
    state_count = 1
    operations = 0
    representative_costs = {
        candidate.item_key: (
            candidate.token_count,
            candidate.byte_count,
            len(candidate.citations),
        )
        for candidate in representatives
    }
    for candidate in representatives:
        candidate_mask = sum(
            label_bits[label] for label in candidate.required_context_facets if label in label_bits
        )
        state_snapshot = [(mask, tuple(mask_states)) for mask, mask_states in states.items()]
        for mask, mask_states in state_snapshot:
            next_mask = mask | candidate_mask
            if next_mask == mask:
                continue
            for chosen, state_tokens, state_bytes, state_citations in mask_states:
                operations += 1
                if operations > MAX_REQUIRED_PACKING_OPERATIONS:
                    raise RequiredContextBudgetError(
                        "Required context packing exceeded its deterministic operation bound"
                    )
                candidate_tokens, candidate_bytes, candidate_citations = representative_costs[
                    candidate.item_key
                ]
                proposal = (
                    (*chosen, candidate),
                    state_tokens + candidate_tokens,
                    state_bytes + candidate_bytes,
                    state_citations + candidate_citations,
                )
                proposal_dimensions = (
                    len(selected) + len(proposal[0]),
                    proposal[1],
                    proposal[2],
                    proposal[3],
                )
                if not all(
                    value <= limit
                    for value, limit in zip(
                        proposal_dimensions,
                        (
                            budget.max_items,
                            budget.max_tokens,
                            budget.max_bytes,
                            budget.max_citations,
                        ),
                        strict=True,
                    )
                ):
                    continue
                frontier = states.setdefault(next_mask, [])
                operations += len(frontier)
                if operations > MAX_REQUIRED_PACKING_OPERATIONS:
                    raise RequiredContextBudgetError(
                        "Required context packing exceeded its deterministic operation bound"
                    )
                if any(
                    len(existing[0]) <= len(proposal[0])
                    and existing[1] <= proposal[1]
                    and existing[2] <= proposal[2]
                    and existing[3] <= proposal[3]
                    for existing in frontier
                ):
                    continue
                previous_count = len(frontier)
                frontier[:] = [
                    existing
                    for existing in frontier
                    if not (
                        len(proposal[0]) <= len(existing[0])
                        and proposal[1] <= existing[1]
                        and proposal[2] <= existing[2]
                        and proposal[3] <= existing[3]
                    )
                ]
                frontier.append(proposal)
                state_count += len(frontier) - previous_count
                if state_count > MAX_REQUIRED_PACKING_STATES:
                    raise RequiredContextBudgetError(
                        "Required context packing exceeded its deterministic state bound"
                    )
    feasible = states.get(full_mask, [])
    if not feasible:
        best_mask = min(
            states,
            key=lambda mask: (-mask.bit_count(), mask),
        )
        missing = {label for label, bit in label_bits.items() if best_mask & bit == 0}
        if missing:
            raise RequiredContextBudgetError(
                "Packet budget cannot represent discovered required context facets: "
                f"{', '.join(sorted(missing))}"
            )
    else:
        chosen, _tokens, _bytes, _citations = min(
            feasible,
            key=lambda state: (
                len(state[0]),
                state[1],
                state[2],
                state[3],
                tuple(_candidate_order(candidate) for candidate in state[0]),
            ),
        )
        for candidate in chosen:
            if not add_if_fits(candidate):  # pragma: no cover - proven by the DP bounds above
                raise RuntimeError("Required context packing diverged from its bounded selection")

    for candidate in ordered:
        if candidate.item_key not in selected_keys:
            add_if_fits(candidate)

    selected.sort(key=_candidate_order)
    omitted = len(ordered) - len(selected)
    limitations = (f"{omitted} lower-priority candidates omitted by budget",) if omitted else ()
    return PacketSelection(tuple(selected), tokens, byte_count, citations, limitations)


def seal_actor_scope(
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
    # This row is the scan's internal snapshot fence. All supported provenance,
    # authorization, and ingestion mutations advance it under the same row lock.
    watermark, _created = RetrievalWatermark.objects.select_for_update().get_or_create(
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
    retrieval_facets: tuple[RetrievalFacet, ...] | None = None,
    required_search_anchors: tuple[RequiredSearchAnchor, ...] | None = None,
) -> tuple[ContextPacketRecord, bool]:
    """Build or reuse an exact immutable packet for one actor/repository snapshot."""
    normalized_task = " ".join(task.split())
    if not normalized_task or len(normalized_task) > 2_000:
        raise ValueError("task must contain between 1 and 2000 characters")
    normalized_phase = phase.upper()
    if normalized_phase not in ContextPacketRecord.Phase.values:
        raise ValueError("phase is invalid")
    budget = budget or PacketBudget()
    facets = _normalized_facets(task=normalized_task, retrieval_facets=retrieval_facets)
    search_anchors = normalize_required_search_anchors(required_search_anchors)
    change_aware = retrieval_facets is not None
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
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SET LOCAL statement_timeout = %s", (4_000,))
            cursor.execute("SET LOCAL lock_timeout = %s", (1_000,))
            cursor.execute("SET LOCAL idle_in_transaction_session_timeout = %s", (5_000,))
    normalized_request: dict[str, object] = {
        "task": normalized_task,
        "phase": normalized_phase,
        "budget": budget.as_dict(),
        "context_scan_version": CONTEXT_SCAN_VERSION,
    }
    if change_aware:
        normalized_request["retrieval_facets"] = [
            {
                "label": facet.label,
                "query": facet.query,
                "anchors": list(facet.anchors),
                "required_if_matched": facet.required_if_matched,
                "coverage_incomplete": facet.coverage_incomplete,
            }
            for facet in facets
        ]
    if search_anchors:
        normalized_request["required_search_anchors"] = [
            anchor.as_dict() for anchor in search_anchors
        ]
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

    anchored_chunks = _required_search_anchor_candidates(
        actor=actor,
        repository_id=repository_id,
        anchors=search_anchors,
        visible_scope_ids=visible_scopes,
    )

    assertions = _assertion_candidates(
        actor=actor,
        repository_id=repository_id,
        facets=facets,
        change_aware=change_aware,
    )
    relationships = _relationship_candidates(
        actor=actor,
        repository_id=repository_id,
        facets=facets,
        change_aware=change_aware,
    )
    chunks: list[PacketCandidate] = []
    per_facet_limit = min(100, max(25, budget.max_items))
    for facet_position, facet in enumerate(facets):
        search_response = search_chunks(
            actor=actor,
            repository_id=repository_id,
            query=facet.query,
            phase=normalized_phase,
            limit=per_facet_limit,
        )
        chunks.extend(
            _chunk_candidate(
                result,
                position,
                facet=facet,
                facet_position=facet_position,
                change_aware=change_aware,
            )
            for position, result in enumerate(search_response.results, start=1)
        )
    relevant_assertions = {
        candidate.source_assertion_id
        for candidate in assertions
        if candidate.source_assertion_id is not None
    }
    conflicts = _conflict_candidates(
        actor=actor,
        repository_id=repository_id,
        selected_assertion_ids=set(
            getattr(assertions, "eligible_assertion_ids", relevant_assertions)
        ),
        relevant_assertion_facets={
            candidate.source_assertion_id: candidate.matched_facets
            for candidate in assertions
            if candidate.source_assertion_id is not None and candidate.matched_facets
        },
        change_aware=change_aware,
    )
    completeness_payload = [
        {
            "kind": "assertion",
            "id": str(candidate.source_assertion_id),
            "payload": candidate.payload,
            "citations": [citation.as_dict() for citation in candidate.citations],
        }
        for candidate in assertions
    ] + [
        {
            "kind": "conflict",
            "id": str(candidate.source_conflict_id),
            "payload": candidate.payload,
            "citations": [citation.as_dict() for citation in candidate.citations],
        }
        for candidate in conflicts
    ]
    completeness = ContextCompleteness(
        assertion_count=len(assertions),
        conflict_count=len(conflicts),
        processed_count=(
            int(getattr(assertions, "processed_count", len(assertions)))
            + int(getattr(conflicts, "processed_count", len(conflicts)))
        ),
        digest=_json_hash(completeness_payload),
        complete=bool(
            getattr(assertions, "complete", True) and getattr(conflicts, "complete", True)
        ),
    )
    if change_aware and conflicts:
        conflict_assertion_ids = {
            assertion_id
            for conflict in conflicts
            for assertion_id in (
                uuid.UUID(cast(str, conflict.payload["left_assertion_id"])),
                uuid.UUID(cast(str, conflict.payload["right_assertion_id"])),
            )
        }
        conflict_facets = {
            assertion_id: tuple(
                sorted(
                    {
                        label
                        for conflict in conflicts
                        if assertion_id
                        in {
                            uuid.UUID(cast(str, conflict.payload["left_assertion_id"])),
                            uuid.UUID(cast(str, conflict.payload["right_assertion_id"])),
                        }
                        for label in conflict.matched_facets
                    }
                )
            )
            for assertion_id in conflict_assertion_ids
        }
        assertions = [
            replace(
                candidate,
                tier=min(candidate.tier, 2),
                selection_reason=(
                    f"Change-aware conflict endpoint: "
                    f"{', '.join(conflict_facets[candidate.source_assertion_id])}"
                ),
                matched_facets=tuple(
                    sorted(
                        {
                            *candidate.matched_facets,
                            *conflict_facets[candidate.source_assertion_id],
                        }
                    )
                ),
                required_context_facets=tuple(
                    sorted(
                        {
                            *candidate.required_context_facets,
                            *conflict_facets[candidate.source_assertion_id],
                        }
                    )
                ),
            )
            if candidate.source_assertion_id in conflict_assertion_ids
            else candidate
            for candidate in assertions
        ]
    selection = _select(
        [*assertions, *relationships, *chunks, *anchored_chunks, *conflicts],
        budget,
        required_context_overflow=tuple(
            facet.label for facet in facets if facet.coverage_incomplete
        ),
    )
    selected_conflicts = sum(
        candidate.source_conflict_id is not None for candidate in selection.candidates
    )
    if conflicts and selected_conflicts < len(conflicts):
        selection = replace(
            selection,
            limitations=(
                *selection.limitations,
                f"{len(conflicts) - selected_conflicts} conflict details omitted by report budget; "
                f"complete scan digest {completeness.digest}",
            ),
        )
    if not completeness.complete:
        selection = replace(
            selection,
            limitations=(
                *selection.limitations,
                "Required assurance context was discovered but could not fit the authorized "
                "bounded packet: ASSURANCE_CONTEXT_INCOMPLETE",
            ),
        )

    # Publication is a separate security boundary: a revocation, scope change, or
    # ingestion watermark movement during scanning invalidates this result.
    current_scopes, current_authorization_hash = _authorization_snapshot(
        actor=actor,
        repository_id=repository_id,
    )
    current_watermark = _watermark(actor=actor, repository_id=repository_id)
    if (
        current_scopes != visible_scopes
        or current_authorization_hash != authorization_hash
        or current_watermark.value != watermark.value
    ):
        raise RequiredContextBudgetError("ASSURANCE_CONTEXT_INCOMPLETE")
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
        "completeness": {
            **completeness.as_dict(),
            "bindings": {
                "organization_id": str(actor.organization_id),
                "repository_id": str(repository_id),
                "authorization_hash": authorization_hash,
                "retrieval_watermark": watermark.value,
                "query_version": CONTEXT_SCAN_VERSION,
            },
        },
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
        candidate.item_id: seal_actor_scope(
            actor=actor,
            repository_id=repository_id,
            source_scope_ids=set(candidate.contributing_scope_ids),
            scope_key=candidate.item_id,
        )
        for candidate in selection.candidates
    }
    selected_scope_ids = {scope.id for scope in item_scopes.values()} or {visible_scopes[0]}
    sealed_scope = seal_actor_scope(
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
            payload=candidate.effective_payload,
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
    actor: ActorContext,
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    reason: str,
    details: dict[str, object] | None = None,
) -> int:
    """Advance a repository watermark and append invalidations without deletion."""
    if actor.organization_id != organization_id:
        raise ValueError("Context invalidation actor must belong to the organization")
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
    from anva.core.services.assurance import _stale_invalidated_context

    affected_runs = list(
        AssuranceRun.objects.select_for_update()
        .filter(
            organization_id=organization_id,
            repository=repository,
            context_packet_id__in=[packet.id for packet in packets],
        )
        .exclude(
            state__in=[
                AssuranceRun.State.STALE,
                AssuranceRun.State.CANCELLED,
                AssuranceRun.State.FAILED,
            ]
        )
        .order_by("created_at", "id")
    )
    for run in affected_runs:
        _stale_invalidated_context(actor=actor, run=run)
    return len(invalidations)
