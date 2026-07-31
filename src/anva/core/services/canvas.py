"""Permission-safe Organizational Canvas projections and presentation-only revisions."""

from __future__ import annotations

import json
import math
import re
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, cast

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from anva.core.exceptions import (
    IdempotencyConflictError,
    OptimisticConcurrencyError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AssertionConflict,
    CanvasAnnotation,
    CanvasFilter,
    CanvasGroup,
    CanvasLayer,
    CanvasNodePlacement,
    CanvasShare,
    CanvasView,
    CanvasViewRevision,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeProposalScope,
    KnowledgeRelationship,
    Membership,
    Organization,
    Repository,
    content_hash,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    authorized_access_scope_ids,
    get_tenant_record,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import authorized_assertion_citations
from anva.core.services.creation import submit_knowledge_proposal
from anva.core.services.events import record_transition
from anva.core.services.graph import GraphEdge, authorized_graph_edges
from anva.core.services.retrieval import authorized_assertions, authorized_entities

CANVAS_NODE_LIMIT = 300
CANVAS_EDGE_LIMIT = 600
CANVAS_REPOSITORY_LIMIT = 100
CANVAS_PATH_DEPTH = 6
CANVAS_PAYLOAD_LIMIT_BYTES = 750 * 1024
CANVAS_LAYOUT_VERSION = "anva-layered-v1"
CANVAS_LAYOUT_ALGORITHM = "deterministic-semantic-columns"
CANVAS_FRESHNESS_STATES = (*KnowledgeAssertion.StalenessState.values, "UNKNOWN")
SECRET_PATTERN = re.compile(
    r"(?i)(?:gh[pousr]_[a-z0-9]{20,}|bearer\s+[a-z0-9._-]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|sessionid\s*=)"
)

VIEW_TYPE_ENTITY_TYPES: dict[str, frozenset[str]] = {
    CanvasView.ViewType.STRATEGY: frozenset(
        {
            "GOAL",
            "METRIC",
            "INITIATIVE",
            "PRODUCT",
            "WORK_ITEM",
            "TASK",
            "PULL_REQUEST",
            "REPOSITORY",
        }
    ),
    CanvasView.ViewType.PRODUCT_SYSTEM: frozenset(
        {
            "PRODUCT",
            "COMPONENT",
            "SERVICE",
            "API",
            "DATA_ASSET",
            "REPOSITORY",
            "TEAM",
        }
    ),
    CanvasView.ViewType.INITIATIVE: frozenset(
        {
            "INITIATIVE",
            "REQUIREMENT",
            "TEAM",
            "PRODUCT",
            "COMPONENT",
            "SERVICE",
            "TASK",
            "WORK_ITEM",
            "PULL_REQUEST",
            "EVIDENCE",
        }
    ),
    CanvasView.ViewType.RISK_POLICY: frozenset(
        {
            "RISK",
            "POLICY",
            "PRODUCT",
            "COMPONENT",
            "SERVICE",
            "TEAM",
            "PULL_REQUEST",
            "CONTROL",
            "INCIDENT",
        }
    ),
    CanvasView.ViewType.CHANGE_HISTORY: frozenset(
        {
            "DECISION",
            "TEAM",
            "COMPONENT",
            "SERVICE",
            "INCIDENT",
            "POLICY",
            "PULL_REQUEST",
        }
    ),
}

TYPE_COLUMNS = {
    value: position
    for position, value in enumerate(
        (
            "GOAL",
            "METRIC",
            "INITIATIVE",
            "PRODUCT",
            "CUSTOMER_COMMITMENT",
            "REQUIREMENT",
            "ACCEPTANCE_CRITERION",
            "COMPONENT",
            "SERVICE",
            "API",
            "DATA_ASSET",
            "ENVIRONMENT",
            "REPOSITORY",
            "TEAM",
            "OWNER",
            "WORK_ITEM",
            "TASK",
            "PULL_REQUEST",
            "RELEASE",
            "EVIDENCE",
            "DECISION",
            "ARCHITECTURAL_DECISION",
            "POLICY",
            "CONTROL",
            "RISK",
            "INCIDENT",
            "UNKNOWN",
        )
    )
}

DEFAULT_LAYERS = (
    ("execution", "Execution", True),
    ("ownership", "Ownership", True),
    ("dependencies", "Dependencies", True),
    ("governance", "Governance", True),
    ("provenance", "Provenance & freshness", True),
)

LAYER_RELATIONSHIPS: dict[str, frozenset[str]] = {
    "execution": frozenset(
        {
            "ADVANCES",
            "IMPLEMENTS",
            "PART_OF",
            "EVIDENCED_BY",
            "CHANGES",
            "BLOCKED_BY",
            "INITIATIVE_SUPPORTS_GOAL",
            "INITIATIVE_AFFECTS_PRODUCT",
            "PRODUCT_IMPLEMENTED_BY_REPOSITORY",
            "COMPONENT_BELONGS_TO_PRODUCT",
            "REPOSITORY_CONTAINS_COMPONENT",
            "SERVICE_IMPLEMENTED_BY_REPOSITORY",
            "REQUIREMENT_SUPPORTS_INITIATIVE",
            "REQUIREMENT_IMPLEMENTED_BY_PULL_REQUEST",
            "ACCEPTANCE_CRITERION_VERIFIED_BY_EVIDENCE",
            "TASK_CHANGES_ENTITY",
            "PULL_REQUEST_CHANGES_ENTITY",
        }
    ),
    "ownership": frozenset(
        {
            "OWNED_BY",
            "MAINTAINED_BY",
            "INITIATIVE_OWNED_BY_TEAM",
            "REPOSITORY_OWNED_BY_TEAM",
            "ENTITY_OWNED_BY_OWNER",
            "ENTITY_REVIEWED_BY_TEAM",
        }
    ),
    "dependencies": frozenset(
        {
            "DEPENDS_ON",
            "SERVICE_DEPENDS_ON_SERVICE",
            "API_PROVIDED_BY_SERVICE",
            "API_CONSUMED_BY_COMPONENT",
            "DATA_ASSET_USED_BY_SERVICE",
        }
    ),
    "governance": frozenset(
        {
            "AFFECTS",
            "GOVERNED_BY",
            "MEASURED_BY",
            "GOAL_MEASURED_BY_METRIC",
            "DECISION_APPLIES_TO_ENTITY",
            "POLICY_APPLIES_TO_ENTITY",
            "RISK_AFFECTS_ENTITY",
            "INCIDENT_AFFECTED_ENTITY",
        }
    ),
    "provenance": frozenset(),
}

RELATIONSHIP_ENDPOINTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "GOAL_MEASURED_BY_METRIC": (frozenset({"GOAL"}), frozenset({"METRIC"})),
    "INITIATIVE_SUPPORTS_GOAL": (frozenset({"INITIATIVE"}), frozenset({"GOAL"})),
    "INITIATIVE_OWNED_BY_TEAM": (frozenset({"INITIATIVE"}), frozenset({"TEAM"})),
    "INITIATIVE_AFFECTS_PRODUCT": (frozenset({"INITIATIVE"}), frozenset({"PRODUCT"})),
    "PRODUCT_IMPLEMENTED_BY_REPOSITORY": (
        frozenset({"PRODUCT"}),
        frozenset({"REPOSITORY"}),
    ),
    "COMPONENT_BELONGS_TO_PRODUCT": (frozenset({"COMPONENT"}), frozenset({"PRODUCT"})),
    "REPOSITORY_OWNED_BY_TEAM": (frozenset({"REPOSITORY"}), frozenset({"TEAM"})),
    "REPOSITORY_CONTAINS_COMPONENT": (
        frozenset({"REPOSITORY"}),
        frozenset({"COMPONENT"}),
    ),
    "SERVICE_IMPLEMENTED_BY_REPOSITORY": (
        frozenset({"SERVICE"}),
        frozenset({"REPOSITORY"}),
    ),
    "SERVICE_DEPENDS_ON_SERVICE": (frozenset({"SERVICE"}), frozenset({"SERVICE"})),
    "API_PROVIDED_BY_SERVICE": (frozenset({"API"}), frozenset({"SERVICE"})),
    "API_CONSUMED_BY_COMPONENT": (frozenset({"API"}), frozenset({"COMPONENT"})),
    "DATA_ASSET_USED_BY_SERVICE": (frozenset({"DATA_ASSET"}), frozenset({"SERVICE"})),
    "DECISION_APPLIES_TO_ENTITY": (
        frozenset({"DECISION", "ARCHITECTURAL_DECISION"}),
        frozenset(KnowledgeEntity.EntityType.values),
    ),
    "POLICY_APPLIES_TO_ENTITY": (
        frozenset({"POLICY"}),
        frozenset(KnowledgeEntity.EntityType.values),
    ),
    "RISK_AFFECTS_ENTITY": (
        frozenset({"RISK"}),
        frozenset(KnowledgeEntity.EntityType.values),
    ),
    "INCIDENT_AFFECTED_ENTITY": (
        frozenset({"INCIDENT"}),
        frozenset(KnowledgeEntity.EntityType.values),
    ),
    "REQUIREMENT_SUPPORTS_INITIATIVE": (
        frozenset({"REQUIREMENT"}),
        frozenset({"INITIATIVE"}),
    ),
    "REQUIREMENT_IMPLEMENTED_BY_PULL_REQUEST": (
        frozenset({"REQUIREMENT"}),
        frozenset({"PULL_REQUEST"}),
    ),
    "ACCEPTANCE_CRITERION_VERIFIED_BY_EVIDENCE": (
        frozenset({"ACCEPTANCE_CRITERION"}),
        frozenset({"EVIDENCE"}),
    ),
    "TASK_CHANGES_ENTITY": (
        frozenset({"TASK"}),
        frozenset(KnowledgeEntity.EntityType.values),
    ),
    "PULL_REQUEST_CHANGES_ENTITY": (
        frozenset({"PULL_REQUEST"}),
        frozenset(KnowledgeEntity.EntityType.values),
    ),
    "ENTITY_OWNED_BY_OWNER": (
        frozenset(KnowledgeEntity.EntityType.values),
        frozenset({"OWNER"}),
    ),
    "ENTITY_REVIEWED_BY_TEAM": (
        frozenset(KnowledgeEntity.EntityType.values),
        frozenset({"TEAM"}),
    ),
}


@dataclass(frozen=True, slots=True)
class CanvasQuery:
    """Bounded, validated Canvas query controls."""

    view_id: uuid.UUID | None = None
    view_revision: int | None = None
    repository_ids: tuple[uuid.UUID, ...] = ()
    entity_types: tuple[str, ...] = ()
    owner: str = ""
    status: str = ""
    risk: str = ""
    freshness: str = ""
    search: str = ""
    layers: tuple[str, ...] = ()
    anchor_id: uuid.UUID | None = None
    depth: int = 2
    node_limit: int = CANVAS_NODE_LIMIT
    edge_limit: int = CANVAS_EDGE_LIMIT

    def __post_init__(self) -> None:
        if len(self.repository_ids) > CANVAS_REPOSITORY_LIMIT:
            raise ValueError("At most 100 repositories may be selected")
        if any(value not in KnowledgeEntity.EntityType.values for value in self.entity_types):
            raise ValueError("Unknown Canvas entity type")
        if any(value not in LAYER_RELATIONSHIPS for value in self.layers):
            raise ValueError("Unknown Canvas layer")
        if self.freshness and self.freshness not in CANVAS_FRESHNESS_STATES:
            raise ValueError("Unknown freshness state")
        if not 1 <= self.depth <= 4:
            raise ValueError("Canvas depth must be between 1 and 4")
        if not 1 <= self.node_limit <= CANVAS_NODE_LIMIT:
            raise ValueError("Canvas node limit must be between 1 and 300")
        if not 1 <= self.edge_limit <= CANVAS_EDGE_LIMIT:
            raise ValueError("Canvas edge limit must be between 1 and 600")
        for value in (self.owner, self.status, self.risk, self.search):
            _safe_text(value, maximum=500)
        if self.view_revision is not None and self.view_revision < 1:
            raise ValueError("Canvas view revision must be positive")


@dataclass(frozen=True, slots=True)
class AuthorizedCanvasEdge:
    repository_id: uuid.UUID
    edge: GraphEdge


def _visible_repositories(
    *,
    actor: ActorContext,
    requested_ids: tuple[uuid.UUID, ...] = (),
) -> tuple[Repository, ...]:
    """Resolve a deterministic union of only repositories visible for Canvas."""
    requested = set(requested_ids)
    candidates = list(
        Repository.objects.filter(
            organization_id=actor.organization_id,
            is_active=True,
        )
        .filter(Q(id__in=requested) if requested else Q())
        .order_by("id")[: CANVAS_REPOSITORY_LIMIT + 1]
    )
    if len(candidates) > CANVAS_REPOSITORY_LIMIT:
        raise ValueError("Canvas repository budget exceeded")
    visible: list[Repository] = []
    for repository in candidates:
        try:
            authorize_action(
                actor=actor,
                repository_id=repository.id,
                action=Action.CANVAS_VIEW,
            )
        except ResourceNotFoundError:
            if requested:
                raise ResourceNotFoundError(NOT_FOUND_MESSAGE) from None
            continue
        visible.append(repository)
    if requested and {repository.id for repository in visible} != requested:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    return tuple(visible)


def _scope_visible_in_repositories(
    *,
    actor: ActorContext,
    scope_id: uuid.UUID,
    repositories: tuple[Repository, ...],
    action: Action,
) -> bool:
    return any(
        scope_id
        in authorized_access_scope_ids(
            actor=actor,
            action=action,
            repository_id=repository.id,
        )
        for repository in repositories
    )


def get_authorized_canvas_view(
    *,
    actor: ActorContext,
    view_id: uuid.UUID,
    action: Action = Action.CANVAS_VIEW,
    for_update: bool = False,
) -> CanvasView:
    """Resolve a view and every saved repository/scope boundary without an oracle."""
    queryset = CanvasView.objects.filter(is_archived=False)
    view = (
        get_tenant_record_for_update(
            queryset=queryset,
            record_id=view_id,
            organization_id=actor.organization_id,
        )
        if for_update
        else get_tenant_record(
            queryset=queryset,
            record_id=view_id,
            organization_id=actor.organization_id,
        )
    )
    repositories = _visible_repositories(
        actor=actor,
        requested_ids=(view.repository_id,) if view.repository_id else (),
    )
    if view.repository_id is not None:
        authorize_action(
            actor=actor,
            repository_id=view.repository_id,
            action=action,
        )
    elif not repositories:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if view.access_scope_id and not _scope_visible_in_repositories(
        actor=actor,
        scope_id=view.access_scope_id,
        repositories=repositories,
        action=action,
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    revision = CanvasViewRevision.objects.filter(
        organization_id=actor.organization_id,
        canvas_view=view,
        revision=view.revision,
    ).first()
    if revision is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    root_id = revision.semantic_query.get("root_entity_id")
    if root_id:
        _authorized_entity_union(
            actor=actor,
            entity_id=uuid.UUID(str(root_id)),
            repositories=repositories,
        )
    return view


def list_canvas_views(*, actor: ActorContext) -> tuple[CanvasView, ...]:
    """List only saved views whose current boundaries remain visible."""
    visible: list[CanvasView] = []
    for view in CanvasView.objects.filter(
        organization_id=actor.organization_id,
        is_archived=False,
    ).order_by("name", "id")[:CANVAS_NODE_LIMIT]:
        try:
            get_authorized_canvas_view(actor=actor, view_id=view.id)
        except ResourceNotFoundError:
            continue
        visible.append(view)
    return tuple(visible)


def _authorized_entity_union(
    *,
    actor: ActorContext,
    entity_id: uuid.UUID,
    repositories: tuple[Repository, ...],
) -> KnowledgeEntity:
    for repository in repositories:
        entity = (
            authorized_entities(
                actor=actor,
                repository_id=repository.id,
                action=Action.CANVAS_VIEW,
            )
            .filter(id=entity_id)
            .first()
        )
        if entity is not None:
            return entity
    raise ResourceNotFoundError(NOT_FOUND_MESSAGE)


def _semantic_query(
    *,
    query: CanvasQuery,
    view: CanvasView | None,
    revision: CanvasViewRevision | None,
) -> dict[str, object]:
    saved = dict(revision.semantic_query) if revision else {}
    if view and not query.entity_types and view.view_type in VIEW_TYPE_ENTITY_TYPES:
        saved.setdefault("entity_types", sorted(VIEW_TYPE_ENTITY_TYPES[view.view_type]))
    if query.entity_types:
        saved["entity_types"] = list(query.entity_types)
    for key, value in (
        ("owner", query.owner),
        ("status", query.status),
        ("risk", query.risk),
        ("freshness", query.freshness),
        ("search", query.search),
    ):
        if value:
            saved[key] = value
    if query.layers:
        saved["layers"] = list(query.layers)
    if query.anchor_id:
        saved["root_entity_id"] = str(query.anchor_id)
    saved["depth"] = query.depth
    return saved


def _candidate_entities(
    *,
    actor: ActorContext,
    repositories: tuple[Repository, ...],
    semantic: dict[str, object],
    access_scope_id: uuid.UUID | None,
) -> tuple[dict[uuid.UUID, KnowledgeEntity], dict[uuid.UUID, set[uuid.UUID]]]:
    entities: dict[uuid.UUID, KnowledgeEntity] = {}
    entity_repositories: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    entity_types = semantic.get("entity_types", [])
    for repository in repositories:
        queryset = authorized_entities(
            actor=actor,
            repository_id=repository.id,
            action=Action.CANVAS_VIEW,
        )
        if access_scope_id:
            queryset = queryset.filter(access_scope_id=access_scope_id)
        if isinstance(entity_types, list) and entity_types:
            safe_types = [
                value for value in entity_types if value in KnowledgeEntity.EntityType.values
            ]
            queryset = queryset.filter(entity_type__in=safe_types)
        search = semantic.get("search")
        if isinstance(search, str) and search:
            queryset = queryset.filter(
                Q(display_name__icontains=search[:500]) | Q(canonical_key__icontains=search[:500])
            )
        for field in ("owner", "status", "risk"):
            value = semantic.get(field)
            if isinstance(value, str) and value:
                queryset = queryset.filter(**{f"attributes__{field}__iexact": value[:500]})
        for entity in queryset.order_by("id")[: CANVAS_NODE_LIMIT + 1]:
            entities[entity.id] = entity
            entity_repositories[entity.id].add(repository.id)
    return entities, entity_repositories


def _authorized_assertion_union(
    *,
    actor: ActorContext,
    repositories: tuple[Repository, ...],
    subject_keys: set[str],
) -> dict[str, list[KnowledgeAssertion]]:
    assertions: dict[str, dict[uuid.UUID, KnowledgeAssertion]] = defaultdict(dict)
    for repository in repositories:
        queryset = authorized_assertions(
            actor=actor,
            repository_id=repository.id,
            action=Action.CANVAS_VIEW,
        ).filter(subject_key__in=subject_keys)
        for assertion in queryset.order_by("id"):
            assertions[assertion.subject_key][assertion.id] = assertion
    return {key: list(values.values()) for key, values in assertions.items()}


def _authorized_edge_union(
    *,
    actor: ActorContext,
    repositories: tuple[Repository, ...],
) -> tuple[list[AuthorizedCanvasEdge], bool]:
    edges: dict[uuid.UUID, AuthorizedCanvasEdge] = {}
    repository_truncated = False
    for repository in repositories:
        records, truncated = authorized_graph_edges(
            actor=actor,
            repository_id=repository.id,
            edge_limit=CANVAS_EDGE_LIMIT,
        )
        repository_truncated = repository_truncated or truncated
        for edge in records:
            edges.setdefault(
                edge.relationship_id,
                AuthorizedCanvasEdge(repository_id=repository.id, edge=edge),
            )
    ordered = sorted(
        edges.values(),
        key=lambda item: (str(item.edge.relationship_id), str(item.repository_id)),
    )
    return ordered, repository_truncated


def _freshness(assertions: list[KnowledgeAssertion]) -> str:
    states = {assertion.staleness_state for assertion in assertions}
    for state in (
        KnowledgeAssertion.StalenessState.CONTRADICTED,
        KnowledgeAssertion.StalenessState.SOURCE_UNAVAILABLE,
        KnowledgeAssertion.StalenessState.STALE,
        KnowledgeAssertion.StalenessState.AGING,
        KnowledgeAssertion.StalenessState.FRESH,
    ):
        if state in states:
            return state
    return "UNKNOWN"


def _layout(
    entities: list[KnowledgeEntity],
    placements: dict[uuid.UUID, CanvasNodePlacement],
) -> dict[uuid.UUID, tuple[float, float]]:
    rows: dict[int, int] = defaultdict(int)
    result: dict[uuid.UUID, tuple[float, float]] = {}
    for entity in sorted(
        entities,
        key=lambda item: (
            TYPE_COLUMNS.get(item.entity_type, len(TYPE_COLUMNS)),
            item.display_name.casefold(),
            str(item.id),
        ),
    ):
        placement = placements.get(entity.id)
        if placement is not None:
            result[entity.id] = (placement.x, placement.y)
            continue
        column = TYPE_COLUMNS.get(entity.entity_type, len(TYPE_COLUMNS))
        row = rows[column]
        rows[column] += 1
        result[entity.id] = (180.0 + column * 270.0, 120.0 + row * 108.0)
    return result


def _focused_ids(
    *,
    root_id: uuid.UUID,
    edges: list[AuthorizedCanvasEdge],
    depth: int,
) -> set[uuid.UUID]:
    adjacency: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for item in edges:
        adjacency[item.edge.source_entity_id].add(item.edge.target_entity_id)
        adjacency[item.edge.target_entity_id].add(item.edge.source_entity_id)
    visited = {root_id}
    frontier = {root_id}
    for _step in range(depth):
        next_frontier: set[uuid.UUID] = set()
        for entity_id in sorted(frontier, key=str):
            next_frontier.update(adjacency[entity_id] - visited)
        visited.update(next_frontier)
        frontier = next_frontier
        if not frontier:
            break
    return visited


def _bounded_integer(value: object, *, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside its bounded range")
    return value


def _canvas_layout_checksum(
    nodes: list[dict[str, object]],
    edges: list[dict[str, object]],
) -> str:
    return content_hash(
        {
            "version": CANVAS_LAYOUT_VERSION,
            "nodes": [{"id": node["id"], "position": node["position"]} for node in nodes],
            "edges": [
                {"id": edge["id"], "source": edge["source"], "target": edge["target"]}
                for edge in edges
            ],
        }
    )


def _canvas_payload_size(payload: dict[str, object]) -> int:
    return len(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    )


def _enforce_canvas_payload_budget(payload: dict[str, object]) -> dict[str, object]:
    """Keep the largest deterministic prefixes that fit the 750 KiB UTF-8 JSON budget."""
    if _canvas_payload_size(payload) <= CANVAS_PAYLOAD_LIMIT_BYTES:
        return payload
    nodes = cast(list[dict[str, object]], payload["nodes"])
    edges = cast(list[dict[str, object]], payload["edges"])
    limitations = cast(list[str], payload["limitations"])
    limitations.append(
        "Visible graph data was reduced to the 750 KiB payload budget; refine filters or focus."
    )
    payload["truncated"] = True

    def refresh() -> None:
        payload["counts"] = {"nodes": len(nodes), "edges": len(edges)}
        layout = cast(dict[str, object], payload["layout"])
        layout["checksum"] = _canvas_layout_checksum(nodes, edges)

    original_edges = list(edges)
    low, high = 0, len(original_edges)
    while low < high:
        midpoint = (low + high + 1) // 2
        edges[:] = original_edges[:midpoint]
        refresh()
        if _canvas_payload_size(payload) <= CANVAS_PAYLOAD_LIMIT_BYTES:
            low = midpoint
        else:
            high = midpoint - 1
    edges[:] = original_edges[:low]
    refresh()

    if _canvas_payload_size(payload) > CANVAS_PAYLOAD_LIMIT_BYTES:
        edges.clear()
        original_nodes = list(nodes)
        low, high = 0, len(original_nodes)
        while low < high:
            midpoint = (low + high + 1) // 2
            nodes[:] = original_nodes[:midpoint]
            refresh()
            if _canvas_payload_size(payload) <= CANVAS_PAYLOAD_LIMIT_BYTES:
                low = midpoint
            else:
                high = midpoint - 1
        nodes[:] = original_nodes[:low]
        refresh()
    if _canvas_payload_size(payload) > CANVAS_PAYLOAD_LIMIT_BYTES:
        raise ValueError("Canvas metadata exceeds the 750 KiB payload budget")
    return payload


def canvas_projection(*, actor: ActorContext, query: CanvasQuery) -> dict[str, object]:
    """Build one bounded org union after per-repository authorization and lineage proof."""
    view: CanvasView | None = None
    revision: CanvasViewRevision | None = None
    if query.view_id:
        view = get_authorized_canvas_view(actor=actor, view_id=query.view_id)
        revision = CanvasViewRevision.objects.filter(
            organization_id=actor.organization_id,
            canvas_view=view,
            revision=query.view_revision or view.revision,
        ).first()
        if revision is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        revision_root = revision.semantic_query.get("root_entity_id")
        if revision_root:
            revision_repositories = _visible_repositories(
                actor=actor,
                requested_ids=(view.repository_id,) if view.repository_id else (),
            )
            _authorized_entity_union(
                actor=actor,
                entity_id=uuid.UUID(str(revision_root)),
                repositories=revision_repositories,
            )
    requested_repositories = query.repository_ids
    if view and view.repository_id:
        requested_repositories = (view.repository_id,)
    elif revision:
        saved_repositories = revision.semantic_query.get("repository_ids", [])
        if isinstance(saved_repositories, list) and saved_repositories:
            requested_repositories = tuple(uuid.UUID(str(value)) for value in saved_repositories)
    repositories = _visible_repositories(
        actor=actor,
        requested_ids=requested_repositories,
    )
    semantic = _semantic_query(query=query, view=view, revision=revision)
    candidates, entity_repositories = _candidate_entities(
        actor=actor,
        repositories=repositories,
        semantic=semantic,
        access_scope_id=view.access_scope_id if view else None,
    )
    assertions = _authorized_assertion_union(
        actor=actor,
        repositories=repositories,
        subject_keys={entity.canonical_key for entity in candidates.values()},
    )
    freshness_filter = semantic.get("freshness")
    if isinstance(freshness_filter, str) and freshness_filter:
        candidates = {
            key: entity
            for key, entity in candidates.items()
            if _freshness(assertions.get(entity.canonical_key, [])) == freshness_filter
        }

    union_edges, repository_edge_truncated = _authorized_edge_union(
        actor=actor,
        repositories=repositories,
    )
    allowed_layers = semantic.get("layers", [])
    if isinstance(allowed_layers, list) and allowed_layers:
        allowed_relationships = set().union(
            *(
                LAYER_RELATIONSHIPS[layer]
                for layer in allowed_layers
                if layer in LAYER_RELATIONSHIPS
            )
        )
        if allowed_relationships:
            union_edges = [
                item for item in union_edges if item.edge.relationship_type in allowed_relationships
            ]
    union_edges = [
        item
        for item in union_edges
        if item.edge.source_entity_id in candidates and item.edge.target_entity_id in candidates
    ]

    root_id_value = semantic.get("root_entity_id")
    root_id = uuid.UUID(str(root_id_value)) if root_id_value else None
    if root_id is not None:
        _authorized_entity_union(
            actor=actor,
            entity_id=root_id,
            repositories=repositories,
        )
        if root_id not in candidates:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        focused = _focused_ids(
            root_id=root_id,
            edges=union_edges,
            depth=_bounded_integer(
                semantic.get("depth", query.depth),
                name="Canvas depth",
                minimum=1,
                maximum=4,
            ),
        )
        candidates = {key: value for key, value in candidates.items() if key in focused}
        union_edges = [
            item
            for item in union_edges
            if item.edge.source_entity_id in candidates and item.edge.target_entity_id in candidates
        ]

    placements: dict[uuid.UUID, CanvasNodePlacement] = {}
    hidden_ids: set[uuid.UUID] = set()
    if revision:
        for placement in CanvasNodePlacement.objects.filter(
            organization_id=actor.organization_id,
            view_revision=revision,
            entity_id__in=candidates,
        ):
            if placement.is_hidden:
                hidden_ids.add(placement.entity_id)
            else:
                placements[placement.entity_id] = placement
    candidates = {
        entity_id: entity for entity_id, entity in candidates.items() if entity_id not in hidden_ids
    }
    union_edges = [
        item
        for item in union_edges
        if item.edge.source_entity_id in candidates and item.edge.target_entity_id in candidates
    ]

    ordered_entities = sorted(
        candidates.values(),
        key=lambda item: (
            TYPE_COLUMNS.get(item.entity_type, len(TYPE_COLUMNS)),
            item.display_name.casefold(),
            str(item.id),
        ),
    )
    node_truncated = len(ordered_entities) > query.node_limit
    ordered_entities = ordered_entities[: query.node_limit]
    selected_ids = {entity.id for entity in ordered_entities}
    selected_edges = [
        item
        for item in union_edges
        if item.edge.source_entity_id in selected_ids and item.edge.target_entity_id in selected_ids
    ]
    edge_truncated = repository_edge_truncated or len(selected_edges) > query.edge_limit
    selected_edges = selected_edges[: query.edge_limit]
    relationship_rows = {
        relationship.id: relationship
        for relationship in KnowledgeRelationship.objects.filter(
            organization_id=actor.organization_id,
            id__in=[item.edge.relationship_id for item in selected_edges],
        ).select_related("assertion")
    }
    coordinates = _layout(ordered_entities, placements)
    assertion_ids = {
        assertion.id
        for entity in ordered_entities
        for assertion in assertions.get(entity.canonical_key, [])
    }
    conflicted_assertion_ids = set(
        AssertionConflict.objects.filter(
            organization_id=actor.organization_id,
            status=AssertionConflict.Status.OPEN,
            left_assertion_id__in=assertion_ids,
            right_assertion_id__in=assertion_ids,
        ).values_list("left_assertion_id", flat=True)
    ) | set(
        AssertionConflict.objects.filter(
            organization_id=actor.organization_id,
            status=AssertionConflict.Status.OPEN,
            left_assertion_id__in=assertion_ids,
            right_assertion_id__in=assertion_ids,
        ).values_list("right_assertion_id", flat=True)
    )

    nodes: list[dict[str, object]] = []
    for entity in ordered_entities:
        entity_assertions = assertions.get(entity.canonical_key, [])
        latest = max(
            entity_assertions,
            key=lambda item: (item.observed_at, str(item.id)),
            default=None,
        )
        x, y = coordinates[entity.id]
        nodes.append(
            {
                "id": str(entity.id),
                "type": entity.entity_type,
                "label": entity.display_name,
                "canonical_key": entity.canonical_key,
                "revision": entity.revision,
                "owner": str(entity.attributes.get("owner", ""))[:300],
                "status": str(entity.attributes.get("status", "UNKNOWN"))[:100],
                "risk": str(entity.attributes.get("risk", "UNSPECIFIED"))[:100],
                "freshness": _freshness(entity_assertions),
                "is_inferred": bool(
                    latest.is_inferred if latest else entity.attributes.get("is_inferred", False)
                ),
                "has_conflict": any(
                    assertion.id in conflicted_assertion_ids for assertion in entity_assertions
                ),
                "provenance": {
                    "kind": (
                        "INFERENCE"
                        if latest and latest.is_inferred
                        else "SOURCE_BACKED"
                        if latest
                        else "IDENTITY_ONLY"
                    ),
                    "observed_at": latest.observed_at.isoformat() if latest else None,
                    "confidence": latest.confidence if latest else None,
                },
                "repository_ids": sorted(
                    str(value) for value in entity_repositories.get(entity.id, set())
                ),
                "position": {"x": x, "y": y},
                "is_pinned": bool(placements.get(entity.id) and placements[entity.id].is_pinned),
            }
        )
    edges = [
        {
            "id": str(item.edge.relationship_id),
            "type": item.edge.relationship_type,
            "source": str(item.edge.source_entity_id),
            "target": str(item.edge.target_entity_id),
            "confidence": item.edge.confidence,
            "observed_at": item.edge.observed_at.isoformat(),
            "repository_id": str(item.repository_id),
            "directed": True,
            "review_state": relationship_rows[item.edge.relationship_id].review_state,
            "freshness": relationship_rows[item.edge.relationship_id].assertion.staleness_state,
            "basis": (
                "INFERENCE"
                if relationship_rows[item.edge.relationship_id].assertion.is_inferred
                else relationship_rows[item.edge.relationship_id].extraction_class
            ),
            "provenance": {
                "assertion_id": str(item.edge.assertion_id),
            },
        }
        for item in selected_edges
    ]
    limitations: list[str] = []
    if node_truncated:
        limitations.append(
            f"Visible nodes were capped at {query.node_limit}; refine filters or focus a node."
        )
    if edge_truncated:
        limitations.append(
            f"Visible relationships were capped at {query.edge_limit}; refine layers or focus."
        )
    if not repositories:
        limitations.append("No repository boundary is currently visible for Canvas.")
    layout_checksum = _canvas_layout_checksum(nodes, edges)
    payload: dict[str, object] = {
        "schema_version": "1",
        # Preserve the semantic meaning of the exact authorized revision when the browser saves
        # presentation-only coordinates. This closed query contains no entity content.
        "semantic_query": semantic,
        "view": (
            {
                "id": str(view.id),
                "name": view.name,
                "type": view.view_type,
                "revision": view.revision,
                "content_hash": revision.content_hash if revision else "",
            }
            if view
            else {
                "id": None,
                "name": "Live organizational view",
                "type": CanvasView.ViewType.CUSTOM,
                "revision": 0,
                "content_hash": "",
            }
        ),
        "repositories": [
            {"id": str(repository.id), "name": repository.name} for repository in repositories
        ],
        "nodes": nodes,
        "edges": edges,
        "counts": {"nodes": len(nodes), "edges": len(edges)},
        "limits": {
            "nodes": query.node_limit,
            "edges": query.edge_limit,
            "depth": query.depth,
            "repositories": CANVAS_REPOSITORY_LIMIT,
            "payload_bytes": CANVAS_PAYLOAD_LIMIT_BYTES,
        },
        "truncated": bool(node_truncated or edge_truncated),
        "limitations": limitations,
        "layout": {
            "algorithm": CANVAS_LAYOUT_ALGORITHM,
            "version": CANVAS_LAYOUT_VERSION,
            "checksum": layout_checksum,
        },
        "generated_at": timezone.now().isoformat(),
    }
    return _enforce_canvas_payload_budget(payload)


def canvas_path(
    *,
    actor: ActorContext,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    repository_ids: tuple[uuid.UUID, ...] = (),
    max_depth: int = CANVAS_PATH_DEPTH,
) -> dict[str, object]:
    """Find a shortest path only within the already-authorized repository union."""
    if not 1 <= max_depth <= CANVAS_PATH_DEPTH:
        raise ValueError("Path depth must be between 1 and 6")
    repositories = _visible_repositories(actor=actor, requested_ids=repository_ids)
    source = _authorized_entity_union(
        actor=actor,
        entity_id=source_id,
        repositories=repositories,
    )
    target = _authorized_entity_union(
        actor=actor,
        entity_id=target_id,
        repositories=repositories,
    )
    union_edges, repository_truncated = _authorized_edge_union(
        actor=actor,
        repositories=repositories,
    )
    union_edges = union_edges[:CANVAS_EDGE_LIMIT]
    adjacency: dict[uuid.UUID, list[tuple[uuid.UUID, AuthorizedCanvasEdge]]] = defaultdict(list)
    for item in union_edges:
        adjacency[item.edge.source_entity_id].append((item.edge.target_entity_id, item))
        adjacency[item.edge.target_entity_id].append((item.edge.source_entity_id, item))
    queue: deque[tuple[uuid.UUID, list[AuthorizedCanvasEdge]]] = deque([(source.id, [])])
    visited = {source.id}
    found: list[AuthorizedCanvasEdge] | None = None
    while queue:
        current, path = queue.popleft()
        if current == target.id:
            found = path
            break
        if len(path) >= max_depth:
            continue
        for neighbor, edge in sorted(
            adjacency[current],
            key=lambda item: (str(item[1].edge.relationship_id), str(item[0])),
        ):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, [*path, edge]))
    return {
        "status": "FOUND" if found is not None else "NO_PERMITTED_PATH",
        "source": {"id": str(source.id), "label": source.display_name},
        "target": {"id": str(target.id), "label": target.display_name},
        "found": found is not None,
        "steps": (
            [
                {
                    "relationship_id": str(item.edge.relationship_id),
                    "type": item.edge.relationship_type,
                    "source": str(item.edge.source_entity_id),
                    "target": str(item.edge.target_entity_id),
                    "repository_id": str(item.repository_id),
                    "explanation": (
                        f"{item.edge.source_name} "
                        f"{item.edge.relationship_type.lower().replace('_', ' ')} "
                        f"{item.edge.target_name}."
                    ),
                }
                for item in found
            ]
            if found is not None
            else []
        ),
        "max_depth": max_depth,
        "truncated": repository_truncated or len(union_edges) >= CANVAS_EDGE_LIMIT,
        "limitation": (
            "No permitted path was found within the bounded current graph." if found is None else ""
        ),
    }


def canvas_entity_detail(
    *,
    actor: ActorContext,
    entity_id: uuid.UUID,
    repository_ids: tuple[uuid.UUID, ...] = (),
) -> dict[str, object]:
    """Return inspector detail after reauthorizing the entity and its assertions."""
    repositories = _visible_repositories(actor=actor, requested_ids=repository_ids)
    entity = _authorized_entity_union(
        actor=actor,
        entity_id=entity_id,
        repositories=repositories,
    )
    assertions = _authorized_assertion_union(
        actor=actor,
        repositories=repositories,
        subject_keys={entity.canonical_key},
    ).get(entity.canonical_key, [])
    assertion_ids = [assertion.id for assertion in assertions]
    conflicts = AssertionConflict.objects.filter(
        organization_id=actor.organization_id,
        status=AssertionConflict.Status.OPEN,
        left_assertion_id__in=assertion_ids,
        right_assertion_id__in=assertion_ids,
    )
    source_details: list[dict[str, object]] = []
    for assertion in sorted(
        assertions,
        key=lambda item: (item.observed_at, str(item.id)),
        reverse=True,
    )[:20]:
        citations: dict[tuple[str, str], dict[str, object]] = {}
        for repository in repositories:
            for citation in authorized_assertion_citations(
                actor=actor,
                repository_id=repository.id,
                assertion_id=assertion.id,
            ):
                key = (str(citation.get("locator", "")), str(citation.get("observed_at", "")))
                citations[key] = {
                    "locator": str(citation.get("locator", ""))[:1_000],
                    "observed_at": citation.get("observed_at"),
                }
        source_details.append(
            {
                "assertion_id": str(assertion.id),
                "predicate": assertion.predicate,
                "freshness": assertion.staleness_state,
                "review_state": assertion.review_state,
                "is_inferred": assertion.is_inferred,
                "confidence": assertion.confidence,
                "observed_at": assertion.observed_at.isoformat(),
                "citations": list(citations.values())[:20],
            }
        )
    return {
        "id": str(entity.id),
        "label": entity.display_name,
        "type": entity.entity_type,
        "canonical_key": entity.canonical_key,
        "revision": entity.revision,
        "summary": str(entity.attributes.get("summary", "No governed summary is available."))[
            :2_000
        ],
        "owner": str(entity.attributes.get("owner", "Unassigned"))[:300],
        "reviewers": list(entity.attributes.get("reviewers", []))[:20],
        "status": str(entity.attributes.get("status", "UNKNOWN"))[:100],
        "freshness": _freshness(assertions),
        "sources": source_details,
        "conflict_count": conflicts.count(),
        "permitted_actions": {
            "view": True,
            "move_in_view": _can(actor, Action.CANVAS_MANAGE),
            "propose_relationship": _can(actor, Action.KNOWLEDGE_PROPOSE),
            "delete_canonical": False,
        },
    }


def _can(actor: ActorContext, action: Action) -> bool:
    try:
        authorize_action(actor=actor, action=action)
    except ResourceNotFoundError:
        return False
    return True


def _normalized_semantic_query(value: dict[str, object]) -> dict[str, object]:
    allowed = {
        "root_entity_id",
        "repository_ids",
        "entity_types",
        "owner",
        "status",
        "risk",
        "freshness",
        "search",
        "layers",
        "depth",
    }
    if set(value) - allowed:
        raise ValueError("Canvas semantic query contains unsupported fields")
    rendered: dict[str, object] = {}
    if "root_entity_id" in value:
        root = value["root_entity_id"]
        if not isinstance(root, str):
            raise ValueError("Canvas root entity must be a UUID string")
        rendered["root_entity_id"] = str(uuid.UUID(root))
    if "repository_ids" in value:
        repositories = value["repository_ids"]
        if not isinstance(repositories, list) or not all(
            isinstance(item, str) for item in repositories
        ):
            raise ValueError("Canvas repositories must be a list of UUID strings")
        if len(repositories) > CANVAS_REPOSITORY_LIMIT:
            raise ValueError("At most 100 repositories may be selected")
        rendered["repository_ids"] = sorted({str(uuid.UUID(item)) for item in repositories})
    for field, vocabulary in (
        ("entity_types", frozenset(KnowledgeEntity.EntityType.values)),
        ("layers", frozenset(LAYER_RELATIONSHIPS)),
    ):
        if field not in value:
            continue
        items = value[field]
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise ValueError(f"Canvas {field} must be a list of strings")
        if any(item not in vocabulary for item in items):
            raise ValueError(f"Canvas {field} contains an unknown value")
        rendered[field] = sorted(set(items))
    for field in ("owner", "status", "risk", "freshness", "search"):
        if field not in value:
            continue
        item = value[field]
        if not isinstance(item, str):
            raise ValueError(f"Canvas {field} must be a string")
        if field == "freshness" and item and item not in CANVAS_FRESHNESS_STATES:
            raise ValueError("Unknown freshness state")
        rendered[field] = _safe_text(item, maximum=500)
    if "depth" in value:
        rendered["depth"] = _bounded_integer(
            value["depth"], name="Canvas depth", minimum=1, maximum=4
        )
    if len(str(rendered)) > 20_000:
        raise ValueError("Canvas semantic query exceeds its size budget")
    return rendered


def create_canvas_view(
    *,
    actor: ActorContext,
    name: str,
    description: str,
    view_type: str,
    semantic_query: dict[str, object],
    repository_id: uuid.UUID | None,
    access_scope_id: uuid.UUID | None,
    idempotency_key: str,
) -> tuple[CanvasView, bool]:
    """Create one saved semantic view and immutable initial revision."""
    if view_type not in CanvasView.ViewType.values:
        raise ValueError("Unknown Canvas view type")
    name = _safe_text(name, maximum=200).strip()
    description = _safe_text(description, maximum=1_000)
    if not name:
        raise ValueError("Canvas view name or description is invalid")
    normalized = _normalized_semantic_query(semantic_query)
    repositories = _visible_repositories(
        actor=actor,
        requested_ids=(repository_id,) if repository_id else (),
    )
    decision = authorize_action(
        actor=actor,
        action=Action.CANVAS_MANAGE,
        repository_id=repository_id,
    )
    if access_scope_id and not _scope_visible_in_repositories(
        actor=actor,
        scope_id=access_scope_id,
        repositories=repositories,
        action=Action.CANVAS_MANAGE,
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    root_id = normalized.get("root_entity_id")
    if root_id:
        _authorized_entity_union(
            actor=actor,
            entity_id=uuid.UUID(str(root_id)),
            repositories=repositories,
        )
    idem_hash = content_hash({"canvas_view_idempotency": idempotency_key})
    request_hash = content_hash(
        {
            "name": name,
            "description": description,
            "view_type": view_type,
            "semantic_query": normalized,
            "repository_id": str(repository_id) if repository_id else None,
            "access_scope_id": str(access_scope_id) if access_scope_id else None,
        }
    )
    initial_presentation = {
        "placements": [],
        "filters": [],
        "layers": [
            {
                "key": key,
                "label": label,
                "is_visible": is_visible,
                "position": position,
            }
            for position, (key, label, is_visible) in enumerate(DEFAULT_LAYERS)
        ],
        "groups": [],
        "annotations": [],
    }
    with transaction.atomic():
        organization = Organization.objects.select_for_update().get(id=actor.organization_id)
        owner_membership = Membership.objects.get(
            organization=organization,
            user_id=uuid.UUID(actor.actor_id),
            is_active=True,
        )
        existing = CanvasView.objects.filter(
            organization=organization,
            idempotency_key=idem_hash,
        ).first()
        if existing:
            get_authorized_canvas_view(
                actor=actor,
                view_id=existing.id,
                action=Action.CANVAS_MANAGE,
            )
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError(
                    "Canvas view idempotency key was reused for different content"
                )
            return existing, False
        view = CanvasView.objects.create(
            organization=organization,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
            owner_membership=owner_membership,
            name=name,
            description=description,
            view_type=view_type,
            created_by_type=actor.actor_type,
            created_by_id=actor.actor_id,
            idempotency_key=idem_hash,
            request_hash=request_hash,
        )
        revision_idem = content_hash({"view": str(view.id), "revision": 1})
        revision = CanvasViewRevision.objects.create(
            organization=organization,
            canvas_view=view,
            revision=1,
            semantic_query=normalized,
            presentation=initial_presentation,
            layout_algorithm=CANVAS_LAYOUT_ALGORITHM,
            layout_version=CANVAS_LAYOUT_VERSION,
            created_by_type=actor.actor_type,
            created_by_id=actor.actor_id,
            idempotency_key=revision_idem,
            request_hash=request_hash,
        )
        CanvasLayer.objects.bulk_create(
            [
                CanvasLayer(
                    organization=organization,
                    view_revision=revision,
                    position=position,
                    key=key,
                    label=label,
                    is_visible=is_visible,
                )
                for position, (key, label, is_visible) in enumerate(DEFAULT_LAYERS)
            ]
        )
        record_transition(
            organization=organization,
            actor=replace(actor, authorization_path=decision.authorization_path),
            target_type="canvasview",
            target_id=view.id,
            from_state="",
            to_state="SAVED",
            revision=view.revision,
            metadata={"view_type": view.view_type},
        )
        return view, True


def _canonical_presentation(
    *,
    placements: list[dict[str, object]],
    filters: list[dict[str, object]],
    layers: list[dict[str, object]],
    groups: list[dict[str, object]],
    annotations: list[dict[str, object]],
) -> dict[str, object]:
    """Validate and normalize every byte covered by a sealed revision hash."""
    canonical_groups = [
        {
            "label": _safe_text(item.get("label"), maximum=200),
            "x": _coordinate(item.get("x")),
            "y": _coordinate(item.get("y")),
            "width": _dimension(item.get("width")),
            "height": _dimension(item.get("height")),
            "position": position,
        }
        for position, item in enumerate(groups)
    ]
    canonical_placements: list[dict[str, object]] = []
    placement_ids: set[uuid.UUID] = set()
    for position, item in enumerate(placements):
        entity_id = uuid.UUID(str(item["entity_id"]))
        if entity_id in placement_ids:
            raise ValueError("Canvas placements repeat a canonical entity")
        placement_ids.add(entity_id)
        group_index = item.get("group_index")
        canonical_group_index: int | None = None
        if group_index is not None:
            canonical_group_index = _bounded_integer(
                group_index,
                name="Canvas group index",
                minimum=0,
                maximum=max(0, len(canonical_groups) - 1),
            )
            if not canonical_groups:
                raise ValueError("Canvas placement references an unavailable group")
        canonical_placements.append(
            {
                "entity_id": str(entity_id),
                "x": _coordinate(item.get("x")),
                "y": _coordinate(item.get("y")),
                "is_pinned": bool(item.get("is_pinned", False)),
                "is_hidden": bool(item.get("is_hidden", False)),
                "group_index": canonical_group_index,
                "position": position,
            }
        )
    canonical_filters: list[dict[str, object]] = []
    for position, item in enumerate(filters):
        value = item.get("value")
        if len(str(value)) > 2_000:
            raise ValueError("Canvas filter value exceeds its size budget")
        canonical_filters.append(
            {
                "field": _filter_field(item.get("field")),
                "operator": _filter_operator(item.get("operator")),
                "value": value,
                "position": position,
            }
        )
    canonical_layers: list[dict[str, object]] = []
    layer_keys: set[str] = set()
    for position, item in enumerate(layers):
        key = _layer_key(item.get("key"))
        if key in layer_keys:
            raise ValueError("Canvas layers repeat a semantic key")
        layer_keys.add(key)
        canonical_layers.append(
            {
                "key": key,
                "label": _safe_text(item.get("label"), maximum=100),
                "is_visible": bool(item.get("is_visible", True)),
                "position": position,
            }
        )
    canonical_annotations = [
        {
            "entity_id": (
                str(uuid.UUID(str(item["entity_id"]))) if item.get("entity_id") else None
            ),
            "body": _safe_text(item.get("body"), maximum=2_000),
            "x": _coordinate(item.get("x")),
            "y": _coordinate(item.get("y")),
            "position": position,
        }
        for position, item in enumerate(annotations)
    ]
    return {
        "placements": canonical_placements,
        "filters": canonical_filters,
        "layers": canonical_layers,
        "groups": canonical_groups,
        "annotations": canonical_annotations,
    }


def save_canvas_revision(
    *,
    actor: ActorContext,
    view_id: uuid.UUID,
    expected_revision: int,
    semantic_query: dict[str, object],
    placements: list[dict[str, object]],
    filters: list[dict[str, object]],
    layers: list[dict[str, object]],
    groups: list[dict[str, object]],
    annotations: list[dict[str, object]],
    idempotency_key: str,
) -> tuple[CanvasViewRevision, bool]:
    """Append presentation state after reauthorizing every canonical reference."""
    if len(placements) > CANVAS_NODE_LIMIT:
        raise ValueError("Canvas placement budget exceeded")
    if len(filters) > 20 or len(layers) > 20 or len(groups) > 50 or len(annotations) > 100:
        raise ValueError("Canvas presentation budget exceeded")
    normalized = _normalized_semantic_query(semantic_query)
    presentation = _canonical_presentation(
        placements=placements,
        filters=filters,
        layers=layers,
        groups=groups,
        annotations=annotations,
    )
    idem_hash = content_hash({"canvas_revision_idempotency": idempotency_key})
    request_hash = content_hash(
        {
            "semantic_query": normalized,
            "presentation": presentation,
        }
    )
    with transaction.atomic():
        view = get_authorized_canvas_view(
            actor=actor,
            view_id=view_id,
            action=Action.CANVAS_MANAGE,
            for_update=True,
        )
        decision = authorize_action(
            actor=actor,
            action=Action.CANVAS_MANAGE,
            repository_id=view.repository_id,
        )
        repositories = _visible_repositories(
            actor=actor,
            requested_ids=(view.repository_id,) if view.repository_id else (),
        )
        entity_ids: set[uuid.UUID] = set()
        for placement in placements:
            entity_ids.add(uuid.UUID(str(placement["entity_id"])))
        for annotation in annotations:
            if annotation.get("entity_id"):
                entity_ids.add(uuid.UUID(str(annotation["entity_id"])))
        for entity_id in sorted(entity_ids, key=str):
            _authorized_entity_union(
                actor=actor,
                entity_id=entity_id,
                repositories=repositories,
            )
        existing = CanvasViewRevision.objects.filter(
            organization_id=actor.organization_id,
            canvas_view=view,
            idempotency_key=idem_hash,
        ).first()
        if existing:
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError(
                    "Canvas revision idempotency key was reused for different content"
                )
            return existing, False
        if view.revision != expected_revision:
            raise OptimisticConcurrencyError(
                f"Expected revision {expected_revision}, found {view.revision}"
            )
        next_revision = view.revision + 1
        revision = CanvasViewRevision.objects.create(
            organization_id=actor.organization_id,
            canvas_view=view,
            revision=next_revision,
            semantic_query=normalized,
            presentation=presentation,
            layout_algorithm=CANVAS_LAYOUT_ALGORITHM,
            layout_version=CANVAS_LAYOUT_VERSION,
            created_by_type=actor.actor_type,
            created_by_id=actor.actor_id,
            idempotency_key=idem_hash,
            request_hash=request_hash,
        )
        group_records: list[CanvasGroup] = []
        for group in cast(list[dict[str, object]], presentation["groups"]):
            record = CanvasGroup.objects.create(
                organization_id=actor.organization_id,
                view_revision=revision,
                label=str(group["label"])[:200],
                x=_coordinate(group["x"]),
                y=_coordinate(group["y"]),
                width=_dimension(group["width"]),
                height=_dimension(group["height"]),
            )
            group_records.append(record)
        group_by_index = dict(enumerate(group_records))
        CanvasNodePlacement.objects.bulk_create(
            [
                CanvasNodePlacement(
                    organization_id=actor.organization_id,
                    view_revision=revision,
                    entity_id=uuid.UUID(str(item["entity_id"])),
                    group=group_by_index.get(cast(int, item["group_index"]))
                    if item.get("group_index") is not None
                    else None,
                    x=_coordinate(item["x"]),
                    y=_coordinate(item["y"]),
                    is_pinned=bool(item.get("is_pinned", False)),
                    is_hidden=bool(item.get("is_hidden", False)),
                )
                for item in cast(list[dict[str, object]], presentation["placements"])
            ]
        )
        CanvasFilter.objects.bulk_create(
            [
                CanvasFilter(
                    organization_id=actor.organization_id,
                    view_revision=revision,
                    position=position,
                    field=_filter_field(item.get("field")),
                    operator=_filter_operator(item.get("operator")),
                    value=item.get("value"),
                )
                for position, item in enumerate(
                    cast(list[dict[str, object]], presentation["filters"])
                )
            ]
        )
        CanvasLayer.objects.bulk_create(
            [
                CanvasLayer(
                    organization_id=actor.organization_id,
                    view_revision=revision,
                    position=position,
                    key=_layer_key(item.get("key")),
                    label=str(item.get("label", ""))[:100],
                    is_visible=bool(item.get("is_visible", True)),
                )
                for position, item in enumerate(
                    cast(list[dict[str, object]], presentation["layers"])
                )
            ]
        )
        CanvasAnnotation.objects.bulk_create(
            [
                CanvasAnnotation(
                    organization_id=actor.organization_id,
                    view_revision=revision,
                    entity_id=(
                        uuid.UUID(str(item["entity_id"])) if item.get("entity_id") else None
                    ),
                    body=str(item["body"])[:2_000],
                    x=_coordinate(item["x"]),
                    y=_coordinate(item["y"]),
                )
                for item in cast(list[dict[str, object]], presentation["annotations"])
            ]
        )
        view.revision = next_revision
        view.save(update_fields=["revision", "updated_at"])
        record_transition(
            organization=view.organization,
            actor=replace(actor, authorization_path=decision.authorization_path),
            target_type="canvasview",
            target_id=view.id,
            from_state="SAVED",
            to_state="SAVED",
            revision=view.revision,
            metadata={
                "presentation_only": True,
                "layout_version": CANVAS_LAYOUT_VERSION,
                "content_hash": revision.content_hash,
            },
        )
        return revision, True


def _coordinate(value: object) -> float:
    number = float(cast(Any, value))
    if not math.isfinite(number) or not -1_000_000 <= number <= 1_000_000:
        raise ValueError("Canvas coordinate is outside its bounded range")
    return number


def _safe_text(value: object, *, maximum: int) -> str:
    rendered = str(value or "")
    if len(rendered) > maximum:
        raise ValueError("Canvas text exceeds its size budget")
    if SECRET_PATTERN.search(rendered):
        raise ValueError("Canvas text resembles a secret and was not persisted")
    return rendered


def _dimension(value: object) -> float:
    number = float(cast(Any, value))
    if not math.isfinite(number) or not 0 < number <= 1_000_000:
        raise ValueError("Canvas dimension is outside its bounded range")
    return number


def _filter_field(value: object) -> str:
    rendered = str(value)
    if rendered not in {"entity_type", "owner", "status", "time", "risk", "freshness"}:
        raise ValueError("Unknown Canvas filter field")
    return rendered


def _filter_operator(value: object) -> str:
    rendered = str(value)
    if rendered not in CanvasFilter.Operator.values:
        raise ValueError("Unknown Canvas filter operator")
    return rendered


def _layer_key(value: object) -> str:
    rendered = str(value)
    if rendered not in LAYER_RELATIONSHIPS:
        raise ValueError("Unknown Canvas layer")
    return rendered


def create_canvas_share(
    *,
    actor: ActorContext,
    view_id: uuid.UUID,
    idempotency_key: str,
    recipient_membership_id: uuid.UUID | None = None,
    expires_at: datetime | None = None,
) -> tuple[CanvasShare, bool]:
    """Create a deep link that still requires the viewer's current authorization."""
    view = get_authorized_canvas_view(
        actor=actor,
        view_id=view_id,
        action=Action.CANVAS_MANAGE,
    )
    decision = authorize_action(
        actor=actor,
        action=Action.CANVAS_MANAGE,
        repository_id=view.repository_id,
    )
    if expires_at is not None and expires_at <= timezone.now():
        raise ValueError("Canvas share expiry must be in the future")
    revision = CanvasViewRevision.objects.get(
        organization_id=actor.organization_id,
        canvas_view=view,
        revision=view.revision,
    )
    recipient: Membership | None = None
    if recipient_membership_id:
        recipient = get_tenant_record(
            queryset=Membership.objects.filter(is_active=True),
            record_id=recipient_membership_id,
            organization_id=actor.organization_id,
        )
    idem_hash = content_hash({"canvas_share_idempotency": idempotency_key})
    request_hash = content_hash(
        {
            "view_id": str(view.id),
            "view_revision_id": str(revision.id),
            "recipient_membership_id": (
                str(recipient_membership_id) if recipient_membership_id else None
            ),
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
    )
    with transaction.atomic():
        Organization.objects.select_for_update().get(id=actor.organization_id)
        existing = CanvasShare.objects.filter(
            organization_id=actor.organization_id,
            idempotency_key=idem_hash,
        ).first()
        if existing:
            resolve_canvas_share(actor=actor, share_id=existing.id)
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError(
                    "Canvas share idempotency key was reused for different content"
                )
            return existing, False
        share = CanvasShare.objects.create(
            organization_id=actor.organization_id,
            canvas_view=view,
            view_revision=revision,
            recipient_membership=recipient,
            created_by_type=actor.actor_type,
            created_by_id=actor.actor_id,
            expires_at=expires_at,
            idempotency_key=idem_hash,
            request_hash=request_hash,
        )
        record_transition(
            organization=view.organization,
            actor=replace(actor, authorization_path=decision.authorization_path),
            target_type="canvasshare",
            target_id=share.id,
            from_state="",
            to_state="ACTIVE",
            revision=view.revision,
            metadata={
                "canvas_view_id": str(view.id),
                "canvas_view_revision_id": str(revision.id),
            },
        )
        return share, True


def resolve_canvas_share(
    *,
    actor: ActorContext,
    share_id: uuid.UUID,
) -> tuple[CanvasView, CanvasViewRevision]:
    """Resolve a share without turning its identifier into bearer authority."""
    share = get_tenant_record(
        queryset=CanvasShare.objects.filter(revoked_at__isnull=True),
        record_id=share_id,
        organization_id=actor.organization_id,
    )
    if share.expires_at and share.expires_at <= timezone.now():
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if share.recipient_membership_id:
        membership = Membership.objects.filter(
            id=share.recipient_membership_id,
            organization_id=actor.organization_id,
            user_id=uuid.UUID(actor.actor_id),
            is_active=True,
        ).first()
        if membership is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    view = get_authorized_canvas_view(actor=actor, view_id=share.canvas_view_id)
    revision = get_tenant_record(
        queryset=CanvasViewRevision.objects.filter(canvas_view=view),
        record_id=share.view_revision_id,
        organization_id=actor.organization_id,
    )
    repositories = _visible_repositories(
        actor=actor,
        requested_ids=(view.repository_id,) if view.repository_id else (),
    )
    root_id = revision.semantic_query.get("root_entity_id")
    if root_id:
        _authorized_entity_union(
            actor=actor,
            entity_id=uuid.UUID(str(root_id)),
            repositories=repositories,
        )
    return view, revision


def propose_canvas_relationship(
    *,
    actor: ActorContext,
    source_id: uuid.UUID,
    target_id: uuid.UUID,
    relationship_type: str,
    repository_id: uuid.UUID,
    expected_source_revision: int,
    expected_target_revision: int,
    rationale: str,
    idempotency_key: str,
) -> tuple[KnowledgeProposal, bool]:
    """Create a review-only relationship proposal; never write a canonical edge."""
    if relationship_type not in RELATIONSHIP_ENDPOINTS:
        raise ValueError("Unknown relationship type")
    rationale = _safe_text(rationale, maximum=2_000).strip()
    if source_id == target_id or not rationale:
        raise ValueError("Relationship proposal endpoints or rationale are invalid")
    decision = authorize_action(
        actor=actor,
        action=Action.KNOWLEDGE_PROPOSE,
        repository_id=repository_id,
    )
    repositories = _visible_repositories(actor=actor, requested_ids=(repository_id,))
    source = _authorized_entity_union(
        actor=actor,
        entity_id=source_id,
        repositories=repositories,
    )
    target = _authorized_entity_union(
        actor=actor,
        entity_id=target_id,
        repositories=repositories,
    )
    allowed_sources, allowed_targets = RELATIONSHIP_ENDPOINTS[relationship_type]
    if source.entity_type not in allowed_sources or target.entity_type not in allowed_targets:
        raise ValueError("Relationship endpoints do not match the typed vocabulary")
    if source.access_scope_id != target.access_scope_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    request = {
        "source_id": str(source.id),
        "target_id": str(target.id),
        "relationship_type": relationship_type,
        "repository_id": str(repository_id),
        "expected_source_revision": expected_source_revision,
        "expected_target_revision": expected_target_revision,
        "rationale": rationale,
    }
    idem_hash = content_hash({"canvas_relationship_idempotency": idempotency_key})
    request_hash = content_hash(request)
    with transaction.atomic():
        Organization.objects.select_for_update().get(id=actor.organization_id)
        locked_source = get_tenant_record_for_update(
            queryset=KnowledgeEntity.objects.filter(is_active=True),
            record_id=source.id,
            organization_id=actor.organization_id,
        )
        locked_target = get_tenant_record_for_update(
            queryset=KnowledgeEntity.objects.filter(is_active=True),
            record_id=target.id,
            organization_id=actor.organization_id,
        )
        authorize_action(
            actor=actor,
            action=Action.KNOWLEDGE_PROPOSE,
            repository_id=repository_id,
            access_scope_id=locked_source.access_scope_id,
        )
        existing = (
            KnowledgeProposalScope.objects.filter(
                organization_id=actor.organization_id,
                idempotency_key=idem_hash,
            )
            .select_related("knowledge_proposal")
            .first()
        )
        if existing:
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError(
                    "Relationship proposal idempotency key was reused for different content"
                )
            return existing.knowledge_proposal, False
        if (
            locked_source.revision != expected_source_revision
            or locked_target.revision != expected_target_revision
        ):
            raise OptimisticConcurrencyError("A relationship proposal endpoint changed")
        proposal = submit_knowledge_proposal(
            actor=replace(actor, authorization_path=decision.authorization_path),
            summary=(
                f"Propose {locked_source.display_name} "
                f"{relationship_type.lower().replace('_', ' ')} "
                f"{locked_target.display_name}"
            ),
            proposed_changes=[
                {
                    "operation": "PROPOSE_RELATIONSHIP",
                    "source_entity_id": str(locked_source.id),
                    "target_entity_id": str(locked_target.id),
                    "relationship_type": relationship_type,
                    "rationale": rationale,
                    "canonical_mutation_applied": False,
                }
            ],
            anva_sources=[
                {
                    "kind": "CANONICAL_ENTITY",
                    "id": str(locked_source.id),
                    "revision": locked_source.revision,
                },
                {
                    "kind": "CANONICAL_ENTITY",
                    "id": str(locked_target.id),
                    "revision": locked_target.revision,
                },
            ],
        )
        KnowledgeProposalScope.objects.create(
            organization_id=actor.organization_id,
            knowledge_proposal=proposal,
            repository_id=repository_id,
            access_scope_id=locked_source.access_scope_id,
            idempotency_key=idem_hash,
            request_hash=request_hash,
        )
        return proposal, True
