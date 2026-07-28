"""Permission-safe, typed, bounded traversal of the organization graph."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from django.db import connection

from anva.core.services.authorization import Action
from anva.core.services.context import ActorContext
from anva.core.services.retrieval import authorized_scope_ids

MAX_GRAPH_DEPTH = 4
MAX_GRAPH_DEGREE = 100
MAX_GRAPH_EDGES = 500

_GRAPH_SQL = """
WITH RECURSIVE
authorized_edges AS MATERIALIZED (
    SELECT
        relationship.id AS relationship_id,
        relationship.relationship_type,
        relationship.source_entity_id,
        relationship.target_entity_id,
        relationship.source_entity_type,
        relationship.target_entity_type,
        source_entity.canonical_key AS source_key,
        source_entity.display_name AS source_name,
        target_entity.canonical_key AS target_key,
        target_entity.display_name AS target_name,
        relationship.assertion_id,
        relationship.source_location_id,
        relationship.source_observation_id,
        relationship.access_snapshot_id,
        relationship.observed_at,
        relationship.confidence
    FROM core_knowledgerelationship relationship
    JOIN core_knowledgeentity source_entity
      ON source_entity.id = relationship.source_entity_id
     AND source_entity.organization_id = relationship.organization_id
    JOIN core_knowledgeentity target_entity
      ON target_entity.id = relationship.target_entity_id
     AND target_entity.organization_id = relationship.organization_id
    JOIN core_knowledgeassertion assertion
      ON assertion.id = relationship.assertion_id
     AND assertion.organization_id = relationship.organization_id
    JOIN core_sourceobservation observation
      ON observation.id = relationship.source_observation_id
     AND observation.organization_id = relationship.organization_id
    JOIN core_sourcedocument document
      ON document.id = observation.source_document_id
     AND document.organization_id = observation.organization_id
    JOIN core_sourcecontainer container
      ON container.id = document.source_container_id
     AND container.organization_id = document.organization_id
    JOIN core_sourceconnection source_connection
      ON source_connection.id = container.source_connection_id
     AND source_connection.organization_id = container.organization_id
    JOIN core_accesssnapshot snapshot
      ON snapshot.id = relationship.access_snapshot_id
     AND snapshot.organization_id = relationship.organization_id
    WHERE relationship.organization_id = %(organization_id)s
      AND source_connection.repository_id = %(repository_id)s
      AND relationship.access_scope_id = ANY(%(scope_ids)s::uuid[])
      AND snapshot.revoked_at IS NULL
      AND assertion.valid_until IS NULL
      AND relationship.review_state <> 'REJECTED'
      AND document.state = 'PRESENT'
      AND observation.status = 'PRESENT'
      AND observation.source_revision_id = document.current_revision_id
),
walk AS (
    SELECT
        root.*,
        1 AS depth,
        ARRAY[root.source_entity_id, root.target_entity_id]::uuid[] AS path
    FROM (
        SELECT *
        FROM authorized_edges
        WHERE source_entity_id = %(start_entity_id)s
        ORDER BY relationship_id
        LIMIT %(degree_limit)s
    ) root
    UNION ALL
    SELECT
        next_edge.*,
        walk.depth + 1 AS depth,
        walk.path || next_edge.target_entity_id AS path
    FROM walk
    CROSS JOIN LATERAL (
        SELECT *
        FROM authorized_edges candidate
        WHERE candidate.source_entity_id = walk.target_entity_id
          AND NOT candidate.target_entity_id = ANY(walk.path)
        ORDER BY candidate.relationship_id
        LIMIT %(degree_limit)s
    ) next_edge
    WHERE walk.depth < %(depth_limit)s
)
SELECT
    relationship_id,
    relationship_type,
    source_entity_id,
    target_entity_id,
    source_entity_type,
    target_entity_type,
    source_key,
    source_name,
    target_key,
    target_name,
    assertion_id,
    source_location_id,
    source_observation_id,
    access_snapshot_id,
    observed_at,
    confidence,
    depth
FROM walk
ORDER BY depth, relationship_id
LIMIT %(edge_limit)s
"""


@dataclass(frozen=True, slots=True)
class GraphEdge:
    relationship_id: uuid.UUID
    relationship_type: str
    source_entity_id: uuid.UUID
    target_entity_id: uuid.UUID
    source_entity_type: str
    target_entity_type: str
    source_key: str
    source_name: str
    target_key: str
    target_name: str
    assertion_id: uuid.UUID
    source_location_id: uuid.UUID
    source_observation_id: uuid.UUID
    access_snapshot_id: uuid.UUID
    observed_at: datetime
    confidence: float
    depth: int

    def as_dict(self) -> dict[str, object]:
        return {
            "relationship_id": str(self.relationship_id),
            "relationship_type": self.relationship_type,
            "source": {
                "id": str(self.source_entity_id),
                "type": self.source_entity_type,
                "key": self.source_key,
                "name": self.source_name,
            },
            "target": {
                "id": str(self.target_entity_id),
                "type": self.target_entity_type,
                "key": self.target_key,
                "name": self.target_name,
            },
            "assertion_id": str(self.assertion_id),
            "source_location_id": str(self.source_location_id),
            "source_observation_id": str(self.source_observation_id),
            "access_snapshot_id": str(self.access_snapshot_id),
            "observed_at": self.observed_at.isoformat(),
            "confidence": self.confidence,
            "depth": self.depth,
        }


@dataclass(frozen=True, slots=True)
class GraphResult:
    start_entity_id: uuid.UUID
    depth_limit: int
    degree_limit: int
    edge_limit: int
    truncated: bool
    edges: tuple[GraphEdge, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "start_entity_id": str(self.start_entity_id),
            "limits": {
                "depth": self.depth_limit,
                "degree": self.degree_limit,
                "edges": self.edge_limit,
            },
            "truncated": self.truncated,
            "edges": [edge.as_dict() for edge in self.edges],
        }


def traverse_graph(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    start_entity_id: uuid.UUID,
    depth: int = 2,
    degree: int = MAX_GRAPH_DEGREE,
    edge_limit: int = MAX_GRAPH_EDGES,
) -> GraphResult:
    """Traverse only an authorized edge relation, with conservative hard caps."""
    if depth < 1 or depth > MAX_GRAPH_DEPTH:
        raise ValueError("depth must be between 1 and 4")
    if degree < 1 or degree > MAX_GRAPH_DEGREE:
        raise ValueError("degree must be between 1 and 100")
    if edge_limit < 1 or edge_limit > MAX_GRAPH_EDGES:
        raise ValueError("edge_limit must be between 1 and 500")
    scope_ids = list(
        authorized_scope_ids(
            actor=actor,
            repository_id=repository_id,
            action=Action.KNOWLEDGE_VIEW,
        )
    )
    if not scope_ids:
        return GraphResult(start_entity_id, depth, degree, edge_limit, False, ())
    with connection.cursor() as cursor:
        cursor.execute(
            _GRAPH_SQL,
            {
                "organization_id": actor.organization_id,
                "repository_id": repository_id,
                "scope_ids": scope_ids,
                "start_entity_id": start_entity_id,
                "depth_limit": depth,
                "degree_limit": degree,
                "edge_limit": edge_limit + 1,
            },
        )
        rows = cursor.fetchall()
    truncated = len(rows) > edge_limit
    edges = tuple(GraphEdge(*row) for row in rows[:edge_limit])
    return GraphResult(
        start_entity_id=start_entity_id,
        depth_limit=depth,
        degree_limit=degree,
        edge_limit=edge_limit,
        truncated=truncated,
        edges=edges,
    )
