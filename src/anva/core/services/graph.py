"""Permission-safe, typed, bounded traversal of the organization graph."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from django.db import connection

from anva.core.services.authorization import Action, authorize_action
from anva.core.services.context import ActorContext

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
    JOIN core_accessscope edge_scope
      ON edge_scope.id = relationship.access_scope_id
     AND edge_scope.organization_id = relationship.organization_id
     AND edge_scope.is_active
    JOIN core_accessscope source_scope
      ON source_scope.id = source_entity.access_scope_id
     AND source_scope.organization_id = relationship.organization_id
     AND source_scope.is_active
    JOIN core_accessscope target_scope
      ON target_scope.id = target_entity.access_scope_id
     AND target_scope.organization_id = relationship.organization_id
     AND target_scope.is_active
    JOIN core_accessscope assertion_scope
      ON assertion_scope.id = assertion.access_scope_id
     AND assertion_scope.organization_id = relationship.organization_id
     AND assertion_scope.is_active
    JOIN core_sourcelocation location
      ON location.id = relationship.source_location_id
     AND location.organization_id = relationship.organization_id
     AND location.source_observation_id = relationship.source_observation_id
    JOIN core_sourceobservation observation
     ON observation.id = relationship.source_observation_id
     AND observation.organization_id = relationship.organization_id
    JOIN core_parsedsource parsed_source
      ON parsed_source.id = location.parsed_source_id
     AND parsed_source.organization_id = relationship.organization_id
     AND parsed_source.source_revision_id = observation.source_revision_id
    JOIN core_sourcedocument document
      ON document.id = observation.source_document_id
     AND document.organization_id = observation.organization_id
    JOIN core_sourcecontainer container
      ON container.id = document.source_container_id
     AND container.organization_id = document.organization_id
    JOIN core_sourceconnection source_connection
     ON source_connection.id = container.source_connection_id
     AND source_connection.organization_id = container.organization_id
    JOIN core_repository repository
      ON repository.id = source_connection.repository_id
     AND repository.organization_id = source_connection.organization_id
     AND repository.is_active
    JOIN core_accesssnapshot snapshot
     ON snapshot.id = relationship.access_snapshot_id
     AND snapshot.organization_id = relationship.organization_id
     AND snapshot.source_connection_id = source_connection.id
     AND snapshot.access_scope_id = relationship.access_scope_id
    LEFT JOIN core_membership membership
      ON %(actor_type)s = 'USER'
     AND membership.organization_id = relationship.organization_id
     AND membership.user_id = %(actor_id)s
     AND membership.is_active
    LEFT JOIN core_user principal_user
      ON principal_user.id = membership.user_id
     AND principal_user.is_active
    LEFT JOIN core_role role
      ON role.id = membership.role_id
     AND role.organization_id = membership.organization_id
    LEFT JOIN core_serviceidentity service_identity
      ON %(actor_type)s = 'SERVICE'
     AND service_identity.id = %(actor_id)s
     AND service_identity.organization_id = relationship.organization_id
     AND service_identity.is_active
    WHERE relationship.organization_id = %(organization_id)s
      AND repository.id = %(repository_id)s
      AND source_connection.state IN ('ACTIVE', 'DEGRADED')
      AND snapshot.revoked_at IS NULL
      AND assertion.valid_until IS NULL
      AND relationship.review_state <> 'REJECTED'
      AND source_entity.is_active
      AND target_entity.is_active
      AND document.state = 'PRESENT'
      AND observation.status = 'PRESENT'
      AND observation.source_revision_id = document.current_revision_id
      AND observation.sync_run_id = document.last_seen_run_id
      AND EXISTS (
          SELECT 1
          FROM core_accessscopesource edge_scope_source
          WHERE edge_scope_source.organization_id = relationship.organization_id
            AND edge_scope_source.access_scope_id = edge_scope.id
            AND edge_scope_source.source_connection_id = source_connection.id
      )
      AND (
          (
              %(actor_type)s = 'USER'
              AND membership.id IS NOT NULL
              AND principal_user.id IS NOT NULL
          )
          OR (
              %(actor_type)s = 'SERVICE'
              AND service_identity.id IS NOT NULL
          )
      )
      AND (
          (
              %(actor_type)s = 'USER'
              AND role.code IN (
                  'ORG_ADMIN', 'KNOWLEDGE_ADMIN', 'TECHNICAL_OWNER',
                  'PRODUCT_OWNER', 'DEVELOPER', 'REVIEWER',
                  'SECURITY_REVIEWER', 'VIEWER'
              )
          )
          OR EXISTS (
              SELECT 1
              FROM core_accessgrant action_grant
              WHERE action_grant.organization_id = relationship.organization_id
                AND action_grant.action = %(action)s
                AND action_grant.revoked_at IS NULL
                AND (
                    action_grant.expires_at IS NULL
                    OR action_grant.expires_at > CURRENT_TIMESTAMP
                )
                AND (
                    action_grant.repository_id IS NULL
                    OR action_grant.repository_id = repository.id
                )
                AND action_grant.source_connection_id IS NULL
                AND (
                    (
                        %(actor_type)s = 'USER'
                        AND action_grant.membership_id = membership.id
                    )
                    OR (
                        %(actor_type)s = 'SERVICE'
                        AND action_grant.service_identity_id = service_identity.id
                    )
                )
          )
      )
      AND (
          %(credential_id)s::uuid IS NULL
          OR EXISTS (
              SELECT 1
              FROM core_repositoryaccesstoken credential
              WHERE credential.id = %(credential_id)s::uuid
                AND credential.organization_id = relationship.organization_id
                AND credential.repository_id = repository.id
                AND credential.service_identity_id = service_identity.id
                AND credential.revoked_at IS NULL
                AND credential.expires_at > CURRENT_TIMESTAMP
                AND credential.allowed_actions ? %(action)s
          )
      )
      AND (
          (
              %(actor_type)s = 'USER'
              AND (
                  edge_scope.all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership edge_member
                      WHERE edge_member.organization_id = relationship.organization_id
                        AND edge_member.access_scope_id = edge_scope.id
                        AND edge_member.membership_id = membership.id
                  )
              )
              AND (
                  source_scope.all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership source_member
                      WHERE source_member.organization_id = relationship.organization_id
                        AND source_member.access_scope_id = source_scope.id
                        AND source_member.membership_id = membership.id
                  )
              )
              AND (
                  target_scope.all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership target_member
                      WHERE target_member.organization_id = relationship.organization_id
                        AND target_member.access_scope_id = target_scope.id
                        AND target_member.membership_id = membership.id
                  )
              )
              AND (
                  assertion_scope.all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership assertion_member
                      WHERE assertion_member.organization_id = relationship.organization_id
                        AND assertion_member.access_scope_id = assertion_scope.id
                        AND assertion_member.membership_id = membership.id
                  )
              )
          )
          OR (
              %(actor_type)s = 'SERVICE'
              AND (
                  edge_scope.all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity edge_service
                      WHERE edge_service.organization_id = relationship.organization_id
                        AND edge_service.access_scope_id = edge_scope.id
                        AND edge_service.service_identity_id = service_identity.id
                  )
              )
              AND (
                  source_scope.all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity source_service
                      WHERE source_service.organization_id = relationship.organization_id
                        AND source_service.access_scope_id = source_scope.id
                        AND source_service.service_identity_id = service_identity.id
                  )
              )
              AND (
                  target_scope.all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity target_service
                      WHERE target_service.organization_id = relationship.organization_id
                        AND target_service.access_scope_id = target_scope.id
                        AND target_service.service_identity_id = service_identity.id
                  )
              )
              AND (
                  assertion_scope.all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity assertion_service
                      WHERE assertion_service.organization_id = relationship.organization_id
                        AND assertion_service.access_scope_id = assertion_scope.id
                        AND assertion_service.service_identity_id = service_identity.id
                  )
              )
          )
      )
      AND (
          (
              edge_scope.all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository edge_repository
                  WHERE edge_repository.organization_id = relationship.organization_id
                    AND edge_repository.access_scope_id = edge_scope.id
                    AND edge_repository.repository_id = repository.id
              )
          )
          AND (
              source_scope.all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository source_repository
                  WHERE source_repository.organization_id = relationship.organization_id
                    AND source_repository.access_scope_id = source_scope.id
                    AND source_repository.repository_id = repository.id
              )
          )
          AND (
              target_scope.all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository target_repository
                  WHERE target_repository.organization_id = relationship.organization_id
                    AND target_repository.access_scope_id = target_scope.id
                    AND target_repository.repository_id = repository.id
              )
          )
          AND (
              assertion_scope.all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository assertion_repository
                  WHERE assertion_repository.organization_id = relationship.organization_id
                    AND assertion_repository.access_scope_id = assertion_scope.id
                    AND assertion_repository.repository_id = repository.id
              )
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM core_accessscopesource governed_scope_source
          JOIN core_sourceconnection governed_source
            ON governed_source.id = governed_scope_source.source_connection_id
           AND governed_source.organization_id = governed_scope_source.organization_id
          WHERE governed_scope_source.organization_id = relationship.organization_id
            AND governed_scope_source.access_scope_id IN (
                edge_scope.id,
                source_scope.id,
                target_scope.id,
                assertion_scope.id
            )
            AND governed_source.state IN ('REVOKED', 'DISABLED')
      )
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
    authorize_action(
        actor=actor,
        repository_id=repository_id,
        action=Action.KNOWLEDGE_VIEW,
    )
    with connection.cursor() as cursor:
        cursor.execute(
            _GRAPH_SQL,
            {
                "organization_id": actor.organization_id,
                "repository_id": repository_id,
                "actor_type": actor.actor_type,
                "actor_id": uuid.UUID(actor.actor_id),
                "credential_id": actor.credential_id,
                "action": Action.KNOWLEDGE_VIEW.value,
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
