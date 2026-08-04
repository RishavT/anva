"""Permission-safe, typed, bounded traversal of the organization graph."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.db import connection

from anva.core.exceptions import ResourceNotFoundError
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    AuthorizedRepositoryScopes,
    authorize_action,
)
from anva.core.services.context import ActorContext

MAX_GRAPH_DEPTH = 4
MAX_GRAPH_DEGREE = 100
MAX_GRAPH_EDGES = 500
MAX_CANVAS_GRAPH_EDGES = 600

_GRAPH_SQL = """
WITH RECURSIVE
authorized_edges AS MATERIALIZED (
    SELECT
        repository.id AS repository_id,
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
                AND credential.issuer = %(token_issuer)s
                AND credential.audience = %(token_audience)s
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

_AUTHORIZED_EDGE_SELECT = (
    "WITH "
    + _GRAPH_SQL.partition("WITH RECURSIVE\n")[2].partition("\n),\nwalk AS (")[0]
    + """
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
    1 AS depth
FROM authorized_edges
ORDER BY relationship_id
LIMIT %(edge_limit)s
"""
)

_AUTHORIZED_INCIDENT_EDGE_SELECT = (
    "WITH "
    + _GRAPH_SQL.partition("WITH RECURSIVE\n")[2].partition("\n),\nwalk AS (")[0]
    + """
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
    1 AS depth
FROM authorized_edges
WHERE source_entity_id = %(entity_id)s OR target_entity_id = %(entity_id)s
ORDER BY relationship_id
LIMIT %(edge_limit)s
"""
)

_AUTHORIZED_INCIDENT_EDGE_BATCH_SELECT = """
WITH incident_relationships AS MATERIALIZED (
    SELECT relationship.*
    FROM core_knowledgerelationship relationship
    WHERE relationship.organization_id = %(organization_id)s
      AND (
          relationship.source_entity_id = %(entity_id)s
          OR relationship.target_entity_id = %(entity_id)s
      )
),
incident_semantics AS MATERIALIZED (
    SELECT
        relationship.organization_id,
        relationship.id AS relationship_id,
        relationship.relationship_type,
        relationship.source_entity_id,
        relationship.target_entity_id,
        relationship.source_entity_type,
        relationship.target_entity_type,
        source_entity.canonical_key AS source_key,
        source_entity.display_name AS source_name,
        source_entity.access_scope_id AS source_scope_id,
        target_entity.canonical_key AS target_key,
        target_entity.display_name AS target_name,
        target_entity.access_scope_id AS target_scope_id,
        relationship.assertion_id,
        assertion.access_scope_id AS assertion_scope_id,
        relationship.source_location_id,
        relationship.source_observation_id,
        relationship.access_snapshot_id,
        relationship.access_scope_id AS edge_scope_id,
        relationship.observed_at,
        relationship.confidence
    FROM incident_relationships relationship
    JOIN core_knowledgeentity source_entity
      ON source_entity.id = relationship.source_entity_id
     AND source_entity.organization_id = relationship.organization_id
    JOIN core_knowledgeentity target_entity
      ON target_entity.id = relationship.target_entity_id
     AND target_entity.organization_id = relationship.organization_id
    JOIN core_knowledgeassertion assertion
      ON assertion.id = relationship.assertion_id
     AND assertion.organization_id = relationship.organization_id
    WHERE relationship.review_state <> 'REJECTED'
      AND source_entity.is_active
      AND target_entity.is_active
      AND assertion.valid_until IS NULL
      AND (
          cardinality(%(related_entity_types)s::text[]) = 0
          OR CASE
              WHEN relationship.source_entity_id = %(entity_id)s
              THEN relationship.target_entity_type
              ELSE relationship.source_entity_type
          END = ANY(%(related_entity_types)s::text[])
      )
      AND (
          cardinality(%(status_filtered_entity_types)s::text[]) = 0
          OR NOT (
              CASE
                  WHEN relationship.source_entity_id = %(entity_id)s
                  THEN relationship.target_entity_type
                  ELSE relationship.source_entity_type
              END = ANY(%(status_filtered_entity_types)s::text[])
          )
          OR UPPER(
              COALESCE(
                  CASE
                      WHEN relationship.source_entity_id = %(entity_id)s
                      THEN target_entity.attributes ->> 'status'
                      ELSE source_entity.attributes ->> 'status'
                  END,
                  'UNKNOWN'
              )
          ) <> ALL(%(excluded_related_statuses)s::text[])
      )
),
scoped_incidents AS MATERIALIZED (
    SELECT
        incident.*,
        edge_scope.all_memberships AS edge_all_memberships,
        edge_scope.all_service_identities AS edge_all_service_identities,
        edge_scope.all_repositories AS edge_all_repositories,
        source_scope.all_memberships AS source_all_memberships,
        source_scope.all_service_identities AS source_all_service_identities,
        source_scope.all_repositories AS source_all_repositories,
        target_scope.all_memberships AS target_all_memberships,
        target_scope.all_service_identities AS target_all_service_identities,
        target_scope.all_repositories AS target_all_repositories,
        assertion_scope.all_memberships AS assertion_all_memberships,
        assertion_scope.all_service_identities AS assertion_all_service_identities,
        assertion_scope.all_repositories AS assertion_all_repositories
    FROM incident_semantics incident
    JOIN core_accessscope edge_scope
      ON edge_scope.id = incident.edge_scope_id
     AND edge_scope.organization_id = incident.organization_id
     AND edge_scope.is_active
    JOIN core_accessscope source_scope
      ON source_scope.id = incident.source_scope_id
     AND source_scope.organization_id = incident.organization_id
     AND source_scope.is_active
    JOIN core_accessscope target_scope
      ON target_scope.id = incident.target_scope_id
     AND target_scope.organization_id = incident.organization_id
     AND target_scope.is_active
    JOIN core_accessscope assertion_scope
      ON assertion_scope.id = incident.assertion_scope_id
     AND assertion_scope.organization_id = incident.organization_id
     AND assertion_scope.is_active
),
current_lineage AS MATERIALIZED (
    SELECT
        incident.*,
        document.source_container_id
    FROM scoped_incidents incident
    JOIN core_sourcelocation location
      ON location.id = incident.source_location_id
     AND location.organization_id = incident.organization_id
     AND location.source_observation_id = incident.source_observation_id
    JOIN core_sourceobservation observation
      ON observation.id = incident.source_observation_id
     AND observation.organization_id = incident.organization_id
    JOIN core_parsedsource parsed_source
      ON parsed_source.id = location.parsed_source_id
     AND parsed_source.organization_id = incident.organization_id
     AND parsed_source.source_revision_id = observation.source_revision_id
    JOIN core_sourcedocument document
      ON document.id = observation.source_document_id
     AND document.organization_id = incident.organization_id
    WHERE observation.status = 'PRESENT'
      AND document.state = 'PRESENT'
      AND observation.source_revision_id = document.current_revision_id
      AND observation.sync_run_id = document.last_seen_run_id
),
current_sources AS MATERIALIZED (
    SELECT
        incident.*,
        source_connection.id AS source_connection_id,
        repository.id AS repository_id
    FROM current_lineage incident
    JOIN core_sourcecontainer container
      ON container.id = incident.source_container_id
     AND container.organization_id = incident.organization_id
    JOIN core_sourceconnection source_connection
      ON source_connection.id = container.source_connection_id
     AND source_connection.organization_id = incident.organization_id
    JOIN core_repository repository
      ON repository.id = source_connection.repository_id
     AND repository.organization_id = incident.organization_id
     AND repository.is_active
    JOIN core_accesssnapshot snapshot
      ON snapshot.id = incident.access_snapshot_id
     AND snapshot.organization_id = incident.organization_id
     AND snapshot.source_connection_id = source_connection.id
     AND snapshot.access_scope_id = incident.edge_scope_id
    WHERE repository.id = ANY(%(repository_ids)s::uuid[])
      AND source_connection.state IN ('ACTIVE', 'DEGRADED')
      AND snapshot.revoked_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM core_accessscopesource edge_scope_source
          WHERE edge_scope_source.organization_id = incident.organization_id
            AND edge_scope_source.access_scope_id = incident.edge_scope_id
            AND edge_scope_source.source_connection_id = source_connection.id
      )
),
authorized_edges AS MATERIALIZED (
    SELECT
        edge.repository_id,
        edge.relationship_id,
        edge.relationship_type,
        edge.source_entity_id,
        edge.target_entity_id,
        edge.source_entity_type,
        edge.target_entity_type,
        edge.source_key,
        edge.source_name,
        edge.target_key,
        edge.target_name,
        edge.assertion_id,
        edge.source_location_id,
        edge.source_observation_id,
        edge.access_snapshot_id,
        edge.observed_at,
        edge.confidence
    FROM current_sources edge
    LEFT JOIN core_membership membership
      ON %(actor_type)s = 'USER'
     AND membership.organization_id = edge.organization_id
     AND membership.user_id = %(actor_id)s
     AND membership.is_active
    LEFT JOIN core_user principal_user
      ON principal_user.id = membership.user_id
     AND principal_user.is_active
    LEFT JOIN core_role role
      ON role.id = membership.role_id
     AND role.organization_id = edge.organization_id
    LEFT JOIN core_serviceidentity service_identity
      ON %(actor_type)s = 'SERVICE'
     AND service_identity.id = %(actor_id)s
     AND service_identity.organization_id = edge.organization_id
     AND service_identity.is_active
    WHERE (
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
              WHERE action_grant.organization_id = edge.organization_id
                AND action_grant.action = %(action)s
                AND action_grant.revoked_at IS NULL
                AND (
                    action_grant.expires_at IS NULL
                    OR action_grant.expires_at > CURRENT_TIMESTAMP
                )
                AND (
                    action_grant.repository_id IS NULL
                    OR action_grant.repository_id = edge.repository_id
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
                AND credential.organization_id = edge.organization_id
                AND credential.repository_id = edge.repository_id
                AND credential.service_identity_id = service_identity.id
                AND credential.revoked_at IS NULL
                AND credential.expires_at > CURRENT_TIMESTAMP
                AND credential.issuer = %(token_issuer)s
                AND credential.audience = %(token_audience)s
                AND credential.allowed_actions ? %(action)s
          )
      )
      AND (
          (
              %(actor_type)s = 'USER'
              AND (
                  edge.edge_all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership edge_member
                      WHERE edge_member.organization_id = edge.organization_id
                        AND edge_member.access_scope_id = edge.edge_scope_id
                        AND edge_member.membership_id = membership.id
                  )
              )
              AND (
                  edge.source_all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership source_member
                      WHERE source_member.organization_id = edge.organization_id
                        AND source_member.access_scope_id = edge.source_scope_id
                        AND source_member.membership_id = membership.id
                  )
              )
              AND (
                  edge.target_all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership target_member
                      WHERE target_member.organization_id = edge.organization_id
                        AND target_member.access_scope_id = edge.target_scope_id
                        AND target_member.membership_id = membership.id
                  )
              )
              AND (
                  edge.assertion_all_memberships
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopemembership assertion_member
                      WHERE assertion_member.organization_id = edge.organization_id
                        AND assertion_member.access_scope_id = edge.assertion_scope_id
                        AND assertion_member.membership_id = membership.id
                  )
              )
          )
          OR (
              %(actor_type)s = 'SERVICE'
              AND (
                  edge.edge_all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity edge_service
                      WHERE edge_service.organization_id = edge.organization_id
                        AND edge_service.access_scope_id = edge.edge_scope_id
                        AND edge_service.service_identity_id = service_identity.id
                  )
              )
              AND (
                  edge.source_all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity source_service
                      WHERE source_service.organization_id = edge.organization_id
                        AND source_service.access_scope_id = edge.source_scope_id
                        AND source_service.service_identity_id = service_identity.id
                  )
              )
              AND (
                  edge.target_all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity target_service
                      WHERE target_service.organization_id = edge.organization_id
                        AND target_service.access_scope_id = edge.target_scope_id
                        AND target_service.service_identity_id = service_identity.id
                  )
              )
              AND (
                  edge.assertion_all_service_identities
                  OR EXISTS (
                      SELECT 1 FROM core_accessscopeserviceidentity assertion_service
                      WHERE assertion_service.organization_id = edge.organization_id
                        AND assertion_service.access_scope_id = edge.assertion_scope_id
                        AND assertion_service.service_identity_id = service_identity.id
                  )
              )
          )
      )
      AND (
          (
              edge.edge_all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository edge_repository
                  WHERE edge_repository.organization_id = edge.organization_id
                    AND edge_repository.access_scope_id = edge.edge_scope_id
                    AND edge_repository.repository_id = edge.repository_id
              )
          )
          AND (
              edge.source_all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository source_repository
                  WHERE source_repository.organization_id = edge.organization_id
                    AND source_repository.access_scope_id = edge.source_scope_id
                    AND source_repository.repository_id = edge.repository_id
              )
          )
          AND (
              edge.target_all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository target_repository
                  WHERE target_repository.organization_id = edge.organization_id
                    AND target_repository.access_scope_id = edge.target_scope_id
                    AND target_repository.repository_id = edge.repository_id
              )
          )
          AND (
              edge.assertion_all_repositories
              OR EXISTS (
                  SELECT 1 FROM core_accessscoperepository assertion_repository
                  WHERE assertion_repository.organization_id = edge.organization_id
                    AND assertion_repository.access_scope_id = edge.assertion_scope_id
                    AND assertion_repository.repository_id = edge.repository_id
              )
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM core_accessscopesource governed_scope_source
          JOIN core_sourceconnection governed_source
            ON governed_source.id = governed_scope_source.source_connection_id
           AND governed_source.organization_id = governed_scope_source.organization_id
          WHERE governed_scope_source.organization_id = edge.organization_id
            AND governed_scope_source.access_scope_id IN (
                edge.edge_scope_id,
                edge.source_scope_id,
                edge.target_scope_id,
                edge.assertion_scope_id
            )
            AND governed_source.state IN ('REVOKED', 'DISABLED')
      )
),
partitioned_edges AS MATERIALIZED (
    SELECT
        edge.*,
        CASE
            WHEN edge.source_entity_id = %(entity_id)s THEN edge.target_entity_type
            ELSE edge.source_entity_type
        END AS related_entity_type,
        CASE
            WHEN edge.source_entity_id = %(entity_id)s THEN edge.target_name
            ELSE edge.source_name
        END AS related_entity_name,
        CASE
            WHEN edge.source_entity_id = %(entity_id)s THEN edge.target_entity_id
            ELSE edge.source_entity_id
        END AS related_entity_id,
        CASE
            WHEN cardinality(%(partition_related_entity_types)s::text[]) = 0 THEN 0
            WHEN CASE
                WHEN edge.source_entity_id = %(entity_id)s THEN edge.target_entity_type
                ELSE edge.source_entity_type
            END = ANY(%(partition_related_entity_types)s::text[])
            THEN 1
            ELSE 0
        END AS section_partition
    FROM authorized_edges edge
),
ranked_edges AS MATERIALIZED (
    SELECT
        edge.*,
        ROW_NUMBER() OVER (
            PARTITION BY edge.section_partition
            ORDER BY
                CASE
                    WHEN %(section_order)s = 'WORK'
                     AND edge.section_partition = 1
                    THEN edge.observed_at
                END DESC NULLS LAST,
                CASE
                    WHEN %(section_order)s IN ('CONTEXT', 'WORK')
                     AND (%(section_order)s <> 'WORK' OR edge.section_partition = 0)
                    THEN edge.related_entity_type
                END ASC NULLS LAST,
                CASE
                    WHEN %(section_order)s IN ('CONTEXT', 'WORK')
                     AND (%(section_order)s <> 'WORK' OR edge.section_partition = 0)
                    THEN LOWER(edge.related_entity_name)
                END ASC NULLS LAST,
                CASE
                    WHEN %(section_order)s IN ('CONTEXT', 'WORK')
                     AND (%(section_order)s <> 'WORK' OR edge.section_partition = 0)
                    THEN edge.related_entity_id
                END ASC NULLS LAST,
                CASE
                    WHEN %(section_order)s = 'WORK'
                     AND edge.section_partition = 1
                    THEN edge.relationship_id
                END DESC NULLS LAST,
                edge.relationship_id,
                edge.repository_id
        ) AS section_row
    FROM partitioned_edges edge
)
SELECT
    repository_id,
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
    1 AS depth
FROM ranked_edges
WHERE section_row <= %(edge_limit)s
ORDER BY section_partition, section_row
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
class RepositoryGraphEdge:
    repository_id: uuid.UUID
    edge: GraphEdge


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


def authorized_graph_edges(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    edge_limit: int = MAX_CANVAS_GRAPH_EDGES,
) -> tuple[tuple[GraphEdge, ...], bool]:
    """List one repository's fully authorized edges using the traversal's exact CTE."""
    if edge_limit < 1 or edge_limit > MAX_CANVAS_GRAPH_EDGES:
        raise ValueError("Canvas edge_limit must be between 1 and 600")
    authorize_action(
        actor=actor,
        repository_id=repository_id,
        action=Action.CANVAS_VIEW,
    )
    with connection.cursor() as cursor:
        cursor.execute(
            _AUTHORIZED_EDGE_SELECT,
            {
                "organization_id": actor.organization_id,
                "repository_id": repository_id,
                "actor_type": actor.actor_type,
                "actor_id": uuid.UUID(actor.actor_id),
                "credential_id": actor.credential_id,
                "token_issuer": settings.TOKEN_ISSUER,
                "token_audience": settings.TOKEN_AUDIENCE,
                "action": Action.CANVAS_VIEW.value,
                "edge_limit": edge_limit + 1,
            },
        )
        rows = cursor.fetchall()
    return tuple(GraphEdge(*row) for row in rows[:edge_limit]), len(rows) > edge_limit


def authorized_incident_graph_edges(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    entity_id: uuid.UUID,
    edge_limit: int = MAX_CANVAS_GRAPH_EDGES,
) -> tuple[tuple[GraphEdge, ...], bool]:
    """List strict authorized edges incident to one entity before applying its local cap."""
    if edge_limit < 1 or edge_limit > MAX_CANVAS_GRAPH_EDGES:
        raise ValueError("Canvas edge_limit must be between 1 and 600")
    authorize_action(
        actor=actor,
        repository_id=repository_id,
        action=Action.CANVAS_VIEW,
    )
    with connection.cursor() as cursor:
        cursor.execute(
            _AUTHORIZED_INCIDENT_EDGE_SELECT,
            {
                "organization_id": actor.organization_id,
                "repository_id": repository_id,
                "actor_type": actor.actor_type,
                "actor_id": uuid.UUID(actor.actor_id),
                "credential_id": actor.credential_id,
                "token_issuer": settings.TOKEN_ISSUER,
                "token_audience": settings.TOKEN_AUDIENCE,
                "action": Action.CANVAS_VIEW.value,
                "entity_id": entity_id,
                "edge_limit": edge_limit + 1,
            },
        )
        rows = cursor.fetchall()
    return tuple(GraphEdge(*row) for row in rows[:edge_limit]), len(rows) > edge_limit


def authorized_incident_graph_edges_batch(
    *,
    actor: ActorContext,
    authorization: AuthorizedRepositoryScopes,
    entity_id: uuid.UUID,
    edge_limit: int = MAX_CANVAS_GRAPH_EDGES,
    related_entity_types: tuple[str, ...] = (),
    status_filtered_entity_types: tuple[str, ...] = (),
    excluded_related_statuses: tuple[str, ...] = (),
    partition_related_entity_types: tuple[str, ...] = (),
    section_order: str = "RELATIONSHIP",
) -> tuple[tuple[RepositoryGraphEdge, ...], bool]:
    """List a bounded incident section from one actor-bound authorization snapshot."""
    ordered_repository_ids = authorization.repository_ids_for(Action.CANVAS_VIEW)
    boundary_repository_ids = tuple(repository.id for repository in authorization.repositories)
    if (
        not authorization.is_bound_to(actor)
        or ordered_repository_ids != boundary_repository_ids
        or (actor.credential_actions and Action.CANVAS_VIEW.value not in actor.credential_actions)
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if not ordered_repository_ids or len(ordered_repository_ids) > 100:
        raise ValueError("repository_ids must contain between 1 and 100 repositories")
    if edge_limit < 1 or edge_limit > MAX_CANVAS_GRAPH_EDGES:
        raise ValueError("Canvas edge_limit must be between 1 and 600")
    if any(not value or len(value) > 100 for value in related_entity_types):
        raise ValueError("related entity types must be non-empty bounded strings")
    if len(related_entity_types) > 20:
        raise ValueError("related entity type budget exceeded")
    if any(not value or len(value) > 100 for value in status_filtered_entity_types):
        raise ValueError("status-filtered entity types must be non-empty bounded strings")
    if len(status_filtered_entity_types) > 20:
        raise ValueError("status-filtered entity type budget exceeded")
    if status_filtered_entity_types and not related_entity_types:
        raise ValueError("status filtering requires a related entity type filter")
    if any(not value or len(value) > 100 for value in excluded_related_statuses):
        raise ValueError("excluded related statuses must be non-empty bounded strings")
    if len(excluded_related_statuses) > 20:
        raise ValueError("excluded related status budget exceeded")
    if any(not value or len(value) > 100 for value in partition_related_entity_types):
        raise ValueError("partition entity types must be non-empty bounded strings")
    if len(partition_related_entity_types) > 20:
        raise ValueError("partition entity type budget exceeded")
    if partition_related_entity_types and not related_entity_types:
        raise ValueError("partitioning requires a related entity type filter")
    if section_order not in {"RELATIONSHIP", "CONTEXT", "WORK"}:
        raise ValueError("unknown incident section order")
    if section_order != "RELATIONSHIP" and not related_entity_types:
        raise ValueError("section ordering requires a related entity type filter")
    if section_order == "WORK" and not partition_related_entity_types:
        raise ValueError("work ordering requires a partitioned related entity type")
    if actor.repository_id is not None and ordered_repository_ids != (actor.repository_id,):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    with connection.cursor() as cursor:
        cursor.execute(
            _AUTHORIZED_INCIDENT_EDGE_BATCH_SELECT,
            {
                "organization_id": actor.organization_id,
                "repository_ids": list(ordered_repository_ids),
                "actor_type": actor.actor_type,
                "actor_id": uuid.UUID(actor.actor_id),
                "credential_id": actor.credential_id,
                "token_issuer": settings.TOKEN_ISSUER,
                "token_audience": settings.TOKEN_AUDIENCE,
                "action": Action.CANVAS_VIEW.value,
                "entity_id": entity_id,
                "edge_limit": edge_limit + 1,
                "related_entity_types": list(related_entity_types),
                "status_filtered_entity_types": list(status_filtered_entity_types),
                "excluded_related_statuses": list(excluded_related_statuses),
                "partition_related_entity_types": list(partition_related_entity_types),
                "section_order": section_order,
            },
        )
        rows = cursor.fetchall()
    if partition_related_entity_types:
        partition_types = set(partition_related_entity_types)
        rows_by_partition: dict[bool, list[tuple[object, ...]]] = {False: [], True: []}
        for row in rows:
            related_type = row[6] if row[3] == entity_id else row[5]
            rows_by_partition[related_type in partition_types].append(row)
        truncated = any(
            len(partition_rows) > edge_limit for partition_rows in rows_by_partition.values()
        )
        rows = [
            row for partition in (False, True) for row in rows_by_partition[partition][:edge_limit]
        ]
    else:
        truncated = len(rows) > edge_limit
        rows = rows[:edge_limit]
    return (
        tuple(RepositoryGraphEdge(repository_id=row[0], edge=GraphEdge(*row[1:])) for row in rows),
        truncated,
    )


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
                "token_issuer": settings.TOKEN_ISSUER,
                "token_audience": settings.TOKEN_AUDIENCE,
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
