"""Permission-first hybrid search over immutable, source-backed chunks."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.db import connection

from anva.core.services.authorization import Action, authorize_action
from anva.core.services.context import ActorContext
from anva.core.services.ranking import RRF_K, RankingExplanation, phase_terms
from anva.core.services.search_index import (
    EMBEDDING_VERSION,
    INDEX_VERSION,
    deterministic_embedding,
)

MAX_QUERY_CHARACTERS = 500
MAX_SEARCH_RESULTS = 100

_SEARCH_SQL = """
WITH
authorized_chunks AS MATERIALIZED (
    SELECT DISTINCT ON (chunk.id)
        chunk.id AS chunk_id,
        chunk.text,
        chunk.content_hash,
        chunk.pointer,
        document.canonical_url,
        visibility.access_scope_id,
        visibility.source_location_id,
        visibility.source_observation_id,
        visibility.access_snapshot_id,
        visibility.observed_at,
        search_index.search_vector,
        search_index.embedding
    FROM core_sourcechunksearchindex search_index
    JOIN core_sourcechunk chunk
      ON chunk.id = search_index.source_chunk_id
     AND chunk.organization_id = search_index.organization_id
    JOIN core_sourcechunkvisibility visibility
      ON visibility.source_chunk_id = chunk.id
     AND visibility.organization_id = chunk.organization_id
    JOIN core_sourcelocation location
      ON location.id = visibility.source_location_id
     AND location.organization_id = visibility.organization_id
     AND location.source_observation_id = visibility.source_observation_id
     AND location.parsed_source_id = chunk.parsed_source_id
    JOIN core_sourceobservation observation
      ON observation.id = visibility.source_observation_id
     AND observation.organization_id = visibility.organization_id
    JOIN core_parsedsource parsed_source
      ON parsed_source.id = chunk.parsed_source_id
     AND parsed_source.organization_id = chunk.organization_id
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
     ON snapshot.id = visibility.access_snapshot_id
     AND snapshot.organization_id = visibility.organization_id
     AND snapshot.source_connection_id = source_connection.id
     AND snapshot.access_scope_id = visibility.access_scope_id
    JOIN core_accessscope scope
      ON scope.id = visibility.access_scope_id
     AND scope.organization_id = visibility.organization_id
     AND scope.is_active
    LEFT JOIN core_membership membership
      ON %(actor_type)s = 'USER'
     AND membership.organization_id = chunk.organization_id
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
     AND service_identity.organization_id = chunk.organization_id
     AND service_identity.is_active
    WHERE chunk.organization_id = %(organization_id)s
      AND repository.id = %(repository_id)s
      AND source_connection.state IN ('ACTIVE', 'DEGRADED')
      AND visibility.state = 'AVAILABLE'
      AND (
          %(source_location_ids)s::uuid[] IS NULL
          OR visibility.source_location_id = ANY(%(source_location_ids)s::uuid[])
      )
      AND visibility.revoked_at IS NULL
      AND snapshot.revoked_at IS NULL
      AND document.state = 'PRESENT'
      AND observation.status = 'PRESENT'
      AND observation.source_revision_id = document.current_revision_id
      AND observation.sync_run_id = document.last_seen_run_id
      AND EXISTS (
          SELECT 1
          FROM core_accessscopesource scope_source
          WHERE scope_source.organization_id = chunk.organization_id
            AND scope_source.access_scope_id = scope.id
            AND scope_source.source_connection_id = source_connection.id
      )
      AND (
          scope.all_repositories
          OR EXISTS (
              SELECT 1
              FROM core_accessscoperepository scope_repository
              WHERE scope_repository.organization_id = chunk.organization_id
                AND scope_repository.access_scope_id = scope.id
                AND scope_repository.repository_id = repository.id
          )
      )
      AND (
          (
              %(actor_type)s = 'USER'
              AND membership.id IS NOT NULL
              AND principal_user.id IS NOT NULL
              AND (
                  scope.all_memberships
                  OR EXISTS (
                      SELECT 1
                      FROM core_accessscopemembership scope_membership
                      WHERE scope_membership.organization_id = chunk.organization_id
                        AND scope_membership.access_scope_id = scope.id
                        AND scope_membership.membership_id = membership.id
                  )
              )
          )
          OR (
              %(actor_type)s = 'SERVICE'
              AND service_identity.id IS NOT NULL
              AND (
                  scope.all_service_identities
                  OR EXISTS (
                      SELECT 1
                      FROM core_accessscopeserviceidentity scope_service
                      WHERE scope_service.organization_id = chunk.organization_id
                        AND scope_service.access_scope_id = scope.id
                        AND scope_service.service_identity_id = service_identity.id
                  )
              )
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
              WHERE action_grant.organization_id = chunk.organization_id
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
                AND credential.organization_id = chunk.organization_id
                AND credential.repository_id = repository.id
                AND credential.service_identity_id = service_identity.id
                AND credential.revoked_at IS NULL
                AND credential.expires_at > CURRENT_TIMESTAMP
                AND credential.allowed_actions ? %(action)s
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM core_accessscopesource blocked_scope_source
          JOIN core_sourceconnection blocked_source
            ON blocked_source.id = blocked_scope_source.source_connection_id
           AND blocked_source.organization_id = blocked_scope_source.organization_id
          WHERE blocked_scope_source.organization_id = chunk.organization_id
            AND blocked_scope_source.access_scope_id = scope.id
            AND blocked_source.state IN ('REVOKED', 'DISABLED')
      )
      AND search_index.index_version = %(index_version)s
      AND search_index.embedding_version = %(embedding_version)s
    ORDER BY chunk.id, visibility.observed_at DESC, visibility.id
),
query_input AS (
    SELECT websearch_to_tsquery('simple', %(query)s) AS ts_query
),
lexical AS (
    SELECT
        candidate.chunk_id,
        row_number() OVER (
            ORDER BY
                ts_rank_cd(candidate.search_vector, query_input.ts_query) DESC,
                candidate.chunk_id
        ) AS lexical_rank
    FROM authorized_chunks candidate
    CROSS JOIN query_input
    WHERE candidate.search_vector @@ query_input.ts_query
    ORDER BY
        ts_rank_cd(candidate.search_vector, query_input.ts_query) DESC,
        candidate.chunk_id
    LIMIT %(candidate_limit)s
),
semantic AS (
    SELECT
        candidate.chunk_id,
        row_number() OVER (
            ORDER BY candidate.embedding <=> %(embedding)s::vector, candidate.chunk_id
        ) AS semantic_rank
    FROM authorized_chunks candidate
    ORDER BY candidate.embedding <=> %(embedding)s::vector, candidate.chunk_id
    LIMIT %(candidate_limit)s
),
fused AS (
    SELECT
        candidate_id AS chunk_id,
        min(lexical_rank) AS lexical_rank,
        min(semantic_rank) AS semantic_rank,
        sum(score) AS rrf_score
    FROM (
        SELECT
            lexical.chunk_id AS candidate_id,
            lexical.lexical_rank,
            NULL::bigint AS semantic_rank,
            1.0 / (%(rrf_k)s + lexical.lexical_rank) AS score
        FROM lexical
        UNION ALL
        SELECT
            semantic.chunk_id AS candidate_id,
            NULL::bigint AS lexical_rank,
            semantic.semantic_rank,
            1.0 / (%(rrf_k)s + semantic.semantic_rank) AS score
        FROM semantic
    ) ranked
    GROUP BY candidate_id
)
SELECT
    candidate.chunk_id,
    candidate.text,
    candidate.content_hash,
    candidate.pointer,
    candidate.canonical_url,
    candidate.access_scope_id,
    candidate.source_location_id,
    candidate.source_observation_id,
    candidate.access_snapshot_id,
    candidate.observed_at,
    fused.lexical_rank,
    fused.semantic_rank,
    fused.rrf_score
FROM fused
JOIN authorized_chunks candidate ON candidate.chunk_id = fused.chunk_id
ORDER BY fused.rrf_score DESC, candidate.chunk_id
LIMIT %(result_limit)s
"""


@dataclass(frozen=True, slots=True)
class SearchResult:
    """A source-backed result returned only after visibility filtering."""

    chunk_id: uuid.UUID
    text: str
    content_hash: str
    pointer: str
    canonical_url: str
    access_scope_id: uuid.UUID
    source_location_id: uuid.UUID
    source_observation_id: uuid.UUID
    access_snapshot_id: uuid.UUID
    observed_at: datetime
    explanation: RankingExplanation

    def as_dict(self) -> dict[str, object]:
        return {
            "chunk_id": str(self.chunk_id),
            "text": self.text,
            "content_hash": self.content_hash,
            "pointer": self.pointer,
            "canonical_url": self.canonical_url,
            "access_scope_id": str(self.access_scope_id),
            "source_location_id": str(self.source_location_id),
            "source_observation_id": str(self.source_observation_id),
            "access_snapshot_id": str(self.access_snapshot_id),
            "observed_at": self.observed_at.isoformat(),
            "explanation": self.explanation.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class SearchResponse:
    query: str
    authorization_hash: str
    results: tuple[SearchResult, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "query": self.query,
            "authorization_hash": self.authorization_hash,
            "results": [result.as_dict() for result in self.results],
        }


def _vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(format(value, ".12g") for value in vector) + "]"


def search_chunks(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    query: str,
    phase: str | None = None,
    limit: int = 20,
    source_location_ids: tuple[uuid.UUID, ...] | None = None,
) -> SearchResponse:
    """Authorize scopes before running either ranking branch in one bounded query."""
    normalized_query = " ".join(query.split())
    if not normalized_query or len(normalized_query) > MAX_QUERY_CHARACTERS:
        raise ValueError("query must contain between 1 and 500 characters")
    if limit < 1 or limit > MAX_SEARCH_RESULTS:
        raise ValueError("limit must contain between 1 and 100 results")
    if source_location_ids is not None and len(source_location_ids) > 2_000:
        raise ValueError("source location scope exceeds 2000 entries")

    authorize_action(
        actor=actor,
        repository_id=repository_id,
        action=Action.SEARCH,
    )
    authorization_payload = {
        "organization_id": str(actor.organization_id),
        "repository_id": str(repository_id),
        "actor_type": actor.actor_type,
        "actor_id": actor.actor_id,
        "credential_id": str(actor.credential_id) if actor.credential_id else None,
        "action": Action.SEARCH.value,
        "source_location_ids": (
            sorted(str(value) for value in source_location_ids)
            if source_location_ids is not None
            else None
        ),
    }
    authorization_hash = hashlib.sha256(
        json.dumps(
            authorization_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    query_for_embedding = " ".join((normalized_query, *phase_terms(phase)))
    parameters: dict[str, Any] = {
        "organization_id": actor.organization_id,
        "repository_id": repository_id,
        "actor_type": actor.actor_type,
        "actor_id": uuid.UUID(actor.actor_id),
        "credential_id": actor.credential_id,
        "action": Action.SEARCH.value,
        "index_version": INDEX_VERSION,
        "embedding_version": EMBEDDING_VERSION,
        "query": normalized_query,
        "embedding": _vector_literal(deterministic_embedding(query_for_embedding)),
        "candidate_limit": min(MAX_SEARCH_RESULTS * 2, max(limit * 4, 50)),
        "rrf_k": RRF_K,
        "result_limit": limit,
        "source_location_ids": (
            list(source_location_ids) if source_location_ids is not None else None
        ),
    }
    with connection.cursor() as cursor:
        cursor.execute(_SEARCH_SQL, parameters)
        rows = cursor.fetchall()
    results = tuple(
        SearchResult(
            chunk_id=row[0],
            text=row[1],
            content_hash=row[2],
            pointer=row[3],
            canonical_url=row[4],
            access_scope_id=row[5],
            source_location_id=row[6],
            source_observation_id=row[7],
            access_snapshot_id=row[8],
            observed_at=row[9],
            explanation=RankingExplanation(
                lexical_rank=row[10],
                semantic_rank=row[11],
                reciprocal_rank_score=float(row[12]),
                phase=phase.upper() if phase else None,
                phase_terms=phase_terms(phase),
            ),
        )
        for row in rows
    )
    return SearchResponse(
        query=normalized_query,
        authorization_hash=authorization_hash,
        results=results,
    )
