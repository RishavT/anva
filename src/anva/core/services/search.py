"""Permission-first hybrid search over immutable, source-backed chunks."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.db import connection

from anva.core.services.authorization import Action
from anva.core.services.context import ActorContext
from anva.core.services.ranking import RRF_K, RankingExplanation, phase_terms
from anva.core.services.retrieval import authorized_scope_ids
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
    JOIN core_sourceobservation observation
      ON observation.id = visibility.source_observation_id
     AND observation.organization_id = visibility.organization_id
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
      ON snapshot.id = visibility.access_snapshot_id
     AND snapshot.organization_id = visibility.organization_id
    WHERE chunk.organization_id = %(organization_id)s
      AND source_connection.repository_id = %(repository_id)s
      AND visibility.access_scope_id = ANY(%(scope_ids)s::uuid[])
      AND visibility.state = 'AVAILABLE'
      AND visibility.revoked_at IS NULL
      AND snapshot.revoked_at IS NULL
      AND document.state = 'PRESENT'
      AND observation.status = 'PRESENT'
      AND observation.source_revision_id = document.current_revision_id
      AND observation.sync_run_id = document.last_seen_run_id
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
) -> SearchResponse:
    """Authorize scopes before running either ranking branch in one bounded query."""
    normalized_query = " ".join(query.split())
    if not normalized_query or len(normalized_query) > MAX_QUERY_CHARACTERS:
        raise ValueError("query must contain between 1 and 500 characters")
    if limit < 1 or limit > MAX_SEARCH_RESULTS:
        raise ValueError("limit must contain between 1 and 100 results")

    # This evaluates the authorization boundary before the SQL contains ranking.
    scope_ids = list(
        authorized_scope_ids(
            actor=actor,
            repository_id=repository_id,
            action=Action.SEARCH,
        )
    )
    authorization_payload = {
        "organization_id": str(actor.organization_id),
        "repository_id": str(repository_id),
        "actor_type": actor.actor_type,
        "actor_id": actor.actor_id,
        "scope_ids": [str(scope_id) for scope_id in scope_ids],
    }
    authorization_hash = hashlib.sha256(
        json.dumps(
            authorization_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    if not scope_ids:
        return SearchResponse(
            query=normalized_query,
            authorization_hash=authorization_hash,
            results=(),
        )

    query_for_embedding = " ".join((normalized_query, *phase_terms(phase)))
    parameters: dict[str, Any] = {
        "organization_id": actor.organization_id,
        "repository_id": repository_id,
        "scope_ids": scope_ids,
        "index_version": INDEX_VERSION,
        "embedding_version": EMBEDDING_VERSION,
        "query": normalized_query,
        "embedding": _vector_literal(deterministic_embedding(query_for_embedding)),
        "candidate_limit": min(MAX_SEARCH_RESULTS * 2, max(limit * 4, 50)),
        "rrf_k": RRF_K,
        "result_limit": limit,
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
            source_location_id=row[5],
            source_observation_id=row[6],
            access_snapshot_id=row[7],
            observed_at=row[8],
            explanation=RankingExplanation(
                lexical_rank=row[9],
                semantic_rank=row[10],
                reciprocal_rank_score=float(row[11]),
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
