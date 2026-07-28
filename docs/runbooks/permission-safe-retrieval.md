# Permission-safe retrieval

## Purpose

Anva retrieval returns reproducible, source-backed context without allowing inaccessible
knowledge to influence ranking, graph traversal, packet selection, explanations, or cache
identity. The implementation is local and deterministic: PostgreSQL full-text search,
pgvector, a versioned hash embedding, and reciprocal-rank fusion.

## Interfaces

All HTTP routes are beneath `/api/v1` and require a repository-scoped bearer token:

- `POST /search` accepts `repository_id`, `query`, optional `phase`, and optional `limit`.
- `POST /query` returns search results and optionally a bounded graph when
  `start_entity_id` is supplied.
- `POST /context-packets` accepts `repository_id`, `task`, `phase`, and an optional
  item/token/byte/citation `budget`.
- `GET /context-packets/{packet_id}?repository_id=...` returns the exact immutable payload.
- Entity relationship, history, source, and assertion explanation routes support visual
  clients without bypassing the same authorization boundary.

The CLI uses the token only from `ANVA_TOKEN`:

```bash
docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva search --repository-id <uuid> --query "deployment reviewers" --phase PREFLIGHT

docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva context --repository-id <uuid> --task "prepare checkout" --phase PREFLIGHT

docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva packet --repository-id <uuid> <packet-uuid>
```

The MCP process and `/api/v1/mcp/context` route deliberately return `501 Not Implemented`.
Issue #9 owns the protocol transport. The packet service and contracts are reusable by that
future adapter.

## Authorization and ranking

Search and graph resolve the action before executing their bounded SQL, then independently bind
the current database principal, role or grant, repository credential, repository, source,
snapshot, parser lineage, and scope memberships inside the authoritative materialized relation.
Lexical and semantic candidates can read only `authorized_chunks AS MATERIALIZED`; recursive
traversal can read only `authorized_edges AS MATERIALIZED`. Endpoint scopes are authorized
before entity names enter the graph walk, so hidden intermediate nodes cannot influence paths.

Search is bounded to 100 results. Graph traversal has hard ceilings of depth 4, degree 100,
and 500 returned edges. Ties use stable UUID ordering. The current embedding version is
`hash-32-v1`; it is intentionally deterministic and dependency-free, not a claim of
state-of-the-art semantic quality.

## Context packet behavior

Selection order is deterministic:

1. applicable required current policy;
2. direct authorized relationships;
3. phase-relevant assertions;
4. other policy and source excerpts;
5. decisions and incidents;
6. authorized conflicts.

Every selected item contains provenance, freshness, inference status, selection reason,
ranking information, and at least one normalized citation. Provenance is filtered through the
current repository/source/snapshot/parser lineage before candidate formation. Each item receives
its own sealed scope derived from every contributing content and citation scope; the packet scope
is then derived from those item intersections. A required current policy that cannot fit causes
`required_policy_budget_exceeded`; it is never silently dropped.

Packet records, items, citations, search indexes, and invalidations are immutable in
PostgreSQL. An artifact stores the exact original response. The cache key includes normalized
request, actor, repository, authorized scope revisions, access-snapshot hashes, retrieval
watermark, and algorithm/index/embedding versions. Ingestion, assertion review corrections,
source revocation, and permission-schema changes advance the watermark and append invalidations.
Packet reads and cache reuse reauthorize every current item parent and citation lineage. An
invalidated, hidden, revoked, stale-lineage, or missing packet returns the same not-found
contract; immutable historical rows remain stored for audit but are not returned.

## Evaluation

`anva.core.services.retrieval_evals` loads bounded JSONL cases and reports:

- recall@k and precision@k;
- prohibited-content leakage rate;
- stale-before-current preference rate;
- citation coverage.

The checked-in CI-safe example is `tests/fixtures/retrieval-eval.jsonl`. Production evaluation
sets should use stable content hashes and explicit prohibited hashes, contain no source
credentials, and be reviewed like test code.

## Operational checks

Run the complete Docker-only gate:

```bash
make check
```

Confirm PostgreSQL has `vector` and `pg_trgm`, plus
`core_chunk_embedding_hnsw` and `core_chunk_search_fts_gin`, when diagnosing index behavior.
Any embedding or ranking algorithm change requires a new version string and evaluation
comparison; never rewrite an existing index row or packet.

## Current limitations

- Structured assertion matching is bounded and deterministic but does not yet have a
  dedicated policy language or repository profile model.
- The local hash embedding is a reproducible baseline. Operators should not infer general
  language understanding from semantic matches.
- Graph traversal is directed and follows outgoing relationships.
- Context generation is synchronous and creates sealed actor-specific per-item intersections
  plus a packet scope derived from those item scopes.
- Corrections are represented by governed assertion review transitions; richer proposal-based
  correction workflows remain later work.
- MCP transport, hosted embedding providers, rerankers, UI visualization, and distributed
  cache coordination are outside issue #5.
