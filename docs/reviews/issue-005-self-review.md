# Issue 005 self-review

## Scope

Issue #5 adds permission-safe source search, typed graph traversal, deterministic context
packets, explanations, cache invalidation, evaluation metrics, and HTTP/CLI contracts. It does
not implement MCP transport, hosted embeddings, the management UI, or a new agent harness.

## Security and tenant isolation

- Authorization is evaluated before candidate ranking or recursive traversal.
- PostgreSQL queries rank only `authorized_chunks AS MATERIALIZED` and traverse only
  `authorized_edges AS MATERIALIZED`.
- Candidate relations filter tenant, repository, visible scope, source/document state,
  current revision, latest observation, and unrevoked snapshots.
- Same-tenant composite foreign keys protect every new cross-row retrieval relationship.
- Packet scopes are sealed to exactly the requesting principal and repository and derive from
  selected source scopes.
- Foreign and same-tenant hidden canary content is tested for search, score/order influence,
  and graph path influence.

## Reproducibility and integrity

- Chunk search indexes are immutable and versioned by FTS/vector index and embedding version.
- Embeddings are deterministic 32-dimensional hash vectors.
- Reciprocal-rank fusion uses a fixed `k=60`; scores and ties are stable.
- Packet selection has explicit tiers, stable tie breaks, deduplication, and enforced item,
  token, byte, and citation budgets.
- Required current policy fails closed when the budget cannot contain it.
- Every packet item includes provenance, freshness, inference status, selection reason, and a
  citation.
- Packet artifacts support exact reconstruction. Database triggers reject update/delete of
  indexes, packets, items, citations, and invalidations.
- Ingestion, corrections, and revocation append invalidations and advance a repository
  watermark without deleting history.

## Verification evidence

Targeted Compose tests cover:

- fresh migration with `pg_trgm` and `vector`;
- FTS GIN and pgvector HNSW indexes;
- ingestion-time index creation and database immutability;
- repeatable hybrid search;
- hidden candidate search/ranking and graph non-interference;
- graph types and hard caps;
- policy priority, budget failure, packet cache reuse, exact reconstruction, and invalidation;
- offline recall, precision, prohibited leakage, staleness, and citation metrics;
- generated JSON Schema/OpenAPI artifacts and deliberate MCP `501`.

The final PR records the full Docker Compose check and GitHub Actions result.

## Remaining limitations

The deterministic embedding is intentionally modest, graph traversal is directed, context
generation is synchronous, assertion classification relies on governed predicate/subject
conventions, and retrieval evaluation fixtures remain organization-owned data. These are
documented in the retrieval runbook and do not weaken the permission boundary.

