# Issue #4 self-review: Provenance-preserving source ingestion

- Date: 2026-07-28
- Reviewer: implementing agent
- Scope: `RishavT/anva#4`
- Result: Accepted after findings below were fixed

## Acceptance-criteria review

| Requirement | Evidence | Result |
| --- | --- | --- |
| Connector/parser/extractor abstractions and distinct taxonomies | Typed protocols, dataclasses, registries, and exhaustive one-parser routing test | Pass |
| Durable provenance chain | Source connection/container/document/revision/observation/parser/location/extraction models plus composite tenant constraints | Pass |
| Unchanged, changed, and A→B→A | PostgreSQL and orchestration tests prove revision reuse with every observation retained | Pass |
| Parser-version derivations | Same immutable revision accepts distinct version outputs and rejects duplicate version identity | Pass |
| Raw content and visibility separated | Content/revision have no scope snapshot; observation, assertion provenance, chunk visibility, and edges carry validated snapshots | Pass |
| Temporal assertions, conflicts, and review signals | Close-once validity intervals, reappearance reopening, retained conflict pairs, ambiguous entity-resolution outcome | Pass |
| Safe mounted filesystem | Read-only connector, `openat`/`O_NOFOLLOW`, regular files, allowlisted roots, no execution | Pass |
| Required document types as data | Markdown, YAML 1.2, JSON, text, CODEOWNERS, manifests, migrations, workflows, and OpenAPI parsers | Pass |
| Adversarial safety and limits | Symlink/special/path, YAML alias, nested input, malformed item, remote ref, prompt text, and file limit tests | Pass |
| Idempotent staged jobs/cursors/outbox | PostgreSQL leases/retries, explicit handler allowlist, stage record, versioned cursor, transition audit/outbox | Pass |
| Tombstones and reappearance | Full-sync deletion closes visibility/assertions; same bytes reappear under the historical revision | Pass |
| Authorization and revocation | Auth before idempotency/no-op, immutable snapshot propagation, queued cancellation, claimed/page/item revalidation | Pass |
| Filter before ranking/traversal | Authorized chunk and relationship querysets apply tenant/scope/snapshot/document state first | Pass |
| Chunks and normalized relationship edges | Immutable chunks plus observation visibility; typed, scoped, provenance-bearing edges with PostgreSQL endpoint validation | Pass |
| API/CLI/contracts | Connect, sync, inspect, resync, history, revoke routes and token-from-environment Python CLI; generated OpenAPI | Pass |
| Realistic read-only corpus | Optional Compose override ingested sibling `anva-test` corpus and preserved representative SHA-256 fingerprints | Pass |

## Findings fixed during self-review

1. A revision initially carried an access snapshot, which made unchanged content under a new
   permission snapshot impossible to reuse. Visibility now belongs to observations and derived
   visibility records.
2. One generic PostgreSQL trigger referenced record fields from several table shapes. PostgreSQL
   correctly rejected it at runtime; table-specific validation functions replaced it.
3. Connector traversal was deterministic within a directory but not globally, which could skip a
   nested path after cursor resume. Discovery now sorts the bounded complete relative-path set.
4. The first YAML loader applied YAML 1.1 booleans and converted GitHub Actions `on:` into a
   non-string key. A safe YAML 1.2 boolean resolver fixed the real-corpus failure.
5. Source revocation originally relied only on the claimed handler check. It now also cancels
   queued jobs and active runs while claimed jobs revalidate before each page and item.
6. Early persistence had assertions but no committed retrieval chunks or normalized edges.
   `SourceChunk`, `SourceChunkVisibility`, and typed `KnowledgeRelationship` now make #5 a consumer,
   not a reparsing/invention layer.
7. Cursor updates initially replaced opaque values without incrementing revision. Row-locked
   updates now advance the cursor revision.
8. Source selection used `select_for_update` across a nullable outer join, which PostgreSQL rejects.
   The lock now targets the source row only.

## Known limitations

- The only connector is a locally mounted read-only filesystem; remote providers are later issues.
- Filesystem incremental mode still needs bounded discovery because there is no authoritative
  provider change feed; content and derivation writes remain incremental and idempotent.
- Raw bytes are retained in PostgreSQL for the MVP rather than offloaded to object storage.
- Mechanical extraction intentionally recognizes a conservative set of explicit ownership,
  dependency, heading, CODEOWNERS, and migration tokens. Interpretive extraction requires a
  separate reviewed model/evidence path.
- Production erasure policy, remote-source credential lifecycle, and fine-grained operational
  metrics/alerting remain follow-up work.

## Verification evidence

- Focused connector/parser/provenance/orchestration/worker suite: 25 tests passed before the
  external corpus addition; parser suite then passed 12 tests including YAML 1.2 workflow input.
- API, CLI, and generated contract suite: 19 tests passed.
- Sibling `anva-test` read-only corpus: 1 test passed, 187.26 seconds.
- Final Compose gate: format and Ruff passed; strict mypy passed across 70 source files; no
  migration drift; 16 generated contract artifacts verified; 131 tests passed, the corpus-only
  test skipped without its optional mount, and total coverage was 85%.
