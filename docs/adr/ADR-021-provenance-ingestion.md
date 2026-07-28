# ADR-021: Immutable provenance with observation-scoped visibility

- Status: Accepted
- Date: 2026-07-28

## Context

Anva must ingest large, messy organizational corpora without treating files as instructions,
losing history, widening access, or forcing later search/graph work to reparse source documents.
A logical document may move from content A to B and back to A, parser and extractor versions may
change independently, and permissions may change while bytes remain unchanged.

## Decision

Use a connector-neutral chain:

`SourceConnection → SourceContainer → SourceDocument → SourceRevision → SourceObservation →
ParsedSource → SourceLocation → ExtractionResult`.

Raw bytes and parser derivations are immutable and content addressed. A logical document has one
revision per content hash, so A→B→A produces two revisions and three observations. Visibility is
not a property of raw bytes or revisions. Every observation carries an immutable access snapshot;
assertion provenance, chunk visibility, and relationships repeat that snapshot and scope, with
PostgreSQL triggers validating alignment.

Parsers and extractors have explicit, separate taxonomies and version identities. Parser upgrades
create new derivations from the same revision. Automatic ingestion enables only deterministic
mechanical extraction. Conflicting assertions and ambiguous entity resolutions are retained for
review. Derived assertion identity includes both the extraction version and immutable access scope.
An ACL-only observation therefore closes the prior assertion interval and creates a new scoped
assertion and edge without duplicating the raw revision. Retrieval exposes active assertion
intervals and chunks from the document's latest observation only.

Commit bounded `SourceChunk` records and observation-specific `SourceChunkVisibility` records so
retrieval can filter before ranking without reparsing. Commit normalized `KnowledgeRelationship`
edges with typed entity endpoints, assertion/location/observation provenance, confidence, and
scope. PostgreSQL validates actual endpoint types and the allowed type pairs for each edge kind.

The first connector is a read-only mounted filesystem. It opens each path component with
`O_NOFOLLOW`, accepts regular files only, never imports or executes source code, rejects unsafe
YAML aliases and remote OpenAPI references, and applies central byte/node/depth/page limits.
Discovery uses globally ordered priority traversal rather than an eager complete-corpus sort.
Unsafe individual paths become bounded item failures so safe siblings continue.

Incremental discovery cursors are opaque to the orchestrator but persisted in a run-bound envelope.
A retry restores the connector cursor and reconstructs prior progress from committed observations
and failures. Authority is revalidated after fetch and parsing, and the source plus access snapshot
are row-locked across document persistence and final publication. Terminal sync states cannot
transition back into publishing.

PostgreSQL is authoritative for ingestion payload identity. `pgcrypto` triggers recompute SHA-256
over raw bytes, UTF-8 chunks, and recursively canonicalized JSONB parser/extractor output, including
bulk and direct insertion paths that bypass model `save()`.

## Consequences

- Historical evidence and visibility changes are independently reconstructable.
- Revocation can close index visibility without deleting shared immutable content.
- Revocation linearizes against document persistence and final publication through source-row
  locking; work that observes revocation cannot publish derived state or complete the run.
- Search and graph consumers can use committed chunks and edges rather than inventing knowledge.
- PostgreSQL stores raw bytes for this MVP; object-storage offload can preserve the same identity.
- Filesystem incremental sync still performs bounded discovery because a mount has no trustworthy
  change feed; revision, parser, extraction, and cursor writes remain idempotent.
- Adding a remote connector requires a separate credential and SSRF threat review but does not
  change the persistence chain.
