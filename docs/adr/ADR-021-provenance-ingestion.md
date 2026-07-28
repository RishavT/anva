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
review.

Commit bounded `SourceChunk` records and observation-specific `SourceChunkVisibility` records so
retrieval can filter before ranking without reparsing. Commit normalized `KnowledgeRelationship`
edges with typed entity endpoints, assertion/location/observation provenance, confidence, and
scope. PostgreSQL validates actual endpoint types and the allowed type pairs for each edge kind.

The first connector is a read-only mounted filesystem. It opens each path component with
`O_NOFOLLOW`, accepts regular files only, never imports or executes source code, rejects unsafe
YAML aliases and remote OpenAPI references, and applies central byte/node/depth/page limits.

## Consequences

- Historical evidence and visibility changes are independently reconstructable.
- Revocation can close index visibility without deleting shared immutable content.
- Search and graph consumers can use committed chunks and edges rather than inventing knowledge.
- PostgreSQL stores raw bytes for this MVP; object-storage offload can preserve the same identity.
- Filesystem incremental sync still performs bounded discovery because a mount has no trustworthy
  change feed; revision, parser, extraction, and cursor writes remain idempotent.
- Adding a remote connector requires a separate credential and SSRF threat review but does not
  change the persistence chain.
