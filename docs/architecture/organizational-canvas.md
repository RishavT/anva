# Organizational Canvas architecture

## Boundary

The Organizational Canvas is a permission-filtered semantic projection over
canonical knowledge. It is not a second knowledge graph and it is not a
free-form whiteboard. Nodes retain canonical `KnowledgeEntity` UUIDs and
relationships retain canonical `KnowledgeRelationship` UUIDs. Canvas-owned
state is limited to a saved question, presentation coordinates, groups,
annotations, filters, layers, and share metadata.

The server is authoritative. Browser code receives only the already-authorized
projection and never receives hidden records for client-side filtering.

## Persisted model

- `CanvasView` is organization-owned, optionally repository/scope-bound, and
  records its human owner and current revision.
- `CanvasViewRevision` seals the closed semantic query and the complete
  presentation payload with a SHA-256 content hash. Revisions are append-only.
- `CanvasNodePlacement`, `CanvasGroup`, `CanvasFilter`, `CanvasLayer`, and
  `CanvasAnnotation` are immutable children of one exact revision.
- `CanvasShare` names one exact revision. It may be recipient-bound, expired,
  or revoked, but it never grants knowledge access. Revocation records the
  actor, timestamp, idempotency key, and request hash without deleting history.
- relationship drawing creates a typed `KnowledgeProposal` with source and
  target revisions. It does not insert a canonical relationship.

PostgreSQL composite foreign keys enforce same-organization links. Additional
guards bind shares to revisions of the selected view and groups to placements
of the same revision. Database triggers reject updates and deletes of revisions
and their presentation children, including bulk ORM and direct SQL paths.

## Read pipeline and authorization

For every request the service:

1. authenticates the current user session or service bearer actor;
2. authorizes repository boundaries before applying the 100-repository default
   cap (and rejects an explicit missing, foreign, or inaccessible identifier);
3. runs the existing strict repository authorization and provenance CTE for
   each repository independently;
4. unions only those permitted entity and edge results by canonical UUID;
5. applies the closed typed semantic query, observation-time boundary, layer
   selection, and optional four-hop focus expansion;
6. computes deterministic semantic-column placement, citations, freshness,
   conflicts, inspector summaries, and a layout checksum;
7. serializes compact, unescaped UTF-8 JSON, measures those actual response
   bytes, and trims deterministically to the hard response budget.

Repository UUIDs embedded in a semantic query are organization-bound and
authorization-checked at create, save, replay, list, detail, share, and revoke
boundaries. Persisted references cannot be used to bypass a later permission
change. Presentation input is recursively validated as closed JSON; unknown
children, scalar coercions, non-JSON values, non-finite coordinates, and
secret-shaped text at any supported nesting depth are rejected.

Saved-view discovery applies its 300-view cap only after a parameterized
PostgreSQL candidate query has checked the current revision and its live
repository, scope, governed-source, semantic-repository, and root-entity
boundaries against one resolved authorization snapshot. Legacy semantic JSON
is inspected by JSON type and UUID text equality rather than an unsafe cast, so
malformed values fail closed. The bounded candidates still pass through the
ordinary per-view service authorization before any metadata is returned.

The same strict edge CTE is used by the Canvas projection and path service. A
path is bounded to six hops and can contain only nodes and edges visible through
the selected repository set. Missing, foreign, revoked, and inaccessible
identifiers all use the same unavailable response.

Inspector detail uses four fixed invocations of a strict incident-edge variant
of that CTE against the same resolved authorization snapshot. The selected
entity and section type/status predicates are applied before independent `+1`
sentinel bounds: 50 relationships, 20 decisions/policies, 20 risks/incidents,
and separate 20-item active-work and recent-pull-request partitions. Pull
requests retain descending observation-time order and inactive work is removed
before ranking. The permitted endpoints from those sections are unioned for one
bounded hydration query. Selection-scoped questions and their server-rendered
Explorer fallback share one scope resolver. It authorizes the selected entity,
its bounded one-hop endpoints, and their assertions, then maps claim locations
to distinct current indexed root locations by source observation. Search
receives only that bounded root-location set.

Shares re-run this pipeline against the viewer's current permissions. A share
can therefore lose nodes or become unavailable as authorization changes. The
owner or current view manager may revoke an active share with optimistic
revision checking and request-bound idempotency. Revocation is immediate and
auditable, and a revoked share retains its immutable history.

## Determinism and budgets

The normative limits are:

| Resource | Limit |
| --- | ---: |
| Repositories in a projection | 100 |
| Visible nodes | 300 |
| Visible relationships | 600 |
| Semantic focus depth | 4 hops |
| Why-connected path | 6 hops |
| Request or response payload | 750 KiB UTF-8 JSON |

Entities and relationships are ordered by stable UUID. Initial coordinates are
derived from a versioned semantic-column algorithm; saved pins override those
coordinates. When a payload would exceed 750 KiB, edges and then nodes are
trimmed by their deterministic order, counts and checksum are recomputed, and
the response reports truncation and its limitation. Non-finite or unbounded
coordinates are rejected.

An optional `as_of` value includes only entities created by that instant and
assertions or relationships observed by that instant. It is an observation-time
boundary, not a historical identity snapshot: owner, label, and other canonical
entity identity fields reflect the currently authorized entity row. The
resolved `as_of`, focus, depth, repositories, filters, and layers are exposed
back to server-rendered controls, including when they came from a saved view.
Query adapters preserve field presence: omission inherits a saved constraint,
whereas an explicit empty string/list or documented nullable root/time value
removes it. Product session JSON and REST accept exact JSON types only; numeric
strings and booleans are not integer values.

## Browser boundary

The product route server-renders the semantic controls, node and relationship
tables, path form, proposal form, scoped-question form, and all graph data.
Browser-native JavaScript adds Dagre-assisted layout, pan, zoom, fit, minimap,
drag-to-place, spatial keyboard navigation, selection, inspector loading,
focus/expand controls, annotations, save, share/revoke, and an actual
drag-or-keyboard drawn-edge proposal gesture. Drawing never mutates a canonical
edge: its only result is a governed proposal form with typed endpoints. The
document remains useful without JavaScript through the canonical tables and
forms, including a bounded Explorer-backed question fallback.

Dagre runs only on the edge-connected subgraph. Permitted disconnected nodes
are not dropped: unpinned nodes use a deterministic compact grid outside the
occupied connected/pinned bounds, while saved pins always win. This keeps dense
layout cost tied to topology without turning disconnected entities into hidden
or unreachable results.

Dagre 2.0.0 is vendored under `src/anva/static/anva/vendor`, with its license,
legal notice, and reviewed SHA-256 checksums. There is no Node/npm runtime,
package fetch, dynamic code evaluation, browser storage, or cross-origin
network dependency.

## Freshness and truthfulness

Freshness is derived from currently permitted assertions. The precedence is
contradicted, source unavailable, stale, aging, fresh, then unknown when only
entity identity is permitted. The UI includes text for every state and marks
inference separately from source-backed provenance. Canvas never claims that a
layout, annotation, share, or proposal changed canonical knowledge.

Entity detail is a bounded, authorization-filtered view over source citations,
active relationships, decisions and policies, risks and incidents, active work
and recent pull requests, and recent history. Each section is independently
bounded and reports its own truncation plus one aggregate signal without
disclosing hidden totals or identities. Reviewers and conflict state are
rendered explicitly, and empty-state copy does not claim categorical absence
when a permitted section was truncated. A selected entity can also drive a
bounded, repository-authorized organizational question; the answer is scoped
to its permitted one-hop context and Explorer results.
