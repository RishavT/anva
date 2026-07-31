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
  or revoked, but it never grants knowledge access.
- relationship drawing creates a typed `KnowledgeProposal` with source and
  target revisions. It does not insert a canonical relationship.

PostgreSQL composite foreign keys enforce same-organization links. Additional
guards bind shares to revisions of the selected view and groups to placements
of the same revision. Database triggers reject updates and deletes of revisions
and their presentation children, including bulk ORM and direct SQL paths.

## Read pipeline and authorization

For every request the service:

1. authenticates the current user session or service bearer actor;
2. resolves at most 100 currently visible repositories;
3. runs the existing strict repository authorization and provenance CTE for
   each repository independently;
4. unions only those permitted entity and edge results by canonical UUID;
5. applies the closed typed semantic query, layer selection, and optional
   four-hop focus expansion;
6. computes deterministic semantic-column placement, citations, freshness,
   conflicts, inspector summaries, and a layout checksum;
7. trims deterministically to the hard response budget before serialization.

The same strict edge CTE is used by the Canvas projection and path service. A
path is bounded to six hops and can contain only nodes and edges visible through
the selected repository set. Missing, foreign, revoked, and inaccessible
identifiers all use the same unavailable response.

Shares re-run this pipeline against the viewer's current permissions. A share
can therefore lose nodes or become unavailable as authorization changes.

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

## Browser boundary

The product route server-renders the semantic controls, node and relationship
tables, path form, proposal form, and all graph data. Browser-native JavaScript
adds Dagre-assisted layout, pan, zoom, fit, minimap, drag-to-place, spatial
keyboard navigation, selection, inspector loading, save, and share actions.
The document remains useful without JavaScript through the canonical tables and
forms.

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
