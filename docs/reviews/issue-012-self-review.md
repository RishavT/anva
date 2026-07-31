# Issue 012 self-review

## Scope and outcome

MVP-012 adds an organization-wide, permission-filtered Organizational Canvas
over canonical Anva knowledge. It includes saved Strategy, Product-system,
Initiative, Risk-policy, Change-history, and Custom semantic views; immutable
revisions and presentation children; typed filters/layers; deterministic
layout; source/freshness and conflict detail; bounded focus/path traversal;
exact-revision shares; proposal-only relationship drawing; browser-native map
interaction; and a server-rendered list/table equivalent.

The Canvas deliberately does not become a free-form whiteboard, a new source of
canonical truth, a canonical deletion surface, or a client-side authorization
engine.

## Design and architecture review

The visual surface extends the established night-map product language. Semantic
columns, relationship arrows, provenance/freshness state, typed layers, focus,
and the inspector convey meaning; geometric proximity alone does not. The
browser adds pan, zoom, fit, minimap, drag, selection, spatial arrow-key
navigation, save, share, and proposals. Server-rendered controls and tables
remain functional without JavaScript.

Canonical entity IDs cross the Canvas boundary. Saved layout state is a sealed,
content-hashed revision, with coordinates and groups kept separate from entity
and relationship state. A drag/save was verified to increment only the Canvas
revision. A drawn typed relationship creates a governed proposal at exact source
and target revisions and leaves canonical relationships unchanged.

The implementation uses Django, PostgreSQL, browser-native JavaScript, and a
locally vendored Dagre 2.0.0 build. It adds no Node/npm runtime, frontend build
tool, dynamic module download, cross-origin script, or browser persistence.

## Authorization and security review

- Projection starts with current repository visibility, invokes strict
  repository/scoped provenance authorization separately per repository, and
  unions only authorized rows. Hidden records are never loaded into browser
  JSON.
- The hidden-canary integration test proves that adding inaccessible ingested
  data does not change visible nodes, edges, counts, truncation, limitations, or
  layout and that path lookup cannot probe the hidden UUID.
- Shares point to exact immutable revisions but re-run current viewer
  authorization; they are references, not capabilities.
- Composite tenant foreign keys and link guards prevent cross-tenant and
  cross-revision grafting. PostgreSQL triggers enforce append-only revisions
  below the ORM.
- Session mutations retain CSRF protection. Bearer APIs are closed and typed.
  Stale writes fail, idempotent retries return the prior artifact, and
  secret-shaped text/non-finite coordinates are rejected.
- Exact hard caps are 100 repositories, 300 nodes, 600 edges, four semantic
  focus hops, six path hops, and 750 KiB for request/response JSON.

## Verification evidence

- Focused Canvas unit, accessibility, contract, and integration suites cover
  exact caps/vocabularies, deterministic layout and byte trimming, immutable
  revisions, tenant safety, real ingestion lineage, hidden-canary invariance,
  300-node rendering, bearer/session/CSRF boundaries, proposal-only edges,
  vendored assets, and browser safety.
- The isolated Chromium journey passes with a real ingested relationship,
  selection/inspector, drag and save to revision 2, typed proposal submission,
  exact share flow, no-JS table, 320-pixel layout, 200% zoom, no document-level
  overflow, and no unexpected severe console message.
- Five visually reviewed screenshots and dependency checksums are recorded in
  `docs/evidence/issue-012/README.md`.
- Schema migration has no model drift and applies in clean browser/integration
  databases. OpenAPI generation emits the exact Canvas v3 enums, closed
  request schemas, routes, and limits.
- The full repository gate passed with 655 tests, four expected skips, and
  85.21% aggregate coverage. Canvas service coverage is 84.95%.
- The production wheel contains the migration, Canvas template, JS, CSS, and
  vendored Dagre asset. Its non-root runtime image passes `collectstatic`,
  emits hashed/compressed Canvas assets, imports the installed package, and
  passes Django's deploy check apart from the repository's documented
  proxy-owned SSL redirect/HSTS warnings.
- Both database and browser performance reports preserve all 30 post-warm raw
  samples, environment/fixture metadata, query counts, and exact thresholds.

## Acceptance scenarios

- The vocabulary, layers, focus, and path service support the requested
  goal → initiative → product → repository → active-change trace, when those
  source-backed canonical facts are present and permitted.
- The same projection supports service → dependency → owner → decision/policy
  and recent evidence/assurance context for technical owners.
- The inspector and tables surface provenance basis, freshness, conflicts, and
  currently permitted context; path rows explain directed connections.
- A deterministic 300-node integration projection and responsive/browser
  checks demonstrate the standard v3 size budget and accessible equivalence.

These are semantic capabilities, not seeded demo claims: Anva does not invent a
missing organizational relationship to make either path complete.

## Current limitations

- Dense 300-node/600-edge results can still be visually complex. Typed layers,
  focus depth, repository filters, and saved pins are the intended controls.
- Progressive focus is depth-based. Payload truncation reports a deterministic
  bounded prefix but does not yet expose a continuation cursor.
- Why-connected returns one deterministic shortest path up to six hops, not all
  explanations.
- The interactive browser gate uses Chromium only; the no-JS table is the
  cross-browser baseline.
- Layout groups and annotations are persisted and API-ready; the first product
  surface emphasizes node placement, typed filtering, and proposals rather
  than free-form authoring controls.
- Canonical relationship deletion remains intentionally outside Canvas.

## Conclusion

The implementation satisfies the issue's model/revision, semantic-view,
permission-safe traversal, presentation-only edit, proposal, accessibility,
vendored-library, browser evidence, and exact v3 budget requirements while
preserving Anva's canonical knowledge and authorization boundaries.
