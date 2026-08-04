# Issue 012 self-review

## Scope and outcome

MVP-012 adds an organization-wide, permission-filtered Organizational Canvas
over canonical Anva knowledge. It includes saved Strategy, Product-system,
Initiative, Risk-policy, Change-history, and Custom semantic views; immutable
revisions and presentation children; typed filters/layers; deterministic
layout; source/freshness and conflict detail; bounded focus/path traversal;
observation-time filtering; exact-revision shares and auditable revocation;
proposal-only relationship drawing; saved annotations; scoped questions;
browser-native map interaction; and a server-rendered list/table equivalent.

The Canvas deliberately does not become a free-form whiteboard, a new source of
canonical truth, a canonical deletion surface, or a client-side authorization
engine.

## Design and architecture review

The visual surface extends the established night-map product language. Semantic
columns, relationship arrows, provenance/freshness state, typed layers, focus,
and the inspector convey meaning; geometric proximity alone does not. The
browser adds pan, zoom, fit, minimap, drag, selection, spatial arrow-key
navigation, progressive focus, save, share/revoke, annotations, scoped
questions, and proposals. Server-rendered controls and tables remain functional
without JavaScript.

Canonical entity IDs cross the Canvas boundary. Saved layout state is a sealed,
content-hashed revision, with coordinates and groups kept separate from entity
and relationship state. A drag/save was verified to increment only the Canvas
revision. A typed relationship drawn by actual drag or keyboard endpoint
selection creates a governed proposal at exact source and target revisions and
leaves canonical relationships unchanged.

Layout work is bounded to the edge-connected subgraph. Disconnected permitted
nodes remain first-class results and are placed in a deterministic compact grid
beyond the connected/pinned bounds; saved pins override both paths. Browser
regressions prove every disconnected node is rendered and searchable, the grid
does not overlap occupied layout, both connected and isolated pins win, and all
300 positions remain identical across 31 renders.

The implementation uses Django, PostgreSQL, browser-native JavaScript, and a
locally vendored Dagre 2.0.0 build. It adds no Node/npm runtime, frontend build
tool, dynamic module download, cross-origin script, or browser persistence.

## Authorization and security review

- Projection starts with current repository visibility, invokes strict
  repository/scoped provenance authorization separately per repository, and
  unions only authorized rows. Hidden records are never loaded into browser
  JSON.
- Explicit semantic repository UUIDs are same-organization and authorization
  checked before persistence and again at list, detail, replay, share, and
  revoke boundaries. Default repository discovery caps only after
  authorization. Saved-view discovery also checks the current revision's live
  relational and semantic repository, scope/source, and root boundaries before
  its 300-row cap; malformed legacy JSON fails closed and bounded candidates
  still receive ordinary per-view reauthorization.
- Inspector relationships, decisions/policies, risks/incidents, active work,
  and recent pull requests are filtered and independently `+1` bounded inside
  four fixed strict edge statements over one authorization snapshot. The UI
  renders reviewers and conflict state and names every truncated permitted
  section without claiming categorical absence or disclosing omitted totals.
- The hidden-canary integration test proves that adding inaccessible ingested
  data does not change visible nodes, edges, counts, truncation, limitations, or
  layout and that path lookup cannot probe the hidden UUID.
- Shares point to exact immutable revisions but re-run current viewer
  authorization; they are references, not capabilities. Revocation is
  CSRF/authenticated, optimistic, request-idempotent, immediate, and retains
  actor/timestamp/hash history.
- Composite tenant foreign keys and link guards prevent cross-tenant and
  cross-revision grafting. PostgreSQL triggers enforce append-only revisions
  below the ORM.
- Session mutations retain CSRF protection. Bearer APIs are closed and typed.
  Stale writes fail, idempotent retries return the prior artifact, and
  recursively nested secret-shaped text, schema extras, scalar coercions, and
  non-finite coordinates are rejected.
- Exact hard caps are 100 repositories, 300 nodes, 600 edges, four semantic
  focus hops, six path hops, and 750 KiB for request/response JSON. The response
  gate measures the actual compact, unescaped Unicode wire bytes.

## Independent-review blocker closure

| # | Closure | Direct regression evidence |
| ---: | --- | --- |
| 1 | Detail independently pre-filters and bounds active relationships, decisions/policies, risks/incidents, active work, and recent pull requests with current authorization, stable semantics, and no hidden totals; reviewers/conflicts and per-section truncation render truthfully. | `test_canvas_detail_filters_incident_edges_before_global_six_hundred_edge_cap`; `test_canvas_detail_batches_authorization_provenance_and_related_context_queries`; Chromium inspector journey |
| 2 | Semantic repository UUIDs are validated as same-organization and authorized before create/save, then re-authorized on replay. | `test_saved_canvas_boundaries_are_reauthorized_before_persist_or_exposure` |
| 3 | The default repository cap is applied to the authorized sequence, not the tenant's pre-authorization rows. | `test_saved_canvas_boundaries_are_reauthorized_before_persist_or_exposure` with 101 earlier inaccessible repositories |
| 4 | Provenance-only selection has no all-edge fallthrough. | `test_canvas_unions_only_strict_per_repository_authorized_graphs` |
| 5 | Secret detection traverses every supported nested JSON child. | `test_canvas_filter_values_recursively_reject_secret_shaped_strings` |
| 6 | Focus root/depth and progressive one-hop expansion exist in the service, interactive product, and no-JS controls. | `test_canvas_focus_walk_is_undirected_deterministic_and_depth_bounded`; Chromium focus journey; accessibility assertions |
| 7 | List/get/share/save re-authorize revision-embedded repository UUIDs before exposing metadata or projection data; listing authorizes candidates before its 300-view cap so inaccessible or malformed earlier rows cannot crowd out a later visible view. | `test_saved_canvas_boundaries_are_reauthorized_before_persist_or_exposure`; bearer/session integration journeys |
| 8 | Share revocation is authenticated, CSRF-protected for humans, optimistic, request-idempotent, immediate, and history-preserving. | `test_canvas_revisions_are_append_only_idempotent_and_tenant_safe`; session and bearer HTTP integration journeys |
| 9 | Presentation child schemas are closed at runtime and in OpenAPI; detail annotations and scoped questions are bounded and authorized. | strict presentation unit tests; `test_canvas_openapi_surfaces_are_authenticated_bounded_and_closed`; session integration and Chromium journeys |
| 10 | The 750 KiB response gate measures compact unescaped Unicode response bytes and trims deterministically. | `test_canvas_http_wire_budget_is_compact_utf8_and_deterministically_trimmed` |
| 11 | Draw mode accepts a real drag or keyboard source/target gesture, renders a dashed preview, and opens only a typed governed proposal. | Chromium drag-drawn proposal assertion plus unchanged canonical relationship count |
| 12 | Browser evidence uses real ingestion lineage, both required traces, dense topology, hidden-canary denial, and 30-sample interaction metrics. | `test_organizational_canvas_interaction_no_js_and_responsive_evidence` and committed browser report/screenshots |
| 13 | `as_of`, focus, depth, repositories, filters, and layers use the resolved saved semantic state in service responses and form controls. | saved-query unit test; detail/as-of integration test; saved-control HTML assertions |

## Verification evidence

- Focused Canvas unit, accessibility, contract, and integration suites cover
  exact caps/vocabularies, deterministic layout and byte trimming, immutable
  revisions, tenant safety, real ingestion lineage, hidden-canary invariance,
  300-node rendering, observation-time filters, adversarial Unicode wire
  sizing, revocation history, bearer/session/CSRF boundaries, proposal-only
  edges, vendored assets, and browser safety.
- The isolated Chromium journey passes with 167 real ingestion-lineage
  relationships, explicit organizational traces, selection/rich inspector,
  drag and save to revision 2, saved annotation, scoped question, actual
  drag-drawn typed proposal, exact share/revoke flow, dense progressive focus,
  no-JS table, 320-pixel layout, 200% zoom, no document-level overflow, and no
  unexpected severe console message.
- Seven visually reviewed screenshots and dependency checksums are recorded in
  `docs/evidence/issue-012/README.md`. Capture-time regressions assert the
  horizontal bounds of the actual shell, main, sidebar, title, semantic
  controls, and focus control rather than relying on scroll state alone.
- Schema migration has no model drift, applies in clean browser/integration
  databases, and the exact production wheel reverses from migration 0018 to
  0017 then reapplies 0018 successfully. OpenAPI generation emits the exact
  Canvas v3 enums, closed request schemas, routes, and limits.
- The full repository gate passed with 677 tests, four expected skips, and 86%
  aggregate branch coverage. Canvas service coverage is 90%.
- The production wheel contains the migration, Canvas template, JS, CSS, and
  vendored Dagre asset. Its non-root runtime image passes `collectstatic`,
  emits hashed/compressed Canvas assets, imports the installed package, and
  passes Django's deploy check apart from the repository's documented
  proxy-owned SSL redirect/HSTS warnings.
- Both database and browser performance reports preserve all 30 post-warm raw
  samples, environment/fixture metadata, query counts, exact thresholds, and
  source/test commit `662460ae2718cf44d07d2b83e7709e254a000ef5`.
  Recursive report checks recompute p50, p95, max, and sample count from the
  exact rounded values that are serialized in every nested raw sample array.
- Hosted GitHub Actions remains disabled because the repository account's
  billing state cannot safely run workflows. All reported gates were executed
  locally in the isolated Docker Compose profiles; no workflow was enabled as
  part of this issue.

## Acceptance scenarios

- The ingestion-backed browser fixture proves a permitted
  goal → initiative → requirement → pull-request trace.
- The same fixture proves a permitted
  product → component → API → service → repository → team trace.
- Its dense topology has a directed cycle, parallel typed relationships, a
  degree-42 central node, stale and inferred provenance, a conflict, and a
  hidden inactive-scope canary that is absent from the projection.
- The inspector and tables surface provenance basis, freshness, conflicts, and
  bounded currently permitted relationships, decisions/policies,
  risks/incidents, active work/recent pull requests, and history; path rows
  explain directed connections.
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
- `as_of` is an observation-time boundary. Current authorized identity metadata
  is not reconstructed as a historical snapshot.
- The interactive browser gate uses Chromium only; the no-JS table is the
  cross-browser baseline.
- Groups are persisted and API-ready; arbitrary free-form whiteboard authoring
  remains intentionally outside the product boundary.
- Canonical relationship deletion remains intentionally outside Canvas.

## Conclusion

The implementation satisfies the issue's model/revision, semantic-view,
permission-safe traversal, presentation-only edit, proposal, accessibility,
vendored-library, browser evidence, and exact v3 budget requirements while
preserving Anva's canonical knowledge and authorization boundaries.
