# Organizational Canvas threat model

## Scope and protected assets

This review covers `/app/canvas`, `/api/v1/canvas/*`, saved views and revisions,
share creation/resolution/revocation, browser graph data, entity detail,
observation-time queries, scoped questions, path explanations, annotations, and
relationship proposals. Protected assets include tenant knowledge and counts,
hidden entity identities, source/provenance metadata, access topology,
canonical revisions, human proposal authority, session and bearer credentials,
and saved presentation state.

## Trust boundaries

- Query strings, JSON, UUIDs, coordinates, labels, and browser state are
  untrusted.
- Django session and bearer authentication establish an actor, not permission
  to an arbitrary repository, source, scope, entity, or view.
- Authorization and strict provenance filtering happen before union,
  traversal, counts, layout, and serialization.
- The browser is a presentation client. Its hidden elements and JavaScript are
  not authorization boundaries.
- Saved views and shares are references to questions and revisions; they are
  not grants.
- Repository UUIDs are semantic identifiers, not trusted routing hints. They
  are organization-bound and re-authorized before persistence and replay.

## Threats and controls

### Hidden-node disclosure through graph expansion or counts

Each repository is authorized independently with the existing strict
lineage-aware CTE. Only then are results unioned. Filtering a complete graph in
the browser is prohibited. Hidden canary ingestion is covered by an invariance
test: node/edge payloads, counts, truncation, limitations, and layout are
byte-equivalent before and after hidden data is added. A path to the canary
returns the same stable unavailable error as a missing UUID.

The default repository discovery path applies its 100-repository cap only
after authorization, so a run of inaccessible repositories cannot crowd out a
later visible repository. Provenance-only mode has no permissive all-edge
fallthrough. Entity detail and questions use bounded authorized sections and do
not expose hidden section totals. Inspector lookup applies the entity-incident
predicate plus each section's type/status predicate inside the strict
authorized edge CTE before independent `+1` sentinel caps, so a large generic
relationship prefix cannot starve decisions/policies, risks/incidents, active
work, or recent pull requests. The four fixed edge statements reuse the same
actor-bound authorization snapshot, keep query count independent of result
cardinality, and hydrate the union of already-permitted endpoints once.
Question and no-JavaScript Explorer retrieval bridge only the selected entity
and authorized one-hop entities from claim locations to current indexed root
chunks through their shared observation; unrelated same-repository chunks,
stale observations, revoked snapshots, and duplicate chunk roots cannot consume
the evidence cap.

Saved-view listing likewise applies its 300-row cap after a parameterized
candidate query checks the current tenant revision and live relational and
semantic repository, scope/source, and root-entity boundaries. JSON types and
UUID text equality make malformed legacy semantic values fail closed without a
cast exception. Every bounded candidate is then re-authorized through the
ordinary view service, preserving saved ownership metadata and service-actor
visibility; share resolution remains on its separate exact-revision path.
Inaccessible earlier names therefore cannot crowd out a later visible view.

### Share used as an access capability

A share contains no bearer token and names one immutable revision. Resolution
requires an authenticated active actor, re-authorizes the view and underlying
repositories/scopes, checks expiry/revocation and optional recipient binding,
then rebuilds the projection. Deep links cannot preserve withdrawn access.
Revocation requires current manage authorization and the exact pinned revision,
retains CSRF/session or bearer authentication boundaries, binds idempotency to
the request, and transitions active to revoked without deleting the audit row.
Repeated identical revocation is safe; a stale or repurposed request is not.

### Cross-tenant or cross-revision grafting

Tenant-qualified service lookups are reinforced by composite PostgreSQL
foreign keys. Link guards require a share revision to belong to its view and a
placement group to belong to its revision. Tests force deferred constraints to
prove that a foreign organization entity cannot be grafted into a Canvas
revision.

### Layout edit changes canonical knowledge

Layout saves append a content-hashed revision and insert presentation-only
children. They do not update entities or relationships. Model methods and
database triggers reject update/delete of the sealed revision graph. Optimistic
concurrency rejects stale saves and idempotency binds a key to one request
hash.

### Drawn edge bypasses knowledge review

Relationship types use an explicit source/target vocabulary. Proposal creation
checks both canonical entity revisions and current authorization, writes only a
scoped proposal, and leaves the canonical relationship count unchanged.
Canonical deletion is not exposed by Canvas.

### Oversized, malformed, or secret-bearing input

API and product JSON objects are closed and typed. Repository, entity type,
layer, freshness, depth, coordinate, child-count, and text values are bounded.
Secret-shaped text is rejected from queries, names, descriptions, annotations,
groups, filters, and rationales, including recursively nested supported JSON.
Unknown presentation members, scalar coercion, and non-JSON values are rejected.
JSON integers do not accept booleans, numeric strings, or null; UUIDs and text
must be strings, and list members retain their declared scalar type. Only
`anchor_id` and `as_of` accept explicit null in a Canvas query, where null is the
documented request to clear a saved constraint. REST, session JSON, and the
published OpenAPI schema use the same rules.
Requests and responses are capped at 750 KiB; response enforcement measures the
actual compact unescaped Unicode wire bytes. Projection cardinality is capped
at 100 repositories, 300 nodes, and 600 edges.

### XSS, dependency, or browser credential exposure

Django escaping and `json_script` encode server data. The existing CSP permits
same-origin scripts and connections only and denies framing, objects, and base
overrides. Canvas JavaScript uses no cookies, authorization headers, browser
storage, `eval`, Node/npm, CDN, or cross-origin fetch. Dagre 2.0.0 and its legal
files are committed with reviewed SHA-256 checksums.

### Misleading freshness or connectivity

Freshness comes from currently authorized assertions and reports unknown when
only identity is available. Connection explanations use the same bounded
authorized edge set as projection. Detail responses carry per-section and
aggregate truncation signals; the UI names affected permitted sections and
does not imply absence beyond the displayed authorized and bounded result.

An `as_of` query is explicitly an observation-time boundary. It filters entity
creation and assertion/relationship observations, while current authorized
identity metadata remains current; the product states this caveat beside the
control. Saved controls render the server-resolved query rather than ambiguous
raw URL input. Override presence is tracked independently from truthiness, so
explicit empty strings, empty lists, and the documented nullable values clear
saved root, type, owner, status, risk, freshness, search, time, and layer
constraints while omitted controls retain the saved constraint.

## Residual risks and limitations

- The deterministic initial layout and Dagre refinement improve legibility but
  cannot guarantee a hairball-free result for every dense 300-node graph.
- The browser stage covers Chromium. Cross-engine visual regression remains
  future work.
- A six-hop breadth-first explanation returns one deterministic shortest path,
  not every possible organizational explanation.
- Response trimming currently returns a bounded prefix with an explicit
  limitation rather than a continuation cursor. Focus depth provides
  progressive expansion within the saved semantic question.
- Organization administrators can see all data granted by their role; least
  privilege remains an operational responsibility.

## Verification

- Unit/contract: exact vocabularies and limits, closed schemas, deterministic
  layout and response trimming, non-finite coordinates, secret rejection,
  dependency checksum/license, no browser storage or external network code,
  no-JS markup, reduced motion, forced colors, and print behavior.
- Integration: real ingestion lineage, multi-repository union, hidden canary
  invariance, inaccessible path denial, 300-node determinism, append-only
  revisions, tenant graft rejection, stale/idempotent writes, proposal-only
  relationships, share revocation history, observation-time filtering,
  recursively closed presentation input, adversarial Unicode wire sizing,
  CSRF, session HTML, and bearer API boundaries. Adversarial cases include
  selected-evidence/decoy isolation across JSON and no-JavaScript paths, stale
  and duplicate root-chunk lineage, an incident edge ordered after 600
  unrelated edges, explicit saved-filter clearing, and rejected scalar/null
  coercions.
- Browser: keyboard selection, inspector, drag/save, exact-revision sharing,
  revocation, actual drag-drawn proposal, annotations, scoped questions,
  required organizational traces, dense topology/focus, source-backed edge
  rendering, minimap/zoom, 320-pixel no-JS table, 200% zoom, no document
  overflow, and no unexpected severe console entry.
