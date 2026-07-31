# Organizational Canvas threat model

## Scope and protected assets

This review covers `/app/canvas`, `/api/v1/canvas/*`, saved views and revisions,
shares, browser graph data, entity detail, path explanations, and relationship
proposals. Protected assets include tenant knowledge and counts, hidden entity
identities, source/provenance metadata, access topology, canonical revisions,
human proposal authority, session and bearer credentials, and saved
presentation state.

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

## Threats and controls

### Hidden-node disclosure through graph expansion or counts

Each repository is authorized independently with the existing strict
lineage-aware CTE. Only then are results unioned. Filtering a complete graph in
the browser is prohibited. Hidden canary ingestion is covered by an invariance
test: node/edge payloads, counts, truncation, limitations, and layout are
byte-equivalent before and after hidden data is added. A path to the canary
returns the same stable unavailable error as a missing UUID.

### Share used as an access capability

A share contains no bearer token and names one immutable revision. Resolution
requires an authenticated active actor, re-authorizes the view and underlying
repositories/scopes, checks expiry/revocation and optional recipient binding,
then rebuilds the projection. Deep links cannot preserve withdrawn access.

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
groups, filters, and rationales. Requests and responses are capped at 750 KiB;
projection cardinality is capped at 100 repositories, 300 nodes, and 600 edges.

### XSS, dependency, or browser credential exposure

Django escaping and `json_script` encode server data. The existing CSP permits
same-origin scripts and connections only and denies framing, objects, and base
overrides. Canvas JavaScript uses no cookies, authorization headers, browser
storage, `eval`, Node/npm, CDN, or cross-origin fetch. Dagre 2.0.0 and its legal
files are committed with reviewed SHA-256 checksums.

### Misleading freshness or connectivity

Freshness comes from currently authorized assertions and reports unknown when
only identity is available. Connection explanations use the same bounded
authorized edge set as projection. Truncated responses say so; the UI does not
imply absence beyond the displayed authorized and bounded result.

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
  relationships, CSRF, session HTML, and bearer API boundaries.
- Browser: keyboard selection, inspector, drag/save, exact-revision sharing,
  relationship proposal, source-backed edge rendering, minimap/zoom, 320-pixel
  no-JS table, 200% zoom, no document overflow, and no unexpected severe
  console entry.
