# Issue 128 self-review: change-aware assurance context

## Outcome

`start_assurance` now derives bounded retrieval facets from the exact server-authorized pull-request
revision, changed paths and identifiers, linked work and requirements, applied policy controls, and
exact accepted evidence. It does not accept caller-provided packet or citation identities. Relevant
matches must also contain bounded exact server-derived anchors before receiving required priority;
their contradiction endpoints are selected before generic governed/archive fallbacks, while the
existing item/token/byte/citation limits and authorization queries remain in force.

The sealed evaluator request now carries each selected item's material claim payload, freshness,
selection reason, and authorized citation provenance (URL, locator, content hash, and observation
time). Source text and claims remain explicitly quoted evidence rather than evaluator instructions.

## Acceptance evidence

| Requirement | Implementation and test evidence |
| --- | --- |
| Actual change context drives retrieval | Five server-owned facets cover PR/repository, changed identifiers, linked work/requirements, applied controls, and exact evidence. Evidence selected through criterion mapping participates even when no deterministic check names it. Unit coverage validates bounded inert term and exact-anchor derivation. |
| Archives cannot dominate | The checked-in broad-corpus regression deterministically materializes 107 documents: 102 archive distractors and five relevant source classes. A material representation of every relevant source and the conflict precedes every selected archive. |
| Claims, provenance, review, freshness, conflict | The integration assertion inspects the independently claimed sealed evaluator request and proves current/stale claim values, review/staleness states, selection reasons, conflict text, and citation provenance. |
| Permission and tenant isolation | The same broad regression ingests a topic-matched foreign-tenant canary and same-repository unauthorized-scope canary; neither appears in the packet or sealed request. Existing permission-first search and packet reauthorization predicates are unchanged. |
| Bounds fail closed | Required facets become required only after an authorized candidate matches both the facet query and an exact server-derived anchor, avoiding broad-term false coverage and an existence oracle. If every candidate for such a facet is displaced by the fixed budget, the packet records a visible limitation that survives saturated run/report limits, and server-owned readiness becomes `BLOCKED` with `ASSURANCE_CONTEXT_INCOMPLETE`. Required current policy overflow retains its existing hard failure. |
| Determinism and staleness | Unchanged replay reuses the identical run and evaluator artifact. A source change advances the retrieval watermark, immediately marks every linked assurance and evaluator task stale in the invalidation transaction, rebuilds the packet, and changes its artifact hash. Claim replay, new claim, and result submission all fail closed for invalidated context. |
| Independent reviewer boundary | Only `start_assurance` constructs facets. The independent reviewer still receives a sealed immutable request, cannot fetch URLs, and cannot compute readiness. |

## Compatibility and migration review

- No database migration or public HTTP/MCP request change is required.
- `build_context_packet` gains an optional internal `retrieval_facets` argument; callers that omit it
  retain the existing single-task behavior. Tasks up to the documented 2,000 characters now use a
  bounded 500-character search query instead of failing the lower search limit.
- The retrieval algorithm identity advances to `permission-first-rrf-v3-change-aware`, so new
  packets and assurance inputs cannot be confused with prior selection behavior.
- Evaluator `authorized_context` objects gain fields under the intentionally open item schema;
  existing `citation_ids` remain present for result submission compatibility.

## Self-review risks checked

- Facets are capped at eight, queries at 500 characters, terms at 64 characters, exact anchors at 16
  per facet and 200 characters each, and search results remain capped at 100 per facet.
- Packet byte accounting includes the newly recorded facet metadata.
- Semantic-only and unanchored lexical results remain lower-priority fallbacks and cannot falsely
  satisfy the required-if-discovered signal; only permission-filtered lexical matches containing an
  exact server-derived anchor can do so.
- Duplicate chunks found by several facets are stored once while retaining the union of matched
  facets, avoiding budget inflation.
- Contradiction payloads include both authorized endpoint states, and the conflict plus stale
  counterpart are promoted together.

## Verification

- Repository suite: 1,265 passed, 6 expected profile/environment skips.
- Focused change-aware suite: 9 unit tests and the 107-document integration regression passed.
- Ruff formatting/lint and strict mypy passed across 207 source files.
- Django migration drift: none; 33 contract artifacts verified; rendered skills drift: none.
- The checked-in corpus is a deterministic 107-document regression shaped around the published
  failure. The original third-party Halcyon corpus identity/bytes are not present in the permitted
  Anva repositories and are not claimed as checked-in test data.
