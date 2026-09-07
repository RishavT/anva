# Issue 156 self-review

## Security and completeness

- Assertion eligibility is derived from the existing current-provenance and current-
  authorization SQL predicates before relevance, accounting, digesting, or detail.
- Open conflicts require both endpoints in that authorized set and at least one endpoint
  in the complete change-relevant set. Hidden, revoked, stale-lineage, and cross-tenant
  rows therefore do not enter public counts or the digest.
- The retrieval watermark is locked for the transaction and authorization plus watermark
  are recomputed before publication. Supported ingestion, provenance, and scope mutations
  invalidate or serialize against that fence.
- Ordering is `(kind, id)` and pages use strict UUID `id > last_id` keysets. The public
  completeness digest excludes generated packet-item UUIDs.

## Bounds and compatibility

- Pages contain at most 200 rows and provenance hydration contains at most 400 assertion
  IDs. Total work is capped at 50,000 rows, 100,000 operations, and four seconds, leaving
  one second for ranking and sealing inside the v3 five-second context target.
- Packet detail keeps the existing item/token/byte/citation budgets. Omitted conflict
  detail is reported explicitly, while every eligible conflict contributes to the exact
  count/digest and presence of a required conflict representative.
- Exhaustion seals `complete=false`; assurance then uses the existing durable terminal
  failure/report path with `ASSURANCE_CONTEXT_INCOMPLETE`. It cannot become READY and does
  not return the former context-budget 409 dead end.
- Existing packets remain readable because completeness is an additive optional v1
  contract field. New cache keys include the scan version.

## Verification

- Focused unit and MCP contract tests: 35 passed.
- Change-aware Postgres integration plus focused unit tests: 25 passed in 60.40 seconds;
  the integration ingests the proportional 107-source messy corpus represented by the
  pinned 115-file fixture and reaches evaluator review.
- Full unit run: 1,336 passed, 10 skipped. Nine environment-only failures were caused by
  the fallback runtime image lacking `make`, running permission tests as root, MCP host
  configuration, and a deliberately different token-pepper environment. None touched the
  changed paths; focused tests passed in the same container.
- Ruff lint passes. Ruff format passes after formatting the changed Python files.

The normal test-stage image could not be rebuilt because the pinned Debian snapshot host
temporarily failed DNS resolution. Validation therefore used the exact pinned product
image, a private Postgres Compose project, and cached pinned pytest/ruff wheels.
