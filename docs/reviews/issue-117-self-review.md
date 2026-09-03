# Issue 117 self-review: published v0.1.5 operator boundary

## Scope and identities

This change updates stale release/readiness facts and documents why the
published image cannot yet produce final operator evidence:

- product version: `0.1.5`;
- product source: `491cdd7830a7f4d6af7140f6a4744f95c80c46a9`;
- product image: `sha256:19488230c6f7900cda33bd11adc7f1ad824d23b77ee87fd65ac883cd0dacc725`;
- successful release workflow: `33727525411`; and
- operator-tool source: the source embedded in the exact immutable image.

The v0.1.5 image predates the corrected source-role contract. Its exact
deployed tool remains `NOT_ACCEPTED` when paired with a later harness revision;
unshipped current-source tooling is not substituted. A future immutable release
is required before the final operator exercise.

## Fail-closed review

- Generic eligibility continues to require product and operator-tool source
  identity inside one immutable released image; it has no hard-coded future
  release commit.
- Evidence creation compares the supplied product source against the immutable
  image's OCI revision label before invoking the image's own drill tool.
- The published v0.1.5 product source paired with the newer harness is tested as
  `NOT_ACCEPTED`.
- The guide records v0.1.5 identity and the next-image requirement, rather than
  presenting documentation success as runtime eligibility.
- Local tooling still cannot create human approval or signoff events.

## Verification

- The exact published v0.1.5 digest's own `drill-tool` was invoked with product
  source `491cdd7...` and harness source `fc84f9d...`; its recorded status was
  exactly `NOT_ACCEPTED`.
- Focused Docker suite: 52 passed, 1 environment skip.
- Full Docker unit suite: 793 passed, 3 environment skips.
- Docker Ruff formatting: 239 files already formatted after formatting the one
  changed test module.
- Docker Ruff lint: passed.
- `git diff --check`: passed.
- Exact test Compose project, containers, network, and volumes were removed.

The changes remain uncommitted pending independent review.
