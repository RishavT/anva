# Repair v0.1.0 public release metadata without changing the product

## Actual behavior

The public `v0.1.0` Release exists and workflow run `33596661334` succeeded for
all build, publish, attestation, and install-lifecycle jobs. The protected tag
resolves to product source commit
`d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`, and the immutable GHCR image and
13 downloadable assets are public.

However, the public Release body is the stale candidate `RELEASE_NOTES.md`. It
claims the release is unpublished, has no tag, registry digest, provenance, or
GitHub Actions record, and cites older source/image identities. The same stale
claims remain in canonical readiness, checklist, evidence-matrix,
compatibility, operator/install, ownership, and trust documentation.

## Expected behavior

Public and checked-in release metadata must describe the completed technical
publication truthfully while keeping human-owned release gates #43 and #44
open. Repairing metadata must not rebuild or republish the product, move the
tag, change the image digest/runtime/risk decision, discard old attestations,
or silently mutate release assets.

## Reproduction

1. View `https://github.com/RishavT/anva/releases/tag/v0.1.0` and observe the
   contradictory unpublished/no-tag/no-registry/no-Actions statements.
2. View `https://github.com/RishavT/anva/actions/runs/33596661334`; all three
   jobs completed successfully.
3. Resolve `refs/tags/v0.1.0`; it is the verified commit `d919a2c...`.
4. Download all 13 assets, verify the existing `SHA256SUMS`, and inspect
   `release-manifest.json`; publication and immutable image identity exist.

## Acceptance criteria

- Merge one protected-main PR limited to documentation, metadata-repair
  workflow/contracts, and review evidence; keep #43 and #44 open.
- Correct the canonical release note and current readiness/checklist/evidence
  matrix/compatibility/operator/install/ownership/trust documents using the
  exact tag, source commit, image digest, run, and 13-asset inventory.
- Add a manual-only, protected-`release`-environment, concurrency-serialized
  metadata repair workflow. It must pin the exact existing tag/source/image and
  assert the exact current 13 assets and hashes.
- In dry-run mode, generate a closed replacement set consisting only of
  `RELEASE_NOTES.md`, `release-manifest.json`, and `SHA256SUMS`; prove the other
  ten assets are byte-identical and the checksum/manifest closure is valid.
- Before any upload, generate and verify both standard provenance and the
  custom product-source predicate for each of the three replacements. The
  custom predicate binds product source `d919...`, the reviewed metadata
  commit on protected `main`, the correction reason, and repair workflow run.
- Apply mode must snapshot the old triplet and Release body, replace exactly
  that triplet/body, verify anonymous downloads/checksums/manifest,
  standard/custom attestations, and the documented install lifecycle, and
  restore and verify the old triplet/body on any failure after mutation.
- Preserve the old attestations. Do not create `v0.1.1`, request new risk
  approval, rebuild/push the image, change runtime, or execute the repair before
  this PR is reviewed and merged.
- Add test-first contracts, run the full Docker/Compose `make check`, perform a
  browser spot-check, exercise a non-mutating repair dry run against downloaded
  public assets, keep task-owned Docker usage below 5 GB, clean resources, and
  obtain self-review plus independent review. Leave the PR unmerged.
