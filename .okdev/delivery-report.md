# Delivery report: issue #71

## Status

Ready for review. The pull request is intentionally unmerged. No release retry,
tag change, package change, repository-settings change, or Release mutation was
performed while fixing this bug.

## Root cause and correction

Recovery run `33592278376` successfully built, scanned, risk-gated, manifested,
published, and attested `v0.1.0`, then `gh release create` returned HTTP 403.
The publish job had effective `contents: write`; the unnecessary
`--target d919...` made GitHub apply the workflow-file write gate because that
commit differs from default `main` in `.github/workflows/release.yml`.
`GITHUB_TOKEN` cannot be granted that permission.

The workflow now creates the Release for the already-existing immutable tag
with `--verify-tag` and no `--target`. Immediately before create or upload it
re-resolves the live tag, including annotated-tag peeling, and requires exact
agreement among the remote commit, build output, pinned release commit, and
checkout HEAD. After the mutation it queries the Release's tag, re-resolves it,
and again requires the exact source commit.

No PAT, workflow-write permission, default-permission change, tag movement, or
tag-rule change was introduced.

## Regression and verification evidence

- Focused Docker release workflow/documentation/hardening contracts: 27 passed,
  including executable fail-closed tag-resolution error paths.
- Full Docker `make check`: formatting, Ruff, mypy (195 files), migrations,
  33 generated contracts, skill packages, 1,074 tests, 85% coverage, and real
  Chromium 2/2 passed. Five expected profile/stage skips remained.
- Pinned real-Trivy release regression passed old-cache failure, prepared-cache
  first scan and reuse, security controls, foreign collision refusal, and exact
  cleanup.
- `git diff --check`: passed.
- Browser emitted only the already-tracked deferred #49 Canvas performance
  warning (258.3 ms p95 versus unchanged 250 ms); no UI changed in #71.
- All issue-scoped containers, networks, volumes, and generated images were
  removed. Browser-generated tracked evidence was restored to the clean base.
- Independent review round 2: approved with no remaining findings after the
  round-1 Bash command-substitution failure-propagation correction.

## Live immutable evidence

- `main`: `e56fd6137e5d401b13aedc521fe0d8c06095d499` before the fix.
- `v0.1.0`: `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`.
- Canonical GHCR digest:
  `sha256:71a484754b92bf06c35c075eba7b86419f1da0980b7794f53d59f8cc0f6f2f20`.
- GitHub attestation API returned two attestations for that digest, matching the
  successful standard and custom source-binding steps.
- GitHub Release lookup remained 404.
- Active tag ruleset `22026475` covers `refs/tags/v*`, blocks update and
  deletion, and has no bypass actor.
- The retained `release-assets-33592278376` artifact was unexpired.

## Safe recovery decision

GitHub re-runs retain the original event's `GITHUB_SHA` and `GITHUB_REF`. Run
`33592278376` is bound to `e56fd613`, whose workflow contains the broken
`--target`; therefore re-running failed jobs cannot load this correction. After
the PR is reviewed and merged, recovery must be a new dispatch from corrected
protected `main` for `tag=v0.1.0`, after rechecking the immutable tag, canonical
digest, attestations, and absence/source binding of the GitHub Release.

Do not rerun the current failed run. Do not move, delete, or recreate the tag.
Do not delete or overwrite the canonical GHCR package or attestations merely to
repair GitHub Release creation.
