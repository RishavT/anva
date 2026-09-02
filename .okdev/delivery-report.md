# Delivery report: issue #77

## Status

Ready for review. The pull request is intentionally unmerged. No repair
redispatch, manual body edit, release/tag/package/settings mutation, or protected
branch mutation was performed while fixing this bug.

## Root cause and correction

Metadata repair run `33620337769` succeeded through upload and attestation, then
explicitly removed `GH_TOKEN` and `GITHUB_TOKEN` from post-upload
`gh attestation verify`. GitHub CLI requires authentication for attestation API
lookup, even though the repository and artifacts are public.

The ensuing rollback restored the old assets/body, but verification compared a
body rendered by `gh release view --jq`, which appended CLI output framing. The
workflow now retains its job-scoped least-privilege token for attestation lookup
while public release-asset downloads remain anonymous. Body snapshot and
rollback verification use `gh api` JSON decoded directly to exact UTF-8 bytes.
Consumer docs state this authentication boundary explicitly.

## Regression and verification evidence

- Focused Docker Ruff and workflow regressions: 23 passed.
- Executable rollback matrix: bodies ending in zero, one, and two newlines,
  crossed with ordinary failure, HUP, INT, and TERM, restore exact body bytes and
  audited assets.
- Executable post-upload loop test requires a present `GH_TOKEN` for the real
  extracted workflow commands.
- actionlint v1.7.12: passed for the changed workflow.
- Full unique-project Docker `make check`: formatting, Ruff, mypy, migrations,
  generated contracts, skills, 1,112 tests, five expected skips, 85% coverage,
  and real Chromium 2/2 passed.
- Chromium emitted only deferred issue #49's unchanged Canvas p95 warning
  (255.8 ms versus 250 ms); browser-generated tracked evidence was restored.
- Public read-only Docker dry-run with both GitHub tokens removed downloaded and
  verified all 13 assets and decoded/matched the exact 9,687-byte Release body.
- Authenticated read-only attestation lookup returned four statements for the
  repaired `RELEASE_NOTES.md` digest.
- Independent review: approved with no findings; independent focused Docker run
  passed 23/23 and review resources were cleaned.

## Recovery boundary

The failed repair workflow must not be redispatched from this fix. After review
and merge, a human may decide whether to run the corrected repair workflow.
Before any future mutation, recheck protected main, immutable tag/source,
current release inventory/body, canonical package digest, attestations, and the
workflow's replacement closure and rollback gates.
