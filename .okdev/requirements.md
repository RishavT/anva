# Release metadata repair authentication and byte-exact rollback

Issue: https://github.com/RishavT/anva/issues/77

## Actual versus expected

Run `33620337769` uploaded and attested the replacement metadata, then failed
its post-upload verification because the workflow explicitly removed both
GitHub tokens before `gh attestation verify`. GitHub CLI requires authentication
for attestation API lookup, including for public repositories.

The failure trap restored the original assets and body, but its verification
reported `cmp: EOF on old-release-body.md after byte 9687, line 164`. The body
snapshot used `gh release view --jq .body > file`; CLI rendering adds an output
newline and therefore cannot preserve an API string byte-for-byte.

## Reproduction evidence

- Protected `main`: `146f4ec44d5caaba8dfea893a9b087bd3b5f8083`.
- Immutable `refs/tags/v0.1.0`:
  `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`.
- Failed run: https://github.com/RishavT/anva/actions/runs/33620337769.
- Post-upload failure: `gh: To use GitHub CLI in a GitHub Actions workflow,
  set the GH_TOKEN environment variable.`
- Rollback verification failure: `cmp: EOF on old-release-body.md after byte
  9687, line 164`.
- Public API dry-run confirms the current body is exactly 9,687 bytes while
  `RELEASE_NOTES.md` is 9,686 bytes.

## Acceptance criteria

1. Use the job's least-privilege `GH_TOKEN` for post-upload `gh attestation
   verify`; do not claim that attestation lookup is anonymous.
2. Keep public release-asset downloads and checksum verification anonymous and
   document the authentication boundary for attestation lookup.
3. Decode the Release API JSON body string directly to bytes for snapshots and
   rollback comparisons, without CLI/JQ rendering.
4. Executable regressions distinguish bodies ending in zero, one, and multiple
   newlines and prove exact restoration after ordinary failure, HUP, INT, and
   TERM.
5. Do not redispatch repair, edit the body manually, or mutate the release,
   tag, package, repository settings, or protected branch during this fix.
