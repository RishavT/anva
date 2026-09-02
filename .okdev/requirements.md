# GitHub Release creation for immutable existing tag

Issue: https://github.com/RishavT/anva/issues/71

## Actual versus expected

Run `33592278376` completed build, scan, risk, manifest, GHCR publication, and
standard/custom attestations for `v0.1.0` at
`d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`, then failed creating the GitHub
Release. `gh release create --verify-tag --target d919...` returned HTTP 403
despite effective `contents: write`. Explicitly targeting a commit whose tree
changes `.github/workflows/release.yml` relative to default invokes GitHub's
workflow-file permission gate; the job token cannot receive `workflows: write`.

The existing immutable tag must instead be released with `--verify-tag` and no
`--target`. Tag/source equality must remain fail-closed before and after the
release side effect.

## Reproduction evidence

- Protected `main`: `e56fd6137e5d401b13aedc521fe0d8c06095d499`.
- Immutable `refs/tags/v0.1.0`:
  `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`.
- Failed run: https://github.com/RishavT/anva/actions/runs/33592278376.
- Build and all publication/attestation steps passed; release-create alone
  returned `403 Resource not accessible by integration`; verify was skipped.
- GitHub Release API returned 404 for `v0.1.0` after the failure.

## Acceptance criteria

1. Keep `--verify-tag`; prohibit `--target`, PATs, workflow write permission,
   and repository default-permission changes.
2. Immediately before create/upload, re-resolve the exact live remote tag,
   including annotated peeling, and require it to equal the build output,
   pinned release commit, and checkout HEAD.
3. Reject missing, moved, malformed, duplicated, or substituted tag resolution
   before the release mutation.
4. After create/upload, query the Release tag, re-resolve it, and require its
   commit to equal the exact source commit.
5. Never move, delete, or recreate `v0.1.0`; keep tag rules unchanged.
6. Regression contracts require the exact guards and reject `--target`.
7. Document and prove the safe recovery choice from immutable run/workflow/API
   evidence without retrying the release or mutating tags, packages, settings,
   or releases during this fix.
