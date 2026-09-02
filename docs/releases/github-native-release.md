# GitHub-native release

Anva `v0.1.0` is distributed through the repository's GitHub Release and the
digest-addressed image `ghcr.io/rishavt/anva@sha256:…`. The release contains the
wheel, Codex and Claude skill archives, SPDX and CycloneDX SBOMs, security scan
reports, vulnerability dispositions, release notes, manifest, and checksums.

The release workflow uses only the per-job `GITHUB_TOKEN` and GitHub Actions
OIDC. It does not require a registry password or a persistent signing key.
GitHub records keyless standard build-provenance attestations and supplemental
product-source attestations for every downloadable artifact and the pushed OCI
digest. Actions are pinned to immutable commits.

## Repository and environment setup

1. Make the repository public before publishing. Releases and GHCR packages do
   not automatically share visibility; after the first push, confirm that the
   `anva` package is public and linked to this repository in GitHub package
   settings. A private repository produces private release assets even if its
   container package is public.
2. Create a protected GitHub Actions environment named `release`. Require Rishav
   Thakker (`RishavT`) as reviewer and prevent self-review if another authorized
   reviewer is available. Restrict deployment branches/tags to `v0.1.0`.
3. Keep the repository's default workflow-token permission read-only. The build
   job requests `contents: read`, `packages: write`, `id-token: write`, and
   `attestations: write`. Publish requests `packages: read`, `attestations: read`,
   and `contents: write`; verification requests those three permissions
   read-only. No release job requests `artifact-metadata` access.
4. Enable tag protection/rules for `v*` and require the release owner to create
   `v0.1.0` from the reviewed `main` commit. The workflow independently checks
   the tag, project version, exact commit, `main` ancestry, and clean checkout.

The workflow never runs on pull requests. For the `v0.1.0` recovery, wait until
the cache correction has been reviewed and merged to `main`, then load that
corrected workflow definition from `main`:

```sh
gh workflow run release.yml --repo rishavt/anva --ref main -f tag=v0.1.0
```

Workflow identity and product-source identity are deliberately separate. The
dispatch ref selects the reviewed workflow on `main`; the workflow checks out
the existing `v0.1.0` tag, independently resolves it, and requires its commit
to remain `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`. Before checkout replaces
the working tree with that immutable source, the reviewed workflow prepares the
run-owned Trivy cache before checking out the tag. The standard SLSA provenance
records the main dispatch identity, which identifies the reviewed workflow but
is not the product-source identity. The separate, supplemental source-binding
predicate is the authoritative product-source binding: its signed in-toto
statement binds each file or OCI subject digest to the independently resolved
`sourceTag`, `sourceRef`, `sourceCommit`, and release `version`. Publish and
verification jobs cryptographically verify the GitHub signature and signer
workflow, then inspect those predicate fields against the build outputs before
accepting the subjects.
Do not move, delete, or recreate the tag, and do not dispatch the recovery
before the correction is reviewed and merged.

## Publish

After the final commit is on `main`, create and push the exact tag:

```sh
git fetch origin main --tags
git switch --detach <reviewed-full-commit>
git tag -s v0.1.0 -m 'Anva 0.1.0'
git push origin refs/tags/v0.1.0
```

If no local GPG identity is maintained, use a GitHub-created verified tag or a
lightweight protected tag. Artifact identity does not depend on that tag's local
signature: the workflow generates keyless GitHub attestations tied to its OIDC
identity and immutable commit.

The workflow builds and verifies local release artifacts before pushing. It
then resolves the registry digest, attests the image and files, creates the
GitHub Release, downloads it again, verifies checksums and attestations, pulls
the image by digest, runs the CLI, migrates a fresh stack, and seeds the demo.
Only this successful lifecycle completes the workflow.

## Consumer verification

Install GitHub CLI, authenticate if GitHub requires it, and verify downloaded
assets and the exact OCI image:

```sh
gh release download v0.1.0 --repo rishavt/anva --dir anva-v0.1.0
(cd anva-v0.1.0 && sha256sum --check SHA256SUMS)
for artifact in anva-v0.1.0/*; do
  gh attestation verify "$artifact" --repo rishavt/anva
done
gh attestation verify 'oci://ghcr.io/rishavt/anva@sha256:<digest>' \
  --repo rishavt/anva

ANVA_SOURCE_COMMIT=d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac
ANVA_SOURCE_TAG=v0.1.0
ANVA_SOURCE_VERSION=0.1.0
ANVA_SOURCE_PREDICATE_TYPE=https://github.com/RishavT/anva/attestations/source/v1
verify_source_binding() {
  gh attestation verify "$1" --repo rishavt/anva \
    --predicate-type "$ANVA_SOURCE_PREDICATE_TYPE" \
    --signer-workflow RishavT/anva/.github/workflows/release.yml \
    --format json | jq -e \
      --arg commit "$ANVA_SOURCE_COMMIT" \
      --arg ref "refs/tags/$ANVA_SOURCE_TAG" \
      --arg repository "https://github.com/RishavT/anva" \
      --arg tag "$ANVA_SOURCE_TAG" \
      --arg version "$ANVA_SOURCE_VERSION" \
      'map(select(.verificationResult.statement.predicate["sourceCommit"] == $commit)
        | select(.verificationResult.statement.predicate["sourceRef"] == $ref)
        | select(.verificationResult.statement.predicate["sourceRepository"] == $repository)
        | select(.verificationResult.statement.predicate["sourceTag"] == $tag)
        | select(.verificationResult.statement.predicate["version"] == $version))
        | length > 0'
}
for artifact in anva-v0.1.0/*; do
  verify_source_binding "$artifact"
done
verify_source_binding 'oci://ghcr.io/rishavt/anva@sha256:<digest>'
docker pull 'ghcr.io/rishavt/anva@sha256:<digest>'
```

The default `gh attestation verify` commands validate standard SLSA provenance.
The `verify_source_binding` commands separately validate the authoritative
immutable product-source predicate. Both must pass. Use the digest published by
the successful workflow, never only the mutable version tag.

## Rerun, rollback, and failure handling

The concurrency group allows one `v0.1.0` publisher at a time. Release creation
uses the already-existing tag with `--verify-tag`; it deliberately omits
`--target`, because supplying a target is unnecessary for an existing tag and
can make GitHub require workflow-file write permission. Immediately before any
release create or upload, and again after it, the workflow resolves the live
tag and requires its commit to equal the pinned, build-verified source commit.
It never moves, deletes, or recreates the tag.

If only publish or verify failed, prefer **Re-run failed jobs** on the original
run only when that run's workflow `head_sha` is still the corrected protected
`main` revision. This reuses the run identity and executes the failed job plus
its dependent verification job; successful build outputs and artifacts remain
the inputs. If the original run predates the correction, or its workflow source
does not equal current protected `main`, dispatch `release.yml` from `main` with
`tag=v0.1.0` instead. Before either recovery, require the tag to remain pinned,
the GitHub Release to be absent (or already bound to that tag), and the existing
canonical GHCR digest and standard/custom attestations to verify. Never rerun
all jobs merely to repair Release creation, and never overwrite the canonical
package or attestations as part of that repair.

For failed run `33592278376`, a new dispatch is required after this correction
merges. GitHub records that run's `head_sha` as `e56fd6137e5d401b13aedc521fe0d8c06095d499`,
whose workflow still supplied `--target`. [GitHub re-runs retain the original
event's `GITHUB_SHA` and `GITHUB_REF`](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs),
so **Re-run failed jobs** would execute
the same broken workflow definition rather than this correction. The retained
`release-assets-33592278376` artifact is evidence from that run, not authority
to mix its old workflow attempt with a new definition.

Existing release assets are replaced only after fresh checks and attestations;
a release whose tag resolves to another commit is rejected. Consumers remain
pinned to the recorded digest, so a failed or partial rerun cannot silently
change an installed image.

If image publication or attestation itself fails, do not use the pushed tag;
inspect and delete only a demonstrably incomplete GHCR package version through
GitHub's package UI, then rerun the same commit. If those gates succeeded and
only GitHub Release creation failed, retain and verify the canonical digest and
attestations; do not delete or overwrite them. If post-publication verification
fails, mark the release as withdrawn, retain its evidence for audit, fix forward
under a new version, and do not move or overwrite the original Git tag. Roll
back a deployed instance only to a previously verified digest and follow the
paired database and object-store procedure in the install/upgrade/uninstall
runbook.
