# GitHub-native release

Anva `v0.1.0` is distributed through the repository's GitHub Release and the
digest-addressed image `ghcr.io/rishavt/anva@sha256:…`. The release contains the
wheel, Codex and Claude skill archives, SPDX and CycloneDX SBOMs, security scan
reports, vulnerability dispositions, release notes, manifest, and checksums.

The release workflow uses only the per-job `GITHUB_TOKEN` and GitHub Actions
OIDC. It does not require a registry password or a persistent signing key.
GitHub records keyless build-provenance attestations for every downloadable
artifact and the pushed OCI digest. Actions are pinned to immutable commits.

## Repository and environment setup

1. Make the repository public before publishing. Releases and GHCR packages do
   not automatically share visibility; after the first push, confirm that the
   `anva` package is public and linked to this repository in GitHub package
   settings. A private repository produces private release assets even if its
   container package is public.
2. Create a protected GitHub Actions environment named `release`. Require Rishav
   Thakker (`RishavT`) as reviewer and prevent self-review if another authorized
   reviewer is available. Restrict deployment branches/tags to `v0.1.0`.
3. Keep the repository's default workflow-token permission read-only. The
   release job requests only `contents`, `packages`, `id-token`, and
   `attestations` write permissions.
4. Enable tag protection/rules for `v*` and require the release owner to create
   `v0.1.0` from the reviewed `main` commit. The workflow independently checks
   the tag, project version, exact commit, `main` ancestry, and clean checkout.

The workflow never runs on pull requests. A manual dispatch accepts only an
already-existing exact `v0.1.0` tag and must itself be dispatched with that tag
as its Git ref; it is not an escape hatch for arbitrary refs or versions:

```sh
gh workflow run release.yml --repo rishavt/anva --ref v0.1.0 -f tag=v0.1.0
```

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
docker pull 'ghcr.io/rishavt/anva@sha256:<digest>'
```

Use the digest published by the successful workflow, never only the mutable
version tag.

## Rerun, rollback, and failure handling

The concurrency group allows one `v0.1.0` publisher at a time. A rerun must
resolve the same tag and commit. Existing release assets are replaced only
after fresh checks and attestations; a release targeting another commit is
rejected. Consumers remain pinned to the recorded digest, so a failed or
partial rerun cannot silently change an installed image.

If publication fails before GitHub Release creation, do not use the pushed tag;
inspect and delete only the failed GHCR package version through GitHub's package
UI, then rerun the same commit. If post-publication verification fails, mark the
release as withdrawn, retain its evidence for audit, fix forward under a new
version, and do not move or overwrite the original Git tag. Roll back a deployed
instance only to a previously verified digest and follow the paired database and
object-store procedure in the install/upgrade/uninstall runbook.
