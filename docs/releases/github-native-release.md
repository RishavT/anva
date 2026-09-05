# GitHub-native v0.1.6 release

## Publication outcome

This procedure completed successfully in protected run
[`33781714974`](https://github.com/RishavT/anva/actions/runs/33781714974).
The immutable tag resolves to source
`e89b06aed8207cc32eee0eeebde4a2731f0c0203`; the published image is
`ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`.
All 12 public assets and the image passed post-publication verification. The
separate operator gate completed in signoff run `33910747236`. Subsequent source
changes are fix-forward preparation for `v0.1.7`, not mutations of v0.1.6.

The release workflow publishes only an existing exact `v0.1.6` tag. It is a
manual `workflow_dispatch` loaded from reviewed `main`, requires the full
lowercase candidate commit. Its first job is non-publishing and creates an
attested exact-candidate risk proposal. Every job capable of publishing remains
behind the protected `release` environment. No release job has
`artifact-metadata` access or uses a long-lived secret: the proposal job has
read-only content plus OIDC/attestation write; build has `actions: read`,
`contents: read`, `packages: write`, `id-token: write`, and `attestations:
write`; publish uses `packages: read`, `attestations: read`, and `contents:
write`; verify uses those permissions read-only.

## Immutable identity and approval order

1. Merge the reviewed preparation to protected `main` and record its full commit.
2. Separately create the protected `v0.1.6` tag at that exact commit. Never move,
   delete, or recreate it.
3. RishavT personally dispatches the reviewed workflow from `main`, supplying
   both identities and an expiry no more than 30 days away:

```sh
ANVA_SOURCE_COMMIT=<reviewed-full-40-character-commit>
gh workflow run release.yml --repo rishavt/anva --ref main \
  -f tag=v0.1.6 -f source_commit="$ANVA_SOURCE_COMMIT" \
  -f risk_expires_on=YYYY-MM-DD
```

4. The unprotected proposal job performs two independent, cache-empty builds in
   separately created pinned BuildKit daemons. Both must produce the same OCI
   archive bytes, manifest, config, uncompressed rootfs identities, and layer
   blobs. It scans that canonical archive after an exact copy into a loopback-only
   registry, without publishing or applying
   an exception. It uploads a GitHub-attested canonical proposal containing the
   exact tag/source, OCI archive SHA-256 and size, OCI manifest digest, fresh report checksum,
   complete HIGH/CRITICAL tuples, runtime-controls fingerprint, and expiry. The
   canonical image vulnerability report, SPDX/CycloneDX SBOMs, and database
   metadata are retained beside the proposal. Every Trivy invocation records an
   explicit engine exit and canonical command identity, then receives
   format-specific semantic validation. The secret-redacted source report also
   applies the HIGH/CRITICAL policy. A content-hashed evidence manifest binds all
   successful reports, SBOMs, status manifests, diagnostics, bounded logs, and
   database metadata into the proposal and eventual decision. An engine error,
   malformed JSON schema, or source-policy finding fails before proposal/digest
   creation; an `always()` artifact safely retains every completed non-secret or
   sanitized output for that exact run attempt.
   The image build uses the Compose `api` definition through BuildKit Bake with
   timestamp rewriting anchored to the candidate commit's `SOURCE_DATE_EPOCH`;
   transient apt and uv cache records are excluded from the runtime filesystem.
   Maintainers can exercise the same-input and changed-input invariants locally or
   in a Docker-capable CI runner with
   `scripts/test_release_oci_reproducibility.sh`; it requires the exact revision,
   source epoch, build-input hash, and reviewed digest-pinned BuildKit image in
   the corresponding `ANVA_*` environment variables.
   OCI verification never extracts a layer. It requires normalized relative
   member paths and safe relative hardlink targets. Symlink targets are retained
   as inert archive metadata and may contain relative `..` components used by
   the pinned base image; their encoding and length remain bounded.
5. The publishing job waits at the protected `release` environment. RishavT
   downloads the proposal artifact, verifies every GitHub attestation and
   SHA-256 value, inspects the exact image report, validated source report,
   passing scan diagnostic, and database evidence, and
   personally approves or rejects the pending
   environment deployment in GitHub. No workflow, agent, or API call approves it.
6. After approval, the job queries GitHub's immutable review history for this
   exact run and requires exactly one initial `approved` review for environment
   `release`, by `RishavT`, with no other approver. It canonically binds that
   record into the decision. Later protected jobs may add approval records, but
   publication requires every approved record to be unambiguously for `release`
   by exact `RishavT`, and requires the original bound hash to match exactly one
   record. It verifies the attested OCI archive and proposal binding, copies
   those exact bytes with a digest-pinned tool into a loopback-only registry,
   and rescans that image; it does not rebuild the approved image. It requires
   digest, tuples, and runtime controls to equal the reviewed proposal. It then creates
   and attests a decision binding the
   proposal SHA-256, GitHub approval-record SHA-256, both report checksums,
   source, digest, tuples, controls, run, reviewer, and expiry. The decision and
   its attestation verify before any publication mutation. The successful
   v0.1.5 approval and its associated evidence authorize only the immutable
   v0.1.5 release; they cannot be replayed or used to authorize v0.1.6. The
   v0.1.0 approval remains older historical evidence and likewise cannot
   authorize v0.1.6.

The workflow resolves the direct or peeled remote tag, checks out that tag, and
requires the tag, checkout, supplied commit, and `main` ancestry to agree. It
rechecks the live tag and checkout immediately before the first GHCR push.
Immediately before GitHub Release creation it re-verifies the risk decision
attestation and every bound proposal, approval, source, image, report, database,
runtime, reviewer, run, and current-expiry field, then rechecks the live tag.
A source or evidence mismatch fails closed.

## Artifacts and attestations

Public release asset download and checksum validation do not require GitHub
authentication. GitHub attestation lookup does, so authenticate with
`gh auth login` or a scoped `GH_TOKEN` before verifying provenance.

The exact checkout produces the wheel, install archive, skill archives,
SPDX/CycloneDX SBOMs, Trivy reports, reviewed risk record, release notes,
manifest, and checksums. The image OCI revision, manifest source, and artifact
source predicates all name the same commit. GitHub Actions OIDC produces
standard provenance plus the supplemental
`https://github.com/RishavT/anva/attestations/source/v1` predicate for every
download and the immutable OCI digest.

Before publication, verify checksums, risk binding, tag identity, signer
workflow, standard provenance, and custom predicate fields. After publication,
download everything again, pull the image by digest, extract the install bundle,
run Compose config without a rebuild, migrate a clean stack, verify readiness
and representative CLI/API behavior, and seed the demo twice.

## Consumer verification

```sh
gh release download v0.1.6 --repo rishavt/anva --dir anva-v0.1.6
(cd anva-v0.1.6 && sha256sum --check SHA256SUMS)
ANVA_SOURCE_COMMIT="$(jq -er '.source_commit' anva-v0.1.6/release-manifest.json)"
ANVA_SOURCE_TAG=v0.1.6
ANVA_SOURCE_VERSION=0.1.6
ANVA_SOURCE_PREDICATE_TYPE=https://github.com/RishavT/anva/attestations/source/v1
for artifact in anva-v0.1.6/*; do
  gh attestation verify "$artifact" --repo rishavt/anva
done
```

Consumers must additionally inspect the supplemental predicate and require its
`sourceCommit`, `sourceRef`, `sourceTag`, repository, and version fields to equal
the values above. Pull and deploy only the digest in `release-manifest.json`,
never an unverified mutable version tag.

## Failure, rollback, and cleanup

Never overwrite a tag, release, release asset, attestation, or digest. If the
release already exists, the workflow fails; `--clobber` and ordinary release
asset repair are forbidden. Abandon a failed
candidate and fix forward from a newly reviewed commit. The rollback predecessor
is the verified v0.1.5 image
`ghcr.io/rishavt/anva@sha256:19488230c6f7900cda33bd11adc7f1ad824d23b77ee87fd65ac883cd0dacc725`;
use that exact digest only when schema compatibility is established. Otherwise,
stop writers and restore the paired database/object backup. Retain
failure and provenance evidence. Cleanup may remove only the exact run-labelled
Compose project, local registry, scanner cache, and test volumes; global Docker
pruning is forbidden.

The one-time `.github/workflows/release-metadata-repair.yml` remains exclusively
for the published v0.1.0 history and must not be used for v0.1.6.
