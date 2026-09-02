# Delivery report: issue #67

## Status

**Ready for review/merge. Hosted recovery is not yet executed.**

The release-cache correction and immutable `v0.1.0` recovery controls are
implemented and locally verified. Review round 3 approved the settled diff with
no remaining MUST FIX findings. The GitHub-hosted recovery run, attestations,
package publication, and GitHub Release verification remain deliberately
deferred until this correction is reviewed and merged to `main`.

Do not retry the release before merge. Do not move, delete, or recreate
`refs/tags/v0.1.0`.

## Executive summary

Issue [#67](https://github.com/rishavt/anva/issues/67) fixes the failed release
scan without granting the scanner additional privilege. The failure occurred
because Docker created a fresh named Trivy cache volume owned by root while the
scanner ran as UID/GID `1001:1001`; Trivy could not create `/cache/fanal` and
failed before image push, attestation, or publication.

The current Compose definition now mounts its run-owned cache over the pinned
Trivy image's sticky `/tmp` and uses `/tmp/trivy-cache`. For immutable
`v0.1.0` recovery, the corrected workflow on `main` prepares the exact labeled
cache volume before checking out the old tag, whose Compose file still mounts
the volume at `/cache`. Docker's first mount preserves the pinned image's
root-owned mode-`1777` `/tmp`; the unprivileged preparer creates `fanal` as the
runner UID/GID, allowing the old tagged scanner definition to use it safely.

## What changed and why

- `compose.release.yaml` mounts `release-trivy-cache` at `/tmp` and sets
  `TRIVY_CACHE_DIR=/tmp/trivy-cache`. This fixes clean-run behavior for the
  corrected source without a root initializer, capability, or host permission
  change.
- `.github/workflows/release.yml` creates the exact
  `${COMPOSE_PROJECT}_release-trivy-cache` volume before tag checkout, refuses
  pre-existing collisions, applies and validates Compose project/volume labels,
  and prepares it with the pinned Trivy image as the runner UID/GID. The
  preparer has a read-only root filesystem, drops all capabilities, enables
  no-new-privileges, uses no network, and receives no Docker socket.
- Build cleanup validates the exact project and volume labels before removal.
  It never performs engine-wide cleanup and refuses foreign same-name volumes.
- Recovery documentation now instructs operators to dispatch the reviewed
  workflow from `main` only after merge, while retaining the immutable tag as
  the product source.
- Static release-workflow, hardening, and documentation tests plus a real
  pinned-Trivy Docker regression cover initialization, reuse, identity binding,
  effective controls, foreign collisions, and cleanup.

## Immutable `v0.1.0` recovery semantics

Workflow-definition identity and product-source identity are intentionally
separate:

1. Manual recovery loads `.github/workflows/release.yml` from reviewed `main`.
2. It accepts only existing tag `v0.1.0`.
3. The build independently resolves the lightweight or annotated remote tag and
   requires it to equal
   `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`.
4. Checkout HEAD, build output `source_commit`, OCI revision, risk acceptance,
   manifests, publication target, and provenance inputs are bound to that exact
   commit rather than the branch-dispatch `GITHUB_SHA`.
5. Publish and verify each check out the build-verified source SHA and
   independently re-resolve the live remote tag before artifact download,
   release mutation, registry authentication, or published verification.
6. A missing, wrong, or moved tag; version mismatch; branch-source
   substitution; checkout mismatch; or remote-tag race fails before the
   corresponding publication or verification side effects.

The workflow does not move, delete, or recreate the tag.

## Security invariants

The release scanner remains non-root with:

- `read_only: true`;
- `cap_drop: [ALL]`;
- `no-new-privileges:true`;
- a read-only Docker socket mount;
- no privileged mode or added capability;
- no broad host permission change; and
- cleanup restricted to the unique, correctly labeled Compose project volume.

Scan contents, vulnerability exception matching, risk gates, checksums,
attestation ordering, and fail-closed publication ordering are unchanged.

## Requirement and verification summary

| Requirement area | Implementation and observed evidence |
| --- | --- |
| Fresh cache initialization and reuse | Real pinned Trivy scan against a fresh old-style `/cache` mount failed with `mkdir /cache/fanal: permission denied`; workflow preparation then enabled two successful scans, with `fanal.db` and a marker reused. |
| Scanner hardening | Compose inspection confirmed non-root UID/GID, read-only root filesystem, all capabilities dropped, no-new-privileges, and socket `RW=false`. Preparer inspection confirmed the same rootfs/capability controls plus `network=none` and only the cache mount. |
| Fail-closed release behavior | Job-specific static tests verify build, publish, and verify identities and ensure checks occur before release or verification side effects. Existing scan, risk, checksum, and attestation ordering remains intact. |
| Deterministic scoped cleanup | Exact project resources were removed after every Docker run. A foreign same-name volume was refused and preserved; only the test harness removed its own recognized fixture afterward. |
| Immutable recovery | Local tag, live remote tag, and checkout HEAD were all observed at `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`. Publish and verify consume the build job's exact `source_commit` and independently resolve the remote tag. |
| Tag immutability and retry gate | No tag or GitHub state was mutated. Documentation explicitly prohibits retry before merge and prohibits moving, deleting, or recreating `v0.1.0`. |

## Test, review, and manual results

- Adjacent release suite: **48/48 passed**.
- Focused workflow/hardening/documentation suite after round-two changes:
  **18/18 passed**.
- Independent pre-round-three release pass: **46/46 passed**.
- Real Docker regression: old unprepared definition failed as expected; prepared
  definition passed first scan and cache reuse scan.
- Ruff, shell syntax, Compose configuration, and `git diff --check`: passed.
- Review round 3: **APPROVED**, with no MUST FIX findings.
- Manual spot-check: **10/10 passed**, covering local/live remote identity,
  Compose rendering, effective controls, exact failure reproduction,
  preparation, first scan, reuse, foreign collision preservation, and cleanup.
- Cleanup: all issue-scoped containers, networks, volumes, and temporary project
  image tags were removed after testing.

## Deployment and recovery instructions

After the correction is reviewed and merged to `main`, an authorized operator
may load the corrected workflow while naming the immutable product tag:

```sh
gh workflow run release.yml --repo rishavt/anva --ref main -f tag=v0.1.0
```

The hosted run must then be observed through all build, scan, risk, checksum,
attestation, publication, download, and install-verification gates. A failure
must remain failed closed and be investigated; it does not authorize moving or
recreating the tag.

This command has intentionally **not** been executed during implementation,
review, testing, or delivery preparation.

## Deferred validation and known limitations

- The real GitHub-hosted recovery, environment approval, GHCR publication,
  attestations, and GitHub Release lifecycle are deferred until after merge.
- No release retry has occurred, and no GitHub settings, tag, package, release,
  or repository state was changed by this work.
- No UI, browser, E2E, screenshot, or load testing applies to this
  release-infrastructure-only change. There are therefore no screenshots in
  this delivery report.

## Recommendation

Merge the approved correction to `main`, confirm the protected `v0.1.0` tag
still resolves to the pinned commit, then perform one authorized hosted recovery
dispatch using the command above. Treat the hosted workflow result—not this
local report—as the final publication outcome.
