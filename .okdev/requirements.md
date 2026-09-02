# Release scanner cache and immutable v0.1.0 recovery

## Actual versus expected

The owner-authorized release run `33533018419` for immutable tag `v0.1.0` at
`d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac` failed in `release-scan` before any
image push, attestation, or publication. Docker created the run-owned named
Trivy cache volume as root, while `release-scanner` ran as runner UID/GID
`1001:1001`; Trivy therefore could not create `/cache/fanal`.

On a clean runner, the first and subsequent scan/gate invocations must be able
to use the fresh cache while the scanner remains unprivileged and all existing
release gates remain fail-closed.

## Reproduction

With no project cache volume present, set `ANVA_HOST_UID=1001`,
`ANVA_HOST_GID=1001`, and `ANVA_DOCKER_GID` to the Docker socket group. Run the
release scanner through the release Compose project. The old code fails its
first Trivy command with `mkdir /cache/fanal: permission denied`. Run
`33533018419` is the authoritative occurrence; an isolated local Compose
reproduction produced the same ownership failure.

## Affected components

- `compose.release.yaml`: scanner identity and cache lifecycle.
- `Makefile`: scan/gate orchestration.
- `.github/workflows/release.yml`: clean-run orchestration and immutable-tag
  recovery identity.
- Release workflow and hardening tests, including a Docker-backed fresh-cache
  regression.

## Acceptance criteria

1. A real pinned Trivy container can initialize and reuse a newly created,
   run-owned cache while running as configured non-root UID/GID.
2. `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, the read-only
   Docker socket mount, and scanner non-root execution remain in force. No
   privileged mode, added capability, broad host permission change, or
   engine-wide cleanup is introduced.
3. Scan contents, vulnerability exception matching, the risk gate, checksums,
   attestations, and release ordering are unchanged and remain fail-closed.
4. Behavior is deterministic on a clean runner and cleanup touches only the
   unique release Compose project's resources.
5. A regression fails on the old definition and passes after the fix, covering
   fresh cache initialization, reuse, and the effective security controls.
6. Recovery loads the corrected workflow from `main`, but resolves, checks out,
   builds, scans, manifests, attests, and publishes only existing tag `v0.1.0`
   at `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`.
7. The recovery path fails before publication side effects for a wrong/missing
   tag, moved tag, version mismatch, or branch-source substitution.
8. Nothing moves, deletes, or recreates `refs/tags/v0.1.0`; no retry occurs
   until the correction is reviewed and merged.

## Recovery design constraint

For `workflow_dispatch`, the workflow-definition identity and product-source
identity are intentionally separate. Dispatch must use the corrected default
branch workflow, accept only `v0.1.0`, check out that exact tag, resolve its
commit independently, and bind every source revision field to that resolved tag
commit rather than the branch-dispatch `GITHUB_SHA`.

The expected behavior is unambiguous. The implementation mechanism may vary
only if it meets every security and regression criterion above.
