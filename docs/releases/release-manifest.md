# Release manifest lifecycle

`release/release-manifest.json` and `release/SHA256SUMS` are generated release
assets. They are deliberately ignored by Git and must never be committed as the
source of release truth. A manifest that embeds its own containing commit would
create an unresolvable revision loop.

The tracked contract is
[`release-manifest.schema.json`](release-manifest.schema.json), together with the
generator and verifier in `anva.release`. `make release-manifest` obtains the exact
current commit and local OCI image identity, rejects an image whose OCI revision
does not equal that commit, regenerates both metadata files, and then verifies every
artifact byte, size, basename, and checksum. Package archives, both SBOM formats,
image/source scans, vulnerability dispositions, release notes, and any supplied
evidence/provenance archive are all inventoried rather than inferred.

The final worktree check consumes NUL-delimited Git status from the trusted host. It
allows only ignored paths named by the verified manifest plus the two generated
metadata files. Modified tracked files and every other untracked or ignored path are
release blockers. The Trivy cache is a Docker named volume so cache content cannot
be confused with a publishable artifact.

Before attaching the generated directory to a release, run the same verifier again
with the exact commit, image reference, and image ID. `publication_status` remains
`generated_unpublished`: registry digest and signature identity belong to the later
authorized publication record, not to this local pre-publication manifest. Never
reuse an existing `release/` directory for another candidate; `release-build` starts
with `release-clean` and the verifier rejects stale candidate identity, extra files,
unsafe paths, symlinks, and checksum drift.

The published v0.1.6 schema-v2 manifest therefore still contains the honest
build-stage value `generated_unpublished`. That value describes when those
manifest bytes were generated. This does not mean that v0.1.6 remained unpublished.
Protected run `33781714974`, the immutable `v0.1.6` tag, the GHCR
digest, the GitHub Release, attestations, and post-publication verification are
the separate publication record. Do not rewrite the build-stage field after the
fact or falsify the generator/schema contract.

`release-build` obtains the runtime image from the Compose `api` build definition
through BuildKit Bake and requires the Docker exporter to rewrite layer timestamps
to `SOURCE_DATE_EPOCH`. The Dockerfile also removes timestamp-bearing apt logs and
cache data and uv's installation-cache record. Those files are not runtime inputs;
retaining them would make identical source builds produce different layer DiffIDs.
Changing the source revision or another declared build input must still change the
image identity.

The runtime's exact Debian packages are resolved from a timestamped Debian snapshot,
not the moving distribution mirrors. APT continues to verify Debian's signed archive
metadata; only the snapshot's inevitably expired `Valid-Until` timestamp is disabled.
The build verifies every installed package version with `dpkg-query` before removing
APT metadata. To update the pins, select a snapshot timestamp at or after the desired
package first appeared, change `DEBIAN_SNAPSHOT` and `OPENSSL_DEBIAN_VERSION` together,
build from an empty project cache, and retain the successful build transcript plus the
resulting OCI/build-input provenance and vulnerability scan. Never move only the
snapshot timestamp or replace signature verification with `trusted=yes`.

Schema-v1 manifests remain useful only as historical evidence. They are intentionally
rejected by the release verifier and must be regenerated as schema v2 from the exact
candidate; editing or copying an old manifest is not a supported migration path.

## Published v0.1.0 metadata correction

The original public schema-v2 manifest honestly described its pre-publication
generation state, but became stale once run `33596661334` successfully published
and verified the release. Issue #74's controlled repair derives a schema-v3
`anva.published-release-manifest` from the exact downloaded bytes. It records the
tag, product source, immutable image digest, publication run, reviewed metadata
commit, repair run, correction reason, and exact three replaced assets. The
pre-publication generator and schema-v2 contract remain unchanged; the repair
script separately verifies the public schema-v3 closure and ten immutable assets.
