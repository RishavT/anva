# MVP-013 evidence index

This index records the immutable local release-candidate evidence for MVP-013.
It is an exact-source verification record, not a publication attestation: no
release tag, registry digest, signature/provenance, package publication, GitHub
Actions execution, or public release is claimed.

## Candidate identity

- Issue: `rishavt/anva#13`
- Candidate version: `0.1.0`
- Source commit: `94231d7e57767b18a4cd9546ad5bf33afc13a735`
- Source tree: `43395db015a2205c739647c1b6dfb9b02626abd2`
- Local runtime image: `anva-mvp13:0.1.0`
- Runtime image ID:
  `sha256:c6ae3a8abfd4c54d91df94be0dfe7f1bc1c52e73da58a4617b2bc30a3b1f6f2c`
- Runtime OCI revision: `94231d7e57767b18a4cd9546ad5bf33afc13a735`
- Runtime image size: 356,842,368 bytes
- Reproducible image creation time: `2025-09-01T00:00:00Z`
- Git tag, registry digest, signature/provenance, and publication record: not
  produced

The product, runtime, test, operations, and scan results below bind to that
source commit and tree. A later commit that changes only these narrative
documents is a documentation descendant of the verified source candidate; it
does not change or invalidate the parent candidate's immutable artifacts. It
also must not be substituted for `94231d7e...` as the tested product/runtime
identity. Any product, dependency, build-input, or release-artifact change
requires a new candidate and new evidence.

## Immutable evidence and release metadata

- Evidence archive:
  `release/anva-evidence-94231d7e57767b18a4cd9546ad5bf33afc13a735.tar.gz`
- Archive size: 4,648,450 bytes
- Archive SHA-256:
  `d90916f8063911757a05f8e0b16e25e5a64063609046a04e44aea9065d6dbeb8`
- Release manifest SHA-256:
  `ece6cbb1ca97908c383026c0e0f2e782f9ea9b43a3d7ab5d04272d685e8ab8e9`
- `SHA256SUMS` SHA-256:
  `0bee340d464f79ccbbe0fe88dc439aab587c37e9fcf706f7b87827f0b8f48060`
- Wheel SHA-256:
  `ad3ee8bc91fca3a5ced940f4f1757d2830e69a4436659ada74594ca273f2b9c9`
- Evidence freeze time: `2026-08-07T09:36:36Z`

The manifest records the local image ID, exact source commit, wheel, both skill
archives, both image SBOMs, image/source scan reports, reviewed vulnerability
exceptions, release notes, and the evidence archive. `SHA256SUMS` covers those
artifacts plus the release manifest. These are local ignored release outputs;
they have not been uploaded or signed.

## Exact-source verification results

All source mounts used for the broad, corpus, and browser lanes were read-only,
and the candidate repository was clean before and after each applicable lane.

| Lane | Exact result |
| --- | --- |
| Static and generated artifacts | `uv lock` resolved 78 packages; Ruff format checked 182 files; Ruff lint returned zero findings; mypy checked 158 files with zero errors; 24 generated contracts verified; migrations reported no model drift. |
| Broad Compose suite | 765 collected; 762 selected; 761 passed; one expected skip for the separately executed live-MCP Compose profile; three browser/corpus tests deselected; zero failures/errors; 274.48 seconds. |
| Coverage | 85.41424161141758% combined line/branch coverage; 13,733/15,459 lines and 3,144/4,300 branches covered. |
| External corpus | One `corpus` acceptance test selected and passed; 764 deselected; zero failures/errors/skips; 216.96 seconds. `anva-test` was read-only and clean at commit `a66787b0f3d009d6e599813ad5fefd847e603b7e`, tree `47f11e3ebd8452ddd9675c5406b457d44bffc9a2`. |
| Browser | Two Chromium journeys passed with zero failures/errors/skips in 107.501 seconds; Chromium and ChromeDriver were `151.0.7922.71`; 19 screenshots/performance artifacts were checksummed. |
| Live MCP | Two official-Python-client tests passed with zero failures/errors/skips in 1.647 seconds against both the write-capable service and the actual read-only service. |

The one broad-suite skip is expected because the live MCP test requires a
separate topology and was executed once in that topology. It is not an
unexecuted release case.

## Operations evidence

The disposable exact-image drill used the local runtime image identified above
and Compose-managed PostgreSQL/MinIO:

- the database and object-store guards rejected hostile configuration with
  exit 2 before stopping writers, and the writer set was preserved;
- the operation mutex rejected a competing operation with exit 2;
- a deliberately incomplete backup failed with exit 2, left an inactive
  partial generation, and preserved the prior `current` pointer;
- the paired backup and checksum manifest verified successfully and activated
  a new unique generation;
- an injected restore failure exited 2 and left Anva writers stopped;
- a subsequent restore succeeded with migration and representative model counts
  invariant;
- migration rehearsal reversed only the disposable clone to `core.0019`,
  migrated it forward to head, and left the live database counts and migration
  state invariant; and
- the runtime and rehearsal projects left zero containers, networks, or volumes
  after cleanup.

This evidence covers disposable synthetic data and Compose-managed MinIO only.
It does not establish external object-store backup, point-in-time recovery,
encryption/key management, cross-version application compatibility, or
deployment-sized recovery timing.

## Security scans and SBOMs

`make release-scan-gate` ran once and exited 0 against the exact local runtime
image and source candidate.

- Image scan: 203 total vulnerability tuples: 6 critical, 18 high, 70 medium,
  100 low, and 9 unknown. All 24 high/critical package tuples map to 14 reviewed
  no-vendor-fix exception IDs; zero high/critical tuples were fixable or
  unwaived. The exceptions were reviewed on 2026-08-04 and expire on
  **2026-08-18**. This is not a zero-high/critical claim; expiry requires
  re-review, update, or release blocking.
- Source scan: zero high/critical vulnerabilities, zero high/critical
  misconfigurations, and zero secrets. It still reports four fixable Django
  vulnerabilities below the release threshold: one medium
  (`CVE-2026-5766`) and three low (`CVE-2026-35192`, `CVE-2026-6907`, and
  `CVE-2026-7666`), plus low Dockerfile finding `DS026` (no `HEALTHCHECK`).
  These are residual findings, not a clean-scan claim.
- SBOMs: CycloneDX 1.6 contains 159 components and 160 dependency entries;
  SPDX 2.3 contains 160 packages and 323 relationships.

The scan project and scanner image were removed, the task Trivy cache was
reduced to its tracked one-byte placeholder, and top-level release artifacts
were preserved.

## Resource and cleanup record

The final conservative task footprint was 1,993,367,109 bytes with the named
builder cache at 0 bytes, below the 5,000,000,000-byte working limit. The scan
lane's measured pre-cleanup footprint was 3,386,349,325 bytes, also below the
limit. This was a measured task constraint, not a Docker-engine quota. Cleanup
was restricted to exact task projects, images, and cache; no engine-wide prune
was used or is authorized by this record.

## Open and deferred gates

The exact local evidence does not close these boundaries:

- no tag, registry digest, signature/provenance, package/image publication,
  GitHub Actions run, or public release exists;
- the exact corpus ingestion acceptance passed, but the full `anva-test`
  non-browser/browser baselines and all 31 isolated assurance-oracle scenarios
  were not executed as a release gate;
- sealed fresh-agent Codex/Claude executions and human
  user/operator/developer acceptance remain deferred;
- external object-store and deployment-sized recovery were not exercised;
- physical deletion/legal erasure, post-setup reauthentication, persistent
  telemetry aggregation, dashboards, alert delivery, distributed trace export,
  OAuth/enterprise SSO, accepted byte/archive upload, external model inference,
  production Terraform, billing, and multi-browser support remain outside the
  demonstrated boundary; and
- the source lower-severity findings and image exceptions described above
  remain subject to disposition and expiry review.

Retention appends expiry state only after explicit expiry and the organization
minimum have passed and cleans only that organization's expired rate buckets.
Decommission is access revocation, not hard deletion; it requires a
setup-authenticated human session no older than 15 minutes, CSRF, and two exact
confirmations. Because no post-setup reauthentication exists, decommission is
unavailable after that window.

## Status source of truth

Use the [requirements/evidence matrix](../../releases/requirements-evidence-matrix.md)
for requirement status and the [release checklist](../../releases/release-checklist.md)
for the remaining release gates. Exact local verification must not be
misrepresented as publication or human acceptance, and a missing artifact must
not be replaced with a prose assertion.
