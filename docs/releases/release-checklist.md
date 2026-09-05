# MVP-013 release checklist

This checklist records the published v0.1.6 self-hosted MVP boundary. A checked
item is backed by execution evidence, not documentation alone. Future `v0.1.7`
preparation must create a new checklist and must not alter or replay v0.1.6
identities, decisions, approvals, artifacts, or attestations.

## Exact release identity

- [x] Tag/source: `v0.1.6` / `e89b06aed8207cc32eee0eeebde4a2731f0c0203`.
- [x] Immutable image:
  `ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`.
- [x] Protected release run
  [33781714974](https://github.com/RishavT/anva/actions/runs/33781714974)
  completed Build exact risk proposal, Build and attest, Create GitHub Release,
  and Verify published release.
- [x] Twelve public assets include the wheel, install and skill archives,
  SPDX/CycloneDX SBOMs, source/image reports, exact risk decision, manifest,
  notes, and `SHA256SUMS`.
- [x] Standard provenance and supplemental source predicates bind every public
  subject and OCI digest to the exact tag/source.
- [x] The manifest's `generated_unpublished` value remains the truthful
  build-stage status of those bytes; hosted release/run/digest evidence records
  the later publication state.

## Install and lifecycle

- [x] Fresh downloaded-bundle Compose installation used the published image
  without rebuilding and required no host Python, Node.js, npm, or Go.
- [x] Resolved production configuration, unique-secret requirements, TLS and
  exact trusted-proxy responsibilities are documented and gated.
- [x] Migrations, readiness, idempotent synthetic demo, terminal-only token
  handling, preserve-data uninstall, and exact-project clean uninstall passed.
- [x] Skill/MCP installers and uninstall paths refuse to overwrite or remove
  modified user content.
- [x] Backup generation/verification, paired restore into a clean project,
  injected failure handling, writer stop/resume, and disposable migration
  reversal/reapply are exercised.
- [x] Restored tenant, audit, provenance, artifact, and object identities are
  compared to the paired manifest within the Compose-managed MinIO boundary.
- [ ] External object-store and deployment-sized recovery are not claimed;
  they remain post-MVP issue #38.

## Security and privacy

- [x] Product and feature threat models are reviewed.
- [x] Cross-tenant API/search/Canvas/MCP/artifact and source/credential
  revocation matrices pass.
- [x] All six pinned TST-007 artifact byte classes pass through Anva.
- [x] Five hostile source classes remain inert across two tenants with zero
  mutation or leakage.
- [x] Logs, traces, metrics, reports, packages, images, and release evidence
  pass bounded secret/canary checks.
- [x] Source/image scans, exact 13-CVE/16-tuple time-bounded risk decision,
  SBOMs, licenses, and repository checks passed for the published digest.
- [x] Retention/decommission behavior, access revocation, retained data, and
  unsupported legal-erasure claims are documented and tested.
- [ ] OAuth, external model governance, managed deployment, and commercial
  penetration testing remain post-MVP issue #40.

## Operations

- [x] Dependency-free liveness and database/migration/object-store readiness
  checks pass.
- [x] Database-backed process-shared rate limiting and stable
  `429`/`Retry-After` behavior pass.
- [x] Correlated structured logs, W3C trace identifiers, protected metrics,
  exact proxy attribution, and bounded logging pass.
- [x] The deployment-owned metrics/proxy, credential, permission-leak,
  restore, storage, retention/decommission and escalation drill completed.
- [x] Rishav Thakker is the named release, security, application, platform,
  and operations/on-call owner with primary and alternate escalation paths.
- [x] Protected operator signoff run
  [33910747236](https://github.com/RishavT/anva/actions/runs/33910747236)
  and the final anchor attestations verify; exact drill cleanup is 0/0/0.
- [ ] Persistent aggregation, dashboards, alert delivery, and distributed
  tracing remain post-MVP issue #39.

## Test and evaluation

- [x] Formatting, Ruff, typing, migration drift, generated contracts, skill
  packaging, coverage, security, MCP, and browser gates pass.
- [x] Exact-current post-fix CI
  [33951634105](https://github.com/RishavT/anva/actions/runs/33951634105)
  passed 1,255 tests with six documented skips, then both required Chromium
  journeys, and cleaned its Compose resources.
- [x] All 31 committed public cases import and replay deterministically with
  stable identities, equal aggregates, clean-reader tamper rejection,
  foreign-authority denial, and inert canary.
- [x] One representative context-free independent review over the messy
  knowledge corpus passed; its two minor defects were fixed and tested.
- [x] The separate multi-stage `anva-test#18` contracts-root defect remains
  honestly open and is not represented as completed product evidence.
- [x] Canvas issue #49 preserves both passing/failing measurements and the
  unchanged 250 ms p95 target under its explicit post-MVP disposition.

## Completion record

- [x] Checksummed result logs, screenshots, performance/coverage reports,
  scans, SBOMs, lifecycle reports, evaluation results, limitations, and
  requirement mappings are indexed.
- [x] Product release gate #43 and operator gate #44 are complete.
- [x] Operator drill UUID `3933a24e-f70a-4869-9041-7f2db668db8d` has final
  ledger SHA-256
  `2338af9ee4d83469e461d02394051b73c02845718741cdea3b7ae8afadfede41`.
- [x] Release and drill task projects report zero containers, networks, and
  volumes; private temporary drill material was removed.
- [x] Post-MVP issues #37–#40 and #49 are explicit and are not converted into
  self-hosted MVP completion claims.

## Fix-forward boundary

Current `main` contains changes after immutable source `e89b06a`, including the
operator-finalizer correction and this documentation reconciliation. These
bytes are not v0.1.6 artifacts. `v0.1.7` is the next patch and remains pending a
new reviewed source/tag, fresh risk decision, protected approvals, artifacts,
attestations, publication, and post-publication verification.
