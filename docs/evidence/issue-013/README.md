# MVP-013 evidence index

This index separates the current shared-worktree validation snapshot from the
still-missing exact-commit release record. The summarized results below were
observed during MVP-013 implementation. They are development evidence, not a
published release attestation: raw command logs, immutable runner identity,
timestamps, exact source commit, and checksummed result artifacts have not yet
been indexed here.

## Candidate identity

- Issue: `rishavt/anva#13`
- Candidate version: `0.1.0`
- Git commit: not recorded
- Git tag: not created
- Registry image reference/digest: not published or recorded
- Signature/provenance: not produced
- GitHub Actions: workflow execution status not recorded; this work does not add,
  enable, or change a workflow

## Worktree validation snapshot

- Broad Compose suite: 721 passed, one expected live-MCP skip, three deselected,
  and 85% branch coverage.
- Focused MVP-013 suite: 54 passed.
- Fresh Compose official-Python-client MCP acceptance: 2 passed.
- Headless Chromium product journeys: 2 passed.
- Historical release image result: zero fixable high/critical vulnerability
  findings. The current gate also records 14 reviewed no-vendor-fix exceptions
  that expire on 2026-08-18; it is not a zero-high/critical result.
- Source security scan: zero high/critical findings.
- Atomic-generation PostgreSQL/Compose-managed-MinIO backup, checksum
  verification, failed-restore stop behavior, and successful restore/resume:
  passed in a disposable worktree Compose project. An incomplete generation did
  not replace `current`; the deliberately failed migration left every prior
  writer stopped. External object-store backup was not exercised or supported.
- Disposable schema rehearsal from migration `0020` back to `0019` and forward
  to `0020`: passed. The rehearsal project was removed with its volume/network,
  while the live project remained at `0020` and returned healthy.

The landed hardening now writes unique backup generations and atomically moves a
regular `current` pointer only after verification; dynamically quiesces and
resumes only the Anva writers that were running; leaves writers stopped after a
failed restore; and rehearses reversal/forward migration only in a guarded,
disposable restored database clone. The current demo is `run --rm`, uses no Docker log
driver, and exposes its fresh token only to the attached terminal. These exact
semantics passed the worktree drills above but still await exact-commit
revalidation.

Release hardening also rejects untracked worktree files, binds the image OCI
revision to clean `HEAD`, rebuilds/verifies skill archives, and gates the source
vulnerability/secret/misconfiguration scan while excluding operator-owned
`.git`, secret, backup, release-output, and local-cache paths from the
distributable report. These are implemented controls, not final publication
evidence.

Local wheel, Codex/Claude skill archives, SPDX/CycloneDX image SBOMs, and scan
reports exist in the ignored `release/` working directory. A paired backup exists
in the ignored `backups/` directory. They are deliberately not described as
durable release artifacts because the clean-exact-commit manifest and
`SHA256SUMS` have not been generated and no registry/package publication has
occurred.

## Required evidence set

Before release closure, a local or external named reviewer must record immutable
or checksummed exact-commit artifacts for:

- unit, integration, end-to-end, migration, and organization-isolation tests;
- deterministic evaluation and adversarial acceptance results with thresholds;
- dependency, container, secret, and static-analysis scans, including all 14
  temporary image exceptions, their 2026-08-18 expiry, and disposition;
- SBOM, build provenance, image digest, release-manifest checksum, and source
  revision;
- one-command clean install and demo bootstrap on a clean host;
- upgrade, schema rollback decision, data-preserving rollback, and clean restore;
- PostgreSQL/object-store paired backup manifest and checksum verification;
- metrics fail-closed authentication and HTTPS, readiness, rate-limit,
  exact-proxy-IP attribution, server-error retention, and sensitive-data review;
- retention and decommission state, isolation, audit, interruption, and recovery
  checks;
- preserve-data and destructive uninstall, including host integration cleanup;
  and
- fresh-agent installation and user/operator/developer documentation review.

The external `anva-test` corpus and sealed fresh-agent Codex/Claude cases remain
deferred from this snapshot, as does human user/operator/developer acceptance.
Physical source/object deletion is not implemented: retention appends expiry
state only after both explicit expiry and the organization minimum have passed,
and cleans rate buckets only for that organization. Decommission requires a
setup-authenticated human web session no older than 15 minutes, CSRF, and two
exact confirmations while rejecting bearer tokens/CLI; it revokes access while
retaining governed history. There is no login or post-setup reauthentication
flow, so decommission cannot be performed after that window. This is an open
release limitation, not an implemented recovery path.
Telemetry is limited to process-local Prometheus counters, correlated JSON logs,
and W3C trace context; no persistent aggregation, dashboards, alert delivery, or
distributed trace exporter is claimed.

The task-owned Docker footprint observed during worktree validation stayed
below 5 GB with exact-project/image/cache cleanup. That is an observed task
constraint, not an engine-enforced limit; cleanup must not touch unrelated
Docker resources.

Each evidence record should include UTC start/end times, exact commit and image
digests, runner/environment versions, exact commands or test identifiers, exit
status, summarized result, artifact checksum/link, and reviewer. Redact secrets
and source content.

## Status source of truth

Use the [requirements/evidence matrix](../../releases/requirements-evidence-matrix.md)
for requirement status and the [release checklist](../../releases/release-checklist.md)
for the release gate. A missing artifact remains pending; do not replace it with
a prose assertion or retroactively label an unrecorded command as passing.
