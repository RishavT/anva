# Changelog

All notable Anva changes are recorded here. Versions follow semantic versioning
once a release tag exists.

## Unreleased — MVP-013 release hardening

Status: draft. This entry is not a release announcement.

The current MVP-013 worktree implements:

- production configuration validation, rate limiting, correlated structured
  request logs, retained server errors, health/readiness checks, fail-closed
  authenticated process metrics, and exact trusted-proxy handling;
- auditable server-time retention runs with organization-minimum/tenant cleanup,
  and setup-session/CSRF/two-confirmation organization decommissioning. The
  current product has no post-setup reauthentication flow, so decommission is
  unavailable after the setup-authenticated session is more than 15 minutes old;
- Compose installation with terminal-only ephemeral demo, atomic-generation
  backup, failure-safe restore, disposable-clone migration rehearsal, upgrade,
  rollback, and uninstall procedures;
- release packaging, security scans, SBOMs, compatibility records, and a
  requirement-to-evidence matrix. Release closure rejects untracked input and
  OCI revision mismatch, rebuilds/verifies skills, gates source
  vulnerability/secret/misconfiguration results, and records 14 reviewed
  no-vendor-fix image exceptions through 2026-08-18.

Worktree verification has covered the 721-pass broad Compose suite, focused
release tests, the live MCP client, an earlier fixable high/critical scan result,
atomic-generation paired backup/clean restore, injected failure with writers
left stopped, successful restore/resume, and isolated reversal/forward schema
rehearsal without changing the live database. These are shared-worktree results;
exact clean-commit release revalidation remains pending. Local wheel, skill,
SBOM, and scan outputs have also been built. These results are not a published
release: no release tag, registry digest, signed provenance, final exact-commit
checksum manifest, external corpus/fresh-agent result, or human acceptance
record exists. This work does not add, enable, or change a GitHub Actions
workflow. See
[`docs/releases/mvp-013.md`](docs/releases/mvp-013.md).

The task-owned Docker footprint observed during worktree validation remained
below 5 GB using exact project/image/cache cleanup. This is not an engine-wide
enforced quota and does not authorize pruning unrelated Docker resources.
