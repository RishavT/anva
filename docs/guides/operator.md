# Operator guide

This guide is for operators preparing to evaluate Anva `v0.1.2` after its
protected release completes. It does not
replace the release checklist or the still-open human exercise in #44. Use the
verified digest-addressed image and public release assets; source checkout is a
fallback, not the public product identity.

## Operating sequence

1. Review [compatibility](../releases/compatibility.md), release limitations,
   the [threat model](../security/product-threat-model.md), and production secret
   requirements.
2. Follow [install and upgrade](../runbooks/install-upgrade-uninstall.md). Record
   exact image digests, OCI/source revision, Compose project name, and resolved
   configuration. Production must use `ANVA_ENV=production`, debug off, exact
   hosts/URLs, out-of-band secrets, a metrics token, HTTPS, and exact trusted
   proxy IPs.
3. Verify readiness and protected metrics, then establish alerting appropriate to
   the deployment. See [observability and rate limits](../runbooks/observability-and-rate-limits.md).
4. Create and restore-test a paired PostgreSQL/object-store recovery point before
   accepting production data. See [backup and restore](../runbooks/backup-and-restore.md).
5. Exercise retention and decommission only through the documented, authorized
   workflow. See [retention and decommission](../runbooks/retention-and-decommission.md).
6. Use the preserve-data uninstall by default. A clean uninstall destroys only
   the targeted Compose volumes; external data and host configuration require
   separate handling.

## Routine checks

Track readiness dependencies, error/latency/rate-limit signals, storage and
database capacity, migration state, backup age and restore-test age, credential
rotation, and pending lifecycle operations. Correlate incidents by request ID and
trace context, without placing credentials or source content in telemetry.

## Boundaries and escalation

Anva's retention run does not physically remove source content, and
organization decommissioning revokes access while retaining governed history.
Neither is a legal-erasure attestation. Stop and escalate when organization
identity is ambiguous, backups cannot be verified, schema compatibility is
unknown, or the requested destruction exceeds the documented workflow.

Backup activation is generation-based and atomic. A failed restore intentionally
leaves previously running writers stopped; a migration reversal must run only
inside the guarded disposable rehearsal project. Decommission requires a human
session authenticated within 15 minutes, CSRF, and both exact confirmations;
never substitute a bearer token or CLI call.

Clean up only the resolved Compose project, exact Anva images, and task-owned
cache paths. Do not run an engine-wide prune or touch unrelated Docker
resources. The worktree exercise stayed below its 5 GB task budget, but Anva
does not enforce that budget at the Docker engine.
