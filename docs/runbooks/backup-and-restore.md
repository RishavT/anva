# Backup and restore

An Anva recovery point must cover PostgreSQL and object storage together.
Backing up only one can leave database metadata inconsistent with stored source
objects. Queue and retrieval-cache state is stored in PostgreSQL in this release.

MVP-013 provides Compose-owned backup, checksum verification, and restore
commands. Exact local candidate evidence at source commit `94231d7e...` and
runtime image ID `c6ae3a8a...` covers atomic generation activation, inactive
partial-generation pointer preservation, hostile guard and mutex rejection,
failure-safe writer handling, successful restore with state invariance, and
disposable schema rehearsal. Deployment-sized recovery and an external
object-store procedure remain unverified.

## Create a paired backup

```sh
ANVA_BACKUP_DIR=/absolute/operator-controlled/path make backup
```

The target discovers which Anva writers are currently running, stops only those
services, creates a PostgreSQL custom-format dump, mirrors the configured
object-storage bucket, writes and verifies a manifest, atomically activates the
generation, and resumes exactly the writers it stopped. The discovered set can
include `api`, `worker`, `github-worker`, `mcp`, and `mcp-read-only`; stopped or
disabled variants are not started as a side effect. Ensure no writer outside the
Compose project can mutate either store during the recovery point.

This operational target is implemented and drilled for the Compose-managed
MinIO service. Application compatibility with an S3-compatible runtime endpoint
does not make `make backup` an external object-store backup tool. Do not use it
for an external store; select, verify, and evidence a provider-appropriate paired
backup procedure instead.

Before a backup, restore, or rehearsal can stop a writer, the operations guard
requires the application endpoint to be exactly `http://minio:9000` and requires
its bucket and access credentials to match the Compose MinIO identity. Internal
bucket customization therefore sets both `ANVA_OBJECT_STORAGE_BUCKET` and
`ANVA_MINIO_BUCKET` to the same value; application access credentials similarly
match `ANVA_MINIO_ROOT_USER` and `ANVA_MINIO_ROOT_PASSWORD`. A mismatch fails
closed without rendering credentials. These operations intentionally do not
support an external endpoint.

Each attempt writes to a unique
`generations/<UTC-timestamp>-<process-id>/` directory. A regular text `current`
pointer selects the recovery point used by `backup-verify` and `restore`. The
pointer is atomically replaced only after the new database dump, object mirror,
manifest, and checksum verification succeed. A failed attempt can leave an
incomplete, inactive generation, but it cannot replace the last activated
recovery point. Inspect and remove such a generation only after resolving its
exact path and confirming it is not referenced by `current`.

The generated `manifest.json` records the Anva version, creation time, relative
path, byte size, and SHA-256 digest for every backed-up file. It requires both
`database.dump` and the object-store installation sentinel. The manifest does
not record an image digest, database transaction identifier, schema inventory,
encryption state, or semantic row/object counts.

The backup operation:

- writes database and object data through short-lived Compose jobs with the
  checked-in job restrictions;
- fails closed if either copy or manifest creation fails; and
- resumes exactly the previously running Anva writers when the attempt exits,
  including after a failed backup step.

The operator must place `ANVA_BACKUP_DIR` on access-controlled storage, encrypt
and copy it off-host as policy requires, and apply an independent retention
policy. A successful command is not proof of recoverability.

## Validate a backup

Before accepting it:

1. Run `ANVA_BACKUP_DIR=/absolute/path make backup-verify` to resolve the
   activated `current` generation and verify its exact inventory, sizes, and
   SHA-256 checksums against the manifest. A legacy fixed-root backup without a
   `current` pointer is still accepted for migration purposes.
2. Confirm the manifest identifies both the database and object archive.
3. If operator storage encryption is used, confirm the decryption key is
   available through the recovery process and is not embedded in the backup.
4. Restore into a clean, isolated Compose project and run integrity checks.
5. Record the evidence and then destroy the isolated recovery environment using
   the clean-uninstall procedure.

## Restore into a clean project

Never restore over a running production project. Select a new, unique Compose
project name, ensure it has no existing data volumes, and point at the absolute
backup directory:

```sh
COMPOSE_PROJECT=anva-restore-check \
ANVA_BACKUP_DIR=/absolute/operator-controlled/path \
make restore
```

`make restore` verifies the activated backup manifest before changing either
store, discovers and stops only the Anva writers currently running in the target
project, restores PostgreSQL and object storage, runs current migrations, and
then resumes exactly those writers. The checksum validator rejects a missing,
altered, duplicate, unsafe, or partial inventory. The restore target itself does
not prove that a project is empty and uses `pg_restore --clean`; the operator
must enforce the clean-project precondition.

If database restore, object restore, or migration fails after writers have been
stopped, the target deliberately leaves those writers stopped. Do not start
them until both stores and schema have been inspected and either the restore has
completed successfully or an approved recovery decision has been made. Record
the failure and the pre-restore writer set in the incident evidence.

After restore, verify:

- readiness and current migration state;
- tenant, audit, provenance, artifact, and object identities against the source
  recovery point;
- representative repository access and authorization boundaries; and
- object retrieval and background processing.

Capture timestamps, digests, manifest checksum, checks performed, and final cleanup in
the release evidence.

Destroy only the isolated verification project after review:

```sh
COMPOSE_PROJECT=anva-restore-check make uninstall-clean
```

Confirm the exact project name and resolved resources before this destructive
command. Do not use an engine-wide Docker prune for routine cleanup and do not
remove unrelated containers, volumes, images, or caches.

## Recovery limitations

- Scheduled backups, point-in-time recovery, backup encryption/key management,
  cross-version restoration, incremental backups, and large-dataset timing are
  not implemented or verified for MVP-013.
- The Compose operations do not back up or restore an independently configured
  external object store. The successful exact-candidate drill covers local
  Compose-managed MinIO only.
- The exact-candidate drill covered the unique generation pointer, dynamic
  writer set, failed-restore stop behavior, successful restore/resume, and
  disposable-clone reversal to `core.0019` and forward to head while live state
  remained invariant. No older application binary or production dataset was
  exercised.
- A backup can reintroduce data that was decommissioned or expired after it was
  taken. Operators must reconcile current policy before reopening restored data.
- Application-level decommissioning does not delete retained backups. Backup
  expiry and secure destruction remain operator responsibilities.
