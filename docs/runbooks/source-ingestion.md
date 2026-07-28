# Runbook: Read-only source ingestion

## Preconditions

- The API and worker use the same absolute in-container source path.
- The host path is mounted `:ro` into both services.
- Its in-container parent is listed in the colon-separated
  `ANVA_FILESYSTEM_ALLOWED_ROOTS`.
- The repository token in `ANVA_TOKEN` has `source.sync`, `source.view`, and, for incident
  response, `source.revoke`.
- An active repository and access scope already exist.

Never place a repository token in command arguments, logs, source configuration, or job payloads.

## Connect and synchronize

The CLI calls the authenticated `/api/v1` endpoints:

```bash
anva source connect \
  --repository-id <uuid> \
  --access-scope-id <uuid> \
  --external-key filesystem:org/repo \
  --display-name "Organization repository" \
  --root /fixtures/org-repo

anva source sync <source-connection-uuid>
anva source inspect <source-connection-uuid>
```

`connect` is idempotent for identical configuration and rejects reuse of an external key for a
different root/scope/repository. `sync` captures the current access boundary before enqueueing.
`inspect` returns bounded counters and the latest run, never raw content or failure internals.

Use `anva source resync <uuid>` for a fresh full discovery after correcting configuration or parser
failures. Full discovery tombstones missing documents; reappearance creates a new observation and
reuses an identical historical revision.

## Detect and diagnose

- `PARTIALLY_COMPLETED`: inspect the run counters and secret-safe `IngestionFailure` codes. One
  malformed item does not invalidate successful items.
- `FAILED` or a retried job: inspect worker logs by correlation/job/run UUID. Do not log raw source.
- `file_too_large`, depth/token/node limits: confirm the file is legitimate before changing a
  central limit and rerunning all adversarial tests.
- `unsafe_or_unavailable_path`: check for symlinks, special files, mount disappearance, or an
  allowlist mismatch.
- `source_revoked`: expected when queued or leased work lost authority.

The discovery cursor is opaque and versioned. Do not hand-edit it. A full resync safely replaces
its value while preserving revision history.

## Revoke and recover

```bash
anva source revoke <source-connection-uuid> --expected-revision <n>
```

Revocation atomically deactivates dependent scopes, revokes snapshots and available chunk
visibility, cancels pending jobs and active runs, and causes leased workers to fail revalidation.
Retrieval filters revoked content before ranking or graph traversal. Reconnect as a new governed
source after reviewing the incident; a revoked connection is not silently reactivated.

Preserve source/run/job IDs, access snapshot hash, audit/outbox IDs, failure codes, image version,
and mount configuration. Preserve immutable provenance unless legal deletion policy requires a
separately reviewed erasure operation.

## External corpus acceptance

With the sibling `../anva-test` repository present:

```bash
make corpus
```

The override mounts it read-only, ingests the realistic mixed corpus, checks expected document
taxonomies, and verifies representative file hashes are unchanged.
