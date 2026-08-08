# Retention and organization decommissioning

MVP-013 implements organization-scoped retention and decommission operations.
Authorization, idempotency, retained-data, caller-time rejection, tenant-bucket
isolation, and fail-closed access tests pass in the exact source candidate
`94231d7e...`. Manual interruption/recovery and human acceptance remain open.
The post-MVP-013 issue 29 candidate additionally deletes exact owned accepted
evidence bytes with a retryable storage lifecycle; this is local candidate
evidence and does not change the identity of the historical MVP-013 release
record.

## Authorization and audit expectations

Retention requires an authenticated actor in the target organization with
`RETENTION_MANAGE`; a suitably scoped repository service token may run it.
Decommission is deliberately narrower: it requires the human web session
established during one-time setup to be active in the target organization, have
`RETENTION_MANAGE`, and be no more than 15 minutes old, plus CSRF validation and
two exact confirmations. Repository bearer tokens, service identities, and the
CLI are rejected for decommission. The current product has no login or
post-setup reauthentication flow. Therefore, after the setup-authenticated
session is older than 15 minutes, an operator cannot decommission until such a
flow is implemented; there is no documented bypass. Requests crossing an
organization boundary must fail. Record the human or service actor,
organization, request/correlation ID, result, and timestamps without logging
credentials or source content.

## Run retention

Endpoint:

```http
POST /api/v1/organizations/{organization_id}/retention-runs
Authorization: Bearer <repository-token>
Content-Type: application/json

{"dry_run": true}
```

The HTTP contract does not accept a caller-supplied `reference_time`; the server
owns the clock used for eligibility and rejects unknown fields. Begin with
`dry_run: true`, review the returned counts, then repeat with `dry_run: false`
only after confirming the target organization and policy.

Evidence is eligible only when both its explicit `retention_expires_at` has
passed and its completion time is older than the organization's configured
minimum-retention cutoff. Current candidate behavior appends expiration events
for that eligible evidence, removes expired rate-limit buckets belonging only
to the same organization, and then attempts physical deletion of linked
accepted evidence bytes. It also deletes unlinked accepted blobs older than the
organization cutoff. Selection is tenant-qualified and bounded to 10,000 blobs.
`dry_run: true` reports candidates without changing retention state or deleting
bytes.

The response reports `evidence_blob_bytes_deleted` and
`evidence_blob_bytes_delete_failed`. A successful object deletion preserves the
authorization, blob metadata, evidence, retention event, and audit history and
marks the blob `DELETED`; a storage failure remains `DELETE_FAILED` for retry.
It still reports `source_content_deleted: 0`: source-ingestion content is not
hard-deleted. This is bounded evidence-byte lifecycle management, not proof of
legal erasure.

## Decommission an organization

Endpoint:

```http
POST /api/v1/organizations/{organization_id}/decommission
Cookie: sessionid=<recent-human-session>
X-CSRFToken: <matching-csrf-token>
Content-Type: application/json

{
  "confirmation": "exact-organization-slug",
  "acknowledgement": "DECOMMISSION exact-organization-slug"
}
```

The setup-created session must have authenticated within the preceding 15 minutes,
`confirmation` must exactly match the organization's slug, and
`acknowledgement` must exactly equal `DECOMMISSION ` followed by that same slug.
There is no reauthentication, bearer-token, or CLI alternative. Outside that
window this endpoint is unavailable in the current release candidate. Before
proceeding:

1. verify the organization ID and slug through a second channel;
2. take and validate any backup required by policy;
3. record the approvals and intended retention/legal-hold outcome; and
4. warn users that access will be revoked.

Current behavior revokes source access and disables memberships, service
identities, repositories, scopes, and tokens before marking the organization
decommissioned. The issue 29 candidate then attempts deletion of every
tenant-qualified accepted evidence blob in `AVAILABLE` or `DELETE_FAILED`, up
to the 10,000-blob safety bound, and reports successful and failed byte
deletions separately. Governed content, blob metadata, and history are retained;
source-ingestion content is not physically deleted. The operation is therefore
access revocation plus bounded accepted-evidence byte deletion, not tenant hard
deletion or a legal-erasure workflow.

## Validation and recovery

After either operation, verify that the returned organization matches the
request, audit/evidence records exist, expected access is denied, unrelated
organizations remain usable, `evidence_blob_bytes_delete_failed` is zero or is
explicitly escalated, and metrics/logs show no unexpected failure. Never mark a
failed blob deleted or remove an object manually; deletion checks per-object
ownership metadata and retry state.

There is no API to undo decommissioning. Recovery may require an
operator-controlled backup and an approved, isolated restoration procedure; a
restore can also revive credentials or data that policy says must remain
disabled. Escalate rather than manually editing lifecycle fields.

## Known limitations

- No login or post-setup reauthentication flow refreshes the decommission
  authentication timestamp. Decommission is therefore available only during
  the first 15 minutes of the setup-authenticated session and is unavailable
  afterward until that product flow exists.
- Scheduled policy execution, physical source deletion, backup expiry, legal
  hold, erasure attestation, and an approved restoration workflow are not
  demonstrated. Accepted evidence-byte deletion is not source deletion or
  complete tenant erasure.
- The operations are transaction-bounded and have deterministic replay
  identities, and object deletion has retryable `DELETE_FAILED` state, but
  large-tenant timing and manual interruption/recovery exercises remain open.
- A successful HTTP status is not sufficient acceptance evidence; verify state,
  isolation, audit records, and retained/deleted data explicitly.
