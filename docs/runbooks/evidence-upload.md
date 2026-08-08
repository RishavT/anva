# Accepted evidence upload runbook

## Purpose and scope

Use this procedure when CI submits small, exact-commit evidence bytes to Anva.
It covers authorization, one-time upload, failure handling, storage verification,
and incident escalation. It does not cover arbitrary build artifacts, URL fetch,
malware analysis, or legal erasure.

The authoritative HTTP contract is `contracts/openapi/v1/openapi.json`; limits
and threat controls are recorded in the
[accepted evidence upload threat model](../security/evidence-upload-threat-model.md).

## Preconditions

- The target organization, repository, access scope, pull request number, and
  full lowercase 40-character head commit are known.
- The normal bearer credential resolves to the submitting actor and has
  `EVIDENCE_SUBMIT` authority for that repository and scope.
- The final upload bytes already exist locally. Compute their exact byte length
  and lowercase SHA-256 before requesting authorization.
- The artifact is 1–4,096 bytes and is valid evidence JSON, ZIP, or TAR. Client
  filename and content type do not influence server media detection.
- `ANVA_OBJECT_STORAGE_ENDPOINT`, bucket, region, access key, and secret key are
  configured consistently for API, worker, backup, and restore processes. In
  production the endpoint must use deployment-approved TLS and credentials.
- CI can hold the upload token in a masked in-memory secret for one request.
  Never print it, persist it in an artifact, pass it as a URL parameter, or copy
  it into a ticket.

## Submit evidence bytes

### 1. Request a one-time authorization

```http
POST /api/v1/repositories/{repository_id}/pull-requests/{pull_request_number}/evidence-upload-authorizations
Authorization: Bearer <repository-credential>
Content-Type: application/json

{
  "schema_version": "1.0",
  "access_scope_id": "<access-scope-uuid>",
  "commit_sha": "<40-character-lowercase-head>",
  "filename": "evidence.zip",
  "declared_sha256": "<64-character-lowercase-sha256>",
  "declared_size": 631,
  "idempotency_key": "<unique-ci-run-and-artifact-key>"
}
```

A new request returns `201`, an authorization ID, a relative `upload_path`, a
ten-minute expiry, and `upload_token`. Treat that token as write-only. An exact
idempotent replay returns `200` and the same metadata, but `upload_token` is
null. Reusing the key for different request content returns a conflict.

If the `201` response is lost before CI captures the token, do not expect a
replay to recover it. Create a fresh authorization with a new idempotency key;
the orphaned unused grant will expire.

### 2. PUT the exact bytes once

```http
PUT /api/v1/evidence-upload-authorizations/{authorization_id}/content
Authorization: Bearer <same-actor-credential>
X-Anva-Evidence-Upload-Token: <one-time-upload-token>
X-Anva-Content-SHA256: <same-declared-sha256>
Content-Type: application/octet-stream
Content-Length: <same-declared-size>

<exact evidence bytes>
```

Both credentials are required. The bearer actor/credential, authorization ID,
header digest, byte count, and uploaded content must match the authorization.
The server consumes the token when it reserves the attempt, before parsing or
storage. Do not automatically retry the same PUT after a timeout or connection
loss. Request a new authorization and resubmit the same immutable bytes.

A successful `201` returns the accepted `evidence_blob_id`, verified SHA-256 and
size, byte-detected media type, bounded archive summary, and storage state
`AVAILABLE`. Preserve IDs, digest, commit, and response correlation ID as CI
metadata; do not preserve either credential.

### 3. Link only the accepted blob

When submitting the evidence manifest, use `artifact_blob_id` only on the entry
whose repository, scope, pull request, commit, content hash, and byte size match
the accepted blob. The service and PostgreSQL trigger reject cross-target,
foreign-tenant, duplicate, unaccepted, or deleted blob links.

## Failure handling

| Status | Meaning and action |
| --- | --- |
| `400` | The declared digest/size, streaming request, or JSON framing is invalid. Discard the grant, recompute the immutable file, and request a new authorization. |
| `401` | Normal actor authentication failed. Rotate or repair the bearer credential; do not expose the upload token while debugging. |
| `404` | Target or upload authorization is unavailable. Missing, foreign, expired, revoked, consumed, wrong-actor, and wrong-token cases intentionally converge. Re-authorize the current target. |
| `409` | Idempotency input conflicts or the request cannot safely transition. Use a new key only after confirming the target and bytes. |
| `413` | Whole upload exceeds 4,096 bytes. Split evidence at the producer or submit metadata-only evidence; do not raise the server limit ad hoc. |
| `415` | Byte-sniffed media is not accepted. Produce valid JSON, ZIP, or TAR evidence. |
| `422` | The bounded inspector rejected schema, head, content hash, secret, archive metadata/path/member, nesting, executable, encryption, or compression behavior. Treat the artifact as unsafe; never bypass inspection. |
| `429` | The shared API abuse limit fired. Honor `Retry-After`, then request a fresh authorization if the old one may have expired. |
| `503` | Object storage or finalization failed. Preserve the safe code/correlation ID and follow the storage incident procedure below. Never manually mark the upload accepted. |

Safe error codes identify the failed class without echoing tokens, bytes, object
keys, or endpoints. Search structured logs by correlation ID, not by artifact
content.

## Storage incident procedure

1. Pause new evidence submissions through normal repository/token revocation or
   deployment traffic controls. Do not stop unrelated read paths unless the
   incident requires it.
2. Confirm API readiness and the configured bucket using existing health and
   deployment checks. Verify endpoint/TLS/IAM configuration without printing
   credentials.
3. Record counts and IDs for `RECEIVING`, `RECOVERING`, `AVAILABLE`,
   `DELETE_PENDING`, and `DELETE_FAILED` records in the affected tenant. Do not
   dump raw token hashes, ownership hashes, object keys, or uploaded content
   into the incident record.
4. For an interrupted upload, allow the bounded recovery service to delete only
   an object whose owner metadata matches the authorization. If cleanup fails,
   keep the row retry-visible; do not force `REJECTED`.
5. For retention/decommission deletion failures, leave `DELETE_FAILED` intact.
   A later approved retention run or the system-authorized inactive-tenant
   decommission retry retries eligible exact objects. A decommission run remains
   `FAILED`, never `COMPLETED`, while retryable object cleanup remains.
6. Escalate ownership mismatch, unexpected object presence, repeated verification
   failure, or persistent cleanup failure as a security incident. Preserve safe
   object metadata and audit transitions before any approved destructive action.

There is no public stale-upload recovery endpoint or scheduled recovery worker in
this candidate. Recovery is explicitly bound to one authorized repository and
access scope. A persistent `RECEIVING` or `RECOVERING` record therefore requires
an approved, reviewed operator action; direct database edits and manual bucket
deletion are not supported recovery procedures.

## Retention and decommission verification

Retention and decommission select at most 10,000 tenant-qualified blob records
per cleanup attempt and report:

- `evidence_blob_candidates` where applicable;
- `evidence_blob_bytes_deleted`; and
- `evidence_blob_bytes_delete_failed`.

Verify failed deletions explicitly. A successful byte deletion changes blob
storage state to `DELETED` while keeping authorization, blob metadata, evidence,
retention events, and audit history. `source_content_deleted: 0` still means
source-ingestion content was not physically erased. These operations are not a
legal-erasure attestation.

Decommission considers every state except `DELETED`, including an already
`DELETE_PENDING` object. Before completion it locks the organization and proves
that no non-deleted blob or nonterminal upload object remains. A candidate
error, failed/pending deletion, or additional batch keeps the run `FAILED` and
eligible for the system-authorized retry; completed retries are idempotent.

## Evidence to preserve and escalation

Preserve the correlation ID, tenant/repository/scope/PR/commit, authorization,
blob and evidence IDs, declared/verified digest and size, detected media type,
safe failure code, state-transition timestamps, storage lifecycle state, and
deployment version. Never preserve raw credentials or unsafe bytes in routine
logs.

Escalate immediately for cross-tenant visibility, accepted digest/size/head
mismatch, token disclosure, ownership mismatch, unexpected executable or nested
archive acceptance, unexplained object overwrite, or deletion of a non-owned
object. Keep the affected authorization and metadata history intact for review.

## Known limitations

- Accepted uploads are limited to 4 KiB and the documented JSON/ZIP/TAR shape.
- Structural inspection is not antivirus scanning or producer-signature
  verification.
- Lost successful PUT responses have no blob-status lookup endpoint; use a new
  authorization rather than replaying the consumed token.
- Revocation and stale cleanup exist as service operations but are not public
  HTTP/operator workflows in this candidate.
- Deployment-specific S3 proxy, TLS, IAM, replication, quota, backup, and
  recovery behavior remains an operator responsibility.
