# Accepted evidence upload threat model

## Scope and protected assets

This review covers the accepted byte boundary introduced for CI evidence:

- issuing a short-lived upload authorization for one tenant, repository, access
  scope, pull request, and exact 40-character Git commit;
- consuming that authorization once while streaming hostile JSON, ZIP, or TAR
  bytes through the production inspector;
- retaining only verified bytes in S3-compatible object storage and immutable
  binding metadata in PostgreSQL;
- linking an accepted blob to evidence with the same tenant, repository, scope,
  pull request, commit, digest, and size; and
- deleting exact owned bytes during retention or organization decommissioning
  while preserving lifecycle metadata and audit history.

Protected assets are tenant isolation, repository and scope authority, exact
commit provenance, upload and bearer credentials, object-store integrity,
database availability, evidence history, and the guarantee that uploaded bytes
are never executed or extracted.

Client filenames, declared sizes and digests, request headers, archive metadata,
member names, JSON keys and values, compression metadata, and object-store
responses are hostile. The authenticated bearer credential establishes an
actor; it does not authorize an arbitrary upload target. The upload token is a
second, narrower credential and is not a replacement for normal actor
authorization.

## Authorization and lifecycle

An authorization is valid for ten minutes and is bound to the authenticated
actor type, actor ID, credential ID, tenant, repository, access scope, pull
request, commit, declared digest, and declared size. Raw upload and idempotency
tokens are stored only as domain-separated keyed hashes. The raw upload token is
returned once. An exact authorization replay returns the same metadata with a
null token; reuse of the idempotency key for different input is rejected.

The state machine is:

`ISSUED -> RECEIVING -> ACCEPTED|REJECTED`, with unused grants able to become
`EXPIRED` or `REVOKED`. Reservation happens under a database row lock before any
content validation result is disclosed, so concurrent consumers cannot use the
same grant. A failed owned-object cleanup deliberately remains `RECEIVING` for
bounded recovery instead of falsely claiming that no bytes remain.

## Threats, controls, and verification

| Threat | Control | Verification |
| --- | --- | --- |
| Foreign tenant/repository/scope graft | Central `EVIDENCE_SUBMIT` authorization, tenant-qualified lookups, actor/credential binding, composite database foreign keys, and exact evidence/blob binding trigger | Cross-tenant authorization and direct database-graft tests |
| Stale or other-commit bytes satisfy readiness | Authorization, inspected manifest/results, blob, evidence, PR, and manifest all require the same lowercase 40-character commit | Wrong-head fixtures and accepted-blob linking tests |
| Token replay or concurrent double consumption | Ten-minute opaque single-use token, keyed hash at rest, row-locked `ISSUED -> RECEIVING` reservation, and stable unavailable response after consumption | Replay and concurrent-consumer integration tests |
| Credential or oracle leakage | Upload token returned once, exact replay returns null, token and secret patterns are redacted, authorization happens before detailed validation, and errors omit bytes, token, object key, and storage endpoint | Secret-canary response/log tests and foreign/missing equivalence |
| Declared metadata hides different bytes | Bounded streaming recomputes byte count and SHA-256; request header, authorization, uploaded bytes, object metadata, HEAD size, and bounded GET digest must agree | Size/digest mismatch and live MinIO verification tests |
| Oversized request or decompression bomb | Outer, manifest, member, cumulative-expanded, compression-ratio, entry-count, path-depth, and chunk limits are enforced while reading | Boundary unit matrix and TST-007 oversized fixture |
| Traversal or canonical path collision | POSIX-relative canonical paths only; absolute, drive, `..`, backslash, NUL, control, duplicate separator, noncanonical, duplicate, and Unicode/case canonical collisions reject | Hostile path matrix and TST-007 Glass fixture |
| Link, device, FIFO, socket, or executable content escapes inspection | Links and special files reject; executable modes, executable suffixes, shebang/ELF/PE magic, and nested archive suffix/magic reject; no extraction or subprocess API is used | ZIP/TAR special-file and executable matrix |
| Encrypted, ambiguous, or unsupported archive bypass | Media type is byte-sniffed; only JSON, ZIP and TAR are accepted; ZIP encryption, comments/extras, data-descriptor ambiguity, unsupported compression, and malformed metadata reject | Format/metadata unit tests |
| Malformed or ambiguous JSON changes meaning | Duplicate-safe JSON decoding, closed exact schemas, bounded depth/text, exact results path, exact head, and recomputed results-content hash | Malformed/schema-invalid fixtures and contract tests |
| Uploaded secret is retained or echoed | Actual bytes are scanned for configured credential patterns before storage; safe errors and structured redaction never include matching content | TST-007 Harbor fixture and log canary test |
| Existing foreign object is overwritten or deleted | Random server-generated key, conditional `If-None-Match: *` PUT, per-authorization ownership metadata, and ownership-checked cleanup/delete | Precondition-conflict/no-delete integration test |
| Truncated or corrupt object is marked accepted | Acceptance requires successful conditional PUT, HEAD metadata/size validation, and a bounded GET digest before the blob row and accepted transition commit | PUT/HEAD/GET failure tests and live MinIO path |
| Database finalization fails after object write | Owned bytes are deleted before terminal rejection; cleanup failure remains retry-visible for bounded stale recovery | Injected database-failure and cleanup-recovery tests |
| Retention deletes another tenant's bytes | Candidate selection is tenant-qualified and bounded to 10,000 blobs; deletion rechecks stored ownership metadata and uses an explicit pending/failed/deleted lifecycle | Retention/decommission isolation and retry tests |
| Uploaded content triggers network or command execution | Inspector uses only bounded in-process parsing; it does not dereference URLs, extract members, import uploaded code, invoke Perl/Archive::Tar, or start subprocesses | Architecture guard and non-executing parser review |

## Fixed parser limits

| Limit | Value |
| --- | ---: |
| Whole upload | 4,096 bytes |
| JSON manifest | 512 bytes |
| Archive members | 8 |
| Member path depth | 4 |
| Compressed bytes per member | 1,024 bytes |
| Expanded bytes per member | 1,024 bytes |
| Cumulative expanded bytes | 1,536 bytes |
| Compression ratio | 50:1 |
| Streaming read chunk | 256 bytes |

These are product security limits, not tuning defaults. Raising one requires a
new resource-abuse review, boundary tests, and operational capacity evidence.

## Storage deletion and incident response

Accepted blob metadata is immutable. Physical bytes use
`AVAILABLE -> DELETE_PENDING -> DELETED|DELETE_FAILED`; deleting an already
deleted blob is idempotent. A missing owned object can be finalized as deleted,
but an ownership mismatch fails closed. Retention/decommission responses report
successful and failed evidence-byte deletions separately. They do not erase the
authorization, blob metadata, evidence, retention history, audit records, or
source content.

For suspected compromise, stop new evidence submissions using normal access
revocation, preserve the correlation ID, authorization/blob/evidence IDs,
actor/credential ID, repository/commit, transition history, safe failure code,
and object metadata. Never copy the raw token or uploaded bytes into tickets or
logs. Do not manually delete an object or edit lifecycle rows: an ownership
mistake can destroy another object or make recovery state dishonest.

## Residual risks and limits

- There is no antivirus engine, content-disarm sandbox, producer signature, or
  transparency log. Acceptance proves bounded structural integrity and binding,
  not that arbitrary document content is benign.
- Only very small JSON/ZIP/TAR evidence is supported. Other media, encrypted
  archives, nested archives, and executable content deliberately fail closed.
- The live object-store exercise covers the configured S3-compatible MinIO
  boundary. Deployment-specific proxy, TLS, IAM, quota, replication, and outage
  behavior still require operational validation.
- Bounded stale-receiving recovery exists as a service path but has no public
  operator endpoint or scheduled-worker wiring in this candidate. Operators
  must escalate persistent `RECEIVING` records rather than edit them.
- Retention and decommission delete accepted evidence bytes but retain governed
  metadata/history and do not establish legal erasure.

## Verification evidence

Issue 29 exercises six pinned TST-007 byte artifacts from read-only
`RishavT/anva-test`: malformed JSON (Drift), oversized JSON (Elder), invalid
schema (Flint), traversal/executable ZIP (Glass), secret-pattern bytes (Harbor),
and a safe ZIP (Linden). The first five are passed unchanged to the production
inspector. The upstream Linden artifact uses a synthetic 64-character head; the
test first proves that raw mismatch rejects, then explicitly re-seals an
in-memory copy with the authorized 40-character Git commit and recomputed
content hash before proving acceptance. This is not a byte-for-byte safe-upload
claim for the upstream Linden file.
