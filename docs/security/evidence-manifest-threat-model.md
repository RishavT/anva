# Threat model: Intent, policy, and evidence manifests

## Assets and trust boundaries

Protected assets are tenant work intent, mandatory controls, exception authority, exact-commit
evidence, approval history, audit/outbox history, database availability, and credentials. Work,
policy, simulation, and evidence JSON cross the authenticated API boundary as hostile input.
Repository tokens remain environment-only in the CLI.

Manifest fields are declarations, not executable instructions. An artifact reference or source URL
does not grant the service authority to access that location.

## Threats and controls

| Threat | Control | Verification |
| --- | --- | --- |
| Stale or other-commit evidence satisfies readiness | Full lowercase commit binding on manifest, evidence, mapping, and database trigger | Exact-versus-stale mapping integration test |
| Prose is promoted to evidence | `WorkSummary` is a separate model and evidence mapping queries only `Evidence` | Summary-only gap integration test |
| Lower scope weakens mandatory control | Additive merge; policy syntax cannot remove controls; exact authority-checked override only | Lower advisory/override/revocation integration test |
| Nondeterministic replay | Exact policy versions, work revision/hash, active override IDs, engine version, stable ordering, explicit reference time; mapping persists PR/time/engine/input hash | Repeat evaluation hash/id and mapping-input tests |
| Tenant or repository graft | Central authorization, scoped lookup, composite organization foreign keys | Forced cross-tenant constraint test |
| Traversal or platform-dependent paths | Repository-relative normalized POSIX paths; reject absolute, `..`, backslash, control, duplicate separators | Hostile path unit tests |
| Credential persistence | Recursive sensitive-key and secret-pattern rejection before persistence; generic API errors | Secret-canary tests |
| SSRF or local file access | HTTPS source URL validation; manifest ingestion never dereferences URLs or opens artifact paths; accepted upload storage uses only the configured S3-compatible endpoint | Manifest boundary and upload architecture tests |
| Command execution | Commands are bounded inert strings stored only as evidence metadata; accepted archives are inspected in process without extraction, import, or subprocess execution | Nonexecuting manifest/upload boundary review |
| Oversized or deeply nested input | Manifest API uses a 64 KiB body/service limit, 500 entries, bounded arrays/strings, depth limit, and closed schemas; the separate accepted-byte boundary has stricter fixed limits | Contract, parser, and boundary tests |
| Forged manual approval | Manual evidence requires exact approved authority record, work revision, repository, criterion/work/linked-requirement target, completion/expiry validity | Service and database binding checks |
| Read-only actor creates immutable history | Policy simulation and evidence mapping require assurance-execution authority plus exact repository/scope visibility | Role matrix and denied-mutation integration tests |
| Historical rewrite | Immutable artifact plus PostgreSQL update/delete triggers; retention changes append events | Direct update rejection test |

## Retention and incident response

Evidence metadata begins with an append-only ACTIVE retention event. Expiry or deletion status is a
new event; evidence history is not rewritten. An optional `artifact_blob_id` may link an entry to
bytes already accepted by the separately authorized, bounded upload boundary. The database rejects
an unaccepted, deleted, duplicate, foreign-tenant, wrong-repository/scope/PR/commit/hash/size link.
See the [accepted evidence upload threat model](evidence-upload-threat-model.md).

On suspected manifest compromise, revoke the repository token, preserve the response correlation
ID, manifest ID, commit, producer identity, audit/outbox events, and retention history. Do not
fetch the referenced URL/path during investigation. Reject and rotate any exposed credential
outside Anva.

## Residual risks

- Manifest-only producer content hashes and statuses remain attested metadata. When an entry links
  an accepted blob, Anva verifies byte size/digest, archive shape, commit binding, object metadata,
  and a bounded object read; producer signing and malware analysis still do not exist.
- Repository/role approval is implemented; product/team/entity/classification delegation is not.
- The accepted upload boundary supports only 4 KiB JSON/ZIP/TAR evidence. There is no malware
  scanner, URL fetch, producer signature/transparency log, or scheduled stale-upload recovery.
- Retention/decommission can delete owned accepted evidence bytes, but preserve governed metadata
  and history and do not establish legal erasure.
- Multiple contributing access scopes must currently be the same scope; generalized materialized
  intersection is deferred.
