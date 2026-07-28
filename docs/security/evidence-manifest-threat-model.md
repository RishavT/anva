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
| SSRF or local file access | HTTPS source URL validation; ingestion never dereferences URLs or opens artifact paths | Service contains no network/file/archive/subprocess operation |
| Command execution | Commands are bounded inert strings stored only as evidence metadata | Nonexecuting service boundary and review |
| Oversized or deeply nested input | 64 KiB body/service limit, 500 entries, bounded arrays/strings, depth limit, closed schemas | Contract and boundary tests |
| Forged manual approval | Manual evidence requires exact approved authority record, work revision, repository, criterion/work/linked-requirement target, completion/expiry validity | Service and database binding checks |
| Read-only actor creates immutable history | Policy simulation and evidence mapping require assurance-execution authority plus exact repository/scope visibility | Role matrix and denied-mutation integration tests |
| Historical rewrite | Immutable artifact plus PostgreSQL update/delete triggers; retention changes append events | Direct update rejection test |

## Retention and incident response

Evidence metadata begins with an append-only ACTIVE retention event. Expiry or deletion status is a
new event; evidence history is not rewritten. Actual artifact bytes are outside this slice.

On suspected manifest compromise, revoke the repository token, preserve the response correlation
ID, manifest ID, commit, producer identity, audit/outbox events, and retention history. Do not
fetch the referenced URL/path during investigation. Reject and rotate any exposed credential
outside Anva.

## Residual risks

- Producer content hashes and statuses are attested metadata until signed upload and binary
  verification exist.
- Repository/role approval is implemented; product/team/entity/classification delegation is not.
- There is no archive upload, malware scanner, URL fetch, signed upload identity, rate-limiting
  subsystem, or automatic retention deletion.
- Multiple contributing access scopes must currently be the same scope; generalized materialized
  intersection is deferred.
