# Threat model: Manual-diff assurance

## Assets and trust boundaries

Protected assets are exact repository/PR identity, diff bytes, work requirements, policy and
evidence decisions, permission-scoped context, evaluator queue leases, findings, readiness,
reports, knowledge, credentials, and tenant separation. Manual PR metadata, unified diff content,
and evaluator output are hostile. Authorized Anva context and deterministic results are trusted
only at their exact persisted versions.

## Threats and controls

| Threat | Control | Verification |
| --- | --- | --- |
| Diff executes or fetches code | Strict in-memory parser; no subprocess, import, checkout, URL fetch, apply, test, or file traversal | Parser/service review and focused tests |
| Traversal, binary, oversized, ambiguous diff | Relative POSIX paths; reject `..`, absolute/backslash/control/quoted paths, binary/combined forms, bad hunk counts; 1 MB/30k-line/500-path/2k-hunk limits | Hostile diff unit cases |
| Prompt injection in PR or diff | Untrusted content remains under `untrusted_change`; fixed separate instructions; fake injection scenario | Evaluator and report security tests |
| Evaluator decides readiness | Result schema has no outcome/readiness field; fixed server precedence over persisted checks/policy/gaps | Contract and deterministic-failure integration tests |
| Fabricated citation | Diff citation must fall within exact old/new hunk range; source citation must belong to exact authorized context packet; evidence/criterion IDs are allowlisted | Unsupported citation integration test |
| Stale review published | Current PR revision/head checked at start, claim, and submit; new revision stales prior active/completed run and cancels pending work | New-head and same-head metadata tests |
| Initiator self-review | Immutable run initiator actor/credential; claim skips every task initiated by the authenticated actor | Self-review and database-trigger tests |
| Queue theft, identity switching, or replay | Dedicated `assurance.review`; every source boundary reauthorized; row lock with `SKIP LOCKED`; bounded lease/attempts; task bound to authenticated actor and exact credential; caller claimant is audit-only; single-use token hash; exact identical-submit replay only for the bound identity | Claim/submit, role, revoked/expired credential, and identity-switch tests |
| Tenant graft | Central authorization plus composite `(organization_id, id)` foreign keys | Migration and PostgreSQL tests |
| Historical rewrite | Content-addressed artifacts and update/delete triggers for assurance history | Direct update/delete rejection |
| XSS or deployment claim through report | Markdown escaping, HTML escaping, prohibited-claim removal, fixed disclaimer | Golden and injection tests |
| Silent knowledge mutation | Post-merge path creates cited proposals only; no accept/apply transition | Post-merge safety test |
| Credential persistence | Secret-pattern rejection; only credential UUIDs and authorization paths enter immutable audit/history; claim token stored only as SHA-256 and returned once; evaluator packet excludes environment/DB credentials | Audit-redaction and integration canaries |

## Incident response

Revoke the repository token, stop task claiming, preserve correlation/run/task/attempt/artifact IDs,
and mark the affected PR revision superseded. Do not fetch or execute the submitted diff while
investigating. Rotate any credential detected outside Anva; rejected secret-bearing content is not
persisted.

## Residual risks

- Manual diff bytes are operator-attested; provider signature/fetch verification is not included.
- The engine does not establish runtime behavior, rollout capacity, compliance, or deployment
  approval.
- A valid authorized source may itself contain incorrect or adversarial prose.
- Storage retention and per-tenant quotas need production policy beyond input bounds.
- Manual evaluator availability depends on deployment operations; Anva provides a provider-neutral
  external queue and does not embed or host a Codex/Claude evaluator.
