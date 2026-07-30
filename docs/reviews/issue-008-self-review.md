# Issue #8 self-review: GitHub App adapter

## Scope and acceptance evidence

| Requirement | Implementation | Verification |
| --- | --- | --- |
| Least-privilege installable App | Reviewed manifest, closed setup permission allowlist, one-repository short-lived token minting | Manifest/contract/security tests and permissions review |
| Signature and replay safety | Raw-byte HMAC before parsing, bounded normalized JSON, global delivery UUID/checksum identity | Parser, HTTP, collision, and concurrent-delivery tests |
| Tenant-safe installation/repository mapping | Explicit numeric mapping, central admin authorization, composite tenant foreign keys | Authorization and PostgreSQL graft tests |
| PR and Check ingestion | Current provider PR/diff fetch, immutable core revision/observations, exact-commit check observations | Out-of-order, duplicate, fork, and check tests |
| Exact-head Check/report | One current projection per PR/kind, deterministic Check/comment rendering, bounded annotations and marker | Queue/render integration tests |
| Durable outbound effects | Frozen write intent, explicit outbox event, lease/attempt history, rate-limit backoff and ambiguous-write adoption | Retry, concurrency, ambiguity, spoof, and immutability tests |
| Revocation | Cancels assurance/evaluator/jobs/writes, revokes grants/tokens/sources, blocks future network calls | Revocation integration tests |
| Credential/process isolation | Webhook secret only in API; App key only in dedicated worker; no provider network code in core services | Compose and source-boundary tests |
| API/CLI/worker/contracts/docs | Versioned binding/status/revoke routes, bounded CLI file input, dedicated worker, publication schema/OpenAPI, runbook/ADR/threat model | Contract, CLI, worker, and drift tests |

## Self-review findings fixed

1. Nullable `select_related` rows were initially included in `FOR UPDATE`; PostgreSQL rejected
   those queries. Locking now targets only the mutable root row.
2. Delivery parsing initially accepted a noncanonical uppercase UUID spelling. Delivery headers
   must now equal the canonical UUID string exactly.
3. The ordinary worker could have claimed provider jobs and failed them as unregistered. Core and
   GitHub workers now claim disjoint allowlisted kinds.
4. A binding response initially reported whether the installation, rather than the repository
   binding, was created. It now returns correct idempotent `201`/`200` semantics.
5. Reconfiguring a previously revoked repository binding restored the binding but not its repository
   state or transition audit. Explicit reconfiguration now reactivates the repository, restores only
   the reviewed App grants, and records the transition; revoked source connections and tokens remain
   revoked.
6. Installation revocation audit initially always claimed an `ACTIVE` prior state. It now preserves
   an actual `SUSPENDED` prior state.
7. Unmapped and invalid deliveries originally risked becoming tenant or parsing oracles. Signature
   verification precedes parsing and tenant lookup, while unmapped verified events receive the same
   bounded acknowledgement class without storage.
8. Outbound effects initially had no safe answer for lost responses. Frozen payloads, external
   adoption rules, append-only attempts, and retry leases make ambiguous responses recoverable
   without duplicate App content.
9. The draft manifest declared setup/callback URLs even though user OAuth installation ownership
   verification is not implemented. GitHub warns that setup `installation_id` values are
   spoofable. Those URLs were removed; the private MVP App now requires documented
   deployment-operator verification, and self-service installation is an explicit non-goal.

## Limitations

Live GitHub validation is intentionally skipped by issue scope; the deterministic fake and client
contract cover provider behavior. The App is private and setup is operator-assisted; the binding
API alone does not prove GitHub-account ownership and must not be exposed as self-service. Only
public GitHub is supported. The adapter does not execute
code, download workflow artifacts, ingest issues/reviews/push events, manage branch protection, map
organization membership, or grant merge/deployment approval. Adoption examines at most 100 Checks
or comments and fails closed on ambiguity. Automatic assurance requires configured exact policy
versions; otherwise PR/check state is still ingested. Retention quotas and GitHub Enterprise Server
support remain future work.

## Verification

All local application tooling ran in the isolated `anva-i8-impl` Docker project:

- The expanded focused gate passed 116 tests. The final client/boundary/contract subset passed
  24 tests before the full gate.
- Ruff formatting and linting passed; strict mypy passed for all 107 source and test files.
- Django configuration, migration drift, generated-contract drift (24 artifacts), Compose
  rendering, and `git diff --check` passed.
- The final full gate passed 405 tests with one expected skip for the deliberately unmounted
  external corpus. Coverage met the repository's 85% threshold.
- A production-settings smoke applied every migration through `core.0012_github_app_adapter` to a
  fresh database, reported no deployment-check errors, and brought a read-only API, core worker,
  and dedicated GitHub worker to readiness against PostgreSQL and MinIO. Runtime inspection
  confirmed the API received only the webhook secret, the core worker received no GitHub
  configuration, and the GitHub worker received App configuration without the webhook secret.
- Task-owned Docker resources remained below 1 GB effective footprint and were removed after the
  gates.

The local Docker daemon could not resolve package-index hosts while rebuilding the image, so local
tests used the preserved locked test image with the current source mounted read-only and the newly
locked PyJWT/cryptography packages in a temporary dependency volume. Hosted CI must therefore
provide the clean-image build evidence; its result is recorded on the pull request rather than
claimed here.
