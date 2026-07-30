# Issue #8 self-review: GitHub App adapter

## Scope and acceptance evidence

| Requirement | Implementation | Verification |
| --- | --- | --- |
| Least-privilege installable App | Reviewed manifest, closed setup permission allowlist, one-repository short-lived token minting | Manifest/contract/security tests and permissions review |
| Signature and replay safety | Raw-byte HMAC before parsing, bounded normalized JSON, global delivery UUID/checksum identity | Parser, HTTP, collision, and concurrent-delivery tests |
| Tenant-safe installation/repository mapping | Explicit numeric mapping, central admin authorization, composite tenant foreign keys | Authorization and PostgreSQL graft tests |
| PR and Check ingestion | Per-PR PostgreSQL serialization and locked authority before provider I/O, provider snapshots bracketing the diff, final provider recheck with transactional rollback, immutable core revision/observations, exact-commit check observations | Delayed-head concurrency, synchronized duplicate, provider-change, rollback, fork, and check tests |
| Exact-head Check/report | One current projection per PR/kind, deterministic Check/comment rendering, bounded annotations and marker | Queue/render integration tests |
| Durable outbound effects | Frozen write intent, explicit outbox event, lease/attempt history, rate-limit backoff and ambiguous-write adoption | Retry, concurrency, ambiguity, spoof, and immutability tests |
| Suspension and revocation | Suspend/unsuspend reconciles App-JWT-only provider truth and later accepted lifecycle deliveries under the installation lock before mutation; reconciled suspension drains authorized effects and cancels derived work/access; revocation remains terminal | Lifecycle ordering/mismatch/error, suspension race/drain, and revocation tests |
| Credential/process isolation | Webhook secret only in API; App key only in dedicated worker; no provider network code in core services; live HTTP rejects every redirect and validates installation-token syntax/lifetime | Compose, source-boundary, redirect, and token-response tests |
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
10. Installation suspension initially changed only the installation state, leaving the service
    identity, bindings, grants, queued work, assurance, publications, repository tokens, and
    sources usable. Suspension now atomically disables that authority and derived work. Every
    credential-bearing provider read/write holds installation/binding authority locks, so
    suspension either wins before network access or waits for the already-authorized transaction
    to drain. Unsuspension is an explicit installation event that restores only the service
    identity, non-revoked and non-archived bindings/repositories, and the reviewed grants; it does
    not replay cancelled work, restore revoked tokens/source connections, or materialize a
    completed pre-suspension run that had not already produced a publication.
11. The sequential stale-delivery test did not cover two workers that observed different provider
    heads and completed in reverse order. Pull-request refresh now uses a transaction-scoped
    PostgreSQL advisory lock per binding/PR, accepts only a diff bracketed by identical full
    provider snapshots, and performs a final provider recheck before commit. A moving provider
    state is retried within a bound; a final mismatch raises a transient safe error and rolls back
    the revision, observation, assurance, and other local effects.
12. The live client initially relied on the standard redirect handler and accepted an arbitrary
    non-empty installation token with any future expiry. The credential-bearing client now rejects
    all redirects, including same-origin redirects, requires bounded `ghs_` token syntax, and
    accepts only timezone-aware expiries between 30 seconds and 65 minutes from validation time.
13. Suspend/unsuspend initially trusted the delivery action after signature verification. A delayed
    or retried old unsuspend could therefore restore authority after a newer suspension. Lifecycle
    mutation now holds the installation lock, rejects an older delivery when a later lifecycle
    delivery has already been accepted, and reconciles the target action against GitHub's current
    numeric installation record. The reconciliation GET uses only an App JWT and never mints an
    installation token. Superseded or provider-mismatched deliveries become durable ignored
    history; provider/network errors and malformed responses fail before authority mutation and
    follow bounded retry handling.

## Limitations

Live GitHub validation is intentionally skipped by issue scope; the deterministic fake and client
contract cover provider behavior. The App is private and setup is operator-assisted; the binding
API alone does not prove GitHub-account ownership and must not be exposed as self-service. Only
public GitHub is supported. The adapter does not execute
code, download workflow artifacts, ingest issues/reviews/push events, manage branch protection, map
organization membership, or grant merge/deployment approval. Adoption examines at most 100 Checks
or comments and fails closed on ambiguity. Automatic assurance requires configured exact policy
versions; otherwise PR/check state is still ingested. Retention quotas and GitHub Enterprise Server
support remain future work. Provider truth that does not stabilize within three bracket attempts is
retried as a transient synchronization failure rather than ingested.

## Verification

The preceding independent-review remediation checkpoint was verified in the isolated task Docker
project:

- The complete focused GitHub boundary passed 84 of 84 tests, including suspension lifecycle and
  drain races, delayed/current provider concurrency, advisory-lock contention, bracket/final
  provider changes, publication staleness, redirect rejection, and token-response validation.
- Ruff formatting checked all 122 files and linting passed. Strict mypy passed all 107 source
  files. Django configuration checks passed, there was no migration drift, and all 24 generated
  contracts matched their checked-in artifacts.
- The repository-wide full gate passed 418 tests with one intentional skip for the deliberately
  unmounted external corpus. Coverage was 86%.
- A production-settings smoke applied every migration through `core.0012_github_app_adapter` to a
  fresh database. The deployment check reported zero errors and four existing warnings. The API,
  core worker, and dedicated GitHub worker became healthy against PostgreSQL and MinIO.
- Runtime assertions confirmed safe credential isolation: the API received only its webhook
  secret, the core worker received no GitHub credentials, and only the GitHub worker received its
  App configuration/private-key mount without the webhook secret.
- The task's effective peak Docker footprint was approximately 1.3 GB, below the 5 GB limit. Exact
  task containers, networks, volumes, and temporary files were cleaned after verification.

The subsequent lifecycle-order remediation was verified separately:

- Red-before probes reproduced all three PostgreSQL lifecycle failures and all eight missing
  client-boundary controls: delayed and failed/retried old unsuspend deliveries restored authority
  after a newer suspension, provider failures did not gate lifecycle mutation, and no App-JWT-only
  installation-state boundary existed.
- The final complete GitHub boundary passed 100 of 100 tests. It covers later-delivery
  supersession, provider-state mismatch in both directions, provider failure without authority
  mutation, App-JWT-only lifecycle reads with no installation-token mint, and malformed,
  oversized, wrong-installation, naive-time, and far-future responses.
- Ruff formatting checked all 122 files and linting passed. Strict mypy passed all 107 source
  files. Django configuration checks passed, there was no migration drift, and all 24 generated
  contracts matched their checked-in artifacts.
- The final repository-wide gate passed 434 tests with one intentional unmounted-corpus skip and
  86% coverage.
- A fresh production-settings smoke applied every migration through
  `core.0012_github_app_adapter`; the deployment check reported zero errors and three existing
  warnings. The API, core worker, and GitHub worker became healthy, and credential-isolation
  assertions passed.
- The exact task image was 569,694,108 bytes (approximately 543 MiB), and the fresh production
  database volume used approximately 73.5 MiB. The effective task footprint remained well below
  5 GB. Exact lifecycle containers, networks, volumes, image, and temporary smoke files were
  removed after verification.

After the full gate, a review-only test strengthening added an explicit timezone-naive timestamp
case and pinned the oversized-response fixture to the 256 KiB lifecycle boundary. The complete
live-client file then passed 47 tests; no production code changed after the full and production
gates.

Normal Compose rebuilds encountered Docker DNS failures, but an exact current-dependency image was
built successfully with host networking and used for the final focused, full, and production
gates. Hosted clean-image CI for the eventual pushed lifecycle commit is still recorded separately
and is not claimed here.
