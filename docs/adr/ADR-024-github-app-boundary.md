# ADR-024: Isolated GitHub App adapter

- Status: Accepted
- Date: 2026-07-30
- Owners: Anva platform

## Context

Anva must observe GitHub pull requests and checks and publish exact-head assurance without making
GitHub a dependency of core assurance. Webhook bodies, pull-request prose, diffs, forks, and
provider responses are hostile. GitHub writes can be duplicated by retries or become ambiguous
when a response is lost after the provider commits a request.

## Decision

GitHub is an adapter around the provider-neutral assurance domain:

- the API verifies HMAC-SHA256 over the exact raw webhook bytes before JSON parsing or tenant
  lookup;
- a preconfigured installation and numeric repository mapping is the only tenant-routing input;
- immutable normalized deliveries and mutable processing projections are stored separately;
- pull-request processing takes a transaction-scoped PostgreSQL advisory lock per binding/PR,
  locks active installation/binding authority before any credential-bearing provider call, accepts
  only a diff bracketed by identical full provider snapshots, and performs a final provider
  recheck before committing the existing nonexecuting manual-diff ingestion and assurance effects;
- Checks and comments are frozen, exact-head write intents backed by an outbox and append-only
  attempt history;
- a dedicated GitHub worker is the only process with the App private key and live network client;
- live clients mint short-lived tokens restricted to one stored numeric repository ID and the
  reviewed permission set, reject every HTTP redirect, and validate the returned token's bounded
  `ghs_` syntax and expiry;
- before a suspend or unsuspend delivery mutates authority, the worker reconciles current provider
  state with `GET /app/installations/{installation_id}` using App-JWT authority only; it never mints
  an installation token for this lifecycle read;
- suspend/unsuspend processing holds the installation lock and treats a later accepted lifecycle
  delivery as superseding an older one. A superseded action or one that disagrees with current
  provider state becomes a durable ignored processing result; provider errors or malformed
  responses fail without changing authority and follow the bounded job retry path;
- a reconciled suspension atomically disables the installation principal, grants, bindings,
  repository context, and derived work while preserving an explicit narrow unsuspend path;
  revocation remains terminal and preserves immutable audit history.

The ordinary worker claims only core allowlisted jobs. The GitHub worker claims only GitHub event
jobs and outbound writes. Core assurance and other core services do not import provider clients or
network libraries.

## Alternatives considered

- A GitHub-specific assurance engine was rejected because it would duplicate policy, evidence,
  staleness, and readiness rules.
- Long-lived installation tokens in the database were rejected because they enlarge the credential
  boundary and complicate revocation.
- Direct webhook-to-GitHub writes were rejected because delivery retries and ambiguous responses
  require durable intent, leasing, adoption, and attempt history.
- Running a workflow in the pull-request branch was rejected because forks and changed code must
  never receive Anva credentials or execute inside this adapter.
- Treating a provider read as current merely because it followed a webhook was rejected because
  concurrent workers can complete in reverse order. A local PR refresh lock plus bracket/final
  provider checks supplies a defined serialization point without trusting delivery order.
- Treating suspension as a state label was rejected because queued and in-flight effects require an
  atomic drain/cancellation boundary and explicit reauthorization semantics.
- Treating webhook arrival order or action as current installation truth was rejected because a
  delayed or retried old unsuspend could otherwise override a newer suspension.
- Minting an installation token to verify lifecycle state was rejected because the installation may
  be suspended and the broader credential is unnecessary. The fixed installation endpoint accepts
  the App JWT already held by the isolated worker.

## Consequences

GitHub outages delay event processing and publication without changing assurance history. Exact
head changes, suspension, and revocation cancel stale writes before network access. A provider
snapshot that changes during synchronization causes bounded refresh or full transactional rollback
and retry. Provider reads and outbound writes occur while holding installation/binding authority
locks: suspension either wins before network access or waits for the already-authorized transaction
to drain. Explicit unsuspension restores reviewed authority but not cancelled jobs, revoked tokens,
source connections, or completed pre-suspension runs that had not yet been published. The adapter
requires PostgreSQL and a separately deployed credential-bearing worker. Initial operation supports
public GitHub only and bounds adoption searches to the first 100 provider results.

Suspend and unsuspend therefore depend on one additional bounded provider read. If GitHub is
unavailable or its installation response is malformed, Anva retains the prior local authority
state, records the processing failure, and retries rather than applying an unverified lifecycle
mutation. An authenticated lifecycle delivery that no longer matches current provider state is
retained as an ignored historical delivery.

## Security impact

The API receives only rotating webhook secrets. The GitHub worker receives only the App ID, slug,
and read-only private-key secret mount; it does not receive webhook secrets. Installation tokens
are held in memory for one request and are not logged or persisted. Token responses must use
bounded `ghs_` syntax and an aware expiry 30 seconds to 65 minutes in the future. Credentialed
requests reject all redirects rather than forwarding authorization to another hop. Human comments
with a copied Anva marker are never adopted unless the author is the configured App bot.
Lifecycle reconciliation uses only a short-lived App JWT for the fixed numeric installation path;
it does not request, expose, or persist an installation token.

## Privacy impact

Only bounded normalized webhook fields are retained. Raw webhook bodies, authorization headers,
installation tokens, and private keys are not stored. Pull-request title, description, and diff
remain governed data under the existing assurance retention rules.

## Operational impact

Operators must register the reviewed manifest, configure repository mappings, provide a private-key
secret file, run the `github` Compose profile, monitor event/write status, and rotate webhook
secrets and App keys independently. Operators must treat suspension as a drain point and explicitly
redeliver/restart desired current work after an installation is unsuspended; unmaterialized
pre-suspension completed runs remain retired. Operators must also monitor failed/ignored lifecycle
processing reasons rather than manually changing local installation state.

## Revisit conditions

Review this decision before supporting GitHub Enterprise Server, organization-member mapping,
provider-hosted code execution, artifact download, more permissions/events, or adoption pagination
beyond 100 results.
