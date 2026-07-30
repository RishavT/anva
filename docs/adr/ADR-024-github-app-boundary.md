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
- pull-request processing fetches current provider state, then uses the existing nonexecuting
  manual-diff ingestion and assurance services;
- Checks and comments are frozen, exact-head write intents backed by an outbox and append-only
  attempt history;
- a dedicated GitHub worker is the only process with the App private key and live network client;
- live clients mint short-lived tokens restricted to one stored numeric repository ID and the
  reviewed permission set;
- revocation cancels future adapter work, revokes associated repository access, and preserves
  immutable audit history.

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

## Consequences

GitHub outages delay event processing and publication without changing assurance history. Exact
head changes and revocation cancel stale writes before network access. The adapter requires
PostgreSQL and a separately deployed credential-bearing worker. Initial operation supports public
GitHub only and bounds adoption searches to the first 100 provider results.

## Security impact

The API receives only rotating webhook secrets. The GitHub worker receives only the App ID, slug,
and read-only private-key secret mount; it does not receive webhook secrets. Installation tokens
are held in memory for one request and are not logged or persisted. Human comments with a copied
Anva marker are never adopted unless the author is the configured App bot.

## Privacy impact

Only bounded normalized webhook fields are retained. Raw webhook bodies, authorization headers,
installation tokens, and private keys are not stored. Pull-request title, description, and diff
remain governed data under the existing assurance retention rules.

## Operational impact

Operators must register the reviewed manifest, configure repository mappings, provide a private-key
secret file, run the `github` Compose profile, monitor event/write status, and rotate webhook
secrets and App keys independently.

## Revisit conditions

Review this decision before supporting GitHub Enterprise Server, organization-member mapping,
provider-hosted code execution, artifact download, more permissions/events, or adoption pagination
beyond 100 results.
