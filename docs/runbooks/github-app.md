# Runbook: GitHub App adapter

## Register and configure the App

Review and replace the example URLs in `deploy/github/app-manifest.yaml`, then register the manifest
with GitHub. Do not add permissions without updating the permissions review and tests. Configure
the webhook URL as:

```text
https://<anva-host>/webhooks/github
```

MVP setup is deployment-operator-assisted. The checked-in App is private and does not declare a
setup/callback URL. Before calling the binding API, an operator must independently confirm the
installation, account, selected repository IDs, and permission snapshot in GitHub App settings.
Do not expose this API as a self-service handler for a setup-URL query: GitHub documents that the
`installation_id` query parameter can be spoofed. A future public/self-service flow must authorize
the installer and verify that the installation is associated with that GitHub user before binding.

Store one or more comma-separated webhook secrets in `ANVA_GITHUB_WEBHOOK_SECRETS` for rotation.
Place the App PEM key in a root/operator-owned regular file outside the image and set
`ANVA_GITHUB_APP_PRIVATE_KEY_FILE_HOST` to that file. Never place PEM data in `.env`.

Create a repository-binding JSON file with the GitHub installation snapshot, numeric repository
identity, Anva access-scope UUID, and optional exact policy/work revision:

```json
{
  "access_scope_id": "00000000-0000-4000-8000-000000000010",
  "installation_id": 1234567,
  "account_id": 7654321,
  "account_login": "example-org",
  "account_type": "Organization",
  "repository_selection": "selected",
  "permissions": {
    "actions": "read",
    "checks": "write",
    "contents": "read",
    "issues": "write",
    "metadata": "read",
    "pull_requests": "read"
  },
  "external_repository_id": 987654321,
  "full_name": "example-org/service",
  "default_branch": "main",
  "private": true,
  "archived": false,
  "auto_assurance": true,
  "policy_version_ids": [],
  "work_item_revision_id": null
}
```

With an admin-capable repository token in `ANVA_TOKEN`:

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva github configure \
  --repository-id <repository-uuid> --config /fixtures/github-binding.json

docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva github status \
  --repository-id <repository-uuid>
```

The binding call is idempotent only for the same installation and numeric repository identity.
Cross-tenant or identity-changing reuse fails closed. Numeric mapping prevents webhook-body tenant
routing, but it is not proof that the configuring Anva administrator controls the GitHub account;
that proof is the deployment operator's responsibility in this MVP.

## Run and observe

Start the ordinary stack and the isolated credential-bearing worker:

```bash
docker compose up --build -d
docker compose --profile github up --build -d github-worker
docker compose ps
```

Only `api` receives webhook secrets. Only `github-worker` receives the App ID, slug, and private-key
secret mount. The ordinary worker, MCP, and CLI processes do not receive either credential class.

The status command reports the installation/binding state, last delivery processing state, and last
outbound-write state/error. Expected publication behavior is one current `Anva / Assurance` Check
and one App-authored marked comment for each evaluated head. The content names the exact commit and
does not grant merge or deployment approval.

PR synchronization is serialized per binding and PR. The worker locks active installation/binding
authority before any provider call, accepts a diff only when identical full provider snapshots
bracket it, then rechecks provider truth before committing local effects. This protects both the
suspension drain boundary and the current projection when delivery workers observe different heads.

## Retry and recovery

- `github_rate_limited`: the durable write moves to `RETRY` using the greater of exponential
  backoff and provider `Retry-After`.
- `github_ambiguous_write`: the next attempt searches for the same App Check/name/head or
  App-authored marker and adopts it; human marker copies are ignored.
- `github_pull_request_changed_during_sync`: provider truth changed during the bounded refresh or
  final recheck. The local transaction was rolled back; allow the durable job to retry.
- `github_http_3xx`: the live client deliberately rejects all redirects, including same-origin
  redirects. Verify GitHub/API routing; do not bypass this control or manually replay a bearer
  token.
- `github_token_response_invalid`: the token was not bounded `ghs_` syntax, lacked a timezone-aware
  expiry, or its remaining lifetime was outside 30 seconds to 65 minutes. Verify system time and
  App configuration, then rotate credentials if the response remains unexpected.
- `STALE_HEAD` or `SUPERSEDED_PUBLICATION`: the write is cancelled without constructing a client.
- `GITHUB_ACCESS_REVOKED`: the write and outbox event are retired without network access.
- invalid signature/body: GitHub receives a stable 4xx response; inspect only safe correlation and
  delivery IDs, never body/token/key data.
- unmapped delivery: returns `202` without revealing tenant state; configure the mapping before a
  deliberate redelivery.

## Suspend and unsuspend

A GitHub installation suspension is a temporary but complete access stop. When the verified
`installation/suspend` event finishes, Anva has deactivated the installation service identity,
reviewed grants, eligible bindings and repository context; cancelled active assurance/evaluator
work, queued provider jobs and pending writes; retired current publications; revoked repository
tokens; and marked associated source connections revoked. New non-lifecycle deliveries are stored
as ignored and are not queued.

There are two intentional race outcomes:

- If suspension acquires installation authority first, no later provider read or write begins.
- A provider read or outbound write that already acquired installation/binding authority is allowed
  to finish. Suspension waits for that transaction and returns only after it has drained; all
  remaining eligible work is then cancelled.

Only a verified `installation/unsuspend` event reactivates a suspended installation. It restores the
service identity, non-revoked/non-archived bindings and repository context, and exactly the reviewed
grants. It does not replay cancelled deliveries/jobs/writes, revive publications or assurance,
publish a completed pre-suspension run that had not yet produced an intent, unrevoke source
connections, or issue replacement repository tokens. After unsuspension, verify the binding status,
reconnect required sources, issue fresh credentials through their normal workflow, and deliberately
redeliver or restart only current work.

## Revoke

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva github revoke \
  --repository-id <repository-uuid>
```

Revocation is terminal for that binding/installation record. It cancels active
assurance/evaluator/provider jobs and pending writes, revokes associated repository tokens and
source health, deactivates future repository context, and preserves immutable delivery,
observation, report, attempt, and audit history. Reconfiguration is an explicit admin operation and
requires newly issued repository credentials and source reconnection where needed.

For an installation-wide incident, revoke/delete the installation in GitHub first, stop the GitHub
worker, rotate the key and webhook secret, then investigate using identifiers only.
