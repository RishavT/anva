# Runbook: Bootstrap and repository tokens

## Scope

Create the first local organization, capture the one-time repository credential, rotate or revoke
credentials, and respond to suspected exposure. These commands use only the versioned API.

## Preconditions

- Start the exposed local stack and wait for `api` to become healthy.
- Set unique `ANVA_SECRET_KEY`, `ANVA_TOKEN_PEPPER`, and `ANVA_BOOTSTRAP_SECRET` values outside
  disposable local development.
- Never place plaintext tokens in shell history, command-line arguments, tickets, or logs.

## One-time bootstrap

Bootstrap is permitted only while no organization exists. Send `POST /api/v1/bootstrap` with the
configured `X-Anva-Bootstrap-Secret` and:

```json
{
  "organization_slug": "acme",
  "organization_name": "Acme",
  "admin_email": "admin@example.com",
  "admin_display_name": "Anva Admin",
  "repository_external_id": "github:acme/platform",
  "repository_name": "Platform"
}
```

The `token` response field is the only plaintext copy Anva returns. Transfer it directly into the
approved secret store, then discard the response. PostgreSQL stores only a keyed SHA-256 digest.
A repeated bootstrap request fails closed.

## Issue and rotate

An active credential needs `token.manage` plus every requested action and must target its own
repository. Issue with `POST /api/v1/repositories/{repository_id}/tokens`. Rotation uses
`POST /api/v1/tokens/{token_id}/rotate`; the old token becomes invalid in the same transaction and
the replacement plaintext is returned once.

Token lifetimes must be positive and no longer than 90 days. Use the narrowest action set and
shortest practical lifetime for CI/CD agents.

## Revoke and investigate

Call `DELETE /api/v1/tokens/{token_id}` from a separately authenticated administrator. Confirm the
row has `revoked_at` and review `last_used_at` plus tenant audit events. Expired, revoked, unknown,
and malformed credentials deliberately return the same client error.

If the token pepper may be compromised, plan a pepper rotation that invalidates all extant tokens,
then issue replacements from trusted administration. Preserve correlation IDs and audit records;
do not preserve plaintext credentials.

## Source revocation

`POST /api/v1/source-connections/{source_connection_id}/revoke` requires the expected revision.
The transaction deactivates direct and derived scopes and revokes access snapshots before future
retrieval. If the propagation safety bound aborts the transaction, do not manually mark only the
source row revoked; investigate and remediate the entire lineage atomically.
