# Runbook: Product UI

## Start and bootstrap

Use the normal Compose topology and exposed-port override:

```bash
docker compose -f compose.yaml -f compose.expose.yaml up --build -d
docker compose ps
```

Open `http://localhost:18080`. On an empty database, `/` redirects to `/setup`.
Enter the configured `ANVA_BOOTSTRAP_SECRET` and the organization, first human
administrator, repository boundary, retention, model-processing, skill, and
assurance choices. Successful setup rotates into a human session and opens the
onboarding checklist.

The bootstrap secret is not a future password. After logout or session expiry,
the current MVP requires an operator-approved session-entry mechanism or local
reset; the access page does not claim password, GitHub, OAuth, or SSO support.

## Operate

- Attention: resolve blocked assurance, unreviewed/stale knowledge, and source
  health before browsing general activity.
- Onboarding: treat only observed stored state as complete.
- Explorer: search within one visible repository; entity details show
  freshness, review state, provenance, conflicts, revisions, and accessible
  relationships.
- Knowledge review: confirm/reject/stale governed assertions or create a cited
  correction proposal. A correction never directly overwrites knowledge.
- Source health: request sync or type `REVOKE` to confirm revocation.
- Repository: confirm purpose, owner, commands, checks, and sensitive paths
  with the displayed revision.
- Assurance: verify exact head/evaluated/report commits, currentness, blockers,
  deterministic checks, findings, evidence, versions, and limitations.
- Skills: use non-secret compatibility diagnostics; provision repository tokens
  only through the operator workflow.
- Audit: available only to organization administrators and security reviewers.

## Browser verification

Run the production-independent Chromium stage:

```bash
make browser
```

It creates evidence screenshots under
`docs/evidence/issue-011/screenshots`, checks setup through mobile navigation,
rejects unexpected severe console messages, inspects accessible control names,
and verifies no horizontal overflow at 390 pixels.

Run the complete release gate with:

```bash
make check
```

## Migration recovery

The product tables are in core migration `0015`. Inspect and apply:

```bash
docker compose run --rm api python -m anva.manage showmigrations core
docker compose run --rm api python -m anva.manage migrate --noinput
```

Before rollback, preserve organization settings, repository profile, and scoped
proposal data. Rolling back to core `0014` deletes those tables.

## Troubleshooting

- Redirect to `/access`: the session is missing, expired, the user is inactive,
  or the membership is inactive.
- Stable 404: the identifier is absent, foreign, revoked, or outside current
  repository/scope access; the UI deliberately does not distinguish them.
- Stable 409: reload the detail and resubmit against its current revision.
- Disabled buttons: `ANVA_WEB_READ_ONLY=true`.
- Live developer-skill status: `ANVA_MCP_URL` identifies the MCP transport URL and
  `ANVA_MCP_ALLOWED_HOSTS` must contain its exact host. The web process derives and probes only
  the bounded `/diagnostics` route; it does not follow redirects or accept a URL from a request.
- Missing GitHub/source/assurance completion: confirm the corresponding stored
  binding, successful sync, context packet, or run; do not manually mark it
  complete.

Preserve the correlation identifier, route, time, non-secret browser console
messages, and exact commit. Never attach cookies, bootstrap secrets, tokens,
environment files, or source payloads to an issue.
