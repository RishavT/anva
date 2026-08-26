# Issue 51 fresh-install scope discovery evidence

Date: 2026-08-26

## Result

PASS. A genuinely fresh, wheel-installed Anva runtime exposed its authoritative repository access
scope through `anva demo`. The exact returned `repository_id` and `access_scope_id` then authorized
a read-only filesystem source connection and sync through installed public CLI/API interfaces.

## Boundary

- Compose project: `anva-scope51fresh`
- Runtime image built from the issue 51 worktree: `anva-scope51:fresh`
- Source: `/home/rishav/Documents/personal/brain/anva-test`, mounted read-only at
  `/fixtures/anva-test` in API, worker, and CLI containers
- No database inspection or private acceptance-harness state
- The one-time token stayed in one ephemeral CLI container environment and was never printed,
  redirected, or persisted

## Redacted observed output

```text
BOOTSTRAP status=created
repository_id=d983d50a-1470-4673-95b9-7fd20ab4be2e
access_scope_id=ee0915d4-9477-4cdd-b61a-0d72a5f141fd
token_present=true
CONNECT source_connection_id=5219bdd5-ad2d-49ec-82fe-87b1dcdf075e
run_status=PARTIALLY_COMPLETED discovered_count=619 failed_count=23
```

`PARTIALLY_COMPLETED` is a successful bounded-ingestion terminal state: usable files were committed
while 23 unsupported/unsafe entries in the intentionally large and messy repository were isolated.
The discovery defect is therefore resolved independently of corpus cleanliness.

## Automated checks

```text
35 passed in 50.39s
All checks passed!  # Ruff
```

The 35 tests comprise 34 existing CLI unit tests and the new integration/contract bootstrap-scope
test. The new test binds the returned scope, repository, service identity, and organization and
checks the existing all-repositories/all-service-identities semantics of the local demo scope.
