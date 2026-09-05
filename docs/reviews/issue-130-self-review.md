# Issue 130 self-review

## Scope and root cause

The `PREPARING` state persisted `source_connection_id` and `sync_run_id`, but `start()` ignored
both checkpoints on replay. After a long sync completed and the next public boundary stopped, a
documented retry attempted a second filesystem-source mutation before it could inspect the
completed sync. The production API correctly rejected that duplicate boundary.

The fix is limited to acceptance orchestration. It reconciles the two persisted checkpoints in
order: a sync without its source is rejected as invalid state, an existing source is not recreated,
and an existing sync is observed through `listSourceSyncRuns` rather than restarted. All later
product interactions remain public API or MCP calls.

## Failure evidence and redaction

`start()` records its current stable stage. A caught runner or product-boundary rejection writes
`operator-diagnostic.json` atomically beside the private resume record with mode `0600`. The
allowlisted document contains only schema version, status, run ID, stage, reason code, and an
optional HTTP status. It never includes exception text, response content, URLs, headers, or
credentials. Public CLI errors retain their existing generic contract.

Authorization failures are deliberately collapsed to `authorization_rejected`; unavailable API
or MCP transport is `boundary_unavailable`; a bounded sync wait is `sync_timeout`; semantic
validation is `semantic_assertion_failed`; other runner and boundary failures remain generic.
This is operator-actionable without becoming an authentication or response oracle.

## Replay and boundary review

- A valid completed-sync replay performs only a sync-status read before continuing.
- Wrong, expired, and reused synthetic tokens fail on that read and perform no mutation.
- A sync checkpoint without a source checkpoint fails closed before a product request.
- Source and sync identifiers remain UUID-only state fields under the existing state validator.
- The acceptance initiator gains the repository-scoped read action `artifact.view`, which is the
  minimum permission required to reauthorize its cached context-packet artifact during finalization.
  It gains no `all_*`, administrative, cross-repository, or cross-organization access. The fix does
  not expose response bodies, import product internals, or couple runtime behavior to the test
  harness.
- The resumed full synthetic journey still uses distinct initiator/reviewer credentials, creates
  one work item/policy/evidence manifest, starts only the primary and intentional stale-probe
  assurance runs, rejects the stale head, and seals the completed result.

## Verification

All commands ran in disposable Docker containers with the issue worktree mounted and `--rm`.
Deterministic unit checks used isolated boundaries; the production-sized integration deliberately
used real Compose PostgreSQL and MinIO services plus live localhost Django and MCP HTTP servers.

- Ruff format and lint: 242 files clean.
- Focused acceptance and boundary suites: 46 passed.
- Full mypy: 208 source files clean.
- Full runtime suite: 1,271 passed with 6 expected browser/profile/Docker-CLI skips. The 14 release
  hardening tests were also run in a network-isolated Docker test image containing `/usr/bin/make`
  and all passed, covering all 1,285 applicable tests.
- Contract generation and drift validation verified all 33 artifacts; migration and rendered-skill
  drift checks were clean.
- The production-sized integration passed in 51.17 seconds with 107 files and 214,313 bytes. It
  used real ingestion and a persisted sync duration beyond 20 seconds, exercised wrong, expired,
  and rotated-old credentials through real HTTP 401 responses, recovered with a replacement
  credential, and negotiated the official MCP client with the live server. It then completed work,
  policy, evidence, primary/stale assurance, reviewer handoff/submission, and idempotent sealed
  finalization while asserting that sources, syncs, documents, chunks, objects, and later workflow
  records were not duplicated.
