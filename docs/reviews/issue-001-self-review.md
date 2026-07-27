# Issue #1 self-review: Python and Compose foundation

- Date: 2026-07-28
- Reviewer: implementing agent
- Scope: `RishavT/anva#1`
- Result: Accepted after findings below were fixed

## Acceptance-criteria review

| Requirement | Evidence | Result |
| --- | --- | --- |
| Fresh `docker compose up --build -d` reaches healthy | Reset removed only the `anva` project and volumes; API, worker, MCP, PostgreSQL, and MinIO became healthy; `migrate` and `minio-init` exited 0 | Pass |
| Python 3.12+ Django modular monolith and four entrypoints | Locked Python 3.12/Django package; Gunicorn API, dedicated worker, dedicated MCP WSGI process, and Compose CLI service | Pass |
| PostgreSQL, pgvector, MinIO, migrations | Health-checked services; migration `0001_enable_vector_extension`; integration test queries `pg_extension`; bucket init is idempotent | Pass |
| Compose-owned engineering checks | `make check` runs formatter check, Ruff, strict mypy, all 39 pytest cases, and an 85% coverage gate inside the isolated `anva-tests` project | Pass |
| No host application runtime | Docker/Compose are the only runtime prerequisites; no frontend package or Go module exists | Pass |
| Browser-native UI foundation | Semantic Django template, accessible skip link/status UI, CSS, plain browser JavaScript, collected static assets served by WhiteNoise | Pass |
| Canonical v3 plan and decision/operations docs | Canonical copy has the same SHA-256 as the source; ADR, runbook, and threat-model templates plus three accepted ADRs are present | Pass |
| CI parity | GitHub Actions calls `make ci`, which delegates to the same `make check` used locally | Pass |
| Prohibited scope absent | Search found no agent runtime, workflow engine, graph library/database, customer-code execution, model SDK, or Docker socket mount | Pass |
| Install/reset/troubleshooting instructions | README documents internal and optionally exposed starts, tests, reset semantics, and dependency troubleshooting | Pass |

## v3 Section 30 review

### Product and Anva quality

This issue exposes only foundation behavior and labels the MCP protocol and empty worker
honestly. It makes no readiness or assurance claim about customer code. Provenance,
inference, organization scope, revision, staleness, and correction do not yet apply because
no knowledge assertion or tenant data model exists.

### Code and tests

Domain-independent dependency checks live in a service module; web adapters remain thin.
External database, boolean, worker interval, and object endpoint inputs are validated.
Migrations and MinIO bucket setup are idempotent. Type, format, and lint checks pass.
Unit, integration, HTTP contract, MCP contract, and browser-shell smoke suites pass. There
is no authorization surface or model behavior to evaluate in this slice.

### Security, documentation, and evidence

Processes run as an unprivileged user. Secrets are neither copied into images nor returned
by health responses. Readiness failures sanitize connection detail. The threat model
documents trust boundaries, prompt-injection non-applicability, local retention/deletion,
and production hardening gaps. README, ADRs, and the runbook cover all introduced behavior.
Command results and acceptance mappings are recorded here and in the pull request.

## v3 Section 31 review

- General: purpose-specific typed functions, explicit configuration parsing, structured
  JSON HTTP errors, small dependency interfaces, UTC Django configuration, and migration
  ownership are present.
- Backend: service functions own readiness checks; views and WSGI adapters are thin. There
  are no tenant operations, state transitions, external writes, outbox events, or recursive
  queries yet.
- Frontend: semantic HTML, keyboard skip path, screen-reader text, reduced-motion handling,
  and explicit failure/retry status are present. No UI authorization inference exists.
- Skills, prompts, and reports: not introduced by this foundation issue.

## Findings fixed during self-review

1. The initial JSON-style logging format used incompatible formatter syntax and prevented
   Django startup. Corrected and covered by every test process startup.
2. The initial default host ports collided on shared machines. Base Compose now publishes
   no ports, so the exact acceptance command is reliable; an explicit override provides
   documented local browser ports.
3. Initial tests covered behavior but only reached 72% coverage. Added focused CLI, worker,
   configuration-failure, MCP readiness, and redaction tests; final coverage is 96%.
4. Gunicorn initially had no static-file server. Added WhiteNoise, image-time
   `collectstatic`, static discovery coverage, and a live-image CSS request check.
5. Runtime images initially included developer tools. Split dependency installation so
   pytest, mypy, and Ruff exist only in the test target.
6. Test dependencies initially shared the main Compose project. Test commands now use the
   separate `anva-tests` project and never touch development containers or volumes.
7. Negative numeric worker intervals could raise an unhandled exception. Startup now
   rejects non-numeric, zero, and negative values with exit code 2.
8. Supply-chain wording overstated pinning. The threat model now explicitly records
   remaining image and CI-action digest pinning work.

## Known limitations

- MCP protocol/tool schemas, tenant identity, authorization, knowledge/provenance models,
  agent skills, pull-request assurance, and organizational canvas are later issues.
- The worker intentionally registers no job handlers and checks dependencies only at
  startup.
- Object-storage readiness currently supports the local HTTP MinIO endpoint; production
  TLS/authenticated storage checks require the deployment design.
- Local defaults are not production credentials. TLS termination, secret management, CSP,
  HSTS, image/action digest pinning, backups, and tenant retention/deletion controls remain
  required before production deployment.
- The smoke suite verifies rendered browser-visible markup and static delivery, but a real
  browser automation stack is deferred until interactive canvas behavior exists.
