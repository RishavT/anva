# Anva

Anva is the connective intelligence behind how your organization builds.

This repository currently contains the installable engineering foundation: a Python 3.12
Django modular monolith with independent API, worker, MCP, and CLI process boundaries,
PostgreSQL with pgvector, and S3-compatible object storage. The current backend includes
tenant identity, repository credentials, access scopes, permission-first hybrid retrieval,
bounded graph traversal, immutable context packets, and read-only filesystem ingestion with
immutable provenance, chunks, and normalized relationship edges. It also provides versioned work
intent, deterministic additive policy calculation, authority-pinned overrides, and immutable
commit-bound evidence manifests with criterion evidence/gaps. Independent assurance can ingest a
bounded manual PR diff without executing it, pin exact policy/context/evidence/evaluator versions,
run a context-limited manual evaluator queue, validate cited findings, compute server-owned
readiness, and render immutable Markdown/HTML review reports. It also includes an isolated,
least-privilege GitHub App adapter: verified idempotent webhooks,
current provider PR/Check observations, exact-head Check/comment publication, and durable
revocation-aware retries. It intentionally
does **not** contain a coding-agent runtime, workflow engine, graph database, or customer-code
sandbox.

## Prerequisites

- Docker Engine 24+ with the Docker Compose v2 plugin
- Make (optional; every target prints the underlying Compose command)
- 4 GB of free memory

No host Python, Node.js, npm, or Go installation is used.

## Install and run

From a fresh clone:

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
```

The checked-in Compose defaults also allow `docker compose up --build -d` without an `.env`
file. Copying `.env.example` makes local configuration explicit and gives you one place to
change credentials. The base stack publishes no host ports, which makes this exact command
safe on shared development and CI machines.

To open the UI and local storage console from the host, use the optional port-mapping
override:

```bash
docker compose down
docker compose -f compose.yaml -f compose.expose.yaml up --build -d
```

- Application: <http://localhost:18080>
- API liveness: <http://localhost:18080/health/live>
- API readiness: <http://localhost:18080/health/ready>
- MCP process readiness: <http://localhost:18081/health/ready>
- MinIO API: <http://localhost:19000>
- MinIO console: <http://localhost:19001>

These URLs apply only when `compose.expose.yaml` is included.

Wait until `docker compose ps` reports `api`, `worker`, `mcp`, `postgres`, and `minio` as
healthy. One-shot `migrate` and `minio-init` services should show a successful exit.

## Checks and tests

All application tooling executes inside Compose:

```bash
make format-check
make lint
make type
make migrations-check
make contracts-check
make unit
make integration
make corpus
make contract
make smoke
make coverage
make check
```

`make check` is the same entrypoint used by GitHub Actions. The optional `make corpus` target
requires the sibling `../anva-test` repository and mounts it at `/fixtures/anva-test:ro`; it
fingerprints representative files before and after a full ingestion. The integration suite uses a
separate `anva-tests` Compose project with non-persistent `test-postgres` and `test-minio`
services, never the development containers or data volumes. Remove that project after a
local test session with `make test-down`.

To format source files:

```bash
make format
```

The test container writes formatting changes as UID/GID 1000 by default. If your account
uses different IDs, set `ANVA_HOST_UID` and `ANVA_HOST_GID` in `.env`.

To refresh the dependency lock after deliberately changing `pyproject.toml`:

```bash
make lock
```

Review and commit both `pyproject.toml` and `uv.lock`.

Regenerate and verify the checked-in JSON Schema, OpenAPI, MCP, and example contracts with
`make contracts` and `make contracts-check`. Generated contract files are deterministic and
must not be edited directly.

## CLI and common operations

```bash
make cli
make logs
make migrate
make shell
make down
```

The worker claims PostgreSQL-leased allowlisted jobs and revalidates source/snapshot access before
and during ingestion. MCP exposes health endpoints, while the full MCP protocol and versioned
`/api/v1/mcp/context` route return `501 Not Implemented` until issue #9.

Bootstrap and repository-token operations are documented in
[the credential runbook](docs/runbooks/bootstrap-and-repository-tokens.md). A repository token
is opaque, repository/action scoped, stored only as a keyed digest, and returned in plaintext
only when issued or rotated.

Filesystem source lifecycle commands use the versioned API. Put the repository token in
`ANVA_TOKEN` (never a command-line argument), then run commands such as:

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva source inspect <source-connection-uuid>
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva source sync <source-connection-uuid>
```

Connect, resync, revoke, failure recovery, and read-only mount setup are documented in
[the ingestion runbook](docs/runbooks/source-ingestion.md).

Versioned work import, policy simulation, evidence submission, deterministic replay, and current
limitations are documented in
[the intent/policy/evidence runbook](docs/runbooks/intent-policy-evidence.md).

Manual diff ingestion, exact assurance starts, fresh evaluator claim/submit, reports, staleness,
and post-merge proposal safety are documented in
[the manual-diff assurance runbook](docs/runbooks/manual-diff-assurance.md).

GitHub App registration, repository binding, the isolated credential-bearing worker, status,
retry recovery, and revocation are documented in
[the GitHub App runbook](docs/runbooks/github-app.md). The normal stack does not start the
credential-bearing process; enable it explicitly with `docker compose --profile github up -d
github-worker`.

Permission-safe search, graph, context packet, CLI, evaluation, cache, and limitation details
are documented in
[the retrieval runbook](docs/runbooks/permission-safe-retrieval.md).

## Reset

This deletes only Anva's local Compose containers and named volumes:

```bash
make reset
docker compose up --build -d
```

The reset removes the local PostgreSQL database and MinIO objects. It cannot be undone.

## Troubleshooting

- Port collision with the optional exposed stack: set `ANVA_API_PORT`, `ANVA_MCP_PORT`,
  `ANVA_MINIO_API_PORT`, or `ANVA_MINIO_CONSOLE_PORT` in `.env`. The base stack does not
  publish ports.
- Unhealthy service: run `docker compose ps` and `docker compose logs <service>`.
- Stale image after a source edit: run `docker compose build --no-cache api worker mcp`.
- Migration failure: inspect `docker compose logs migrate postgres`, then use `make reset`
  only when destroying local data is acceptable.
- MinIO initialization failure: inspect `docker compose logs minio minio-init`; credentials
  must match across the two services.
- Lock mismatch: run `make lock`, inspect `uv.lock`, and rebuild.
- Source root rejected: mount it read-only in API and worker, then include its in-container
  absolute parent in `ANVA_FILESYSTEM_ALLOWED_ROOTS`.

See [the local development runbook](docs/runbooks/local-development.md) for dependency failure
behavior, [the authorization threat model](docs/security/tenancy-authorization-threat-model.md)
for tenant and credential boundaries, and
[the foundation threat model](docs/security/foundation-threat-model.md) for deployment
hardening requirements.

## Repository map

```text
src/anva/config/       Django settings and API process configuration
src/anva/contracts/    Canonical versioned JSON/OpenAPI/MCP contract source
src/anva/core/         Tenant models, state machines, artifacts, jobs, audit, and outbox
src/anva/ingestion/    Read-only connectors, bounded parsers, and mechanical extractors
src/anva/foundation/   Service-owned health and deployment invariants
src/anva/entrypoints/  API-adjacent CLI, worker, and MCP process boundaries
src/anva/templates/    Server-rendered semantic HTML
src/anva/static/       Browser-native CSS and JavaScript
tests/                 Unit, integration, contract, and smoke suites
docs/product/          Canonical product requirements
docs/adr/              Architecture decisions
docs/runbooks/         Operational procedures
docs/security/         Threat models
```

## Product source of truth

The canonical v3 product requirements and implementation plan is checked in at
`docs/product/anva-product-requirements-and-implementation-plan-v3.md`. Issue scope and
acceptance criteria remain the authority for incremental delivery.
