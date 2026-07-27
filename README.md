# Anva

Anva is the connective intelligence behind how your organization builds.

This repository currently contains the installable engineering foundation: a Python 3.12
Django modular monolith with independent API, worker, MCP, and CLI process boundaries,
PostgreSQL with pgvector, and S3-compatible object storage. The foundation intentionally
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
make unit
make integration
make contract
make smoke
make coverage
make check
```

`make check` is the same entrypoint used by GitHub Actions. The integration suite uses a
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

## CLI and common operations

```bash
make cli
make logs
make migrate
make shell
make down
```

The worker is a deliberately empty process shell. MCP exposes health endpoints, while
`/mcp` returns `501 Not Implemented` until the protocol and authorization model are built
in their own milestone.

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

See [the local development runbook](docs/runbooks/local-development.md) for dependency
failure behavior and [the foundation threat model](docs/security/foundation-threat-model.md)
for trust boundaries and production hardening requirements.

## Repository map

```text
src/anva/config/       Django settings and API process configuration
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
