# Runbook: Local development stack

## Purpose and scope

Install, verify, troubleshoot, and reset the Docker Compose development topology.

## Preconditions

- Work only inside the Anva repository.
- Docker Engine and Docker Compose v2 are available.
- No local ports are required by the base topology. To use the optional exposed topology,
  local ports 18080, 18081, 19000, and 19001 must be available. PostgreSQL is never
  published to the host by default.

## Start and verify

```bash
docker compose up --build -d
docker compose ps
docker compose run --rm api python -m anva.manage showmigrations
docker compose --profile tools run --rm cli
```

Expected: long-running services become healthy, migrations show `[X]`, and the CLI returns
JSON with `"status": "ready"`.

For browser access, restart with `docker compose -f compose.yaml -f compose.expose.yaml up
--build -d`.

## Dependency failure behavior

- API and MCP liveness continue to report the process as alive.
- API, MCP, and CLI readiness report `not_ready` and return a failing status.
- The worker fails closed during startup and never creates its readiness marker.
- Responses expose dependency names and error classes at most; credentials and endpoints
  are not returned.

Inspect:

```bash
docker compose ps
docker compose logs api worker mcp migrate postgres minio minio-init
```

## Test isolation

`make check` creates separate `test-postgres` and `test-minio` services without persistent
volumes. Tests never connect to development service names.

## Reset

Confirm local data can be discarded, then run:

```bash
docker compose down --volumes --remove-orphans
docker compose up --build -d
```

This permanently deletes only Compose-managed local Anva database and object data.

## Evidence and escalation

Preserve `docker compose ps`, the relevant service logs, exact image versions, and the
failing command. Never paste `.env` or database URLs into an issue.
