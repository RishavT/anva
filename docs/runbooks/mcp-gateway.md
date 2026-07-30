# MCP gateway runbook

## Start locally

```sh
docker compose up --build -d postgres minio minio-init migrate api mcp
docker compose run --rm cli mcp diagnose --mcp-url http://mcp:8001
```

Streamable HTTP is at `/mcp`. Health and non-secret diagnostics are at
`/health/live`, `/health/ready`, and `/diagnostics`.

Bootstrap or issue a repository token through the existing administration API.
Configure the MCP client URL and `Authorization: Bearer <token>`. Never write the
token to a repository, generated MCP file, log, or command history. Rotate via
`POST /api/v1/tokens/{id}/rotate`; revoke via `DELETE /api/v1/tokens/{id}`.

## Read-only deployment

Set `ANVA_MCP_READ_ONLY=true`. Proposal tools disappear from discovery. Direct
proposal calls return `read_only_mode`. Reads/resources keep normal auth.

## Compatibility

Every tool argument sends `contract_version: "1"`. Supported protocol revisions
are `2024-11-05`, `2025-03-26`, `2025-06-18`, and `2025-11-25`.

`unsupported_contract_version` means client/server Anva contracts differ.
Refresh discovery/install a compatible package. An HTTP 400 for unsupported MCP
version means the host must negotiate a revision from `/diagnostics`.

## Diagnostics

```sh
docker compose ps
docker compose logs --no-log-prefix mcp migrate postgres
docker compose run --rm cli mcp diagnose --mcp-url http://mcp:8001
```

- `401`: missing, malformed, expired, rotated, revoked, wrong-audience, or
  inactive-principal/repository token.
- `resource_not_found`: target missing or outside tenant/repo/action/scope.
- `read_only_mode`: proposal calls disabled.
- `invalid_cursor`: altered or replayed with another identity/tool/query.
- `input_limit_exceeded`: narrow a structured proposal or other tool input.
- `output_limit_exceeded`: narrow request or reduce page.
- connection failure: verify health, URL, ingress/TLS, and DNS.

Do not enable debug responses to distinguish hidden foreign targets.

## Acceptance test and cleanup

```sh
docker compose --profile mcp-test run --rm mcp-client-test
docker compose --profile mcp-test down -v --remove-orphans
```

Use a fresh project database because bootstrap is intentionally one-time.

## Incident response

1. Revoke the token and confirm new MCP initialization returns 401.
2. Inspect `MCPToolInvocation` by org/repo/request/time; it has no arguments.
3. Inspect unexpected `PROPOSED` records; do not accept them.
4. Rotate credentials and review action grants.
5. For suspected tenant leakage, disable MCP, preserve evidence, and escalate.
