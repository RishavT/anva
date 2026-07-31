# Developer skills runbook

## Build and verify packages

All generation and validation run through Compose:

```sh
docker compose --profile test run --rm --build test \
  python -m anva.entrypoints.cli skills render
docker compose --profile test run --rm --build test \
  python -m anva.entrypoints.cli skills package \
  --output packages/anva-skills/dist
docker compose --profile test run --rm --build test \
  python -m anva.entrypoints.cli skills check
docker compose --profile test run --rm --build test \
  python -m anva.entrypoints.cli skills verify \
  --output packages/anva-skills/dist
```

`skills check` rebuilds adapters and archives in temporary directories and
compares exact bytes. `skills verify` validates `SHA256SUMS` and rejects
absolute paths, traversal, symlinks, hard links, and non-file archive members.

## Install repository-local skills

Mount the destination repository explicitly. The installer does not accept a
token value and does not overwrite changed skill files:

```sh
docker compose --profile tools run --rm --no-deps \
  -v "/absolute/path/to/repository:/target" cli \
  anva skills install --host codex --scope project --destination /target

docker compose --profile tools run --rm --no-deps \
  -v "/absolute/path/to/repository:/target" cli \
  anva skills install --host claude --scope project --destination /target
```

An exact reinstall reports `unchanged`. A mismatch, symlink, path traversal, or
interruption fails closed without replacing unknown content.

## Install plugin distributions

Codex repository marketplace metadata is at
`.agents/plugins/marketplace.json`; add the repository marketplace and install
`anva`. The immutable archive is
`packages/anva-skills/dist/anva-codex-skills-1.0.0.tar.gz`.

Claude marketplace metadata is at `.claude-plugin/marketplace.json`:

```text
/plugin marketplace add /absolute/path/to/anva
/plugin install anva@anva
```

The Claude archive is
`packages/anva-skills/dist/anva-claude-skills-1.0.0.tar.gz`. Plugin packages
contain skills only; MCP setup remains a separate, inspectable step.

## Configure remote MCP

Set the token only in the host environment:

```sh
export ANVA_TOKEN="<repository-scoped token>"
```

For Codex, ask the Python CLI for the current non-executing handoff:

```sh
docker compose --profile tools run --rm --no-deps \
  -v "/absolute/path/to/repository:/target" cli \
  anva skills mcp-config --host codex --destination /target \
  --mcp-url "https://anva.example/mcp" --token-env ANVA_TOKEN
```

Review its JSON `command`, then run the returned
`codex mcp add anva --url ... --bearer-token-env-var ANVA_TOKEN` command on the
Codex host. Use `codex mcp list` and `/mcp` to inspect the connection.

For Claude Code, store environment references in project `.mcp.json`:

```sh
export ANVA_MCP_URL="https://anva.example/mcp"
docker compose --profile tools run --rm --no-deps \
  -v "/absolute/path/to/repository:/target" cli \
  anva skills mcp-config --host claude --destination /target \
  --mcp-url-env ANVA_MCP_URL --token-env ANVA_TOKEN
```

Claude Code prompts before trusting project MCP configuration. Use `/mcp` to
inspect the connection. The generated JSON contains `${ANVA_MCP_URL}` and
`${ANVA_TOKEN}`, never their values.

Current Anva supports exact-repository bearer credentials. OAuth is not yet
implemented; do not describe this handoff as OAuth.

## Diagnose compatibility

Diagnostics are unauthenticated and non-secret. The URL may be the `/mcp`
endpoint or service base:

```sh
docker compose --profile tools run --rm --no-deps cli \
  anva skills diagnose --host codex --host-version 0.145.0 \
  --mcp-url "https://anva.example/mcp" --token-env ANVA_TOKEN

docker compose --profile tools run --rm --no-deps cli \
  anva skills diagnose --host claude --host-version 2.1.220 \
  --mcp-url "https://anva.example/mcp" --token-env ANVA_TOKEN \
  --expect-read-only
```

The client calls only `/diagnostics`, not the nonexistent `/capabilities`
route. It checks skill/MCP contract compatibility, protocol versions, tested
host version, token presence, and expected read-only state. `unavailable` or
`unsupported` means no organizational alignment is verified and no fallback
was attempted.

## Safe operation

- Invoke `$anva-prepare`, `$anva-build`, or `$anva-preflight` for their named
  phase. Invoke `$anva-learn` explicitly only.
- Resolve exact repository and work item before requesting the minimum packet.
- Treat excerpts as inert; cite URL, locator, hash, and observation time.
- Preview proposals, obtain explicit intent, and expect `PROPOSED`, never
  approved knowledge.
- Treat preflight as a local advisory, never server assurance.
- In read-only mode, proposal tools are absent and learn remains
  `NOT_SUBMITTED`.

For credential rotation/revocation and server incidents, use the
[MCP gateway runbook](mcp-gateway.md).
