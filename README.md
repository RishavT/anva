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

The repository also packages host-neutral `anva-prepare`, `anva-build`,
`anva-preflight`, explicit-only `anva-learn`, and operator-triggered
`anva-assurance-review` workflows for Codex and Claude Code. Generated
repository skills and installable plugins use the existing
authenticated MCP facade for developer workflows and the protected file
handoff for assurance review; packages contain no customer knowledge,
endpoint, or credential.

The browser product is a server-rendered, JavaScript-optional operating surface
for onboarding, attention triage, permission-aware knowledge exploration,
source health, human review, repository profiles, work and policy inspection,
pull-request assurance, developer-skill diagnostics, and privileged audit.
Human sessions resolve active membership and role state on every request and
never reuse repository service tokens.

## Prerequisites

- Docker Engine 24+ with the Docker Compose v2 plugin
- Make (optional; every target prints the underlying Compose command)
- 4 GB of free memory

No host Python, Node.js, npm, or Go installation is used.

## Install and run

From a fresh clone, the shortest local demo path is:

```bash
cp .env.example .env
make install-demo
```

Without Make, run:

```bash
docker compose up --build --wait
docker compose --profile demo run --rm --no-deps demo
```

The checked-in Compose defaults also allow `docker compose up --build -d` without an `.env`
file. Copying `.env.example` makes local configuration explicit and gives you one place to
change credentials. `make install-demo` builds the wheel-installed runtime, waits for the
dependencies and migrations, and idempotently creates synthetic demo data. The demo repository
JSON response includes `repository_id` and its usable `access_scope_id`; use those values with
the documented [`anva source connect`](docs/runbooks/source-ingestion.md) command. The repository
token is printed only to the attached terminal: the one-shot container uses no Docker logging
driver and is removed after the command. Do not redirect or retain that output. Use `make up` when
demo data is not wanted. The base stack publishes no host ports, which makes these commands safe
on shared development and CI machines.

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
make skills-check
make unit
make integration
make contract
make smoke
make browser
make coverage
make check
```

`make check` is the same entrypoint used by GitHub Actions. External acceptance uses a separately
exported public bundle, never a sibling repository checkout. Pin its manifest, copy its allowlisted
regular files through the network-disabled adapter, and verify the canonical volume:

```bash
export ANVA_ACCEPTANCE_INPUT_DIR=/absolute/path/to/public-input
export ANVA_ACCEPTANCE_MANIFEST_SHA256=<64-lowercase-hex>
make acceptance-canonicalize
make acceptance-verify
export ANVA_ACCEPTANCE_STATE_DIR=/private/path/state
export ANVA_ACCEPTANCE_CREDENTIAL_DIR=/private/path/credentials
make acceptance-start
# Supply the reviewer-only token and handoff directory.
make acceptance-review-request
# An independent evaluator writes the public result; submit it with reviewer auth.
make acceptance-review-submit
# Supply the initiator-only token and results directory.
make acceptance-finalize
make acceptance-down
```

Only `acceptance-adapter` receives the raw bind mount. Product and runner services receive the
ephemeral canonical volume read-only. Product execution pauses for an independently authenticated
evaluator and seals deterministic public results only after exact-head completion. See the
[acceptance corpus runbook](docs/runbooks/acceptance-corpus.md). The integration suite uses a
separate `anva-tests` Compose project with non-persistent `test-postgres` and `test-minio`
services, never the development containers or data volumes. Remove that project after a local
test session with `make test-down`.

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

Build the local candidate wheel/skill archives, image SBOMs, scan reports, final
manifest, and `SHA256SUMS` with `make release-artifacts`. The final manifest
refuses tracked or untracked worktree changes and verifies that the image's OCI
revision is the exact source commit. Skill archives are rebuilt and verified in
the release builder. The source gate excludes operator-owned secrets, backups,
release outputs, `.git`, and local tool caches from the distributable scan, then
gates vulnerability, secret, and misconfiguration findings. The image gate uses
the exact approved 13-CVE/16-package-tuple no-fix set through 2026-09-25, as
recorded in
[`vulnerability-exceptions.json`](docs/security/vulnerability-exceptions.json);
it does not claim that the image has no high/critical findings. On Linux, set
`ANVA_DOCKER_GID` to the group ID of `/var/run/docker.sock` so the non-root
scanner can inspect the local image. This creates local, ignored artifacts; it
does not publish, sign, or tag them.

Render, package, and exact-check the Codex/Claude distributions with
`make skills-render`, `make skills-package`, and `make skills-check`. Fresh
installation, environment-only MCP handoff, checksums, diagnostics, read-only
behavior, and provider limitations are documented in
[the developer skills runbook](docs/runbooks/developer-skills.md).

## CLI and common operations

```bash
make cli
make logs
make migrate
make shell
make down
```

Release lifecycle operations are also Compose-owned:

```bash
make backup
make backup-verify
make migration-rehearsal
make uninstall       # preserve named data volumes
make uninstall-clean # destructive: remove this Compose project's named volumes
```

Read the [operator guide](docs/guides/operator.md), [user
guide](docs/guides/user.md), and [developer guide](docs/guides/developer.md),
plus the [install/upgrade/uninstall](docs/runbooks/install-upgrade-uninstall.md)
and [backup/restore](docs/runbooks/backup-and-restore.md) runbooks before using
these beyond local evaluation. Use the GitHub-native release assets and
digest-addressed GHCR image only after completing the verification steps in the
install runbook; source-checkout installation remains available as a fallback.
See the [MVP-013 release notes](docs/releases/mvp-013.md), [compatibility
matrix](docs/releases/compatibility.md), and [current readiness
audit](docs/releases/current-release-readiness.md) for the public `v0.1.0`
identity and its still-open human gates.

After a test or drill, remove only the named task project with `make test-down`
or `COMPOSE_PROJECT=<exact-project> make uninstall-clean`; inspect the resolved
project before deletion. Remove only explicitly identified Anva images and the
task-owned `release/.trivy-cache` when they are no longer needed. The exact
MVP-013 candidate exercise kept its task-owned Docker footprint below 5 GB
through this scoped cleanup, but Anva does not configure or enforce an
engine-wide 5 GB cap, and these commands must not prune unrelated Docker
resources.

The worker claims PostgreSQL-leased allowlisted jobs and revalidates source/snapshot access before
and during ingestion. The dedicated MCP process exposes authenticated, stateless, versioned
Streamable HTTP at `/mcp`. Its tools call the same bounded domain facade as
`POST /api/v1/mcp/tools/{tool_name}`; source text is untrusted inert data and proposal tools create
review-only `PROPOSED` records.

Bootstrap and repository-token operations are documented in
[the credential runbook](docs/runbooks/bootstrap-and-repository-tokens.md). A repository token
is opaque, repository/action scoped, stored only as a keyed digest, and returned in plaintext
only when issued or rotated.

Start and diagnose MCP, or run the real official-Python-client Compose acceptance:

```bash
docker compose up --build -d postgres minio minio-init migrate api mcp
docker compose run --rm cli mcp diagnose --mcp-url http://mcp:8001
docker compose --profile mcp-test run --rm mcp-client-test
```

See [the MCP runbook](docs/runbooks/mcp-gateway.md), [architecture
decision](docs/adr/ADR-025-versioned-authenticated-mcp-gateway.md), and [threat
model](docs/security/mcp-gateway-threat-model.md).

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

Manual diff ingestion, exact assurance starts, independent `assurance.review` actor/credential
claim/submit, reports, staleness, and post-merge proposal safety are documented in
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
contracts/             Standalone OpenAPI, MCP, JSON Schema, examples, and acceptance protocol
packages/anva-skills/  Portable workflow source and generated host distributions
docs/product/          Canonical product requirements
docs/adr/              Architecture decisions
docs/runbooks/         Operational procedures
docs/security/         Threat models
```

## Product source of truth

The canonical v3 product requirements and implementation plan is checked in at
`docs/product/anva-product-requirements-and-implementation-plan-v3.md`. Issue scope and
acceptance criteria remain the authority for incremental delivery.

## License, support, and contributions

Anva is source-available proprietary software, not open-source software. See [LICENSE](LICENSE)
and [NOTICE](NOTICE) before using or distributing it. Product support is described in
[SUPPORT.md](SUPPORT.md), security reports must follow [SECURITY.md](SECURITY.md), and proposed
changes must follow [CONTRIBUTING.md](CONTRIBUTING.md).
