# Compatibility matrix

Status: candidate declarations with worktree verification; exact-commit release
and publication verification remain pending.

| Component | Candidate boundary | Evidence status |
| --- | --- | --- |
| Docker Engine | 24 or newer, as declared by the project README | Not rerun for MVP-013 |
| Docker Compose | v2 plugin; Compose is the only supported application and operational interface | Exact version not yet recorded |
| Host operating system | A Docker-supported Linux host is the primary boundary | macOS/Windows host behavior unverified |
| Python | `>=3.12,<3.13`; runtime image uses Python 3.12 | Local wheel and wheel-installed runtime image built; not published |
| Django | Locked by `uv.lock`/`pyproject.toml` | Source scan reported zero high/critical findings; exact-commit result pending |
| PostgreSQL | PostgreSQL 16 with pgvector | Current worktree atomic-generation backup, failed/successful restore handling, and disposable `0019`→`0020` reversal/forward rehearsal passed; exact-commit rerun pending |
| Object storage | Application runtime accepts a configured S3-compatible bucket; operational backup drill uses Compose-managed MinIO | Authenticated bucket readiness and current paired MinIO backup/restore passed locally; external object-store backup is unsupported and unverified |
| MCP | Contract version `1`; Streamable HTTP through the official Python SDK | Fresh Compose official-client acceptance passed two tests; exact-commit rerun pending |
| Context packet | Schema version `1` | Generated-contract verification passed in the worktree |
| Skills | Portable skill version `1.0.0` | Release build now rebuilds and verifies Codex/Claude archives; final exact-commit manifest/checksums and fresh-agent runs pending |
| Codex | Historically tested with Codex CLI `0.145.0` | Historical evidence only; release rerun required |
| Claude Code | Historically tested with Claude Code `2.1.220` | Historical evidence only; release rerun required |
| Browser | Headless Chromium 151 in the project browser-test image | Two MVP-013 worktree browser journeys passed; decommission requires a setup-authenticated session no older than 15 minutes and has no post-setup reauthentication flow; exact-commit evidence pending |
| Other browsers | No support claim | Deferred |

## Version compatibility rules

- Server, wheel, image, skill and release-manifest versions must be recorded
  together. A package version does not imply compatibility with an arbitrary
  server.
- Clients send MCP `contract_version: "1"`. Unsupported versions fail closed;
  they are not silently translated.
- An exact tested host version is evidence, not a minimum or maximum support
  promise.
- This is the first proposed public MVP release. There is no previous public
  Anva release for an N-1 compatibility claim. Migration `core.0019` is the
  internal pre-MVP-013 schema rehearsal source.
- Beginning with the release after MVP-013, the project should test the current
  server against the immediately previous stable skill version and document
  any intentional incompatibility.

## Deployment compatibility

The Compose topology is the supported installation unit. Running the wheel
directly on a host, substituting SQLite, omitting pgvector, or using an
unreviewed object-storage API is unsupported. Reverse proxies and TLS
termination are deployment responsibilities; production settings assume a
correct trusted proxy boundary and HTTPS. Only exact IPs configured in
`ANVA_TRUSTED_PROXY_IPS` may supply forwarded client/protocol headers. Declared
read-only/capability/no-new-privileges hardening applies to Anva application
containers; it is not a universal assurance for every third-party dependency
container.
