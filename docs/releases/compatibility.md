# Compatibility matrix

Status: candidate declarations with exact local verification at source commit
`94231d7e57767b18a4cd9546ad5bf33afc13a735`; publication verification remains
pending.

Every exact result below binds to source tree
`43395db015a2205c739647c1b6dfb9b02626abd2`, local runtime image
`anva-mvp13:0.1.0` ID
`sha256:c6ae3a8abfd4c54d91df94be0dfe7f1bc1c52e73da58a4617b2bc30a3b1f6f2c`,
and the [immutable local evidence archive](../evidence/issue-013/README.md).

| Component | Candidate boundary | Evidence status |
| --- | --- | --- |
| Docker Engine | 24 or newer, as declared by the project README | Exact candidate runner used Docker client/server `29.6.2` |
| Docker Compose | v2 plugin; Compose is the only supported application and operational interface | Exact candidate runner used Docker Compose `5.3.1` |
| Host operating system | A Docker-supported Linux host is the primary boundary | Exact lanes passed on Linux; macOS/Windows host behavior unverified |
| Python | `>=3.12,<3.13`; runtime image uses Python 3.12 | Wheel and wheel-installed local runtime image built; browser runner used Python `3.12.13`; not published |
| Django | Locked by `uv.lock`/`pyproject.toml` | Exact source scan has zero high/critical findings but retains one medium and three low fixable Django findings |
| PostgreSQL | PostgreSQL 16 with pgvector | Exact-image atomic-generation backup, failed/successful restore handling, and disposable `0019`→head reversal/forward rehearsal passed |
| Object storage | Application runtime accepts a configured S3-compatible bucket; operational backup drill uses Compose-managed MinIO | Authenticated bucket readiness and current paired MinIO backup/restore passed locally; external object-store backup is unsupported and unverified |
| MCP | Contract version `1`; Streamable HTTP through the official Python SDK | Two exact-candidate official-client tests passed against write-capable and actual read-only services |
| Context packet | Schema version `1` | 24 generated contracts verified at the exact source candidate |
| Skills | Portable skill version `1.0.0` | Codex/Claude archives rebuilt, verified, checksummed, and indexed; fresh-agent runs remain pending |
| Codex | Historically tested with Codex CLI `0.145.0` | Historical evidence only; release rerun required |
| Claude Code | Historically tested with Claude Code `2.1.220` | Historical evidence only; release rerun required |
| Browser | Headless Chromium/ChromeDriver `151.0.7922.71` in the project browser-test image | Two exact-source browser journeys passed; decommission requires a setup-authenticated session no older than 15 minutes and has no post-setup reauthentication flow |
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
