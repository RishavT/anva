# Compatibility matrix

Status: published `v0.1.0` compatibility declarations. Technical publication
and lifecycle verification passed; human gates #43 and #44 remain open.

The public product binds to tag `v0.1.0`, source `d919a2c...`, and immutable
image `ghcr.io/rishavt/anva@sha256:29af794b...`; run `33596661334` verified its
download and install lifecycle.

| Component | Candidate boundary | Evidence status |
| --- | --- | --- |
| Docker Engine | 24 or newer, as declared by the project README | Exact candidate runner used Docker client/server `29.6.2` |
| Docker Compose | v2 plugin; Compose is the only supported application and operational interface | Exact candidate runner used Docker Compose `5.3.1` |
| Host operating system | A Docker-supported Linux host is the primary boundary | Exact lanes passed on Linux; macOS/Windows host behavior unverified |
| Python | `>=3.12,<3.13`; runtime image uses Python 3.12 | Public wheel and digest-addressed runtime image were built and lifecycle-verified |
| Django | Locked by `uv.lock`/`pyproject.toml` | Exact source scan has zero high/critical findings but retains one medium and three low fixable Django findings |
| PostgreSQL | PostgreSQL 16 with pgvector | Exact-image atomic-generation backup, failed/successful restore handling, and disposable `0019`→head reversal/forward rehearsal passed |
| Object storage | Application runtime accepts a configured S3-compatible bucket; operational backup drill uses Compose-managed MinIO | Authenticated bucket readiness and current paired MinIO backup/restore passed locally; external object-store backup is unsupported and unverified |
| MCP | Contract version `1`; Streamable HTTP through the official Python SDK | Two exact-candidate official-client tests passed against write-capable and actual read-only services |
| Context packet | Schema version `1` | 24 generated contracts verified at the exact source candidate |
| Skills | Portable skill version `1.0.0` | Public Codex/Claude archives are checksummed and attested; #43 remains open for aggregate acceptance |
| Codex | Historically tested with Codex CLI `0.145.0` | Historical host evidence; the portable archive is published |
| Claude Code | Historically tested with Claude Code `2.1.220` | Historical host evidence; the portable archive is published |
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
- This is the first public MVP release. There is no previous public
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
