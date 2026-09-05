# Compatibility matrix

Status: published `v0.1.6` compatibility declarations. Technical publication,
post-publication lifecycle verification, and the separate operator drill passed.

The public product binds to tag `v0.1.6`, source
`e89b06aed8207cc32eee0eeebde4a2731f0c0203`, and immutable image
`ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`;
release run `33781714974` verified its download and install lifecycle, and
operator-signoff run `33910747236` completed the separate human gate.

| Component | Candidate boundary | Evidence status |
| --- | --- | --- |
| Docker Engine | 24 or newer, as declared by the project README | Exact candidate runner used Docker client/server `29.6.2` |
| Docker Compose | v2 plugin; Compose is the only supported application and operational interface | Exact candidate runner used Docker Compose `5.3.1` |
| Host operating system | A Docker-supported Linux host is the primary boundary | Exact lanes passed on Linux; macOS/Windows host behavior unverified |
| Python | `>=3.12,<3.13`; runtime image uses Python 3.12 | Public wheel and digest-addressed runtime image were built and lifecycle-verified |
| Django | Locked by `uv.lock`/`pyproject.toml` | Exact source scan has zero high/critical findings and records three MEDIUM and eight LOW Django vulnerability findings |
| PostgreSQL | PostgreSQL 16 with pgvector | Exact-image atomic-generation backup, failed/successful restore handling, and disposable `0019`→head reversal/forward rehearsal passed |
| Object storage | Application runtime accepts a configured S3-compatible bucket; operational backup drill uses Compose-managed MinIO | Authenticated bucket readiness and current paired MinIO backup/restore passed locally; external object-store backup is unsupported and unverified |
| MCP | Contract version `1`; Streamable HTTP through the official Python SDK | Two exact-candidate official-client tests passed against write-capable and actual read-only services |
| Context packet | Schema version `1` | 24 generated contracts verified at the exact source candidate |
| Skills | Portable skill version `1.0.0` | Public Codex/Claude archives are checksummed, attested, and covered by the completed aggregate product gate |
| Codex | Historically tested with Codex CLI `0.145.0` | Historical host evidence; the portable archive is published |
| Claude Code | Historically tested with Claude Code `2.1.220` | Historical host evidence; the portable archive is published |
| Browser | Headless Chromium/ChromeDriver `151.0.7922.71` in the project browser-test image | Two exact-source browser journeys passed; decommission requires a setup-authenticated session no older than 15 minutes and has no post-setup reauthentication flow |
| Other browsers | No support claim | Deferred |

The immutable source-security asset also records three MEDIUM and eight LOW
Django vulnerability findings. They are lower-severity compatibility evidence,
not part of the separately approved 14-unique-CVE/18-high-or-critical-tuple
image-risk decision.

## Version compatibility rules

- Server, wheel, image, skill and release-manifest versions must be recorded
  together. A package version does not imply compatibility with an arbitrary
  server.
- Clients send MCP `contract_version: "1"`. Unsupported versions fail closed;
  they are not silently translated.
- An exact tested host version is evidence, not a minimum or maximum support
  promise.
- The verified v0.1.5 digest is the rollback predecessor only when its declared
  schema boundary is compatible. Migration `core.0019` remains the internal
  pre-MVP-013 rehearsal source.
- `v0.1.7` is the next fix-forward patch. It has no compatibility claim until a
  separately reviewed candidate tests the current server against the v0.1.6
  skill/package boundary and documents any intentional incompatibility.

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
