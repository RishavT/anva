# Threat model: Engineering foundation

## Assets

- PostgreSQL data and future tenant-scoped knowledge assertions.
- MinIO objects and future source artifacts.
- Service credentials and Django signing key.
- Build integrity and migration history.
- Readiness evidence used by operators and orchestrators.

## Actors and trust boundaries

The browser crosses the HTTP boundary into the API. API, worker, MCP, and CLI processes
cross network boundaries into PostgreSQL and MinIO. Container images cross the registry
boundary during build and install. Local `.env` values cross from the operator into
containers.

No customer repository is cloned or executed. No external model receives content. No
knowledge ingestion exists in this slice.

## Threats and mitigations

| Threat | Current mitigation | Residual risk / follow-up |
| --- | --- | --- |
| Default credentials used outside local development | Examples label them local-only; production rejects the default Django key | Deployment secret management is a later issue |
| Secrets leaked through health output | Readiness returns dependency names and sanitized details only | Structured logging policy must be extended with request context |
| Unauthorized data access | Central tenant/repository/action authorization and pre-retrieval access scopes | See the tenancy and authorization threat model; database RLS is deferred |
| Supply-chain drift | Python dependencies and core runtime/MinIO tags are version-pinned; CI builds the lock | Pin all image and CI-action digests, including the pgvector major tag, before production |
| Clickjacking or content sniffing | Django security headers deny framing and MIME sniffing | Add production TLS/HSTS and CSP after deployment topology is selected |
| Prompt injection | No model call, ingestion, or prompt exists | Treat retrieved content as untrusted when model features are introduced |
| Destructive reset | Reset is explicit and scoped to Compose volumes | Production procedures must never reuse the local reset command |
| Customer-code compromise | Customer code is neither cloned nor executed | Preserve this boundary unless a separately reviewed sandbox design is approved |

## Retention and deletion

The foundation stores tenant identity, authorization, knowledge-state foundations, audit, jobs,
and operator-created MinIO objects. `make reset` deletes local database and object volumes.
Production tenant retention and deletion workflows remain out of scope.

## Verification

- Unit tests cover invalid configuration, dependency failure, and health redaction.
- Contract tests ensure the unimplemented MCP surface does not overclaim readiness.
- Integration tests prove PostgreSQL, pgvector, and MinIO availability.
- Compose health checks prove process-level readiness.
- CI invokes the exact Compose-owned local checks.
