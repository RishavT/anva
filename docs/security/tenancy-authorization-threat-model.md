# Threat model: Tenancy, authorization, and repository credentials

## Scope and assets

This model covers organization identity, memberships and roles, service identities, repositories,
access grants and scopes, source connections and access snapshots, permission-filtered retrieval,
repository bearer tokens, local bootstrap, and authorization audit events.

Protected assets include source-derived knowledge, titles and identifiers, Canvas topology,
search rank and result counts, MCP context, immutable artifacts, assurance state, policy and
finding decisions, membership data, credential material, and authorization history.

## Actors and trust boundaries

- A human or coding agent crosses the HTTP boundary using a repository token.
- The API resolves the token to one active service identity, organization, repository, issuer,
  audience, and action set. Caller-supplied tenant or role claims are not trusted.
- Internal workers may call low-level state machines; externally initiated assurance and
  knowledge operations must enter through authorization-owning service wrappers.
- Authoritative creation services are trust boundaries. Sync, assurance, assertion, and artifact
  creation resolve central authorization before target lookup, validation, or idempotent return.
  Assertions and artifacts cannot enter these paths without an effective access scope; assertions
  additionally require non-empty provenance.
- PostgreSQL is the final tenant-integrity boundary. Application checks are reinforced with
  composite foreign keys and triggers.
- Source content is untrusted data. It is not credential or authorization metadata.

## Threats and controls

| Threat | Control | Verification |
| --- | --- | --- |
| IDOR or tenant UUID guessing | Tenant-scoped lookups; one constant foreign/missing error | API comparison tests use the same correlation ID and response body |
| Search/ranking disclosure | Scope queryset is filtered before text match or future ranking | A foreign canary query returns an empty result |
| Canvas or graph traversal leak | Start node is permission filtered before serialization or traversal | Foreign and missing Canvas IDs are indistinguishable |
| MCP context exfiltration | MCP context uses the same authorized assertion retrieval | Foreign and missing MCP requests are indistinguishable |
| Artifact or title disclosure | Artifact requires active visible scope; errors omit object metadata | Canary artifact payload never appears in errors |
| Cross-tenant relationship grafting | Deferrable composite foreign keys and a same-tenant derivation trigger | PostgreSQL integration tests force immediate validation |
| Derived data widens access | Every dimension is intersected and materialized; empty is deny; a final seal makes boundary fields, lineage, and through rows database-immutable | Membership/repository intersection plus direct SQL/ORM mutation tests |
| Stale source access after revocation | Source lineage propagates to descendants; scopes and snapshots revoke atomically | Retrieval succeeds before revocation and fails after |
| Role or service claim forgery | Active principal and role are loaded from PostgreSQL | Role/action tests ignore caller authorization-path claims |
| Repository-token replay | Keyed SHA-256 storage, issuer/audience, expiry, repository/action binding | Expired, revoked, malformed, and unknown tokens share one 401 |
| Token theft through database | Only a keyed digest is stored; plaintext is returned once | Persistence and audit tests reject plaintext |
| Rotation race or predecessor reuse | Row lock, one-to-one lineage, immediate predecessor revocation | Old token fails immediately; replacement succeeds |
| Authorization bypass via idempotency | Creation, revocation, and assurance services authorize before an existing/no-op return | Existing-record viewer tests and terminal artifact canaries |
| Unauthorized finding/policy change | Dedicated actions restricted to authorized roles/grants | Viewer credential gets 404 and no state mutation |
| Unauthorized assurance mutation or artifact attachment | Repository mapping plus `assurance.execute`; every supplied or already-attached artifact is re-resolved through caller/repository/source/scope visibility before transition | Viewer denied; same-tenant out-of-scope artifact fails on active and terminal/idempotent paths without side effects |
| Bootstrap takeover | Constant-time secret comparison, PostgreSQL advisory transaction lock, one-time empty-database condition | First request succeeds; second fails without an existence detail |
| Secret leakage in logs/audit/outbox | Recursive allowlisted audit metadata; common key, token, cookie, password, private-key, API-key, and provider-token detection; pre-handler structured redaction that omits exception messages | Nested key/value, `api_key`, `sk_live`, exception, audit, outbox, and logger tests |

## Credential lifecycle

Repository tokens use the opaque `anva_v1.<id>.<secret>` format. The identifier only selects a
candidate row; authentication still uses constant-time digest comparison and validates active
repository/service state, issuer, audience, expiry, and revocation. Tokens have a maximum
90-day lifetime. Rotation creates one replacement and revokes the predecessor in one transaction.
Revocation affects the next authentication attempt; no application token cache exists.

Operational logs may include the token record UUID as an audit correlation identifier. They must
never include the plaintext secret, Authorization header, bootstrap secret, token pepper, source
credentials, or unrestricted source content.

Source ingestion is not yet an exposed boundary in this slice. When introduced, adapters must
classify and redact untrusted source payloads before logging, and may call authoritative
assertion/artifact creation only with the derived effective scope and provenance. Parser or
connector convenience APIs must not bypass those creation services.

## Failure and abuse behavior

Authentication failures return `invalid_credential` with one message. Authorized-principal
failures involving absent, foreign, out-of-repository, out-of-scope, revoked, or disallowed
records return `resource_not_found` with one message. This deliberately sacrifices diagnostic
specificity at the client boundary. Operators correlate the response UUID with secret-safe logs
and tenant audit events.

Source-revocation traversal is limited to 32 levels and 2,000 scopes. The transaction aborts
rather than partially revoking. Operators must investigate lineage cycles or unexpected fanout
before retrying with a reviewed migration or batch procedure.

## Retention, deletion, and incident response

Token rows retain hashed credential identity, rotation lineage, expiry, revocation, and last-use
timestamps for audit. Access snapshots retain permission evidence and a revocation timestamp but
never source credentials. Tenant deletion and production retention schedules remain a later
milestone.

For suspected token exposure: revoke the token, rotate its replacement only from a separately
authenticated administrator, inspect last-use and audit correlation, and rotate
`ANVA_TOKEN_PEPPER` through a planned all-token invalidation if the pepper may be exposed. Never
paste token strings or environment files into tickets.

## Residual risks and follow-up

- Database row-level security is not enabled; service filtering and composite constraints are
  the current defense in depth.
- Human login/federation, team-derived authorization, and delegated administration are not
  exposed through HTTP yet.
- Pre-ingestion payload classification and connector-specific credential scrubbing remain future
  adapter work; the current authoritative persistence and logging boundaries fail closed.
- Finding and policy persistence is not part of this slice; their endpoints enforce the future
  authorization boundary and explicitly return `AUTHORIZED_NOT_IMPLEMENTED` only to allowed
  callers.
- A distributed cache or separate search/ranking service must not be added until invalidation
  and pre-ranking permission propagation have their own design review.
- Rate limiting, production secret management, TLS/HSTS, retention, and organization deletion
  are deployment/domain follow-ups.
