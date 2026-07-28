# Issue #3 self-review: Tenancy, authorization, and permission propagation

- Date: 2026-07-28
- Reviewer: implementing agent
- Scope: `RishavT/anva#3`
- Result: Accepted after independent-review remediation

## Acceptance-criteria review

| Requirement | Evidence | Result |
| --- | --- | --- |
| Organizations and active principals | Organization, user, membership, role, team, service identity, and external identity models | Pass |
| Tenant integrity | Explicit organization ownership plus PostgreSQL composite foreign keys and a derived-scope trigger | Pass |
| Role, repository, source, and action authorization | One central decision service; database-resolved roles/grants; parameterized matrix tests | Pass |
| Access scopes and snapshots | Principal/repository/source scopes; content-addressed immutable snapshots | Pass |
| Derived data never widens access | Set intersection with unrestricted and empty dimensions kept distinct; sealed materialized boundary and lineage protected by PostgreSQL triggers | Pass |
| Cross-tenant non-disclosure | Foreign and missing organization/API/search/Canvas/MCP/artifact cases have identical contracts | Pass |
| Filtering before ranking/traversal | Shared authorized queryset precedes search matching and object serialization | Pass |
| Source revocation propagation | Direct and transitive scopes deactivate and snapshots revoke in one bounded transaction | Pass |
| Repository credential lifecycle | Keyed hash only, one-time plaintext return, expiry, revocation, rotation, last-use, issuer/audience, repository/action binding | Pass |
| Sensitive creation and mutation controls | Sync, assurance, assertion, and artifact creation authorize before lookup/no-op; assurance reauthorizes every artifact; finding/policy boundaries require dedicated actions | Pass |
| Bootstrap and administration | Secret-gated, advisory-lock-protected, empty-database bootstrap creates roles, admin, repository, service identity, grants, scope, and seven-day token | Pass |
| Audit and logging | Audit records resolved actor and decision path; recursively allowlisted metadata and JSON logging reject/redact common credentials before audit, outbox, or handlers | Pass |
| Versioned REST contract | `/api/v1` routes and generated OpenAPI include tenancy, token, retrieval, assurance, and revocation boundaries | Pass |

## Security review

Authorization never trusts the caller's `authorization_path` or a role header. Human roles and
service identities are resolved from active database state. An opaque repository credential can
only reduce service-grant authority: its repository must match and its action set must contain the
requested action.

Tenant and scope filters are constructed before content text matching. Foreign, missing,
out-of-repository, out-of-scope, disabled, and revoked records converge on the same not-found
contract. Authentication failures likewise converge on one invalid-credential contract. Tests use
foreign canary titles and payloads to detect accidental serialization.

Database constraints cover new same-tenant relationships even for direct ORM writes. The
access-scope self-relation uses a trigger because Django's implicit many-to-many table has no
organization column. Access snapshots use a database trigger so bulk updates cannot rewrite
historical permission evidence. Derived scopes have an explicit final seal. PostgreSQL prevents
boundary-flag widening, reactivation, unsealing, deletion, and mutation of membership,
service-identity, repository, source, or derivation-lineage rows after that seal. Source
revocation remains a permitted one-way deactivation, and non-derived administrative scope
lifecycle remains available.

## Findings fixed during self-review

1. Access snapshot creation initially emitted a second audit event for a content-identical
   snapshot. It now audits only the first creation.
2. Repository grants initially risked matching another repository when no repository was supplied.
   Grant filtering now treats omitted repository/source dimensions as global-only.
3. Source revocation initially risked returning an idempotent response before authorization. It
   authorizes the source first and only then permits the no-op.
4. The OpenAPI bearer scheme initially inherited a JWT label even though tokens are opaque. It now
   declares `AnvaRepositoryToken`.
5. Low-level assurance transitions had tenant safety but no external role/repository decision.
   The versioned API now enters through `execute_assurance_transition`, which resolves the
   repository and `assurance.execute` permission before state mutation.
6. Application validation alone would not protect newly introduced relationships. Composite
   foreign keys now cover roles, memberships, teams, scopes, snapshots, grants, repositories,
   services, tokens, rotation lineage, knowledge, and artifacts.
7. Creation services could previously return an existing sync/assurance record or create
   assertions/artifacts before central authorization. They now authorize concrete IDs before
   lookup, validation, or idempotency; assertions and artifacts require and persist an effective
   scope.
8. Assurance execution authorized the run but trusted tenant-only artifact lookup. It now
   permission-resolves every supplied and already-attached artifact before mutation, including
   terminal/idempotent transitions.
9. A derived scope could be widened through direct ORM/SQL boundary or through-table mutation.
   Derivation now seals its fully materialized boundary, and PostgreSQL rejects subsequent
   boundary/lineage mutation while preserving one-way revocation.
10. Audit/log filtering missed `api_key`, `sk_live`, nested secret fields, and exception messages.
    Audit metadata is recursively allowlisted and secret-bearing values fail before both audit and
    outbox persistence; structured logs redact common secret formats and emit only exception type.

## Known limitations

- Human federation/login and service-identity, role, team, and repository administration
  endpoints are later slices. This issue supplies the authoritative models, membership endpoint,
  local bootstrap, and repository-token administration.
- Team membership is modeled and tenant constrained; team-derived scope/grant evaluation is
  deferred until hierarchical team semantics are specified.
- Finding and policy persistence is not yet present. The versioned placeholder endpoints enforce
  their dedicated authorization actions and never claim a mutation occurred.
- Search currently performs a bounded PostgreSQL text match. A later vector/ranking service must
  preserve pre-ranking permission filtering and revocation invalidation.
- No distributed credential cache exists. Any future cache must prove immediate revocation or use
  a reviewed bounded-staleness policy.
- Source-ingestion adapters are not present yet. They must classify/redact untrusted source data
  and propagate effective scope and provenance into these authoritative creation paths rather
  than adding a bypass.
- PostgreSQL row-level security, rate limiting, production identity federation, tenant deletion,
  and retention automation remain follow-ups.

## Verification evidence

- `docker compose config --quiet`: pass.
- `make check`: pass using the Compose-owned test environment.
- Format check: 61 files already formatted.
- Ruff: pass.
- Strict mypy: 56 source files, no issues.
- Migration drift: `No changes detected`.
- Generated contracts: 16 artifacts verified.
- Pytest: 106 passed in 6.83 seconds.
- Branch coverage: 88%, above the required 85% gate.
