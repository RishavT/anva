# Issue #3 self-review: Tenancy, authorization, and permission propagation

- Date: 2026-07-28
- Reviewer: implementing agent
- Scope: `RishavT/anva#3`
- Result: Accepted

## Acceptance-criteria review

| Requirement | Evidence | Result |
| --- | --- | --- |
| Organizations and active principals | Organization, user, membership, role, team, service identity, and external identity models | Pass |
| Tenant integrity | Explicit organization ownership plus PostgreSQL composite foreign keys and a derived-scope trigger | Pass |
| Role, repository, source, and action authorization | One central decision service; database-resolved roles/grants; parameterized matrix tests | Pass |
| Access scopes and snapshots | Principal/repository/source scopes; content-addressed immutable snapshots | Pass |
| Derived data never widens access | Set intersection with unrestricted and empty dimensions kept distinct; materialized lineage | Pass |
| Cross-tenant non-disclosure | Foreign and missing organization/API/search/Canvas/MCP/artifact cases have identical contracts | Pass |
| Filtering before ranking/traversal | Shared authorized queryset precedes search matching and object serialization | Pass |
| Source revocation propagation | Direct and transitive scopes deactivate and snapshots revoke in one bounded transaction | Pass |
| Repository credential lifecycle | Keyed hash only, one-time plaintext return, expiry, revocation, rotation, last-use, issuer/audience, repository/action binding | Pass |
| Sensitive mutation controls | Knowledge review and assurance transition use authorization-owning domain wrappers; finding/policy boundaries require dedicated actions | Pass |
| Bootstrap and administration | Secret-gated, advisory-lock-protected, empty-database bootstrap creates roles, admin, repository, service identity, grants, scope, and seven-day token | Pass |
| Audit and logging | Audit records resolved actor and decision path; JSON logging redacts credentials before handlers | Pass |
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
historical permission evidence.

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
- Pytest: 96 passed in 4.69 seconds.
- Branch coverage: 88%, above the required 85% gate.
