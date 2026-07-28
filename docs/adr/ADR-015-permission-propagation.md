# ADR-015: Permission propagation and retrieval filtering

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

Anva combines organization knowledge from sources with different access rules. Search,
Canvas traversal, MCP context, derived assertions, and assurance artifacts can leak information
even when the final object lookup is tenant scoped. Ranking position, graph degree, titles, and
the existence of an identifier are all sensitive.

## Decision

Authorization is a domain operation, not an adapter convention. Every externally initiated
operation resolves an active database principal and evaluates a stable action in the central
authorization service. Authority is the intersection of:

- the actor's organization;
- the active human role or service grant;
- the repository and optional source;
- the bearer credential's repository and allowed actions; and
- the active access scope attached to the knowledge or artifact.

Permission filters are applied to querysets before text matching, ranking, graph traversal, or
serialization. Foreign, out-of-scope, revoked, and missing records use one
`resource_not_found` response.

Access scopes normalize membership, service identity, repository, and contributing-source
boundaries. A derived scope is a materialized intersection of every input scope. `None` means an
unrestricted dimension while an empty set means no access; the derivation algorithm never treats
an empty intersection as unrestricted. Derived scopes retain every contributing source so source
revocation can invalidate direct and transitive descendants.

Source permission boundaries are captured as content-addressed access snapshots. Snapshot
identity is immutable in PostgreSQL; only the first revocation timestamp may be added. Revoking
a source deactivates every dependent scope, revokes its snapshots, and makes future retrieval
fail closed.

## Alternatives considered

- Filtering after retrieval or ranking was rejected because counts, ordering, timing, and titles
  can disclose hidden records.
- Copying source ACLs onto every assertion was rejected because revocation would require
  error-prone bulk rewrites.
- Unioning derived scopes was rejected because combining content could widen access.
- Trusting role or organization claims from request headers was rejected because claims must be
  resolved against active database state.

## Consequences

Every new retrieval surface must begin from a permission-filtered queryset. Every new sensitive
action needs a stable `Action`, role/grant decision, and security-matrix test. Derived data must
carry an access scope and contributing-source lineage. Authorization paths are persisted in audit
events, but raw credentials and source content are prohibited from audit metadata.

## Security and privacy impact

The design fails closed and removes identifier-existence oracles across API, search, Canvas, MCP,
artifact, and assurance boundaries. Composite PostgreSQL foreign keys prevent cross-tenant
relationship grafting even when application validation is bypassed.

## Operational impact

Source revocation is transactionally bounded to 2,000 derived scopes and 32 levels. Hitting a
bound is a security-relevant operational event and requires an explicit reviewed remediation,
not partial invalidation.

## Revisit conditions

Revisit when hierarchical teams, delegated cross-organization collaboration, field-level ACLs,
PostgreSQL row-level security, or a separate ranking service is introduced.
