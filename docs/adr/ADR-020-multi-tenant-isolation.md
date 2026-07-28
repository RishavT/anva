# ADR-020: Multi-tenant isolation

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

Anva stores an organization's strategy, decisions, code relationships, evidence, and audit
history. A cross-organization reference or authorization omission would expose sensitive
context and corrupt the organizational graph.

## Decision

Externally addressable records use opaque UUIDs. Every tenant-owned row carries an explicit
organization foreign key. Mutation services require actor context and reject tenant mismatch.
PostgreSQL composite foreign keys enforce same-organization links for source syncs and
assurance artifacts; tenant-scoped uniqueness protects idempotency and content identity.

## Alternatives considered

Application filters alone were rejected because omitted filters become data leaks. One schema
per tenant was rejected for initial operational complexity. PostgreSQL row-level security is
deferred until connection-pooling session context can be proven safe.

## Consequences

Every query and service boundary must make tenant ownership explicit. New links between
tenant-owned models require a composite foreign key or equivalent database constraint. UUIDs
are identifiers, not authorization.

## Security impact

The design provides defense in depth between authorization services and PostgreSQL. Cross-
tenant failures are integration tested. API contracts require authentication, correlation,
and idempotency.

## Privacy impact

Tenant boundaries are privacy boundaries. Retention, export, and deletion operations must be
organization scoped and separately authorized.

## Operational impact

Constraint violations indicate a security-relevant defect. Migrations preserve composite keys
and Compose checks verify model-state drift.

## Revisit conditions

Revisit before shared analytics, delegated cross-organization access, regional sharding, or
PostgreSQL row-level security.
