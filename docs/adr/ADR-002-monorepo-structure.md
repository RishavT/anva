# ADR-002: Python modular monolith in one repository

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

The MVP needs several independently deployable entrypoints but does not yet benefit from
distributed service ownership or separate release trains.

## Decision

Keep application code, server-rendered UI, tests, migrations, and deployment definitions in
one repository and one Python package. Domain logic lives in service modules. HTTP handlers
and integration adapters remain thin. API, worker, MCP, and CLI are separate process
entrypoints built from the same immutable image and locked dependency graph.

PostgreSQL is the authoritative transactional and relational store. pgvector is enabled
through a reviewed migration for later hybrid retrieval. MinIO supplies an S3-compatible
local object-storage boundary.

## Alternatives considered

- Initial microservices: rejected due to operational cost and premature distributed
  transactions.
- Graph database: rejected because the planned MVP requires relational truth plus bounded
  relationship traversal, not a second authoritative store.

## Consequences

- Refactoring and transactions remain straightforward during product discovery.
- Compose gives local and CI environments the same topology.
- Process boundaries can be extracted later only with measured scaling or ownership needs.
- Developers must preserve module boundaries inside the monolith.

## Security impact

One deployable package does not imply one authorization boundary. Tenant identity and
authorization must remain explicit inside later service-layer operations. Extraction into
separate processes must not be used as a substitute for domain authorization.

## Privacy impact

PostgreSQL will be the authoritative store for tenant-scoped records and MinIO for source
artifacts. Later schemas must carry tenant identity explicitly and provide bounded
retention, export, correction, and deletion across both stores.

## Operational impact

One locked image supplies API, worker, MCP, CLI, and migration entrypoints. Database
migrations and object-store initialization complete before long-running processes start.
Operators maintain one release artifact while monitoring and scaling each process
independently.

## Revisit conditions

Revisit when measured scale, failure isolation, compliance boundaries, or independent team
ownership cannot be met by separate processes in the modular monolith. Extraction requires
an explicit data-ownership and migration plan.
