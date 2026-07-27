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

## Consequences

- Refactoring and transactions remain straightforward during product discovery.
- Compose gives local and CI environments the same topology.
- Process boundaries can be extracted later only with measured scaling or ownership needs.
- Developers must preserve module boundaries inside the monolith.

## Alternatives considered

- Initial microservices: rejected due to operational cost and premature distributed
  transactions.
- Graph database: rejected because the planned MVP requires relational truth plus bounded
  relationship traversal, not a second authoritative store.

## Security and privacy

One deployable package does not imply one authorization boundary. Tenant identity and
authorization must remain explicit inside later service-layer operations.
