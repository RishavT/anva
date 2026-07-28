# ADR-016: Transactional outbox and PostgreSQL job queue

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

State mutations will eventually publish pull-request reports, notifications, and integration
writes. Those effects must not be lost after a database commit or emitted for a rolled-back
mutation. Initial background work also needs durable leases and retries.

## Decision

State changes write a tenant-scoped, idempotent outbox row in the same PostgreSQL transaction
as domain state and audit history. Jobs are claimed with `SELECT ... FOR UPDATE SKIP LOCKED`,
expiring leases, bounded attempts, retained errors, and tenant-scoped idempotency keys. An
expired final attempt becomes a retained terminal failure.

## Alternatives considered

Publishing directly after commit was rejected because a process crash loses the effect.
Publishing before commit was rejected because rollback creates false external state. Redis
and a workflow engine were rejected until workload evidence justifies their operational scope.

## Consequences

Consumers must publish idempotently and mark outbox rows only after confirmed delivery. Job
handlers must fit lease windows or add renewal in a later slice. Retry history remains
inspectable.

## Security impact

Only trusted service actors may claim jobs or dispatch outbox rows. Payloads must contain
references, not credentials. Audit events record worker identity.

## Privacy impact

Job and outbox payloads are retained application data. Producers must minimize copied customer
content and follow tenant retention controls.

## Operational impact

Operators monitor lease expiry, attempt exhaustion, outbox age, and error codes. PostgreSQL is
the single recovery boundary for domain state and pending effects.

## Revisit conditions

Revisit when measured throughput, scheduling, or long-running orchestration exceeds PostgreSQL
queue limits, or multi-region dispatch requires a dedicated broker.
