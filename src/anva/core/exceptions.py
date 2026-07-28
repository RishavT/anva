"""Structured domain failures for authoritative operations."""

from __future__ import annotations


class DomainOperationError(ValueError):
    """Base error with a stable machine-readable code."""

    code = "domain_operation_error"


class TenantBoundaryError(DomainOperationError):
    """An actor or related row belongs to another organization."""

    code = "tenant_boundary_violation"


class InvalidStateTransitionError(DomainOperationError):
    """A requested state edge is not part of the authoritative graph."""

    code = "invalid_state_transition"

    def __init__(self, current: str, requested: str, allowed: frozenset[str]) -> None:
        self.current = current
        self.requested = requested
        self.allowed = allowed
        formatted = ", ".join(sorted(allowed)) or "<none>"
        super().__init__(
            f"Cannot transition from {current} to {requested}; allowed transitions: {formatted}"
        )


class OptimisticConcurrencyError(DomainOperationError):
    """A governed record changed after a caller read it."""

    code = "revision_conflict"


class LeaseConflictError(DomainOperationError):
    """A worker attempted to mutate a job without its current lease."""

    code = "job_lease_conflict"


class IdempotencyConflictError(DomainOperationError):
    """An idempotency key was reused for different content."""

    code = "idempotency_conflict"
