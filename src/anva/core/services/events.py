"""Audit and outbox effects that share the caller's database transaction."""

from __future__ import annotations

import uuid

from anva.core.models import AuditEvent, Organization, OutboxEvent
from anva.core.services.context import ActorContext


def record_transition(
    *,
    organization: Organization,
    actor: ActorContext,
    target_type: str,
    target_id: uuid.UUID,
    from_state: str,
    to_state: str,
    revision: int,
    metadata: dict[str, object] | None = None,
) -> None:
    """Persist audit truth and an idempotent external effect together."""
    event_type = f"{target_type}.transitioned"
    AuditEvent.objects.create(
        organization=organization,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        action=event_type,
        target_type=target_type,
        target_id=target_id,
        from_state=from_state,
        to_state=to_state,
        authorization_path=actor.authorization_path,
        request_id=actor.request_id,
        source_ip_hash=actor.source_ip_hash,
        metadata=metadata or {},
    )
    OutboxEvent.objects.create(
        organization=organization,
        aggregate_type=target_type,
        aggregate_id=target_id,
        event_type=event_type,
        payload={
            "from_state": from_state,
            "to_state": to_state,
            "revision": revision,
            **(metadata or {}),
        },
        idempotency_key=(
            f"transition:{target_type}:{target_id}:{revision}:{from_state}:{to_state}"
        ),
    )
