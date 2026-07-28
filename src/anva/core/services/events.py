"""Audit and outbox effects that share the caller's database transaction."""

from __future__ import annotations

import uuid

from anva.core.logging import redact_text
from anva.core.models import AuditEvent, Organization, OutboxEvent
from anva.core.services.context import ActorContext

FORBIDDEN_AUDIT_KEYS = frozenset(
    {
        "authorization",
        "credential",
        "password",
        "raw_source",
        "raw_source_content",
        "secret",
        "token",
    }
)


def _validate_audit_value(value: object, *, key: str = "") -> None:
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in FORBIDDEN_AUDIT_KEYS or normalized_key.endswith(
        ("_password", "_secret", "_token")
    ):
        raise ValueError("Audit metadata contains a forbidden secret field")
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _validate_audit_value(child_value, key=str(child_key))
        return
    if isinstance(value, list | tuple):
        for child_value in value:
            _validate_audit_value(child_value)
        return
    if isinstance(value, str) and redact_text(value) != value:
        raise ValueError("Audit metadata contains credential material")


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
    safe_metadata = metadata or {}
    _validate_audit_value(safe_metadata)
    _validate_audit_value(actor.actor_id)
    _validate_audit_value(actor.authorization_path)
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
        metadata=safe_metadata,
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
            **safe_metadata,
        },
        idempotency_key=(
            f"transition:{target_type}:{target_id}:{revision}:{from_state}:{to_state}"
        ),
    )
