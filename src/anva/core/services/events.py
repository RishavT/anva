"""Audit and outbox effects that share the caller's database transaction."""

from __future__ import annotations

import uuid

from anva.core.logging import redact_text
from anva.core.models import AuditEvent, Organization, OutboxEvent
from anva.core.services.context import ActorContext

ALLOWED_AUDIT_METADATA_KEYS = frozenset(
    {
        "allowed_actions",
        "content_hash",
        "error_code",
        "expires_at",
        "failure_code",
        "head_commit",
        "binding_id",
        "canvas_view_id",
        "canvas_view_revision_id",
        "delivery_id",
        "event_type",
        "external_repository_id",
        "installation_id",
        "invalidated_scope_count",
        "kind",
        "layout_version",
        "claimant_label",
        "lease_owner",
        "membership_id",
        "replacement_token_id",
        "repository_id",
        "reviewer_service_identity_id",
        "reviewer_token_id",
        "publication_id",
        "presentation_only",
        "role_code",
        "service_identity_id",
        "source_scope_ids",
        "superseded_by_head_commit",
        "token_id",
        "view_type",
    }
)

SENSITIVE_AUDIT_KEY_PARTS = frozenset(
    {
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "password",
        "passwd",
        "privatekey",
        "pwd",
        "rawsource",
        "refreshtoken",
        "secret",
        "session",
        "token",
    }
)


def _normalized_audit_key(key: object) -> str:
    return "".join(character for character in str(key).lower() if character.isalnum())


def _validate_audit_value(value: object, *, metadata_key: bool = False) -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            normalized_key = _normalized_audit_key(child_key)
            if str(child_key) not in ALLOWED_AUDIT_METADATA_KEYS:
                if any(part in normalized_key for part in SENSITIVE_AUDIT_KEY_PARTS):
                    raise ValueError("Audit metadata contains a forbidden secret field")
                raise ValueError("Audit metadata contains a non-allowlisted field")
            _validate_audit_value(child_value, metadata_key=True)
        return
    if isinstance(value, list | tuple):
        for child_value in value:
            _validate_audit_value(child_value)
        return
    if isinstance(value, str) and redact_text(value) != value:
        raise ValueError("Audit metadata contains credential material")
    if not isinstance(value, str | int | float | bool | None):
        location = "metadata" if metadata_key else "audit"
        raise ValueError(f"{location.title()} value is not JSON-safe")


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
        credential_id=actor.credential_id,
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
