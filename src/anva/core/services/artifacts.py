"""Content-addressed immutable artifact operations."""

from __future__ import annotations

import uuid

from django.db import transaction

from anva.contracts.validation import validate_payload
from anva.core.exceptions import TenantBoundaryError
from anva.core.models import ImmutableArtifact, Organization, content_hash
from anva.core.services.authorization import get_tenant_record
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition


def create_artifact(
    *,
    actor: ActorContext,
    kind: str,
    schema_name: str,
    schema_version: str,
    payload: dict[str, object],
    revision: int = 1,
) -> tuple[ImmutableArtifact, bool]:
    """Validate and idempotently store one tenant-owned immutable artifact."""
    validate_payload(schema_name, payload)
    if payload.get("schema_version") != schema_version:
        raise ValueError("Artifact schema_version metadata must match payload schema_version")
    digest = content_hash(payload)
    with transaction.atomic():
        organization = Organization.objects.select_for_update().get(id=actor.organization_id)
        artifact = ImmutableArtifact.objects.filter(
            organization=organization,
            kind=kind,
            content_hash=digest,
        ).first()
        if artifact is not None:
            if (
                artifact.schema_name != schema_name
                or artifact.schema_version != schema_version
                or artifact.revision != revision
            ):
                raise TenantBoundaryError(
                    "Artifact content identity cannot be reused with different metadata"
                )
            return artifact, False

        artifact = ImmutableArtifact.objects.create(
            organization=organization,
            kind=kind,
            schema_name=schema_name,
            schema_version=schema_version,
            revision=revision,
            payload=payload,
            content_hash=digest,
        )
        record_transition(
            organization=organization,
            actor=actor,
            target_type="immutable_artifact",
            target_id=artifact.id,
            from_state="",
            to_state="CREATED",
            revision=artifact.revision,
            metadata={"kind": kind, "content_hash": digest},
        )
        return artifact, True


def require_artifact_organization(
    artifact_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> ImmutableArtifact:
    """Load a tenant artifact without distinguishing foreign from absent IDs."""
    return get_tenant_record(
        queryset=ImmutableArtifact.objects.all(),
        record_id=artifact_id,
        organization_id=organization_id,
    )
