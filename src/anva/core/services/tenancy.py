"""Authorized organization membership administration."""

from __future__ import annotations

import uuid
from dataclasses import replace

from django.db import transaction

from anva.core.exceptions import OptimisticConcurrencyError, ResourceNotFoundError
from anva.core.models import Membership, Organization, Role, User
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition


def _authorize_membership_admin(actor: ActorContext) -> str:
    decision = authorize_action(
        actor=actor,
        action=Action.MEMBERSHIP_MANAGE,
        repository_id=actor.repository_id,
    )
    return decision.authorization_path


def list_memberships(
    *,
    actor: ActorContext,
    organization_id: uuid.UUID,
) -> list[Membership]:
    """List memberships only after proving the requested tenant is the actor's."""
    if organization_id != actor.organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    _authorize_membership_admin(actor)
    return list(
        Membership.objects.select_related("user", "role")
        .filter(organization_id=organization_id)
        .order_by("created_at")[:500]
    )


def add_membership(
    *,
    actor: ActorContext,
    organization_id: uuid.UUID,
    email: str,
    display_name: str,
    role_code: str,
) -> Membership:
    """Add one human membership with a same-tenant role and audited authority."""
    if organization_id != actor.organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if not email.strip() or not display_name.strip():
        raise ValueError("email and display_name are required")
    with transaction.atomic():
        authorization_path = _authorize_membership_admin(actor)
        organization = Organization.objects.select_for_update().get(id=organization_id)
        role = Role.objects.filter(
            organization=organization,
            code=role_code,
        ).first()
        if role is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        user, created = User.objects.get_or_create(
            email=email.strip().lower(),
            defaults={"display_name": display_name},
        )
        if not created and not user.is_active:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        membership, membership_created = Membership.objects.get_or_create(
            organization=organization,
            user=user,
            defaults={"role": role},
        )
        if not membership_created:
            return membership
        audit_actor = replace(actor, authorization_path=authorization_path)
        record_transition(
            organization=organization,
            actor=audit_actor,
            target_type="membership",
            target_id=membership.id,
            from_state="",
            to_state="ACTIVE",
            revision=membership.revision,
            metadata={"role_code": role.code},
        )
        return membership


def update_membership(
    *,
    actor: ActorContext,
    membership_id: uuid.UUID,
    role_code: str,
    expected_revision: int,
) -> Membership:
    """Change a role with authorization before idempotency and revision checks."""
    with transaction.atomic():
        membership = get_tenant_record_for_update(
            queryset=Membership.objects.select_related("organization", "role"),
            record_id=membership_id,
            organization_id=actor.organization_id,
        )
        authorization_path = _authorize_membership_admin(actor)
        role = Role.objects.filter(
            organization_id=actor.organization_id,
            code=role_code,
        ).first()
        if role is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        if membership.role_id == role.id:
            return membership
        if membership.revision != expected_revision:
            raise OptimisticConcurrencyError(
                f"Expected revision {expected_revision}, found {membership.revision}"
            )
        previous_role = membership.role.code
        membership.role = role
        membership.revision += 1
        membership.save(update_fields=["role", "revision", "updated_at"])
        audit_actor = replace(actor, authorization_path=authorization_path)
        record_transition(
            organization=membership.organization,
            actor=audit_actor,
            target_type="membership",
            target_id=membership.id,
            from_state=previous_role,
            to_state=role.code,
            revision=membership.revision,
        )
        return membership


def deactivate_membership(
    *,
    actor: ActorContext,
    membership_id: uuid.UUID,
    expected_revision: int,
) -> Membership:
    """Deactivate a membership and preserve an authorized idempotent response."""
    with transaction.atomic():
        membership = get_tenant_record_for_update(
            queryset=Membership.objects.select_related("organization"),
            record_id=membership_id,
            organization_id=actor.organization_id,
        )
        authorization_path = _authorize_membership_admin(actor)
        if not membership.is_active:
            return membership
        if membership.revision != expected_revision:
            raise OptimisticConcurrencyError(
                f"Expected revision {expected_revision}, found {membership.revision}"
            )
        membership.is_active = False
        membership.revision += 1
        membership.save(update_fields=["is_active", "revision", "updated_at"])
        audit_actor = replace(actor, authorization_path=authorization_path)
        record_transition(
            organization=membership.organization,
            actor=audit_actor,
            target_type="membership",
            target_id=membership.id,
            from_state="ACTIVE",
            to_state="INACTIVE",
            revision=membership.revision,
        )
        return membership
