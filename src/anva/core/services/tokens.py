"""One-time repository token issuance, authentication, rotation, and revocation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    Organization,
    Repository,
    RepositoryAccessToken,
    ServiceIdentity,
)
from anva.core.services.authorization import (
    INVALID_CREDENTIAL_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition

TOKEN_PREFIX = "anva_v1"  # noqa: S105
MAX_TOKEN_TTL = timedelta(days=90)


@dataclass(frozen=True, slots=True)
class IssuedRepositoryToken:
    """The only return value that contains a newly issued plaintext token."""

    record: RepositoryAccessToken
    plaintext: str = field(repr=False)


def _hash_token(plaintext: str) -> str:
    return hmac.new(
        str(settings.TOKEN_PEPPER).encode(),
        plaintext.encode(),
        hashlib.sha256,
    ).hexdigest()


def _build_plaintext(token_id: uuid.UUID) -> str:
    return f"{TOKEN_PREFIX}.{token_id}.{secrets.token_urlsafe(32)}"


def _validated_actions(actions: frozenset[Action]) -> list[str]:
    if not actions:
        raise ValueError("At least one token action is required")
    return sorted(action.value for action in actions)


def _create_token(
    *,
    organization: Organization,
    repository: Repository,
    service_identity: ServiceIdentity,
    actions: frozenset[Action],
    expires_at: datetime,
    rotated_from: RepositoryAccessToken | None = None,
) -> IssuedRepositoryToken:
    now = timezone.now()
    if expires_at <= now:
        raise ValueError("Token expiry must be in the future")
    if expires_at - now > MAX_TOKEN_TTL:
        raise ValueError("Token lifetime cannot exceed 90 days")
    token_id = uuid.uuid4()
    plaintext = _build_plaintext(token_id)
    record = RepositoryAccessToken.objects.create(
        id=token_id,
        organization=organization,
        repository=repository,
        service_identity=service_identity,
        token_hash=_hash_token(plaintext),
        allowed_actions=_validated_actions(actions),
        issuer=settings.TOKEN_ISSUER,
        audience=settings.TOKEN_AUDIENCE,
        issued_at=now,
        expires_at=expires_at,
        rotated_from=rotated_from,
    )
    return IssuedRepositoryToken(record=record, plaintext=plaintext)


def issue_bootstrap_repository_token(
    *,
    organization: Organization,
    repository: Repository,
    service_identity: ServiceIdentity,
    actions: frozenset[Action],
    expires_at: datetime,
) -> IssuedRepositoryToken:
    """Issue the first local token; callers must enforce one-time bootstrap."""
    return _create_token(
        organization=organization,
        repository=repository,
        service_identity=service_identity,
        actions=actions,
        expires_at=expires_at,
    )


def issue_repository_token(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    service_identity_id: uuid.UUID,
    actions: frozenset[Action],
    expires_at: datetime,
) -> IssuedRepositoryToken:
    """Issue one token without allowing a credential to mint broader authority."""
    with transaction.atomic():
        repository = get_tenant_record_for_update(
            queryset=Repository.objects.select_related("organization").filter(is_active=True),
            record_id=repository_id,
            organization_id=actor.organization_id,
        )
        service_identity = get_tenant_record_for_update(
            queryset=ServiceIdentity.objects.filter(is_active=True),
            record_id=service_identity_id,
            organization_id=actor.organization_id,
        )
        decision = authorize_action(
            actor=actor,
            action=Action.TOKEN_MANAGE,
            repository_id=repository.id,
        )
        for requested_action in actions:
            authorize_action(
                actor=actor,
                action=requested_action,
                repository_id=repository.id,
            )
        issued = _create_token(
            organization=repository.organization,
            repository=repository,
            service_identity=service_identity,
            actions=actions,
            expires_at=expires_at,
        )
        audit_actor = replace(actor, authorization_path=decision.authorization_path)
        record_transition(
            organization=repository.organization,
            actor=audit_actor,
            target_type="repositoryaccesstoken",
            target_id=issued.record.id,
            from_state="",
            to_state="ISSUED",
            revision=1,
            metadata={
                "repository_id": str(repository.id),
                "service_identity_id": str(service_identity.id),
                "allowed_actions": issued.record.allowed_actions,
                "expires_at": issued.record.expires_at.isoformat(),
            },
        )
        return issued


def authenticate_bearer(authorization_header: str) -> ActorContext:
    """Authenticate a bearer token with one non-oracular failure contract."""
    scheme, separator, plaintext = authorization_header.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not plaintext:
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    parts = plaintext.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    try:
        token_id = uuid.UUID(parts[1])
    except ValueError:
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE) from None

    token = (
        RepositoryAccessToken.objects.select_related(
            "organization",
            "repository",
            "service_identity",
        )
        .filter(id=token_id)
        .first()
    )
    now = timezone.now()
    presented_hash = _hash_token(plaintext)
    stored_hash = token.token_hash if token is not None else "0" * 64
    digest_matches = hmac.compare_digest(stored_hash, presented_hash)
    if (
        token is None
        or not digest_matches
        or token.revoked_at is not None
        or token.expires_at <= now
        or token.issuer != settings.TOKEN_ISSUER
        or token.audience != settings.TOKEN_AUDIENCE
        or token.organization.lifecycle_state != Organization.LifecycleState.ACTIVE
        or not token.repository.is_active
        or not token.service_identity.is_active
    ):
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    try:
        actions = frozenset(Action(value) for value in token.allowed_actions)
    except (TypeError, ValueError):
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE) from None
    RepositoryAccessToken.objects.filter(id=token.id).update(last_used_at=now)
    return ActorContext(
        organization_id=token.organization_id,
        actor_type="SERVICE",
        actor_id=str(token.service_identity_id),
        authorization_path=f"token:{token.id}",
        request_id=uuid.uuid4(),
        repository_id=token.repository_id,
        credential_id=token.id,
        credential_actions=frozenset(action.value for action in actions),
    )


def revoke_repository_token(
    *,
    actor: ActorContext,
    token_id: uuid.UUID,
) -> RepositoryAccessToken:
    """Revoke a token after authorization, including before an idempotent return."""
    with transaction.atomic():
        token = get_tenant_record_for_update(
            queryset=RepositoryAccessToken.objects.select_related(
                "organization",
                "repository",
            ),
            record_id=token_id,
            organization_id=actor.organization_id,
        )
        decision = authorize_action(
            actor=actor,
            action=Action.TOKEN_MANAGE,
            repository_id=token.repository_id,
        )
        if token.revoked_at is not None:
            return token
        token.revoked_at = timezone.now()
        token.save(update_fields=["revoked_at"])
        audit_actor = replace(actor, authorization_path=decision.authorization_path)
        record_transition(
            organization=token.organization,
            actor=audit_actor,
            target_type="repositoryaccesstoken",
            target_id=token.id,
            from_state="ACTIVE",
            to_state="REVOKED",
            revision=1,
        )
        return token


def rotate_repository_token(
    *,
    actor: ActorContext,
    token_id: uuid.UUID,
    expires_at: datetime,
) -> IssuedRepositoryToken:
    """Replace a token once and invalidate its predecessor immediately."""
    with transaction.atomic():
        old_token = get_tenant_record_for_update(
            queryset=RepositoryAccessToken.objects.select_related(
                "organization",
                "repository",
                "service_identity",
            ),
            record_id=token_id,
            organization_id=actor.organization_id,
        )
        if not old_token.repository.is_active or not old_token.service_identity.is_active:
            raise ResourceNotFoundError("Governed record was not found")
        decision = authorize_action(
            actor=actor,
            action=Action.TOKEN_MANAGE,
            repository_id=old_token.repository_id,
        )
        if old_token.revoked_at is not None:
            raise ResourceNotFoundError("Governed record was not found")
        actions = frozenset(Action(value) for value in old_token.allowed_actions)
        issued = _create_token(
            organization=old_token.organization,
            repository=old_token.repository,
            service_identity=old_token.service_identity,
            actions=actions,
            expires_at=expires_at,
            rotated_from=old_token,
        )
        old_token.revoked_at = timezone.now()
        old_token.save(update_fields=["revoked_at"])
        audit_actor = replace(actor, authorization_path=decision.authorization_path)
        record_transition(
            organization=old_token.organization,
            actor=audit_actor,
            target_type="repositoryaccesstoken",
            target_id=old_token.id,
            from_state="ACTIVE",
            to_state="ROTATED",
            revision=1,
            metadata={"replacement_token_id": str(issued.record.id)},
        )
        return issued
