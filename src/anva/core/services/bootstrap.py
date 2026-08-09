"""One-time local organization bootstrap and initial repository administration."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeServiceIdentity,
    BootstrapRecovery,
    Membership,
    Organization,
    Repository,
    Role,
    ServiceIdentity,
    User,
)
from anva.core.services.authorization import INVALID_CREDENTIAL_MESSAGE, Action
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.tokens import (
    IssuedRepositoryToken,
    issue_bootstrap_repository_token,
)


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    organization: Organization
    user: User
    membership: Membership
    repository: Repository
    service_identity: ServiceIdentity
    issued_token: IssuedRepositoryToken
    access_scope: AccessScope
    reviewer_service_identity: ServiceIdentity | None = None
    reviewer_issued_token: IssuedRepositoryToken | None = None
    request_sha256: str | None = None
    recovered: bool = False


SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def _bootstrap_request_sha256(payload: dict[str, str | None]) -> str:
    rendered = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode()
    return hashlib.sha256(rendered).hexdigest()


def bootstrap_local_organization(
    *,
    supplied_secret: str,
    organization_slug: str,
    organization_name: str,
    admin_email: str,
    admin_display_name: str,
    repository_external_id: str,
    repository_name: str,
    independent_reviewer_name: str | None = None,
    idempotency_key: str | None = None,
) -> BootstrapResult:
    """Create the only initial organization and emit a one-time repository token."""
    if not hmac.compare_digest(supplied_secret, str(settings.BOOTSTRAP_SECRET)):
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    required = {
        organization_slug,
        organization_name,
        admin_email,
        admin_display_name,
        repository_external_id,
        repository_name,
    }
    if any(not value.strip() for value in required):
        raise ValueError("Every bootstrap field is required")
    if idempotency_key is not None and SHA256_PATTERN.fullmatch(idempotency_key) is None:
        raise ValueError("Bootstrap idempotency key must be a SHA-256 digest")
    request_sha256 = _bootstrap_request_sha256(
        {
            "organization_slug": organization_slug,
            "organization_name": organization_name,
            "admin_email": admin_email,
            "admin_display_name": admin_display_name,
            "repository_external_id": repository_external_id,
            "repository_name": repository_name,
            "independent_reviewer_name": independent_reviewer_name,
        }
    )

    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [0x414E5641])
        if Organization.objects.exists():
            recovery = None
            if idempotency_key is not None:
                recovery = (
                    BootstrapRecovery.objects.select_for_update(of=("self",))
                    .select_related(
                        "organization",
                        "user",
                        "membership",
                        "repository",
                        "service_identity",
                        "access_scope",
                        "reviewer_service_identity",
                        "issued_token",
                        "reviewer_issued_token",
                    )
                    .filter(idempotency_sha256=idempotency_key)
                    .first()
                )
            if recovery is None or not hmac.compare_digest(recovery.request_sha256, request_sha256):
                raise ResourceNotFoundError("Governed record was not found")
            now = timezone.now()
            if recovery.issued_token.revoked_at is None:
                recovery.issued_token.revoked_at = now
                recovery.issued_token.save(update_fields=["revoked_at"])
            issued = issue_bootstrap_repository_token(
                organization=recovery.organization,
                repository=recovery.repository,
                service_identity=recovery.service_identity,
                actions=frozenset(Action),
                expires_at=now + timedelta(days=7),
            )
            reviewer_issued_token = None
            if recovery.reviewer_service_identity is not None:
                if (
                    recovery.reviewer_issued_token is not None
                    and recovery.reviewer_issued_token.revoked_at is None
                ):
                    recovery.reviewer_issued_token.revoked_at = now
                    recovery.reviewer_issued_token.save(update_fields=["revoked_at"])
                reviewer_issued_token = issue_bootstrap_repository_token(
                    organization=recovery.organization,
                    repository=recovery.repository,
                    service_identity=recovery.reviewer_service_identity,
                    actions=frozenset({Action.ASSURANCE_REVIEW}),
                    expires_at=now + timedelta(days=7),
                )
            recovery.issued_token = issued.record
            recovery.reviewer_issued_token = (
                reviewer_issued_token.record if reviewer_issued_token is not None else None
            )
            recovery.recovery_count += 1
            recovery.save(
                update_fields=[
                    "issued_token",
                    "reviewer_issued_token",
                    "recovery_count",
                    "updated_at",
                ]
            )
            return BootstrapResult(
                organization=recovery.organization,
                user=recovery.user,
                membership=recovery.membership,
                repository=recovery.repository,
                service_identity=recovery.service_identity,
                issued_token=issued,
                access_scope=recovery.access_scope,
                reviewer_service_identity=recovery.reviewer_service_identity,
                reviewer_issued_token=reviewer_issued_token,
                request_sha256=request_sha256,
                recovered=True,
            )

        organization = Organization.objects.create(
            slug=organization_slug,
            name=organization_name,
        )
        roles = {
            code: Role.objects.create(
                organization=organization,
                code=code,
                name=code.replace("_", " ").title(),
            )
            for code in Role.Code.values
        }
        user = User.objects.create(
            email=admin_email.strip().lower(),
            display_name=admin_display_name,
        )
        membership = Membership.objects.create(
            organization=organization,
            user=user,
            role=roles[Role.Code.ORG_ADMIN],
        )
        repository = Repository.objects.create(
            organization=organization,
            external_id=repository_external_id,
            name=repository_name,
        )
        service_identity = ServiceIdentity.objects.create(
            organization=organization,
            name="local-admin",
            issuer=settings.TOKEN_ISSUER,
            audience=settings.TOKEN_AUDIENCE,
        )
        scope = AccessScope.objects.create(
            organization=organization,
            name="Local organization bootstrap",
            all_memberships=True,
            all_service_identities=True,
            all_repositories=True,
        )
        actions = frozenset(Action)
        AccessGrant.objects.bulk_create(
            [
                AccessGrant(
                    organization=organization,
                    service_identity=service_identity,
                    repository=repository,
                    action=action.value,
                )
                for action in actions
            ]
        )
        issued = issue_bootstrap_repository_token(
            organization=organization,
            repository=repository,
            service_identity=service_identity,
            actions=actions,
            expires_at=timezone.now() + timedelta(days=7),
        )
        reviewer_service_identity = None
        reviewer_issued_token = None
        if independent_reviewer_name is not None:
            normalized_reviewer_name = independent_reviewer_name.strip()
            if not normalized_reviewer_name:
                raise ValueError("Independent reviewer name cannot be blank")
            reviewer_service_identity = ServiceIdentity.objects.create(
                organization=organization,
                name=normalized_reviewer_name,
                issuer=settings.TOKEN_ISSUER,
                audience=settings.TOKEN_AUDIENCE,
            )
            AccessScopeServiceIdentity.objects.create(
                organization=organization,
                access_scope=scope,
                service_identity=reviewer_service_identity,
            )
            AccessGrant.objects.create(
                organization=organization,
                service_identity=reviewer_service_identity,
                repository=repository,
                action=Action.ASSURANCE_REVIEW.value,
            )
            reviewer_issued_token = issue_bootstrap_repository_token(
                organization=organization,
                repository=repository,
                service_identity=reviewer_service_identity,
                actions=frozenset({Action.ASSURANCE_REVIEW}),
                expires_at=timezone.now() + timedelta(days=7),
            )
        actor = ActorContext(
            organization_id=organization.id,
            actor_type="USER",
            actor_id=str(user.id),
            authorization_path="bootstrap:local-secret",
            request_id=uuid.uuid4(),
        )
        record_transition(
            organization=organization,
            actor=actor,
            target_type="organization",
            target_id=organization.id,
            from_state="",
            to_state="BOOTSTRAPPED",
            revision=1,
            metadata={
                "membership_id": str(membership.id),
                "repository_id": str(repository.id),
                "service_identity_id": str(service_identity.id),
                "token_id": str(issued.record.id),
            },
        )
        if idempotency_key is not None:
            BootstrapRecovery.objects.create(
                organization=organization,
                request_sha256=request_sha256,
                idempotency_sha256=idempotency_key,
                user=user,
                membership=membership,
                repository=repository,
                service_identity=service_identity,
                access_scope=scope,
                reviewer_service_identity=reviewer_service_identity,
                issued_token=issued.record,
                reviewer_issued_token=(
                    reviewer_issued_token.record if reviewer_issued_token is not None else None
                ),
            )
        return BootstrapResult(
            organization=organization,
            user=user,
            membership=membership,
            repository=repository,
            service_identity=service_identity,
            issued_token=issued,
            access_scope=scope,
            reviewer_service_identity=reviewer_service_identity,
            reviewer_issued_token=reviewer_issued_token,
            request_sha256=request_sha256,
        )
