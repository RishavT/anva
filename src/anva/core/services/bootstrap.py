"""One-time local organization bootstrap and initial repository administration."""

from __future__ import annotations

import hmac
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


def bootstrap_local_organization(
    *,
    supplied_secret: str,
    organization_slug: str,
    organization_name: str,
    admin_email: str,
    admin_display_name: str,
    repository_external_id: str,
    repository_name: str,
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

    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [0x414E5641])
        if Organization.objects.exists():
            raise ResourceNotFoundError("Governed record was not found")

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
        del scope
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
        return BootstrapResult(
            organization=organization,
            user=user,
            membership=membership,
            repository=repository,
            service_identity=service_identity,
            issued_token=issued,
        )
