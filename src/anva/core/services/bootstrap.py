"""One-time local organization bootstrap and initial repository administration."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import F
from django.utils import timezone

from anva.contracts.bootstrap_scope import parse_bootstrap_scope
from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    BootstrapRecovery,
    EvaluatorTask,
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


def _bootstrap_request_sha256(payload: dict[str, object]) -> str:
    rendered = (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode()
    return hashlib.sha256(rendered).hexdigest()


def _rebind_reviewer_tasks_after_recovery(
    *,
    recovery: BootstrapRecovery,
    previous_reviewer_token_id: uuid.UUID | None,
    now: datetime,
) -> None:
    """Move live bound tasks to the replacement token and invalidate old claim material."""
    replacement = recovery.reviewer_issued_token
    reviewer = recovery.reviewer_service_identity
    if previous_reviewer_token_id is None or replacement is None or reviewer is None:
        return
    tasks = EvaluatorTask.objects.filter(
        organization=recovery.organization,
        repository=recovery.repository,
        reviewer_service_identity=reviewer,
        reviewer_token_id=previous_reviewer_token_id,
    )
    tasks.filter(state=EvaluatorTask.State.PENDING).update(
        reviewer_token=replacement,
        revision=F("revision") + 1,
    )
    tasks.filter(state=EvaluatorTask.State.CLAIMED).update(
        reviewer_token=replacement,
        claim_idempotency_sha256="",
        claim_selector_sha256="",
        lease_expires_at=now,
        revision=F("revision") + 1,
    )


def bootstrap_local_organization(
    *,
    supplied_secret: str,
    organization_slug: str,
    organization_name: str,
    admin_email: str | None = None,
    admin_display_name: str | None = None,
    repository_external_id: str | None = None,
    repository_name: str | None = None,
    independent_reviewer_name: str | None = None,
    idempotency_key: str | None = None,
    scope_payload: object | None = None,
) -> BootstrapResult:
    """Create the only initial organization and emit a one-time repository token."""
    if not hmac.compare_digest(supplied_secret, str(settings.BOOTSTRAP_SECRET)):
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
    if not organization_slug.strip() or not organization_name.strip():
        raise ValueError("Every bootstrap field is required")
    legacy_values = (
        admin_email,
        admin_display_name,
        repository_external_id,
        repository_name,
    )
    if scope_payload is None:
        if any(value is None or not value.strip() for value in legacy_values):
            raise ValueError("Every bootstrap field is required")
        scoped = None
    else:
        if (
            any(value is not None for value in legacy_values)
            or independent_reviewer_name is not None
        ):
            raise ValueError("Scoped and legacy bootstrap fields cannot be combined")
        scoped = parse_bootstrap_scope(scope_payload)
    if idempotency_key is not None and SHA256_PATTERN.fullmatch(idempotency_key) is None:
        raise ValueError("Bootstrap idempotency key must be a SHA-256 digest")
    request_payload: dict[str, object] = {
        "organization_slug": organization_slug,
        "organization_name": organization_name,
    }
    if scoped is None:
        request_payload.update(
            {
                "admin_email": admin_email,
                "admin_display_name": admin_display_name,
                "repository_external_id": repository_external_id,
                "repository_name": repository_name,
                "independent_reviewer_name": independent_reviewer_name,
            }
        )
    else:
        request_payload["scope"] = scope_payload
    request_sha256 = _bootstrap_request_sha256(request_payload)

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
            initiator_actions = frozenset(
                Action(value)
                for value in AccessGrant.objects.filter(
                    organization=recovery.organization,
                    service_identity=recovery.service_identity,
                    repository=recovery.repository,
                    revoked_at__isnull=True,
                ).values_list("action", flat=True)
            )
            issued = issue_bootstrap_repository_token(
                organization=recovery.organization,
                repository=recovery.repository,
                service_identity=recovery.service_identity,
                actions=initiator_actions,
                expires_at=now + timedelta(days=7),
            )
            reviewer_issued_token = None
            previous_reviewer_token_id = (
                recovery.reviewer_issued_token_id
                if recovery.reviewer_issued_token is not None
                else None
            )
            if recovery.reviewer_service_identity is not None:
                if (
                    recovery.reviewer_issued_token is not None
                    and recovery.reviewer_issued_token.revoked_at is None
                ):
                    recovery.reviewer_issued_token.revoked_at = now
                    recovery.reviewer_issued_token.save(update_fields=["revoked_at"])
                reviewer_actions = frozenset(
                    Action(value)
                    for value in AccessGrant.objects.filter(
                        organization=recovery.organization,
                        service_identity=recovery.reviewer_service_identity,
                        repository=recovery.repository,
                        revoked_at__isnull=True,
                    ).values_list("action", flat=True)
                )
                reviewer_issued_token = issue_bootstrap_repository_token(
                    organization=recovery.organization,
                    repository=recovery.repository,
                    service_identity=recovery.reviewer_service_identity,
                    actions=reviewer_actions,
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
            _rebind_reviewer_tasks_after_recovery(
                recovery=recovery,
                previous_reviewer_token_id=previous_reviewer_token_id,
                now=now,
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
        if scoped is None:
            assert admin_email is not None
            assert admin_display_name is not None
            assert repository_external_id is not None
            assert repository_name is not None
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
            token_actions = actions
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
        else:
            role_by_key = {
                item.key: Role.objects.create(
                    organization=organization,
                    code=item.code,
                    name=item.name,
                )
                for item in scoped.roles
            }
            membership_by_key: dict[str, Membership] = {}
            user_by_key: dict[str, User] = {}
            for item in scoped.memberships:
                scoped_user = User.objects.create(
                    email=item.email,
                    display_name=item.display_name,
                )
                user_by_key[item.key] = scoped_user
                membership_by_key[item.key] = Membership.objects.create(
                    organization=organization,
                    user=scoped_user,
                    role=role_by_key[item.role_key],
                )
            repository_by_key = {
                item.key: Repository.objects.create(
                    organization=organization,
                    external_id=item.external_id,
                    name=item.name,
                )
                for item in scoped.repositories
            }
            identity_by_key = {
                item.key: ServiceIdentity.objects.create(
                    organization=organization,
                    name=item.name,
                    issuer=settings.TOKEN_ISSUER,
                    audience=settings.TOKEN_AUDIENCE,
                )
                for item in scoped.service_identities
            }
            scope = AccessScope.objects.create(
                organization=organization,
                name=scoped.access_scope.name,
                all_memberships=False,
                all_service_identities=False,
                all_repositories=False,
            )
            AccessScopeMembership.objects.bulk_create(
                [
                    AccessScopeMembership(
                        organization=organization,
                        access_scope=scope,
                        membership=membership_by_key[key],
                    )
                    for key in sorted(scoped.access_scope.membership_keys)
                ]
            )
            AccessScopeRepository.objects.bulk_create(
                [
                    AccessScopeRepository(
                        organization=organization,
                        access_scope=scope,
                        repository=repository_by_key[key],
                    )
                    for key in sorted(scoped.access_scope.repository_keys)
                ]
            )
            AccessScopeServiceIdentity.objects.bulk_create(
                [
                    AccessScopeServiceIdentity(
                        organization=organization,
                        access_scope=scope,
                        service_identity=identity_by_key[key],
                    )
                    for key in sorted(scoped.access_scope.service_identity_keys)
                ]
            )
            AccessGrant.objects.bulk_create(
                [
                    AccessGrant(
                        organization=organization,
                        service_identity=identity_by_key[identity.key],
                        repository=repository_by_key[grant.repository_key],
                        action=action,
                    )
                    for identity in scoped.service_identities
                    for grant in identity.grants
                    for action in sorted(grant.actions)
                ]
            )
            membership = membership_by_key[scoped.primary_membership_key]
            user = user_by_key[scoped.primary_membership_key]
            repository = repository_by_key[scoped.primary_repository_key]
            service_identity = identity_by_key[scoped.initiator_service_identity_key]
            reviewer_service_identity = identity_by_key[scoped.reviewer_service_identity_key]
            scoped_initiator_action_values = next(
                grant.actions
                for identity in scoped.service_identities
                if identity.key == scoped.initiator_service_identity_key
                for grant in identity.grants
                if grant.repository_key == scoped.primary_repository_key
            )
            scoped_reviewer_action_values = next(
                grant.actions
                for identity in scoped.service_identities
                if identity.key == scoped.reviewer_service_identity_key
                for grant in identity.grants
                if grant.repository_key == scoped.primary_repository_key
            )
            reviewer_issued_token = issue_bootstrap_repository_token(
                organization=organization,
                repository=repository,
                service_identity=reviewer_service_identity,
                actions=frozenset(Action(value) for value in scoped_reviewer_action_values),
                expires_at=timezone.now() + timedelta(days=7),
            )
            token_actions = frozenset(Action(value) for value in scoped_initiator_action_values)
        issued = issue_bootstrap_repository_token(
            organization=organization,
            repository=repository,
            service_identity=service_identity,
            actions=token_actions,
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
