"""Central tenant-safe authorization decisions and governed-record lookups."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Model, Q, QuerySet
from django.utils import timezone

from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    Membership,
    Repository,
    RepositoryAccessToken,
    Role,
    ServiceIdentity,
    SourceConnection,
)
from anva.core.services.context import ActorContext

NOT_FOUND_MESSAGE = "Governed record was not found"
INVALID_CREDENTIAL_MESSAGE = "Credential is invalid or expired"


class Action(StrEnum):
    """Stable actions evaluated by the central authorization service."""

    ORG_VIEW = "organization.view"
    MEMBERSHIP_MANAGE = "membership.manage"
    REPOSITORY_VIEW = "repository.view"
    TOKEN_MANAGE = "token.manage"  # noqa: S105
    SOURCE_VIEW = "source.view"
    SOURCE_SYNC = "source.sync"
    SOURCE_REVOKE = "source.revoke"
    KNOWLEDGE_VIEW = "knowledge.view"
    KNOWLEDGE_PROPOSE = "knowledge.propose"
    KNOWLEDGE_REVIEW = "knowledge.review"
    ASSURANCE_EXECUTE = "assurance.execute"
    FINDING_DISMISS = "finding.dismiss"
    POLICY_OVERRIDE = "policy.override"
    WORK_VIEW = "work.view"
    WORK_MANAGE = "work.manage"
    WORK_APPROVE = "work.approve"
    POLICY_VIEW = "policy.view"
    POLICY_MANAGE = "policy.manage"
    EVIDENCE_VIEW = "evidence.view"
    EVIDENCE_SUBMIT = "evidence.submit"
    SEARCH = "search.query"
    CANVAS_VIEW = "canvas.view"
    MCP_CONTEXT = "mcp.context"
    ARTIFACT_VIEW = "artifact.view"
    ARTIFACT_CREATE = "artifact.create"
    SCOPE_MANAGE = "scope.manage"
    GITHUB_MANAGE = "github.manage"


VIEW_ACTIONS = frozenset(
    {
        Action.ORG_VIEW,
        Action.REPOSITORY_VIEW,
        Action.SOURCE_VIEW,
        Action.KNOWLEDGE_VIEW,
        Action.SEARCH,
        Action.CANVAS_VIEW,
        Action.MCP_CONTEXT,
        Action.ARTIFACT_VIEW,
        Action.WORK_VIEW,
        Action.POLICY_VIEW,
        Action.EVIDENCE_VIEW,
    }
)
ROLE_ACTIONS: dict[str, frozenset[Action]] = {
    Role.Code.ORG_ADMIN: frozenset(Action),
    Role.Code.KNOWLEDGE_ADMIN: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.KNOWLEDGE_REVIEW,
            Action.ARTIFACT_CREATE,
            Action.SCOPE_MANAGE,
            Action.WORK_MANAGE,
            Action.POLICY_MANAGE,
        }
    ),
    Role.Code.TECHNICAL_OWNER: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.KNOWLEDGE_REVIEW,
            Action.SOURCE_SYNC,
            Action.ASSURANCE_EXECUTE,
            Action.ARTIFACT_CREATE,
            Action.WORK_MANAGE,
            Action.POLICY_MANAGE,
            Action.EVIDENCE_SUBMIT,
        }
    ),
    Role.Code.PRODUCT_OWNER: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.KNOWLEDGE_REVIEW,
            Action.WORK_MANAGE,
            Action.WORK_APPROVE,
        }
    ),
    Role.Code.DEVELOPER: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.ASSURANCE_EXECUTE,
            Action.ARTIFACT_CREATE,
            Action.EVIDENCE_SUBMIT,
        }
    ),
    Role.Code.REVIEWER: VIEW_ACTIONS
    | frozenset({Action.KNOWLEDGE_PROPOSE, Action.KNOWLEDGE_REVIEW, Action.WORK_APPROVE}),
    Role.Code.SECURITY_REVIEWER: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.FINDING_DISMISS,
            Action.POLICY_OVERRIDE,
            Action.WORK_APPROVE,
            Action.EVIDENCE_SUBMIT,
        }
    ),
    Role.Code.VIEWER: VIEW_ACTIONS,
}


@dataclass(frozen=True, slots=True)
class Principal:
    """Resolved active principal used for one decision."""

    actor_type: str
    principal_id: uuid.UUID
    membership: Membership | None = None
    service_identity: ServiceIdentity | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """An allowed decision and its audit-safe explanation path."""

    action: Action
    authorization_path: str


def get_tenant_record[GovernedModel: Model](
    *,
    queryset: QuerySet[GovernedModel],
    record_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> GovernedModel:
    """Return a tenant-owned record without distinguishing foreign from absent IDs."""
    try:
        return queryset.get(id=record_id, organization_id=organization_id)
    except ObjectDoesNotExist:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE) from None


def get_tenant_record_for_update[GovernedModel: Model](
    *,
    queryset: QuerySet[GovernedModel],
    record_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> GovernedModel:
    """Lock and return a tenant-owned record without an existence oracle."""
    return get_tenant_record(
        queryset=queryset.select_for_update(),
        record_id=record_id,
        organization_id=organization_id,
    )


def resolve_principal(actor: ActorContext) -> Principal:
    """Resolve an active principal without accepting caller-asserted roles."""
    try:
        principal_id = uuid.UUID(actor.actor_id)
    except ValueError:
        raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE) from None

    if actor.actor_type == "USER":
        membership = (
            Membership.objects.select_related("role", "user")
            .filter(
                organization_id=actor.organization_id,
                user_id=principal_id,
                user__is_active=True,
                is_active=True,
            )
            .first()
        )
        if membership is None:
            raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
        return Principal("USER", principal_id, membership=membership)

    if actor.actor_type == "SERVICE":
        service_identity = ServiceIdentity.objects.filter(
            id=principal_id,
            organization_id=actor.organization_id,
            is_active=True,
        ).first()
        if service_identity is None:
            raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
        return Principal("SERVICE", principal_id, service_identity=service_identity)

    raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)


def _active_grants(principal: Principal, action: Action) -> QuerySet[AccessGrant]:
    now = timezone.now()
    grants = AccessGrant.objects.filter(
        action=action,
        revoked_at__isnull=True,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
    if principal.membership is not None:
        return grants.filter(membership=principal.membership)
    return grants.filter(service_identity=principal.service_identity)


def _scope_allows(
    *,
    principal: Principal,
    access_scope: AccessScope,
    repository_id: uuid.UUID | None,
) -> bool:
    if not access_scope.is_active:
        return False
    if AccessScopeSource.objects.filter(
        access_scope=access_scope,
        source_connection__state=SourceConnection.State.REVOKED,
    ).exists():
        return False
    if not access_scope.all_repositories:
        if (
            repository_id is None
            or not AccessScopeRepository.objects.filter(
                access_scope=access_scope,
                repository_id=repository_id,
            ).exists()
        ):
            return False
    if principal.membership is not None:
        return (
            access_scope.all_memberships
            or AccessScopeMembership.objects.filter(
                access_scope=access_scope,
                membership=principal.membership,
            ).exists()
        )
    return (
        access_scope.all_service_identities
        or AccessScopeServiceIdentity.objects.filter(
            access_scope=access_scope,
            service_identity=principal.service_identity,
        ).exists()
    )


def authorize_action(
    *,
    actor: ActorContext,
    action: Action,
    repository_id: uuid.UUID | None = None,
    source_connection_id: uuid.UUID | None = None,
    access_scope_id: uuid.UUID | None = None,
    allow_revoked_source: bool = False,
) -> AuthorizationDecision:
    """Authorize one action without exposing foreign targets or credential capabilities."""
    principal = resolve_principal(actor)
    if actor.repository_id is not None and repository_id != actor.repository_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if actor.credential_id is not None:
        if actor.repository_id is None:
            raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
        current_actions = (
            RepositoryAccessToken.objects.filter(
                id=actor.credential_id,
                organization_id=actor.organization_id,
                repository_id=actor.repository_id,
                service_identity_id=principal.principal_id,
                revoked_at__isnull=True,
                expires_at__gt=timezone.now(),
                issuer=settings.TOKEN_ISSUER,
                audience=settings.TOKEN_AUDIENCE,
                repository__is_active=True,
                service_identity__is_active=True,
            )
            .values_list("allowed_actions", flat=True)
            .first()
        )
        if not isinstance(current_actions, list) or not all(
            isinstance(value, str) for value in current_actions
        ):
            raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
        if action.value not in current_actions:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if actor.credential_actions and action not in actor.credential_actions:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

    allowed = False
    path_parts: list[str] = []
    if actor.credential_id is not None:
        path_parts.append(f"credential:{actor.credential_id}")
    if principal.membership is not None:
        role_actions = ROLE_ACTIONS.get(principal.membership.role.code, frozenset())
        allowed = action in role_actions
        if allowed:
            path_parts.append(f"role:{principal.membership.role.code}")

    grants = _active_grants(principal, action)
    if repository_id is not None:
        grants = grants.filter(Q(repository__isnull=True) | Q(repository_id=repository_id))
    else:
        grants = grants.filter(repository__isnull=True)
    if source_connection_id is not None:
        grants = grants.filter(
            Q(source_connection__isnull=True) | Q(source_connection_id=source_connection_id)
        )
    else:
        grants = grants.filter(source_connection__isnull=True)
    if grants.exists():
        allowed = True
        path_parts.append("grant:active")

    if (
        repository_id is not None
        and not Repository.objects.filter(
            id=repository_id,
            organization_id=actor.organization_id,
            is_active=True,
        ).exists()
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

    if source_connection_id is not None:
        source = SourceConnection.objects.filter(
            id=source_connection_id,
            organization_id=actor.organization_id,
        ).first()
        unavailable_states = (
            set()
            if allow_revoked_source
            else {
                SourceConnection.State.DISABLED,
                SourceConnection.State.REVOKED,
            }
        )
        if source is None or source.state in unavailable_states:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

    if access_scope_id is not None:
        access_scope = AccessScope.objects.filter(
            id=access_scope_id,
            organization_id=actor.organization_id,
        ).first()
        if access_scope is None or not _scope_allows(
            principal=principal,
            access_scope=access_scope,
            repository_id=repository_id,
        ):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        path_parts.append(f"scope:{access_scope.id}")

    if not allowed:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if repository_id is not None:
        path_parts.append(f"repository:{repository_id}")
    if source_connection_id is not None:
        path_parts.append(f"source:{source_connection_id}")
    return AuthorizationDecision(action, ">".join(path_parts))
