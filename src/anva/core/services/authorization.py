"""Central tenant-safe authorization decisions and governed-record lookups."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Exists, Model, OuterRef, Q, QuerySet
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
    Organization,
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
    ASSURANCE_VIEW = "assurance.view"
    ASSURANCE_EXECUTE = "assurance.execute"
    AUDIT_VIEW = "audit.view"
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
    CANVAS_MANAGE = "canvas.manage"
    MCP_CONTEXT = "mcp.context"
    ARTIFACT_VIEW = "artifact.view"
    ARTIFACT_CREATE = "artifact.create"
    SCOPE_MANAGE = "scope.manage"
    GITHUB_MANAGE = "github.manage"
    RETENTION_MANAGE = "retention.manage"


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
        Action.ASSURANCE_VIEW,
    }
)
ROLE_ACTIONS: dict[str, frozenset[Action]] = {
    Role.Code.ORG_ADMIN: frozenset(Action),
    Role.Code.KNOWLEDGE_ADMIN: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.KNOWLEDGE_REVIEW,
            Action.CANVAS_MANAGE,
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
            Action.CANVAS_MANAGE,
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
            Action.CANVAS_MANAGE,
        }
    ),
    Role.Code.DEVELOPER: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.CANVAS_MANAGE,
            Action.ASSURANCE_EXECUTE,
            Action.ARTIFACT_CREATE,
            Action.EVIDENCE_SUBMIT,
        }
    ),
    Role.Code.REVIEWER: VIEW_ACTIONS
    | frozenset(
        {
            Action.KNOWLEDGE_PROPOSE,
            Action.KNOWLEDGE_REVIEW,
            Action.WORK_APPROVE,
            Action.CANVAS_MANAGE,
        }
    ),
    Role.Code.SECURITY_REVIEWER: VIEW_ACTIONS
    | frozenset(
        {
            Action.AUDIT_VIEW,
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


MAX_BATCH_AUTHORIZATION_REPOSITORIES = 100
MAX_BATCH_AUTHORIZATION_SCOPES = 1_000
MAX_BATCH_AUTHORIZATION_SCOPE_BINDINGS = 100_000
_AUTHORIZED_REPOSITORY_SCOPES_PROOF = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthorizedRepositoryScopes:
    """One bounded, current authorization snapshot shared by batched reads."""

    organization_id: uuid.UUID
    actor_type: str
    principal_id: uuid.UUID
    actor_repository_id: uuid.UUID | None
    credential_id: uuid.UUID | None
    credential_actions: tuple[str, ...]
    repositories: tuple[Repository, ...]
    repository_ids_by_action: tuple[tuple[Action, tuple[uuid.UUID, ...]], ...]
    scope_ids_by_repository: tuple[tuple[uuid.UUID, tuple[uuid.UUID, ...]], ...]
    _proof: object

    def __init__(self) -> None:
        raise TypeError("AuthorizedRepositoryScopes can only be resolved by authorization")

    @classmethod
    def _create(
        cls,
        *,
        actor: ActorContext,
        principal_id: uuid.UUID,
        repositories: tuple[Repository, ...],
        repository_ids_by_action: tuple[tuple[Action, tuple[uuid.UUID, ...]], ...],
        scope_ids_by_repository: tuple[tuple[uuid.UUID, tuple[uuid.UUID, ...]], ...],
    ) -> AuthorizedRepositoryScopes:
        instance = object.__new__(cls)
        object.__setattr__(instance, "organization_id", actor.organization_id)
        object.__setattr__(instance, "actor_type", actor.actor_type)
        object.__setattr__(instance, "principal_id", principal_id)
        object.__setattr__(instance, "actor_repository_id", actor.repository_id)
        object.__setattr__(instance, "credential_id", actor.credential_id)
        object.__setattr__(
            instance,
            "credential_actions",
            tuple(sorted(actor.credential_actions)),
        )
        object.__setattr__(instance, "repositories", repositories)
        object.__setattr__(instance, "repository_ids_by_action", repository_ids_by_action)
        object.__setattr__(instance, "scope_ids_by_repository", scope_ids_by_repository)
        object.__setattr__(instance, "_proof", _AUTHORIZED_REPOSITORY_SCOPES_PROOF)
        return instance

    def is_bound_to(self, actor: ActorContext) -> bool:
        """Reject fabricated, mutated, or replayed boundaries before any governed read."""
        try:
            principal_id = uuid.UUID(actor.actor_id)
            repository_ids = tuple(repository.id for repository in self.repositories)
            action_rows_valid = len(
                {action for action, _ids in self.repository_ids_by_action}
            ) == len(self.repository_ids_by_action) and all(
                ids == tuple(sorted(set(ids), key=str)) and set(ids).issubset(repository_ids)
                for _action, ids in self.repository_ids_by_action
            )
            scope_rows_valid = (
                tuple(repository_id for repository_id, _ids in self.scope_ids_by_repository)
                == repository_ids
                and all(
                    ids == tuple(sorted(set(ids), key=str))
                    and len(ids) <= MAX_BATCH_AUTHORIZATION_SCOPES
                    for _repository_id, ids in self.scope_ids_by_repository
                )
                and sum(len(ids) for _repository_id, ids in self.scope_ids_by_repository)
                <= MAX_BATCH_AUTHORIZATION_SCOPE_BINDINGS
            )
            return (
                self._proof is _AUTHORIZED_REPOSITORY_SCOPES_PROOF
                and self.organization_id == actor.organization_id
                and self.actor_type == actor.actor_type
                and self.principal_id == principal_id
                and self.actor_repository_id == actor.repository_id
                and self.credential_id == actor.credential_id
                and self.credential_actions == tuple(sorted(actor.credential_actions))
                and 0 < len(repository_ids) <= MAX_BATCH_AUTHORIZATION_REPOSITORIES
                and repository_ids == tuple(sorted(set(repository_ids), key=str))
                and action_rows_valid
                and scope_rows_valid
            )
        except (AttributeError, TypeError, ValueError):
            return False

    def repository_ids_for(self, action: Action) -> tuple[uuid.UUID, ...]:
        return next(
            (
                repository_ids
                for candidate_action, repository_ids in self.repository_ids_by_action
                if candidate_action == action
            ),
            (),
        )

    def scope_pairs_for(
        self,
        action: Action,
    ) -> tuple[tuple[uuid.UUID, tuple[uuid.UUID, ...]], ...]:
        scope_map = dict(self.scope_ids_by_repository)
        return tuple(
            (repository_id, scope_map.get(repository_id, ()))
            for repository_id in self.repository_ids_for(action)
        )

    def scope_ids_for(self, action: Action) -> tuple[uuid.UUID, ...]:
        return tuple(
            sorted(
                {
                    scope_id
                    for _repository_id, scope_ids in self.scope_pairs_for(action)
                    for scope_id in scope_ids
                },
                key=str,
            )
        )


def current_authorized_scope_filter(
    *,
    actor: ActorContext,
    authorization: AuthorizedRepositoryScopes,
    action: Action,
    scope_id_path: str,
    repository_id_path: str | None = None,
    repository_relation_path: str | None = None,
) -> Q:
    """Build one in-statement recheck for an exact resolved repository/scope pair."""
    if not authorization.is_bound_to(actor):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if actor.credential_actions and action.value not in actor.credential_actions:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if (repository_id_path is None) != (repository_relation_path is None):
        raise ValueError("repository id and relation paths must be supplied together")
    repository_ids = authorization.repository_ids_for(action)
    scope_ids = authorization.scope_ids_for(action)
    if not repository_ids or not scope_ids:
        return Q(**{f"{scope_id_path}__isnull": True}) & Q(**{f"{scope_id_path}__isnull": False})

    principal_id = authorization.principal_id
    allowed_role_codes = tuple(
        role_code for role_code, actions in ROLE_ACTIONS.items() if action in actions
    )
    active_memberships = Membership.objects.filter(
        organization_id=actor.organization_id,
        organization__lifecycle_state=Organization.LifecycleState.ACTIVE,
        user_id=principal_id,
        user__is_active=True,
        is_active=True,
    )
    active_service_identities = ServiceIdentity.objects.filter(
        organization_id=actor.organization_id,
        organization__lifecycle_state=Organization.LifecycleState.ACTIVE,
        id=principal_id,
        is_active=True,
    )
    grant_queryset = AccessGrant.objects.filter(
        organization_id=actor.organization_id,
        action=action.value,
        source_connection__isnull=True,
        revoked_at__isnull=True,
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
    scope_queryset = (
        AccessScope.objects.filter(
            id=OuterRef(scope_id_path),
            organization_id=actor.organization_id,
            is_active=True,
        )
        .exclude(
            accessscopesource__source_connection__state__in=(
                SourceConnection.State.REVOKED,
                SourceConnection.State.DISABLED,
            )
        )
        .order_by()
    )
    if actor.actor_type == "USER":
        principal_active = Q(Exists(active_memberships))
        principal_scope = Q(all_memberships=True) | Q(
            accessscopemembership__organization_id=actor.organization_id,
            accessscopemembership__membership__organization_id=actor.organization_id,
            accessscopemembership__membership__user_id=principal_id,
            accessscopemembership__membership__user__is_active=True,
            accessscopemembership__membership__is_active=True,
        )
        role_allowed = Q(Exists(active_memberships.filter(role__code__in=allowed_role_codes)))
        grant_queryset = grant_queryset.filter(
            membership__organization_id=actor.organization_id,
            membership__user_id=principal_id,
            membership__user__is_active=True,
            membership__is_active=True,
        )
    elif actor.actor_type == "SERVICE":
        principal_active = Q(Exists(active_service_identities))
        principal_scope = Q(all_service_identities=True) | Q(
            accessscopeserviceidentity__organization_id=actor.organization_id,
            accessscopeserviceidentity__service_identity_id=principal_id,
            accessscopeserviceidentity__service_identity__is_active=True,
        )
        role_allowed = Q(pk__isnull=True) & Q(pk__isnull=False)
        grant_queryset = grant_queryset.filter(
            service_identity_id=principal_id,
            service_identity__is_active=True,
        )
    else:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    scope_queryset = scope_queryset.filter(principal_active).filter(principal_scope)

    def current_action_filter(repository_id: uuid.UUID | OuterRef) -> Q:
        typed_repository_id = cast(uuid.UUID, repository_id)
        grants = grant_queryset.filter(
            Q(repository__isnull=True) | Q(repository_id=typed_repository_id)
        )
        action_filter = role_allowed | Q(Exists(grants))
        if actor.credential_id is not None:
            tokens = RepositoryAccessToken.objects.filter(
                id=actor.credential_id,
                organization_id=actor.organization_id,
                repository_id=typed_repository_id,
                service_identity_id=principal_id,
                revoked_at__isnull=True,
                expires_at__gt=timezone.now(),
                issuer=settings.TOKEN_ISSUER,
                audience=settings.TOKEN_AUDIENCE,
                repository__is_active=True,
                service_identity__is_active=True,
                allowed_actions__has_key=action.value,
            )
            action_filter &= Q(Exists(tokens))
        return action_filter

    current_repositories = Repository.objects.filter(
        id__in=repository_ids,
        organization_id=actor.organization_id,
        organization__lifecycle_state=Organization.LifecycleState.ACTIVE,
        is_active=True,
    ).filter(current_action_filter(OuterRef("id")))
    if repository_id_path is not None and repository_relation_path is not None:
        current_repository_filter = Q(
            **{
                f"{repository_id_path}__in": repository_ids,
                f"{repository_relation_path}__organization_id": actor.organization_id,
                f"{repository_relation_path}__is_active": True,
            }
        )
        current_scope = scope_queryset.filter(id__in=scope_ids).filter(
            Q(all_repositories=True)
            | Q(
                accessscoperepository__organization_id=actor.organization_id,
                accessscoperepository__repository_id=OuterRef(repository_id_path),
                accessscoperepository__repository__is_active=True,
            )
        )
        return (
            Q(**{f"{scope_id_path}__in": scope_ids})
            & current_repository_filter
            & Q(Exists(current_scope))
            & current_action_filter(OuterRef(repository_id_path))
        )
    current_scope = scope_queryset.filter(id__in=scope_ids).filter(
        Q(all_repositories=True)
        | Q(
            accessscoperepository__organization_id=actor.organization_id,
            accessscoperepository__repository_id__in=current_repositories.values("id"),
            accessscoperepository__repository__is_active=True,
        )
    )
    return Q(Exists(current_repositories)) & Q(Exists(current_scope))


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
                organization__lifecycle_state=Organization.LifecycleState.ACTIVE,
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
            organization__lifecycle_state=Organization.LifecycleState.ACTIVE,
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
    include_inactive: bool = False,
    include_revoked_sources: bool = False,
) -> bool:
    if not include_inactive and not access_scope.is_active:
        return False
    if (
        not include_revoked_sources
        and AccessScopeSource.objects.filter(
            access_scope=access_scope,
            source_connection__state=SourceConnection.State.REVOKED,
        ).exists()
    ):
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


def resolve_authorized_repository_scopes(
    *,
    actor: ActorContext,
    actions: tuple[Action, ...],
    required_action: Action,
    repository_ids: tuple[uuid.UUID, ...] = (),
    repository_limit: int = MAX_BATCH_AUTHORIZATION_REPOSITORIES,
) -> AuthorizedRepositoryScopes:
    """Resolve repositories, actions, and principal-visible scopes in fixed queries.

    Repository/action pairs remain explicit in the returned object so callers cannot
    turn a union of visible scopes into authorization for a different repository.
    """
    if len(actions) > len(Action):
        raise ValueError("authorization action budget exceeded")
    ordered_actions = tuple(dict.fromkeys(actions))
    if not ordered_actions or required_action not in ordered_actions:
        raise ValueError("required_action must be included in actions")
    if not 1 <= repository_limit <= MAX_BATCH_AUTHORIZATION_REPOSITORIES:
        raise ValueError("repository_limit must be between 1 and 100")
    if len(repository_ids) > repository_limit:
        raise ValueError("repository authorization budget exceeded")
    requested_ids = tuple(sorted(set(repository_ids), key=str))

    principal = resolve_principal(actor)
    role_actions = (
        ROLE_ACTIONS.get(principal.membership.role.code, frozenset())
        if principal.membership is not None
        else frozenset()
    )
    principal_filter = (
        Q(membership=principal.membership)
        if principal.membership is not None
        else Q(service_identity=principal.service_identity)
    )
    grant_queryset = (
        AccessGrant.objects.filter(
            organization_id=actor.organization_id,
            action__in=[action.value for action in ordered_actions],
            revoked_at__isnull=True,
            source_connection__isnull=True,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()))
        .filter(principal_filter)
    )
    token_repository_id: uuid.UUID | None = None
    token_actions: frozenset[str] | None = None
    if actor.credential_id is not None:
        if actor.repository_id is None:
            raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
        token_row = (
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
            .values_list("repository_id", "allowed_actions")
            .first()
        )
        if (
            token_row is None
            or not isinstance(token_row[1], list)
            or not all(isinstance(value, str) for value in token_row[1])
        ):
            raise AuthenticationError(INVALID_CREDENTIAL_MESSAGE)
        token_repository_id = token_row[0]
        token_actions = frozenset(token_row[1])

    repository_queryset = Repository.objects.filter(
        organization_id=actor.organization_id,
        is_active=True,
    )
    if requested_ids:
        repository_queryset = repository_queryset.filter(id__in=requested_ids)
    elif actor.repository_id is not None:
        repository_queryset = repository_queryset.filter(id=actor.repository_id)
    elif required_action not in role_actions:
        required_grants = grant_queryset.filter(action=required_action.value).filter(
            Q(repository__isnull=True) | Q(repository_id=OuterRef("id"))
        )
        repository_queryset = repository_queryset.filter(Exists(required_grants))
    repositories = tuple(repository_queryset.order_by("id")[:repository_limit])
    candidate_repository_ids = {repository.id for repository in repositories}
    grant_rows = tuple(
        grant_queryset.filter(
            Q(repository__isnull=True) | Q(repository_id__in=candidate_repository_ids)
        )
        .order_by("action", "repository_id")
        .values_list("action", "repository_id")
        .distinct()
    )
    global_grants = {
        Action(action) for action, repository_id in grant_rows if repository_id is None
    }
    repository_grants: dict[Action, set[uuid.UUID]] = {action: set() for action in ordered_actions}
    for action_value, repository_id in grant_rows:
        if repository_id is not None:
            repository_grants[Action(action_value)].add(repository_id)

    def action_allowed_for_repository(action: Action, repository_id: uuid.UUID) -> bool:
        if actor.repository_id is not None and repository_id != actor.repository_id:
            return False
        if actor.credential_actions and action.value not in actor.credential_actions:
            return False
        if token_actions is not None and (
            repository_id != token_repository_id or action.value not in token_actions
        ):
            return False
        return (
            action in role_actions
            or action in global_grants
            or repository_id in repository_grants[action]
        )

    permitted_repository_ids_by_action = {
        action: tuple(
            repository.id
            for repository in repositories
            if action_allowed_for_repository(action, repository.id)
        )
        for action in ordered_actions
    }
    required_repository_ids = set(permitted_repository_ids_by_action[required_action])
    if requested_ids and (
        {repository.id for repository in repositories} != set(requested_ids)
        or required_repository_ids != set(requested_ids)
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    repositories = tuple(
        repository for repository in repositories if repository.id in required_repository_ids
    )
    retained_repository_ids = {repository.id for repository in repositories}
    permitted_repository_ids_by_action = {
        action: tuple(
            repository_id
            for repository_id in repository_ids_for_action
            if repository_id in retained_repository_ids
        )
        for action, repository_ids_for_action in permitted_repository_ids_by_action.items()
    }

    scope_ids_by_repository: dict[uuid.UUID, set[uuid.UUID]] = {
        repository.id: set() for repository in repositories
    }
    if repositories:
        scope_queryset = AccessScope.objects.filter(
            organization_id=actor.organization_id,
            is_active=True,
        ).exclude(
            accessscopesource__source_connection__state__in=(
                SourceConnection.State.REVOKED,
                SourceConnection.State.DISABLED,
            )
        )
        if principal.membership is not None:
            scope_queryset = scope_queryset.filter(
                Q(all_memberships=True) | Q(accessscopemembership__membership=principal.membership)
            )
        else:
            scope_queryset = scope_queryset.filter(
                Q(all_service_identities=True)
                | Q(accessscopeserviceidentity__service_identity=principal.service_identity)
            )
        scope_rows = tuple(
            scope_queryset.filter(
                Q(all_repositories=True)
                | Q(accessscoperepository__repository_id__in=retained_repository_ids)
            )
            .order_by("id")
            .values_list("id", "all_repositories")
            .distinct()[: MAX_BATCH_AUTHORIZATION_SCOPES + 1]
        )
        if len(scope_rows) > MAX_BATCH_AUTHORIZATION_SCOPES:
            raise ValueError("scope authorization budget exceeded")
        all_repository_scope_ids = {
            scope_id for scope_id, all_repositories in scope_rows if all_repositories
        }
        explicit_scope_ids = {
            scope_id for scope_id, all_repositories in scope_rows if not all_repositories
        }
        for scope_ids in scope_ids_by_repository.values():
            scope_ids.update(all_repository_scope_ids)
        if explicit_scope_ids:
            bindings = tuple(
                AccessScopeRepository.objects.filter(
                    organization_id=actor.organization_id,
                    access_scope_id__in=explicit_scope_ids,
                    repository_id__in=retained_repository_ids,
                )
                .order_by("repository_id", "access_scope_id")
                .values_list("repository_id", "access_scope_id")
                .distinct()[: MAX_BATCH_AUTHORIZATION_SCOPE_BINDINGS + 1]
            )
            if len(bindings) > MAX_BATCH_AUTHORIZATION_SCOPE_BINDINGS:
                raise ValueError("scope binding authorization budget exceeded")
            for repository_id, scope_id in bindings:
                scope_ids_by_repository[repository_id].add(scope_id)

    return AuthorizedRepositoryScopes._create(
        actor=actor,
        principal_id=principal.principal_id,
        repositories=repositories,
        repository_ids_by_action=tuple(
            (action, permitted_repository_ids_by_action[action]) for action in ordered_actions
        ),
        scope_ids_by_repository=tuple(
            (
                repository_id,
                tuple(sorted(scope_ids_by_repository[repository_id], key=str)),
            )
            for repository_id in sorted(scope_ids_by_repository, key=str)
        ),
    )


def authorized_access_scope_ids(
    *,
    actor: ActorContext,
    action: Action,
    repository_id: uuid.UUID,
    include_inactive: bool = False,
    include_revoked_sources: bool = False,
) -> set[uuid.UUID]:
    """Resolve current principal and scope boundaries before querying scoped records."""
    try:
        authorize_action(
            actor=actor,
            action=action,
            repository_id=repository_id,
        )
    except ResourceNotFoundError:
        return set()

    principal = resolve_principal(actor)
    candidates = AccessScope.objects.filter(
        organization_id=actor.organization_id,
    )
    if not include_inactive:
        candidates = candidates.filter(is_active=True)
    return {
        scope.id
        for scope in candidates
        if _scope_allows(
            principal=principal,
            access_scope=scope,
            repository_id=repository_id,
            include_inactive=include_inactive,
            include_revoked_sources=include_revoked_sources,
        )
    }
