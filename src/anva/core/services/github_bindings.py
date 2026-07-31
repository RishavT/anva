"""Scope-authorized GitHub binding reads shared by API and product surfaces."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from django.db.models import Q, QuerySet

from anva.core.models import GitHubInstallation, GitHubRepositoryBinding
from anva.core.services.authorization import Action, authorized_access_scope_ids
from anva.core.services.context import ActorContext


def authorized_active_github_bindings(
    *,
    actor: ActorContext,
    repository_ids: Iterable[uuid.UUID],
) -> QuerySet[GitHubRepositoryBinding]:
    """Return active bindings only after resolving each repository's authorized scopes."""
    boundary = Q(pk__in=[])
    for repository_id in dict.fromkeys(repository_ids):
        scope_ids = authorized_access_scope_ids(
            actor=actor,
            action=Action.GITHUB_MANAGE,
            repository_id=repository_id,
        )
        boundary |= Q(
            repository_id=repository_id,
            access_scope_id__in=scope_ids,
        )
    return (
        GitHubRepositoryBinding.objects.filter(
            organization_id=actor.organization_id,
            is_active=True,
            is_archived=False,
            revoked_at__isnull=True,
            repository__is_active=True,
            installation__state=GitHubInstallation.State.ACTIVE,
            installation__revoked_at__isnull=True,
            installation__service_identity__is_active=True,
        )
        .filter(boundary)
        .distinct()
    )
