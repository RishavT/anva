"""Permission-filtered retrieval shared by API, search, Canvas, and MCP surfaces."""

from __future__ import annotations

import uuid

from django.db.models import F, Q, QuerySet

from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    ImmutableArtifact,
    KnowledgeAssertion,
    KnowledgeRelationship,
    SourceChunk,
    SourceChunkVisibility,
    SourceConnection,
    SourceDocument,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    resolve_principal,
)
from anva.core.services.context import ActorContext


def visible_scope_ids(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
) -> QuerySet[AccessScope]:
    """Filter scopes by tenant, repository, principal, and source before content queries."""
    principal = resolve_principal(actor)
    scopes = (
        AccessScope.objects.filter(
            organization_id=actor.organization_id,
            is_active=True,
        )
        .filter(Q(all_repositories=True) | Q(accessscoperepository__repository_id=repository_id))
        .exclude(
            accessscopesource__source_connection__state__in=[
                SourceConnection.State.REVOKED,
                SourceConnection.State.DISABLED,
            ]
        )
    )
    if principal.membership is not None:
        scopes = scopes.filter(
            Q(all_memberships=True) | Q(accessscopemembership__membership=principal.membership)
        )
    else:
        scopes = scopes.filter(
            Q(all_service_identities=True)
            | Q(accessscopeserviceidentity__service_identity=principal.service_identity)
        )
    return scopes.distinct()


def authorized_assertions(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    action: Action,
) -> QuerySet[KnowledgeAssertion]:
    """Return a queryset whose authorization filters precede search or traversal."""
    authorize_action(
        actor=actor,
        action=action,
        repository_id=repository_id,
    )
    scopes = visible_scope_ids(actor=actor, repository_id=repository_id)
    return (
        KnowledgeAssertion.objects.filter(
            organization_id=actor.organization_id,
            access_scope__in=scopes,
        )
        .filter(
            Q(assertionprovenance__isnull=True)
            | Q(assertionprovenance__access_snapshot__revoked_at__isnull=True)
        )
        .distinct()
    )


def authorized_source_chunks(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
) -> QuerySet[SourceChunk]:
    """Apply tenant and snapshot visibility before any chunk ranking."""
    authorize_action(
        actor=actor,
        action=Action.SEARCH,
        repository_id=repository_id,
    )
    scopes = visible_scope_ids(actor=actor, repository_id=repository_id)
    return SourceChunk.objects.filter(
        organization_id=actor.organization_id,
        sourcechunkvisibility__access_scope__in=scopes,
        sourcechunkvisibility__state=SourceChunkVisibility.State.AVAILABLE,
        sourcechunkvisibility__access_snapshot__revoked_at__isnull=True,
        sourcechunkvisibility__source_observation__source_document__state=(
            SourceDocument.State.PRESENT
        ),
        sourcechunkvisibility__source_observation__source_revision_id=F(
            "sourcechunkvisibility__source_observation__source_document__current_revision_id"
        ),
    ).distinct()


def authorized_relationships(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
) -> QuerySet[KnowledgeRelationship]:
    """Return committed edges only after scope and snapshot filtering."""
    authorize_action(
        actor=actor,
        action=Action.KNOWLEDGE_VIEW,
        repository_id=repository_id,
    )
    scopes = visible_scope_ids(actor=actor, repository_id=repository_id)
    return KnowledgeRelationship.objects.filter(
        organization_id=actor.organization_id,
        access_scope__in=scopes,
        access_snapshot__revoked_at__isnull=True,
        assertion__valid_until__isnull=True,
        source_observation__source_document__state=SourceDocument.State.PRESENT,
        source_observation__source_revision_id=F(
            "source_observation__source_document__current_revision_id"
        ),
    )


def get_authorized_assertion(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    assertion_id: uuid.UUID,
    action: Action,
) -> KnowledgeAssertion:
    assertion = (
        authorized_assertions(
            actor=actor,
            repository_id=repository_id,
            action=action,
        )
        .filter(id=assertion_id)
        .first()
    )
    if assertion is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    return assertion


def search_assertions(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    query: str,
) -> list[KnowledgeAssertion]:
    """Apply visibility before the bounded text match that stands in for later ranking."""
    if not query.strip() or len(query) > 500:
        raise ValueError("query must contain between 1 and 500 characters")
    return list(
        authorized_assertions(
            actor=actor,
            repository_id=repository_id,
            action=Action.SEARCH,
        )
        .filter(Q(subject_key__icontains=query) | Q(predicate__icontains=query))
        .order_by("created_at")[:50]
    )


def get_authorized_artifact(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    artifact_id: uuid.UUID,
    action: Action = Action.ARTIFACT_VIEW,
) -> ImmutableArtifact:
    """Retrieve an artifact only through an active visible scope."""
    authorize_action(
        actor=actor,
        action=action,
        repository_id=repository_id,
    )
    scopes = visible_scope_ids(actor=actor, repository_id=repository_id)
    artifact = ImmutableArtifact.objects.filter(
        id=artifact_id,
        organization_id=actor.organization_id,
        access_scope__in=scopes,
    ).first()
    if artifact is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    return artifact
