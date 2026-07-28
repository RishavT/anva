"""Access-scope construction, safe intersection, snapshots, and source revocation."""

from __future__ import annotations

import uuid
from dataclasses import replace

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from anva.core.exceptions import OptimisticConcurrencyError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    AccessSnapshot,
    BackgroundJob,
    ContextPacketInvalidation,
    Organization,
    SourceChunkVisibility,
    SourceConnection,
    SyncRun,
    content_hash,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition

MAX_DERIVED_SCOPE_DEPTH = 32
MAX_DERIVED_SCOPES_PER_REVOCATION = 2_000


def _scope_ids(
    *,
    scope: AccessScope,
    all_field: str,
    through_model: type[AccessScopeMembership | AccessScopeServiceIdentity | AccessScopeRepository],
    value_field: str,
) -> set[uuid.UUID] | None:
    if bool(getattr(scope, all_field)):
        return None
    return set(
        through_model.objects.filter(access_scope=scope).values_list(
            value_field,
            flat=True,
        )
    )


def _intersect(
    current: set[uuid.UUID] | None,
    candidate: set[uuid.UUID] | None,
) -> set[uuid.UUID] | None:
    if current is None:
        return None if candidate is None else set(candidate)
    if candidate is None:
        return current
    return current & candidate


def derive_scope_intersection(
    *,
    actor: ActorContext,
    source_scope_ids: list[uuid.UUID],
    name: str,
) -> AccessScope:
    """Create a derived scope whose visibility is never wider than any input."""
    if not source_scope_ids or len(source_scope_ids) > 100:
        raise ValueError("Between 1 and 100 source scopes are required")
    with transaction.atomic():
        decision = authorize_action(
            actor=actor,
            action=Action.SCOPE_MANAGE,
            repository_id=actor.repository_id,
        )
        scopes = list(
            AccessScope.objects.select_for_update()
            .filter(
                organization_id=actor.organization_id,
                id__in=source_scope_ids,
                is_active=True,
            )
            .order_by("id")
        )
        if len(scopes) != len(set(source_scope_ids)):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

        memberships: set[uuid.UUID] | None = None
        services: set[uuid.UUID] | None = None
        repositories: set[uuid.UUID] | None = None
        contributing_sources: set[uuid.UUID] = set()
        for scope in scopes:
            memberships = _intersect(
                memberships,
                _scope_ids(
                    scope=scope,
                    all_field="all_memberships",
                    through_model=AccessScopeMembership,
                    value_field="membership_id",
                ),
            )
            services = _intersect(
                services,
                _scope_ids(
                    scope=scope,
                    all_field="all_service_identities",
                    through_model=AccessScopeServiceIdentity,
                    value_field="service_identity_id",
                ),
            )
            repositories = _intersect(
                repositories,
                _scope_ids(
                    scope=scope,
                    all_field="all_repositories",
                    through_model=AccessScopeRepository,
                    value_field="repository_id",
                ),
            )
            contributing_sources.update(
                AccessScopeSource.objects.filter(access_scope=scope).values_list(
                    "source_connection_id",
                    flat=True,
                )
            )

        organization = Organization.objects.get(id=actor.organization_id)
        derived = AccessScope.objects.create(
            organization=organization,
            name=name,
            all_memberships=memberships is None,
            all_service_identities=services is None,
            all_repositories=repositories is None,
        )
        derived.derived_from.set(scopes)
        AccessScopeMembership.objects.bulk_create(
            [
                AccessScopeMembership(
                    organization=organization,
                    access_scope=derived,
                    membership_id=membership_id,
                )
                for membership_id in sorted(memberships or set())
            ]
        )
        AccessScopeServiceIdentity.objects.bulk_create(
            [
                AccessScopeServiceIdentity(
                    organization=organization,
                    access_scope=derived,
                    service_identity_id=service_id,
                )
                for service_id in sorted(services or set())
            ]
        )
        AccessScopeRepository.objects.bulk_create(
            [
                AccessScopeRepository(
                    organization=organization,
                    access_scope=derived,
                    repository_id=repository_id,
                )
                for repository_id in sorted(repositories or set())
            ]
        )
        AccessScopeSource.objects.bulk_create(
            [
                AccessScopeSource(
                    organization=organization,
                    access_scope=derived,
                    source_connection_id=source_id,
                )
                for source_id in sorted(contributing_sources)
            ]
        )
        derived.is_derived = True
        derived.boundary_sealed_at = timezone.now()
        derived.save(
            update_fields=[
                "is_derived",
                "boundary_sealed_at",
                "updated_at",
            ]
        )
        audit_actor = replace(actor, authorization_path=decision.authorization_path)
        record_transition(
            organization=organization,
            actor=audit_actor,
            target_type="accessscope",
            target_id=derived.id,
            from_state="",
            to_state="DERIVED",
            revision=derived.revision,
            metadata={"source_scope_ids": [str(scope.id) for scope in scopes]},
        )
        return derived


def create_access_snapshot(
    *,
    actor: ActorContext,
    source_connection_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    action: Action = Action.SCOPE_MANAGE,
) -> AccessSnapshot:
    """Capture the exact effective source boundary without secret material."""
    with transaction.atomic():
        decision = authorize_action(
            actor=actor,
            action=action,
            repository_id=actor.repository_id,
            source_connection_id=source_connection_id,
        )
        source = get_tenant_record_for_update(
            queryset=SourceConnection.objects.select_related("organization"),
            record_id=source_connection_id,
            organization_id=actor.organization_id,
        )
        scope = get_tenant_record_for_update(
            queryset=AccessScope.objects.all(),
            record_id=access_scope_id,
            organization_id=actor.organization_id,
        )
        payload: dict[str, object] = {
            "source_connection_id": str(source.id),
            "source_revision": source.revision,
            "source_state": source.state,
            "access_scope_id": str(scope.id),
            "scope_revision": scope.revision,
            "all_memberships": scope.all_memberships,
            "all_service_identities": scope.all_service_identities,
            "all_repositories": scope.all_repositories,
            "membership_ids": sorted(
                str(value)
                for value in AccessScopeMembership.objects.filter(access_scope=scope).values_list(
                    "membership_id", flat=True
                )
            ),
            "service_identity_ids": sorted(
                str(value)
                for value in AccessScopeServiceIdentity.objects.filter(
                    access_scope=scope
                ).values_list("service_identity_id", flat=True)
            ),
            "repository_ids": sorted(
                str(value)
                for value in AccessScopeRepository.objects.filter(access_scope=scope).values_list(
                    "repository_id", flat=True
                )
            ),
            "contributing_source_ids": sorted(
                str(value)
                for value in AccessScopeSource.objects.filter(access_scope=scope).values_list(
                    "source_connection_id", flat=True
                )
            ),
        }
        snapshot, created = AccessSnapshot.objects.get_or_create(
            organization=source.organization,
            source_connection=source,
            content_hash=content_hash(payload),
            defaults={
                "access_scope": scope,
                "scope_revision": scope.revision,
                "payload": payload,
            },
        )
        if created:
            audit_actor = replace(actor, authorization_path=decision.authorization_path)
            record_transition(
                organization=source.organization,
                actor=audit_actor,
                target_type="accesssnapshot",
                target_id=snapshot.id,
                from_state="",
                to_state="CAPTURED",
                revision=snapshot.scope_revision,
                metadata={"content_hash": snapshot.content_hash},
            )
        return snapshot


def revoke_source_connection(
    *,
    actor: ActorContext,
    source_connection_id: uuid.UUID,
    expected_revision: int,
) -> SourceConnection:
    """Revoke a source and every current/derived visibility scope that depends on it."""
    with transaction.atomic():
        decision = authorize_action(
            actor=actor,
            action=Action.SOURCE_REVOKE,
            repository_id=actor.repository_id,
            source_connection_id=source_connection_id,
            allow_revoked_source=True,
        )
        source = get_tenant_record_for_update(
            queryset=SourceConnection.objects.select_related("organization"),
            record_id=source_connection_id,
            organization_id=actor.organization_id,
        )
        if source.state == SourceConnection.State.REVOKED:
            return source
        if source.revision != expected_revision:
            raise OptimisticConcurrencyError(
                f"Expected revision {expected_revision}, found {source.revision}"
            )

        direct_ids = set(
            AccessScopeSource.objects.filter(source_connection=source).values_list(
                "access_scope_id",
                flat=True,
            )
        )
        affected_ids = set(direct_ids)
        frontier = set(direct_ids)
        for _depth in range(MAX_DERIVED_SCOPE_DEPTH):
            if not frontier:
                break
            descendants = set(
                AccessScope.objects.filter(derived_from__id__in=frontier).values_list(
                    "id",
                    flat=True,
                )
            )
            frontier = descendants - affected_ids
            affected_ids.update(frontier)
            if len(affected_ids) > MAX_DERIVED_SCOPES_PER_REVOCATION:
                raise ValueError("Source revocation scope propagation exceeds safety bound")
        else:
            raise ValueError("Source revocation scope propagation exceeds depth bound")

        revoked_at = timezone.now()
        AccessScope.objects.filter(id__in=affected_ids).update(
            is_active=False,
            revision=F("revision") + 1,
            updated_at=revoked_at,
        )
        AccessSnapshot.objects.filter(
            source_connection=source,
            revoked_at__isnull=True,
        ).update(revoked_at=revoked_at)
        for visibility in SourceChunkVisibility.objects.filter(
            organization=source.organization,
            access_snapshot__source_connection=source,
            state=SourceChunkVisibility.State.AVAILABLE,
        ):
            visibility.state = SourceChunkVisibility.State.REVOKED
            visibility.revoked_at = revoked_at
            visibility.save(update_fields=["state", "revoked_at"])
        audit_actor = replace(actor, authorization_path=decision.authorization_path)
        for job in BackgroundJob.objects.filter(
            organization=source.organization,
            kind="ingestion.sync",
            payload__source_connection_id=str(source.id),
            state=BackgroundJob.State.PENDING,
        ):
            job.state = BackgroundJob.State.CANCELLED
            job.completed_at = revoked_at
            job.last_error = "source_revoked"
            job.save(
                update_fields=[
                    "state",
                    "completed_at",
                    "last_error",
                    "updated_at",
                ]
            )
            record_transition(
                organization=source.organization,
                actor=audit_actor,
                target_type="backgroundjob",
                target_id=job.id,
                from_state=BackgroundJob.State.PENDING,
                to_state=BackgroundJob.State.CANCELLED,
                revision=job.attempt_count,
                metadata={"error_code": "source_revoked"},
            )
        for run in SyncRun.objects.filter(
            organization=source.organization,
            source_connection=source,
            state__in=[
                SyncRun.State.REQUESTED,
                SyncRun.State.DISCOVERING,
                SyncRun.State.FETCHING,
                SyncRun.State.PARSING,
                SyncRun.State.INDEXING,
                SyncRun.State.EXTRACTING,
                SyncRun.State.RESOLVING,
                SyncRun.State.PUBLISHING,
            ],
        ):
            previous_run_state = str(run.state)
            run.state = SyncRun.State.CANCELLED
            run.failure_code = "source_revoked"
            run.completed_at = revoked_at
            run.revision += 1
            run.save(
                update_fields=[
                    "state",
                    "failure_code",
                    "completed_at",
                    "revision",
                    "updated_at",
                ]
            )
            record_transition(
                organization=source.organization,
                actor=audit_actor,
                target_type="syncrun",
                target_id=run.id,
                from_state=previous_run_state,
                to_state=SyncRun.State.CANCELLED,
                revision=run.revision,
                metadata={"failure_code": "source_revoked"},
            )
        previous_state = str(source.state)
        source.state = SourceConnection.State.REVOKED
        source.revision += 1
        source.save(update_fields=["state", "revision", "updated_at"])
        record_transition(
            organization=source.organization,
            actor=audit_actor,
            target_type="sourceconnection",
            target_id=source.id,
            from_state=previous_state,
            to_state=SourceConnection.State.REVOKED,
            revision=source.revision,
            metadata={"invalidated_scope_count": len(affected_ids)},
        )
        if source.repository_id is not None:
            from anva.core.services.context_packets import invalidate_context_packets

            invalidate_context_packets(
                organization_id=source.organization_id,
                repository_id=source.repository_id,
                reason=ContextPacketInvalidation.Reason.REVOCATION,
                details={"source_connection_id": str(source.id)},
            )
        return source
