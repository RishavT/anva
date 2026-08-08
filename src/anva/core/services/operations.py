"""Production operations: tenant rate limits, retention, and decommissioning."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import F, OuterRef, Q, Subquery
from django.utils import timezone

from anva.core.exceptions import RateLimitExceededError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    Evidence,
    EvidenceBlob,
    EvidenceRetentionEvent,
    EvidenceUploadAuthorization,
    Membership,
    Organization,
    OrganizationProductSettings,
    RateLimitBucket,
    Repository,
    RepositoryAccessToken,
    RetentionRun,
    ServiceIdentity,
    content_hash,
)
from anva.core.services.authorization import Action, authorize_action
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.evidence_uploads import (
    EvidenceUploadError,
    cleanup_decommissioned_upload_authorizations,
    delete_evidence_blob_bytes,
)
from anva.core.services.scopes import revoke_source_connection

MAX_DECOMMISSION_SOURCES = 1_000
MAX_EVIDENCE_BLOB_DELETIONS = 10_000
MAX_DECOMMISSION_UPLOADS = 10_000
MAX_PREAUTH_RATE_BUCKET_PURGE = 1_000


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Non-secret fixed-window decision safe for response metadata."""

    limit: int
    remaining: int
    retry_after_seconds: int


def _rate_limit(channel: str) -> int:
    limits = {
        "api": settings.ANVA_RATE_LIMIT_API_REQUESTS,
        "mcp": settings.ANVA_RATE_LIMIT_MCP_REQUESTS,
        "web": settings.ANVA_RATE_LIMIT_WEB_REQUESTS,
        "preauth": settings.ANVA_RATE_LIMIT_PREAUTH_REQUESTS,
    }
    try:
        return int(limits[channel])
    except KeyError:
        raise ValueError("Unknown rate-limit channel") from None


def _identity_hash(actor: ActorContext) -> str:
    material = ":".join(
        (
            str(actor.organization_id),
            actor.actor_type,
            actor.actor_id,
            str(actor.credential_id or "human-session"),
        )
    )
    return hmac.new(
        str(settings.SECRET_KEY).encode(),
        material.encode(),
        hashlib.sha256,
    ).hexdigest()


def enforce_rate_limit(
    *,
    actor: ActorContext,
    channel: str,
    now: datetime | None = None,
) -> RateLimitDecision:
    """Atomically enforce one tenant-and-principal fixed window."""
    return _enforce_rate_limit(
        organization_id=actor.organization_id,
        identity_hash=_identity_hash(actor),
        channel=channel,
        now=now,
    )


def enforce_pre_auth_rate_limit(
    *,
    client_key: str,
    now: datetime | None = None,
) -> RateLimitDecision:
    """Bound anonymous/auth-failure traffic using a non-reversible client key."""
    identity_hash = hmac.new(
        str(settings.SECRET_KEY).encode(),
        f"preauth:{client_key}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return _enforce_rate_limit(
        organization_id=None,
        identity_hash=identity_hash,
        channel="preauth",
        now=now,
    )


def _enforce_rate_limit(
    *,
    organization_id: uuid.UUID | None,
    identity_hash: str,
    channel: str,
    now: datetime | None,
) -> RateLimitDecision:
    """Persist one fixed-window decision for a pre-hashed identity."""
    limit = _rate_limit(channel)
    window_seconds = int(settings.ANVA_RATE_LIMIT_WINDOW_SECONDS)
    current = now or timezone.now()
    epoch = int(current.timestamp())
    window_epoch = epoch - (epoch % window_seconds)
    window_start = datetime.fromtimestamp(window_epoch, tz=UTC)
    expires_at = window_start + timedelta(seconds=window_seconds * 2)
    retry_after = max(1, window_seconds - (epoch - window_epoch))
    if not settings.ANVA_RATE_LIMIT_ENABLED:
        return RateLimitDecision(limit=limit, remaining=limit, retry_after_seconds=retry_after)

    with transaction.atomic():
        bucket, _created = RateLimitBucket.objects.select_for_update().get_or_create(
            organization_id=organization_id,
            identity_hash=identity_hash,
            channel=channel,
            window_started_at=window_start,
            defaults={
                "request_count": 0,
                "denied_count": 0,
                "expires_at": expires_at,
            },
        )
        bucket.request_count += 1
        denied = bucket.request_count > limit
        if denied:
            bucket.denied_count += 1
        bucket.save(update_fields=["request_count", "denied_count"])
    if denied:
        raise RateLimitExceededError(retry_after)
    return RateLimitDecision(
        limit=limit,
        remaining=max(0, limit - bucket.request_count),
        retry_after_seconds=retry_after,
    )


def purge_expired_rate_buckets(
    *,
    organization: Organization,
    now: datetime | None = None,
) -> int:
    """Delete one tenant's expired counters; no governed record is affected."""
    deleted, _details = RateLimitBucket.objects.filter(
        organization=organization, expires_at__lte=now or timezone.now()
    ).delete()
    return deleted


def purge_expired_pre_auth_rate_buckets(
    *,
    now: datetime | None = None,
    limit: int = MAX_PREAUTH_RATE_BUCKET_PURGE,
) -> int:
    """Delete one bounded oldest-first batch of expired system pre-auth counters."""
    if isinstance(limit, bool) or not 1 <= limit <= MAX_PREAUTH_RATE_BUCKET_PURGE:
        raise ValueError("Pre-auth rate-bucket cleanup limit must be between 1 and 1000")
    cutoff = now or timezone.now()
    with transaction.atomic():
        bucket_ids = list(
            RateLimitBucket.objects.select_for_update(skip_locked=True)
            .filter(
                organization__isnull=True,
                channel="preauth",
                expires_at__lte=cutoff,
            )
            .order_by("expires_at", "id")
            .values_list("id", flat=True)[:limit]
        )
        if not bucket_ids:
            return 0
        deleted, _details = RateLimitBucket.objects.filter(
            id__in=bucket_ids,
            organization__isnull=True,
            channel="preauth",
            expires_at__lte=cutoff,
        ).delete()
    return deleted


def _retention_blob_candidates(
    *,
    organization: Organization,
    expiring_evidence_ids: list[uuid.UUID],
    cutoff: datetime,
    reference_time: datetime,
) -> tuple[list[uuid.UUID], list[uuid.UUID]]:
    """Resolve bounded exact-tenant byte deletions without changing retained history."""
    latest_retention_state = EvidenceRetentionEvent.objects.filter(
        organization=organization,
        evidence_id=OuterRef("pk"),
        occurred_at__lte=reference_time,
    ).order_by("-occurred_at", "-id")
    deletable_states = (
        EvidenceBlob.StorageState.AVAILABLE,
        EvidenceBlob.StorageState.DELETE_FAILED,
    )
    linked_ids = list(
        Evidence.objects.filter(
            organization=organization,
            artifact_blob__storage_state__in=deletable_states,
        )
        .annotate(latest_retention_state=Subquery(latest_retention_state.values("state")[:1]))
        .filter(
            Q(id__in=expiring_evidence_ids)
            | Q(latest_retention_state=Evidence.RetentionState.EXPIRED)
        )
        .order_by("artifact_blob_id")
        .values_list("artifact_blob_id", flat=True)[: MAX_EVIDENCE_BLOB_DELETIONS + 1]
    )
    remaining = MAX_EVIDENCE_BLOB_DELETIONS + 1 - len(linked_ids)
    unlinked_ids = list(
        EvidenceBlob.objects.filter(
            organization=organization,
            evidence__isnull=True,
            upload_authorization__state="ACCEPTED",
            created_at__lte=cutoff,
            storage_state__in=deletable_states,
        )
        .order_by("id")
        .values_list("id", flat=True)[:remaining]
    )
    if len(linked_ids) + len(unlinked_ids) > MAX_EVIDENCE_BLOB_DELETIONS:
        raise ValueError("Retention run exceeds the 10,000-blob deletion safety bound")
    return linked_ids, unlinked_ids


def _decommission_blob_candidates(*, organization: Organization) -> list[uuid.UUID]:
    blob_ids = list(
        EvidenceBlob.objects.filter(
            organization=organization,
            storage_state__in=(
                EvidenceBlob.StorageState.AVAILABLE,
                EvidenceBlob.StorageState.DELETE_FAILED,
            ),
        )
        .order_by("id")
        .values_list("id", flat=True)[: MAX_EVIDENCE_BLOB_DELETIONS + 1]
    )
    if len(blob_ids) > MAX_EVIDENCE_BLOB_DELETIONS:
        raise ValueError("Decommission exceeds the 10,000-blob deletion safety bound")
    return blob_ids


def _delete_blob_batch(
    *,
    organization_id: uuid.UUID,
    blob_ids: list[uuid.UUID],
    reason: str,
    retention_cutoff: datetime | None = None,
    retention_reference_time: datetime | None = None,
) -> tuple[int, int]:
    """Delete exact object bytes after the selecting transaction has committed."""
    deleted = 0
    failed = 0
    for blob_id in blob_ids:
        try:
            if retention_cutoff is None:
                delete_evidence_blob_bytes(
                    organization_id=organization_id,
                    blob_id=blob_id,
                    reason=reason,
                )
            else:
                delete_evidence_blob_bytes(
                    organization_id=organization_id,
                    blob_id=blob_id,
                    reason=reason,
                    retention_cutoff=retention_cutoff,
                    retention_reference_time=retention_reference_time,
                )
        except EvidenceUploadError:
            failed += 1
        else:
            deleted += 1
    return deleted, failed


def run_retention(
    *,
    actor: ActorContext,
    reference_time: datetime | None = None,
    dry_run: bool = False,
) -> RetentionRun:
    """Apply due expiry, then delete exact tenant bytes outside the DB transaction."""
    now = reference_time or timezone.now()
    authorize_action(
        actor=actor,
        action=Action.RETENTION_MANAGE,
        repository_id=actor.repository_id,
    )
    organization = Organization.objects.filter(
        id=actor.organization_id,
        lifecycle_state=Organization.LifecycleState.ACTIVE,
    ).first()
    if organization is None:
        raise ResourceNotFoundError("Governed record was not found")
    product_settings = OrganizationProductSettings.objects.filter(organization=organization).first()
    retention_days = product_settings.retention_days if product_settings is not None else 365
    cutoff = now - timedelta(days=retention_days)
    request_hash = content_hash(
        {
            "organization_id": str(organization.id),
            "kind": RetentionRun.Kind.SCHEDULED_RETENTION,
            "reference_time": now.isoformat(),
            "dry_run": dry_run,
        }
    )
    with transaction.atomic():
        existing = RetentionRun.objects.filter(
            organization=organization,
            kind=RetentionRun.Kind.SCHEDULED_RETENTION,
            request_hash=request_hash,
        ).first()
        if existing is not None:
            return existing
        run = RetentionRun.objects.create(
            organization=organization,
            kind=RetentionRun.Kind.SCHEDULED_RETENTION,
            state=RetentionRun.State.RUNNING,
            cutoff_at=cutoff,
            dry_run=dry_run,
            request_hash=request_hash,
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
        )
        latest_retention_state = EvidenceRetentionEvent.objects.filter(
            organization=organization,
            evidence_id=OuterRef("pk"),
            occurred_at__lte=now,
        ).order_by("-occurred_at", "-id")
        active_evidence_ids = list(
            Evidence.objects.filter(
                organization=organization,
                completed_at__lte=cutoff,
                retention_expires_at__isnull=False,
                retention_expires_at__lte=now,
            )
            .annotate(latest_retention_state=Subquery(latest_retention_state.values("state")[:1]))
            .filter(latest_retention_state=Evidence.RetentionState.ACTIVE)
            .order_by("id")
            .values_list("id", flat=True)[:10_001]
        )
        if len(active_evidence_ids) > 10_000:
            raise ValueError("Retention run exceeds the 10,000-record safety bound")
        if not dry_run:
            EvidenceRetentionEvent.objects.bulk_create(
                [
                    EvidenceRetentionEvent(
                        organization=organization,
                        evidence_id=evidence_id,
                        state=Evidence.RetentionState.EXPIRED,
                        reason="Configured retention period elapsed",
                        actor_type=actor.actor_type,
                        actor_id=actor.actor_id,
                        occurred_at=now,
                    )
                    for evidence_id in active_evidence_ids
                ]
            )
        expired_rate_buckets = RateLimitBucket.objects.filter(
            organization=organization,
            expires_at__lte=now,
        ).count()
        if not dry_run:
            purge_expired_rate_buckets(organization=organization, now=now)
        initial_summary = {
            "evidence_expired": len(active_evidence_ids),
            "rate_buckets_deleted": expired_rate_buckets,
            "governed_history_retained": True,
            "source_content_deleted": 0,
        }

    linked_blob_ids, unlinked_blob_ids = _retention_blob_candidates(
        organization=organization,
        expiring_evidence_ids=active_evidence_ids,
        cutoff=cutoff,
        reference_time=now,
    )
    deleted = 0
    failed = 0
    if not dry_run:
        deleted, failed = _delete_blob_batch(
            organization_id=organization.id,
            blob_ids=[*linked_blob_ids, *unlinked_blob_ids],
            reason="retention_expired",
            retention_cutoff=cutoff,
            retention_reference_time=now,
        )
    with transaction.atomic():
        run = RetentionRun.objects.select_for_update().get(
            id=run.id,
            organization=organization,
        )
        run.summary = {
            **initial_summary,
            "expired_linked_blob_candidates": len(linked_blob_ids),
            "stale_unlinked_blob_candidates": len(unlinked_blob_ids),
            "evidence_blob_bytes_deleted": deleted,
            "evidence_blob_bytes_delete_failed": failed,
        }
        run.state = RetentionRun.State.COMPLETED
        run.completed_at = now
        run.save(update_fields=["summary", "state", "completed_at"])
        record_transition(
            organization=organization,
            actor=actor,
            target_type="retentionrun",
            target_id=run.id,
            from_state=RetentionRun.State.RUNNING,
            to_state=RetentionRun.State.COMPLETED,
            revision=1,
        )
        return run


def decommission_organization(
    *,
    actor: ActorContext,
    confirmation: str,
    acknowledgement: str,
    reference_time: datetime | None = None,
) -> RetentionRun:
    """Irreversibly revoke tenant access while retaining required audit evidence."""
    now = reference_time or timezone.now()
    if actor.actor_type != "USER" or actor.credential_id is not None:
        raise ResourceNotFoundError("Governed record was not found")
    authorize_action(
        actor=actor,
        action=Action.RETENTION_MANAGE,
        repository_id=actor.repository_id,
    )
    with transaction.atomic():
        organization = (
            Organization.objects.select_for_update().filter(id=actor.organization_id).first()
        )
        if (
            organization is None
            or not hmac.compare_digest(confirmation, organization.slug)
            or not hmac.compare_digest(
                acknowledgement,
                f"DECOMMISSION {organization.slug}",
            )
        ):
            raise ResourceNotFoundError("Governed record was not found")
        request_hash = content_hash(
            {
                "organization_id": str(organization.id),
                "kind": RetentionRun.Kind.ORGANIZATION_DECOMMISSION,
                "confirmation": confirmation,
                "acknowledgement": acknowledgement,
            }
        )
        existing = RetentionRun.objects.filter(
            organization=organization,
            kind=RetentionRun.Kind.ORGANIZATION_DECOMMISSION,
            request_hash=request_hash,
        ).first()
        if existing is not None:
            return existing
        if organization.lifecycle_state != Organization.LifecycleState.ACTIVE:
            raise ResourceNotFoundError("Governed record was not found")
        run = RetentionRun.objects.create(
            organization=organization,
            kind=RetentionRun.Kind.ORGANIZATION_DECOMMISSION,
            state=RetentionRun.State.RUNNING,
            cutoff_at=now,
            dry_run=False,
            request_hash=request_hash,
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
        )

        from anva.core.models import SourceConnection

        sources = list(
            SourceConnection.objects.filter(organization=organization)
            .exclude(state=SourceConnection.State.REVOKED)
            .order_by("id")[: MAX_DECOMMISSION_SOURCES + 1]
        )
        if len(sources) > MAX_DECOMMISSION_SOURCES:
            raise ValueError("Organization source count exceeds the decommission safety bound")
        for source in sources:
            revoke_source_connection(
                actor=actor,
                source_connection_id=source.id,
                expected_revision=source.revision,
            )

        upload_authorizations = list(
            EvidenceUploadAuthorization.objects.select_for_update()
            .filter(
                organization=organization,
                state__in=(
                    EvidenceUploadAuthorization.State.ISSUED,
                    EvidenceUploadAuthorization.State.RECEIVING,
                    EvidenceUploadAuthorization.State.RECOVERING,
                ),
            )
            .order_by("id")[: MAX_DECOMMISSION_UPLOADS + 1]
        )
        if len(upload_authorizations) > MAX_DECOMMISSION_UPLOADS:
            raise ValueError("Organization upload count exceeds the decommission safety bound")
        recovering_upload_ids: list[uuid.UUID] = []
        revoked_uploads = 0
        for upload in upload_authorizations:
            if upload.state == EvidenceUploadAuthorization.State.ISSUED:
                upload.state = EvidenceUploadAuthorization.State.REVOKED
                upload.failure_code = "UPLOAD_ORGANIZATION_DECOMMISSIONED"
                upload.completed_at = now
                upload.save(update_fields=["state", "failure_code", "completed_at"])
                revoked_uploads += 1
                continue
            if upload.reserved_at is not None and now <= upload.reserved_at:
                upload.reserved_at = upload.reserved_at + timedelta(microseconds=1)
            else:
                upload.reserved_at = now
            upload.state = EvidenceUploadAuthorization.State.RECOVERING
            upload.save(update_fields=["state", "reserved_at"])
            recovering_upload_ids.append(upload.id)

        audit_actor = replace(actor, authorization_path="retention:organization-decommission")
        record_transition(
            organization=organization,
            actor=audit_actor,
            target_type="organization",
            target_id=organization.id,
            from_state=Organization.LifecycleState.ACTIVE,
            to_state=Organization.LifecycleState.DELETION_REQUESTED,
            revision=1,
        )
        organization.lifecycle_state = Organization.LifecycleState.DELETION_REQUESTED
        organization.deletion_requested_at = now
        organization.save(update_fields=["lifecycle_state", "deletion_requested_at", "updated_at"])

        counts = {
            "memberships_deactivated": Membership.objects.filter(
                organization=organization, is_active=True
            ).update(is_active=False, revision=F("revision") + 1, updated_at=now),
            "service_identities_deactivated": ServiceIdentity.objects.filter(
                organization=organization, is_active=True
            ).update(is_active=False, revision=F("revision") + 1, updated_at=now),
            "repositories_deactivated": Repository.objects.filter(
                organization=organization, is_active=True
            ).update(is_active=False),
            "tokens_revoked": RepositoryAccessToken.objects.filter(
                organization=organization, revoked_at__isnull=True
            ).update(revoked_at=now),
            "access_scopes_deactivated": AccessScope.objects.filter(
                organization=organization, is_active=True
            ).update(is_active=False, revision=F("revision") + 1, updated_at=now),
            "sources_revoked": len(sources),
            "upload_authorizations_revoked": revoked_uploads,
        }
        record_transition(
            organization=organization,
            actor=audit_actor,
            target_type="organization",
            target_id=organization.id,
            from_state=Organization.LifecycleState.DELETION_REQUESTED,
            to_state=Organization.LifecycleState.DECOMMISSIONED,
            revision=2,
        )
        organization.lifecycle_state = Organization.LifecycleState.DECOMMISSIONED
        organization.decommissioned_at = now
        organization.save(update_fields=["lifecycle_state", "decommissioned_at", "updated_at"])

    upload_cleaned, upload_failed = cleanup_decommissioned_upload_authorizations(
        organization_id=organization.id,
        authorization_ids=recovering_upload_ids,
    )
    blob_ids = _decommission_blob_candidates(organization=organization)
    deleted, failed = _delete_blob_batch(
        organization_id=organization.id,
        blob_ids=blob_ids,
        reason="organization_decommission",
    )
    with transaction.atomic():
        Organization.objects.select_for_update().get(id=organization.id)
        run = RetentionRun.objects.select_for_update().get(
            id=run.id,
            organization=organization,
        )
        run.summary = {
            **counts,
            "evidence_blob_candidates": len(blob_ids),
            "evidence_blob_bytes_deleted": deleted,
            "evidence_blob_bytes_delete_failed": failed,
            "upload_objects_cleaned": upload_cleaned,
            "upload_objects_cleanup_failed": upload_failed,
            "governed_history_retained": True,
            "restoration_requires_operator_backup": True,
        }
        cleanup_failed = failed + upload_failed
        run.state = RetentionRun.State.FAILED if cleanup_failed else RetentionRun.State.COMPLETED
        run.error_code = "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED" if cleanup_failed else ""
        run.completed_at = now
        run.save(update_fields=["summary", "state", "error_code", "completed_at"])
        return run


def retry_decommission_cleanup(
    *,
    actor: ActorContext,
    run_id: uuid.UUID,
    reference_time: datetime | None = None,
) -> RetentionRun:
    """Retry decommission storage cleanup through a system-only inactive-tenant path."""
    if (
        actor.actor_type != "SYSTEM"
        or actor.actor_id != "anva-retention-worker"
        or actor.credential_id is not None
        or actor.repository_id is not None
        or Action.RETENTION_MANAGE.value not in actor.credential_actions
    ):
        raise ResourceNotFoundError("Governed record was not found")
    now = reference_time or timezone.now()
    with transaction.atomic():
        organization = (
            Organization.objects.select_for_update()
            .filter(
                id=actor.organization_id,
                lifecycle_state=Organization.LifecycleState.DECOMMISSIONED,
            )
            .first()
        )
        if organization is None:
            raise ResourceNotFoundError("Governed record was not found")
        run = (
            RetentionRun.objects.select_for_update()
            .filter(
                id=run_id,
                organization=organization,
                kind=RetentionRun.Kind.ORGANIZATION_DECOMMISSION,
                state=RetentionRun.State.FAILED,
                error_code="DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED",
            )
            .first()
        )
        if run is None:
            raise ResourceNotFoundError("Governed record was not found")
        upload_ids = list(
            EvidenceUploadAuthorization.objects.filter(
                organization=organization,
                state=EvidenceUploadAuthorization.State.RECOVERING,
            )
            .order_by("id")
            .values_list("id", flat=True)[: MAX_DECOMMISSION_UPLOADS + 1]
        )
        if len(upload_ids) > MAX_DECOMMISSION_UPLOADS:
            raise ValueError("Organization upload count exceeds the decommission safety bound")

    upload_cleaned, upload_failed = cleanup_decommissioned_upload_authorizations(
        organization_id=organization.id,
        authorization_ids=upload_ids,
    )
    blob_ids = _decommission_blob_candidates(organization=organization)
    deleted, failed = _delete_blob_batch(
        organization_id=organization.id,
        blob_ids=blob_ids,
        reason="organization_decommission",
    )
    with transaction.atomic():
        Organization.objects.select_for_update().get(id=organization.id)
        run = RetentionRun.objects.select_for_update().get(id=run.id)
        cleanup_failed = failed + upload_failed
        run.summary = {
            **run.summary,
            "evidence_blob_candidates": len(blob_ids),
            "evidence_blob_bytes_deleted": deleted,
            "evidence_blob_bytes_delete_failed": failed,
            "upload_objects_cleaned": upload_cleaned,
            "upload_objects_cleanup_failed": upload_failed,
        }
        run.state = RetentionRun.State.FAILED if cleanup_failed else RetentionRun.State.COMPLETED
        run.error_code = "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED" if cleanup_failed else ""
        run.completed_at = now
        run.save(update_fields=["summary", "state", "error_code", "completed_at"])
        return run
