"""Single-use authorization and orchestration for evidence-byte ingestion."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import IO, Final

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    Evidence,
    EvidenceBlob,
    EvidenceRetentionEvent,
    EvidenceUploadAuthorization,
    Organization,
    PullRequest,
    Repository,
    content_hash,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.evidence_archive import (
    _SAFE_MESSAGES,
    DEFAULT_UPLOAD_LIMITS,
    GAP_ARCHIVE_BAD_FORMAT,
    GAP_ARCHIVE_PATH_INVALID,
    GAP_ARCHIVE_SPECIAL_FILE,
    GAP_MANIFEST_MALFORMED,
    GAP_MANIFEST_SCHEMA_INVALID,
    GAP_MANIFEST_TOO_LARGE,
    GAP_MEDIA_TYPE_NOT_ALLOWED,
    GAP_SECRET_PATTERN_DETECTED,
    GAP_UPLOAD_DIGEST_MISMATCH,
    GAP_UPLOAD_SIZE_MISMATCH,
    GAP_UPLOAD_TOO_LARGE,
    EvidenceUploadError,
    InspectedUpload,
    UploadLimits,
    _receive_and_inspect,
    _scan_secret_bytes,
    _UnsafeUploadError,
    _validate_digest,
    inspect_evidence_upload,
)
from anva.core.services.hostile_inputs import validate_full_commit
from anva.integrations.evidence_object_storage import (
    EvidenceObjectNotFoundError,
    EvidenceObjectOwnershipConflictError,
    EvidenceObjectStorage,
    EvidenceStorageError,
)

UPLOAD_TOKEN_PREFIX: Final = "anva_upload_v1"  # noqa: S105
UPLOAD_AUTHORIZATION_TTL: Final = timedelta(minutes=10)
RECOVERY_LEASE_TTL: Final = timedelta(minutes=10)
INSPECTION_VERSION: Final = "tst-007-bounded-upload-v1"
CLEANUP_RETRY_CODE: Final = "EVIDENCE_STORAGE_CLEANUP_RETRY_REQUIRED"

__all__ = [
    "DEFAULT_UPLOAD_LIMITS",
    "GAP_ARCHIVE_BAD_FORMAT",
    "GAP_ARCHIVE_PATH_INVALID",
    "GAP_ARCHIVE_SPECIAL_FILE",
    "GAP_MANIFEST_MALFORMED",
    "GAP_MANIFEST_SCHEMA_INVALID",
    "GAP_MANIFEST_TOO_LARGE",
    "GAP_SECRET_PATTERN_DETECTED",
    "GAP_UPLOAD_DIGEST_MISMATCH",
    "EvidenceObjectStorage",
    "EvidenceStorageError",
    "EvidenceUploadError",
    "InspectedUpload",
    "UploadAuthorizationGrant",
    "UploadLimits",
    "accept_evidence_upload",
    "cleanup_decommissioned_upload_authorizations",
    "delete_evidence_blob_bytes",
    "inspect_evidence_upload",
    "issue_upload_authorization",
    "recover_stale_upload_authorizations",
    "revoke_upload_authorization",
]


@dataclass(frozen=True, slots=True)
class UploadAuthorizationGrant:
    authorization: EvidenceUploadAuthorization
    raw_token: str | None = field(repr=False)
    replayed: bool = False


def _keyed_hash(*, domain: str, value: str) -> str:
    return hmac.new(
        str(settings.TOKEN_PEPPER).encode(),
        f"{domain}:{value}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _ownership_nonce(raw_token: str) -> str:
    return _keyed_hash(domain="evidence-upload-object-owner", value=raw_token)


def _ownership_nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()


def _owner_matches(stored_owner: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_ownership_nonce_hash(stored_owner), expected_hash)


def _validate_filename(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or unicodedata.normalize("NFC", value) != value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or ":" in value
        or value.endswith((" ", "."))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("filename must be a normalized safe basename")
    try:
        _scan_secret_bytes(value.encode())
    except _UnsafeUploadError as error:
        raise ValueError("filename contains credential material") from error
    return value


def _validate_idempotency_key(value: str) -> str:
    if not isinstance(value, str) or not 16 <= len(value) <= 200 or not value.strip():
        raise ValueError("idempotency_key must contain between 16 and 200 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("idempotency_key contains control characters")
    return value


def _build_upload_token(authorization_id: uuid.UUID) -> str:
    return f"{UPLOAD_TOKEN_PREFIX}.{authorization_id}.{secrets.token_urlsafe(32)}"


def _token_id(raw_token: str) -> uuid.UUID | None:
    prefix, separator, remainder = raw_token.partition(".")
    identifier, second_separator, secret = remainder.partition(".")
    if prefix != UPLOAD_TOKEN_PREFIX or separator != "." or second_separator != "." or not secret:
        return None
    try:
        return uuid.UUID(identifier)
    except ValueError:
        return None


@transaction.atomic
def issue_upload_authorization(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    pull_request_number: int,
    commit_sha: str,
    filename: str,
    declared_sha256: str,
    declared_size: int,
    idempotency_key: str,
) -> UploadAuthorizationGrant:
    """Issue one ten-minute, actor-bound upload secret; exact replays disclose no secret."""
    if isinstance(pull_request_number, bool) or pull_request_number < 1:
        raise ValueError("pull_request_number must be positive")
    validate_full_commit(commit_sha)
    filename = _validate_filename(filename)
    declared_sha256 = _validate_digest(declared_sha256)
    if (
        isinstance(declared_size, bool)
        or not isinstance(declared_size, int)
        or not 1 <= declared_size <= DEFAULT_UPLOAD_LIMITS.max_upload_bytes
    ):
        raise ValueError("declared_size must be between 1 and 4096")
    idempotency_key = _validate_idempotency_key(idempotency_key)
    decision = authorize_action(
        actor=actor,
        action=Action.EVIDENCE_SUBMIT,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
    )
    organization = (
        Organization.objects.select_for_update()
        .filter(
            id=actor.organization_id,
            lifecycle_state=Organization.LifecycleState.ACTIVE,
        )
        .first()
    )
    if organization is None:
        raise EvidenceUploadError("resource_not_found", NOT_FOUND_MESSAGE, 404)
    repository = get_tenant_record(
        queryset=Repository.objects.filter(is_active=True),
        record_id=repository_id,
        organization_id=actor.organization_id,
    )
    access_scope = get_tenant_record(
        queryset=AccessScope.objects.filter(is_active=True),
        record_id=access_scope_id,
        organization_id=actor.organization_id,
    )
    pull_request = (
        PullRequest.objects.select_for_update()
        .filter(
            organization=organization,
            repository=repository,
            number=pull_request_number,
        )
        .first()
    )
    if pull_request is None or not hmac.compare_digest(
        pull_request.current_head_commit,
        commit_sha,
    ):
        raise _authorization_unavailable()
    idempotency_hash = _keyed_hash(domain="evidence-upload-idempotency", value=idempotency_key)
    request_hash = content_hash(
        {
            "organization_id": str(actor.organization_id),
            "repository_id": str(repository_id),
            "access_scope_id": str(access_scope_id),
            "pull_request_number": pull_request_number,
            "commit_sha": commit_sha,
            "filename": filename,
            "declared_sha256": declared_sha256,
            "declared_size": declared_size,
            "actor_type": actor.actor_type,
            "actor_id": actor.actor_id,
            "credential_id": str(actor.credential_id) if actor.credential_id else None,
        }
    )
    existing = (
        EvidenceUploadAuthorization.objects.select_for_update()
        .filter(
            organization=organization,
            repository=repository,
            idempotency_hash=idempotency_hash,
        )
        .first()
    )
    if existing is not None:
        if existing.request_hash != request_hash:
            raise IdempotencyConflictError(
                "Evidence upload idempotency key was reused for different content"
            )
        return UploadAuthorizationGrant(existing, None, True)

    now = timezone.now()
    authorization_id = uuid.uuid4()
    raw_token = _build_upload_token(authorization_id)
    try:
        with transaction.atomic():
            authorization = EvidenceUploadAuthorization.objects.create(
                id=authorization_id,
                organization=organization,
                repository=repository,
                access_scope=access_scope,
                pull_request_number=pull_request_number,
                commit_sha=commit_sha,
                filename=filename,
                declared_sha256=declared_sha256,
                declared_size=declared_size,
                token_hash=_keyed_hash(domain="evidence-upload-token", value=raw_token),
                idempotency_hash=idempotency_hash,
                request_hash=request_hash,
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                credential_id=actor.credential_id,
                issued_at=now,
                expires_at=now + UPLOAD_AUTHORIZATION_TTL,
            )
    except IntegrityError:
        winner = EvidenceUploadAuthorization.objects.select_for_update().get(
            organization=organization,
            repository=repository,
            idempotency_hash=idempotency_hash,
        )
        if winner.request_hash != request_hash:
            raise IdempotencyConflictError(
                "Evidence upload idempotency key was reused for different content"
            ) from None
        return UploadAuthorizationGrant(winner, None, True)
    audit_actor = replace(actor, authorization_path=decision.authorization_path)
    record_transition(
        organization=organization,
        actor=audit_actor,
        target_type="evidenceuploadauthorization",
        target_id=authorization.id,
        from_state="",
        to_state=EvidenceUploadAuthorization.State.ISSUED,
        revision=1,
        metadata={
            "repository_id": str(repository.id),
            "content_hash": declared_sha256,
            "expires_at": authorization.expires_at.isoformat(),
            "kind": "EVIDENCE_UPLOAD",
        },
    )
    return UploadAuthorizationGrant(authorization, raw_token, False)


def _authorization_unavailable() -> EvidenceUploadError:
    return EvidenceUploadError(
        "UPLOAD_AUTHORIZATION_UNAVAILABLE",
        "Evidence upload authorization is unavailable.",
        404,
    )


def _actor_matches(authorization: EvidenceUploadAuthorization, actor: ActorContext) -> bool:
    return bool(
        authorization.organization_id == actor.organization_id
        and authorization.actor_type == actor.actor_type
        and hmac.compare_digest(authorization.actor_id, actor.actor_id)
        and authorization.credential_id == actor.credential_id
    )


def _reserve_authorization(
    *,
    authorization_id: uuid.UUID,
    raw_token: str,
    actor: ActorContext,
) -> EvidenceUploadAuthorization:
    expired = False
    with transaction.atomic():
        organization = (
            Organization.objects.select_for_update()
            .filter(
                id=actor.organization_id,
                lifecycle_state=Organization.LifecycleState.ACTIVE,
            )
            .first()
        )
        authorization = (
            EvidenceUploadAuthorization.objects.select_for_update()
            .select_related("repository", "access_scope")
            .filter(id=authorization_id, organization_id=actor.organization_id)
            .first()
        )
        supplied_hash = _keyed_hash(domain="evidence-upload-token", value=raw_token)
        stored_hash = authorization.token_hash if authorization is not None else "0" * 64
        if (
            organization is None
            or authorization is None
            or _token_id(raw_token) != authorization_id
            or not hmac.compare_digest(stored_hash, supplied_hash)
            or not _actor_matches(authorization, actor)
            or authorization.state != EvidenceUploadAuthorization.State.ISSUED
        ):
            raise _authorization_unavailable()
        decision = authorize_action(
            actor=actor,
            action=Action.EVIDENCE_SUBMIT,
            repository_id=authorization.repository_id,
            access_scope_id=authorization.access_scope_id,
        )
        now = timezone.now()
        audit_actor = replace(actor, authorization_path=decision.authorization_path)
        if authorization.expires_at <= now:
            authorization.state = EvidenceUploadAuthorization.State.EXPIRED
            authorization.failure_code = "UPLOAD_AUTHORIZATION_EXPIRED"
            authorization.completed_at = now
            authorization.save(update_fields=["state", "failure_code", "completed_at"])
            record_transition(
                organization=organization,
                actor=audit_actor,
                target_type="evidenceuploadauthorization",
                target_id=authorization.id,
                from_state=EvidenceUploadAuthorization.State.ISSUED,
                to_state=EvidenceUploadAuthorization.State.EXPIRED,
                revision=2,
                metadata={"failure_code": authorization.failure_code},
            )
            expired = True
        else:
            ownership_nonce = _ownership_nonce(raw_token)
            authorization.state = EvidenceUploadAuthorization.State.RECEIVING
            authorization.object_key = f"evidence/v1/{secrets.token_urlsafe(32)}"
            authorization.ownership_nonce_hash = _ownership_nonce_hash(ownership_nonce)
            authorization.reserved_at = now
            authorization.save(
                update_fields=[
                    "state",
                    "object_key",
                    "ownership_nonce_hash",
                    "reserved_at",
                ]
            )
            record_transition(
                organization=organization,
                actor=audit_actor,
                target_type="evidenceuploadauthorization",
                target_id=authorization.id,
                from_state=EvidenceUploadAuthorization.State.ISSUED,
                to_state=EvidenceUploadAuthorization.State.RECEIVING,
                revision=2,
                metadata={"repository_id": str(authorization.repository_id)},
            )
    if expired:
        raise _authorization_unavailable()
    return authorization


@transaction.atomic
def revoke_upload_authorization(
    *,
    authorization_id: uuid.UUID,
    actor: ActorContext,
) -> EvidenceUploadAuthorization:
    """Revoke an unused grant without disclosing whether another tenant owns it."""
    organization = (
        Organization.objects.select_for_update()
        .filter(
            id=actor.organization_id,
            lifecycle_state=Organization.LifecycleState.ACTIVE,
        )
        .first()
    )
    authorization = (
        EvidenceUploadAuthorization.objects.select_for_update()
        .filter(id=authorization_id, organization_id=actor.organization_id)
        .first()
    )
    if (
        organization is None
        or authorization is None
        or authorization.state != EvidenceUploadAuthorization.State.ISSUED
        or not _actor_matches(authorization, actor)
    ):
        raise _authorization_unavailable()
    decision = authorize_action(
        actor=actor,
        action=Action.EVIDENCE_SUBMIT,
        repository_id=authorization.repository_id,
        access_scope_id=authorization.access_scope_id,
    )
    authorization.state = EvidenceUploadAuthorization.State.REVOKED
    authorization.failure_code = "UPLOAD_AUTHORIZATION_REVOKED"
    authorization.completed_at = timezone.now()
    authorization.save(update_fields=["state", "failure_code", "completed_at"])
    record_transition(
        organization=organization,
        actor=replace(actor, authorization_path=decision.authorization_path),
        target_type="evidenceuploadauthorization",
        target_id=authorization.id,
        from_state=EvidenceUploadAuthorization.State.ISSUED,
        to_state=EvidenceUploadAuthorization.State.REVOKED,
        revision=2,
        metadata={"failure_code": authorization.failure_code},
    )
    return authorization


def _reject_reserved_authorization(
    *,
    authorization_id: uuid.UUID,
    actor: ActorContext,
    failure_code: str,
) -> None:
    if failure_code == CLEANUP_RETRY_CODE:
        # Keep the authorization retry-visible without claiming rejection while
        # its owned object might still exist. The bounded recovery worker will
        # retry cleanup and only then make the terminal transition.
        return
    safe_code = (
        failure_code[:100] if re.fullmatch(r"[A-Z0-9_]+", failure_code) else "UPLOAD_REJECTED"
    )
    with transaction.atomic():
        organization = (
            Organization.objects.select_for_update()
            .filter(
                id=actor.organization_id,
                lifecycle_state=Organization.LifecycleState.ACTIVE,
            )
            .first()
        )
        if organization is None:
            return
        authorization = (
            EvidenceUploadAuthorization.objects.select_for_update()
            .filter(id=authorization_id, organization_id=actor.organization_id)
            .first()
        )
        if (
            authorization is None
            or authorization.state != EvidenceUploadAuthorization.State.RECEIVING
        ):
            return
        decision = authorize_action(
            actor=actor,
            action=Action.EVIDENCE_SUBMIT,
            repository_id=authorization.repository_id,
            access_scope_id=authorization.access_scope_id,
        )
        authorization.state = EvidenceUploadAuthorization.State.REJECTED
        authorization.failure_code = safe_code
        authorization.completed_at = timezone.now()
        authorization.save(update_fields=["state", "failure_code", "completed_at"])
        record_transition(
            organization=organization,
            actor=replace(actor, authorization_path=decision.authorization_path),
            target_type="evidenceuploadauthorization",
            target_id=authorization.id,
            from_state=EvidenceUploadAuthorization.State.RECEIVING,
            to_state=EvidenceUploadAuthorization.State.REJECTED,
            revision=3,
            metadata={"failure_code": safe_code},
        )


def _cleanup_owned_object(
    storage: EvidenceObjectStorage,
    authorization: EvidenceUploadAuthorization,
) -> bool:
    """Delete only bytes whose owner metadata matches this authorization."""
    try:
        _, _, stored_owner = storage.head(object_key=authorization.object_key)
    except EvidenceObjectNotFoundError:
        return True
    except EvidenceStorageError:
        return False
    if not _owner_matches(stored_owner, authorization.ownership_nonce_hash):
        return False
    try:
        storage.delete(object_key=authorization.object_key)
    except EvidenceStorageError:
        return False
    return True


def _unsafe_status(code: str) -> int:
    if code == GAP_UPLOAD_TOO_LARGE:
        return 413
    if code == GAP_MEDIA_TYPE_NOT_ALLOWED:
        return 415
    if code in {
        GAP_UPLOAD_SIZE_MISMATCH,
        GAP_UPLOAD_DIGEST_MISMATCH,
        GAP_MANIFEST_MALFORMED,
    }:
        return 400
    return 422


def accept_evidence_upload(
    *,
    authorization_id: uuid.UUID,
    raw_token: str,
    actor: ActorContext,
    stream: IO[bytes],
    content_length: int | None,
    expected_sha256: str,
) -> EvidenceBlob:
    """Consume one upload token before bounded inspection and fail-clean finalization."""
    if not isinstance(raw_token, str) or not raw_token:
        raise _authorization_unavailable()
    authorization = _reserve_authorization(
        authorization_id=authorization_id,
        raw_token=raw_token,
        actor=actor,
    )
    ownership_nonce = _ownership_nonce(raw_token)
    if not _owner_matches(ownership_nonce, authorization.ownership_nonce_hash):
        _reject_reserved_authorization(
            authorization_id=authorization.id,
            actor=actor,
            failure_code="UPLOAD_OWNER_INVALID",
        )
        raise _authorization_unavailable()
    try:
        expected_sha256 = _validate_digest(expected_sha256)
    except ValueError:
        _reject_reserved_authorization(
            authorization_id=authorization.id,
            actor=actor,
            failure_code=GAP_UPLOAD_DIGEST_MISMATCH,
        )
        raise EvidenceUploadError(
            GAP_UPLOAD_DIGEST_MISMATCH,
            _SAFE_MESSAGES[GAP_UPLOAD_DIGEST_MISMATCH],
        ) from None
    if not hmac.compare_digest(expected_sha256, authorization.declared_sha256):
        _reject_reserved_authorization(
            authorization_id=authorization.id,
            actor=actor,
            failure_code=GAP_UPLOAD_DIGEST_MISMATCH,
        )
        raise EvidenceUploadError(
            GAP_UPLOAD_DIGEST_MISMATCH,
            _SAFE_MESSAGES[GAP_UPLOAD_DIGEST_MISMATCH],
        )
    spool: IO[bytes] | None = None
    storage: EvidenceObjectStorage | None = None
    try:
        spool, inspected = _receive_and_inspect(
            stream,
            content_length=content_length,
            expected_size=authorization.declared_size,
            expected_sha256=authorization.declared_sha256,
            commit_sha=authorization.commit_sha,
            limits=DEFAULT_UPLOAD_LIMITS,
        )
    except _UnsafeUploadError as error:
        _reject_reserved_authorization(
            authorization_id=authorization.id,
            actor=actor,
            failure_code=error.code,
        )
        raise EvidenceUploadError(
            error.code,
            _SAFE_MESSAGES[error.code],
            _unsafe_status(error.code),
        ) from None
    except Exception as error:
        _reject_reserved_authorization(
            authorization_id=authorization.id,
            actor=actor,
            failure_code="UPLOAD_STREAM_FAILED",
        )
        raise EvidenceUploadError(
            "UPLOAD_STREAM_FAILED",
            "Evidence upload streaming failed.",
            400,
        ) from error

    try:
        storage = EvidenceObjectStorage()
        try:
            storage.put(
                object_key=authorization.object_key,
                stream=spool,
                size=inspected.verified_size,
                sha256=inspected.content_hash,
                media_type=inspected.detected_media_type,
                ownership_nonce=ownership_nonce,
            )
            stored_size, stored_metadata_hash, stored_owner = storage.head(
                object_key=authorization.object_key
            )
            read_size, read_hash = storage.get_digest(
                object_key=authorization.object_key,
                max_bytes=DEFAULT_UPLOAD_LIMITS.max_upload_bytes,
            )
            if (
                stored_size != inspected.verified_size
                or read_size != inspected.verified_size
                or not hmac.compare_digest(stored_metadata_hash, inspected.content_hash)
                or not _owner_matches(stored_owner, authorization.ownership_nonce_hash)
                or not hmac.compare_digest(read_hash, inspected.content_hash)
            ):
                raise EvidenceStorageError("EVIDENCE_STORAGE_VERIFY_FAILED")
        except EvidenceObjectOwnershipConflictError as error:
            _reject_reserved_authorization(
                authorization_id=authorization.id,
                actor=actor,
                failure_code=error.code,
            )
            raise
        except EvidenceStorageError as error:
            cleaned = _cleanup_owned_object(storage, authorization)
            _reject_reserved_authorization(
                authorization_id=authorization.id,
                actor=actor,
                failure_code=(error.code if cleaned else CLEANUP_RETRY_CODE),
            )
            raise

        try:
            with transaction.atomic():
                organization = (
                    Organization.objects.select_for_update()
                    .filter(
                        id=actor.organization_id,
                        lifecycle_state=Organization.LifecycleState.ACTIVE,
                    )
                    .first()
                )
                if organization is None:
                    raise _authorization_unavailable()
                locked = EvidenceUploadAuthorization.objects.select_for_update().get(
                    id=authorization.id, organization_id=actor.organization_id
                )
                if (
                    locked.state != EvidenceUploadAuthorization.State.RECEIVING
                    or locked.object_key != authorization.object_key
                    or not _actor_matches(locked, actor)
                ):
                    raise _authorization_unavailable()
                decision = authorize_action(
                    actor=actor,
                    action=Action.EVIDENCE_SUBMIT,
                    repository_id=locked.repository_id,
                    access_scope_id=locked.access_scope_id,
                )
                blob = EvidenceBlob.objects.create(
                    organization=organization,
                    repository_id=locked.repository_id,
                    access_scope_id=locked.access_scope_id,
                    upload_authorization=locked,
                    object_key=locked.object_key,
                    content_hash=inspected.content_hash,
                    verified_size=inspected.verified_size,
                    detected_media_type=inspected.detected_media_type,
                    archive_summary=inspected.archive_summary,
                    inspection_version=INSPECTION_VERSION,
                    storage_state=EvidenceBlob.StorageState.AVAILABLE,
                )
                locked.state = EvidenceUploadAuthorization.State.ACCEPTED
                locked.completed_at = timezone.now()
                locked.save(update_fields=["state", "completed_at"])
                record_transition(
                    organization=organization,
                    actor=replace(actor, authorization_path=decision.authorization_path),
                    target_type="evidenceuploadauthorization",
                    target_id=locked.id,
                    from_state=EvidenceUploadAuthorization.State.RECEIVING,
                    to_state=EvidenceUploadAuthorization.State.ACCEPTED,
                    revision=3,
                    metadata={
                        "content_hash": blob.content_hash,
                        "kind": blob.detected_media_type,
                        "repository_id": str(blob.repository_id),
                    },
                )
        except EvidenceUploadError:
            _cleanup_owned_object(storage, authorization)
            raise
        except Exception as error:
            cleaned = _cleanup_owned_object(storage, authorization)
            _reject_reserved_authorization(
                authorization_id=authorization.id,
                actor=actor,
                failure_code=("UPLOAD_FINALIZATION_FAILED" if cleaned else CLEANUP_RETRY_CODE),
            )
            raise EvidenceUploadError(
                "UPLOAD_FINALIZATION_FAILED",
                "Evidence upload finalization failed.",
                503,
            ) from error
        return blob
    except EvidenceStorageError as error:
        if storage is None:
            _reject_reserved_authorization(
                authorization_id=authorization.id,
                actor=actor,
                failure_code=error.code,
            )
        raise
    except EvidenceUploadError:
        raise
    except Exception as error:
        _reject_reserved_authorization(
            authorization_id=authorization.id,
            actor=actor,
            failure_code="EVIDENCE_STORAGE_UNAVAILABLE",
        )
        raise EvidenceUploadError(
            "EVIDENCE_STORAGE_UNAVAILABLE",
            "Evidence object storage is unavailable.",
            503,
        ) from error
    finally:
        if spool is not None:
            spool.close()


def delete_evidence_blob_bytes(
    *,
    organization_id: uuid.UUID,
    blob_id: uuid.UUID,
    reason: str,
    retention_cutoff: datetime | None = None,
    retention_reference_time: datetime | None = None,
) -> EvidenceBlob:
    """Delete exact blob bytes with a retryable, database-guarded lifecycle."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", reason):
        raise ValueError("Deletion reason must be a stable lowercase code")
    if (retention_cutoff is None) != (retention_reference_time is None):
        raise ValueError("Retention cutoff and reference time must be supplied together")
    with transaction.atomic():
        organization = Organization.objects.select_for_update().filter(id=organization_id).first()
        if organization is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        if (
            retention_cutoff is not None
            and organization.lifecycle_state != Organization.LifecycleState.ACTIVE
        ):
            raise EvidenceUploadError(
                "EVIDENCE_BLOB_DELETE_INELIGIBLE",
                "Evidence blob is not eligible for deletion.",
                409,
            )
        blob = get_tenant_record(
            queryset=EvidenceBlob.objects.select_for_update().select_related(
                "upload_authorization"
            ),
            record_id=blob_id,
            organization_id=organization.id,
        )
        if blob.storage_state == EvidenceBlob.StorageState.DELETED:
            return blob
        if blob.storage_state not in {
            EvidenceBlob.StorageState.AVAILABLE,
            EvidenceBlob.StorageState.DELETE_PENDING,
            EvidenceBlob.StorageState.DELETE_FAILED,
        }:
            raise EvidenceUploadError(
                "EVIDENCE_BLOB_DELETE_IN_PROGRESS",
                "Evidence blob deletion is already in progress.",
                409,
            )
        if retention_cutoff is not None and retention_reference_time is not None:
            evidence = (
                Evidence.objects.select_for_update()
                .filter(organization=organization, artifact_blob=blob)
                .first()
            )
            if evidence is None:
                eligible = (
                    blob.upload_authorization.state == EvidenceUploadAuthorization.State.ACCEPTED
                    and blob.created_at <= retention_cutoff
                )
            else:
                retention_events = list(
                    EvidenceRetentionEvent.objects.select_for_update()
                    .filter(organization=organization, evidence=evidence)
                    .order_by("-occurred_at", "-id")
                )
                latest_state = retention_events[0].state if retention_events else None
                eligible = (
                    evidence.completed_at <= retention_cutoff
                    and evidence.retention_expires_at is not None
                    and evidence.retention_expires_at <= retention_reference_time
                    and latest_state == Evidence.RetentionState.EXPIRED
                )
            if not eligible:
                raise EvidenceUploadError(
                    "EVIDENCE_BLOB_DELETE_INELIGIBLE",
                    "Evidence blob is not eligible for deletion.",
                    409,
                )
        if blob.storage_state != EvidenceBlob.StorageState.DELETE_PENDING:
            blob.storage_state = EvidenceBlob.StorageState.DELETE_PENDING
            blob.deletion_reason = reason
            blob.storage_error_code = ""
            blob.save(update_fields=["storage_state", "deletion_reason", "storage_error_code"])

    try:
        storage = EvidenceObjectStorage()
        try:
            _, _, stored_owner = storage.head(object_key=blob.object_key)
        except EvidenceObjectNotFoundError:
            stored_owner = None
        if stored_owner is not None:
            if not _owner_matches(
                stored_owner,
                blob.upload_authorization.ownership_nonce_hash,
            ):
                raise EvidenceObjectOwnershipConflictError()
            storage.delete(object_key=blob.object_key)
    except EvidenceStorageError as error:
        with transaction.atomic():
            Organization.objects.select_for_update().get(id=organization_id)
            failed = EvidenceBlob.objects.select_for_update().get(
                id=blob.id,
                organization_id=organization_id,
            )
            if failed.storage_state == EvidenceBlob.StorageState.DELETED:
                return failed
            if failed.storage_state != EvidenceBlob.StorageState.DELETE_PENDING:
                raise EvidenceUploadError(
                    "EVIDENCE_BLOB_DELETE_IN_PROGRESS",
                    "Evidence blob deletion is already in progress.",
                    409,
                ) from error
            failed.storage_state = EvidenceBlob.StorageState.DELETE_FAILED
            failed.storage_error_code = error.code
            failed.save(update_fields=["storage_state", "storage_error_code"])
        raise

    with transaction.atomic():
        Organization.objects.select_for_update().get(id=organization_id)
        deleted = EvidenceBlob.objects.select_for_update().get(
            id=blob.id,
            organization_id=organization_id,
        )
        if deleted.storage_state == EvidenceBlob.StorageState.DELETED:
            return deleted
        if deleted.storage_state == EvidenceBlob.StorageState.DELETE_FAILED:
            deleted.storage_state = EvidenceBlob.StorageState.DELETE_PENDING
            deleted.storage_error_code = ""
            deleted.save(update_fields=["storage_state", "storage_error_code"])
        if deleted.storage_state != EvidenceBlob.StorageState.DELETE_PENDING:
            raise EvidenceUploadError(
                "EVIDENCE_BLOB_DELETE_IN_PROGRESS",
                "Evidence blob deletion is already in progress.",
                409,
            )
        deleted.storage_state = EvidenceBlob.StorageState.DELETED
        deleted.deleted_at = timezone.now()
        deleted.storage_error_code = ""
        deleted.save(update_fields=["storage_state", "deleted_at", "storage_error_code"])
        return deleted


def recover_stale_upload_authorizations(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    before: datetime,
    limit: int = 100,
) -> int:
    """Claim and clean one exact repository/scope batch of stale upload attempts."""
    if not 1 <= limit <= 1_000:
        raise ValueError("limit must be between 1 and 1000")
    decision = authorize_action(
        actor=actor,
        action=Action.EVIDENCE_SUBMIT,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
    )
    recovery_lease_cutoff = timezone.now() - RECOVERY_LEASE_TTL
    candidate_ids = list(
        EvidenceUploadAuthorization.objects.filter(
            organization_id=actor.organization_id,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
        )
        .filter(
            Q(
                state=EvidenceUploadAuthorization.State.RECEIVING,
                reserved_at__lt=before,
            )
            | Q(
                state=EvidenceUploadAuthorization.State.RECOVERING,
                reserved_at__lt=recovery_lease_cutoff,
            )
        )
        .order_by("reserved_at", "id")
        .values_list("id", flat=True)[:limit]
    )
    cleaned = 0
    for authorization_id in candidate_ids:
        lease_started_at = timezone.now()
        with transaction.atomic():
            organization = (
                Organization.objects.select_for_update()
                .filter(
                    id=actor.organization_id,
                    lifecycle_state=Organization.LifecycleState.ACTIVE,
                )
                .first()
            )
            if organization is None:
                break
            recovery_lease_cutoff = timezone.now() - RECOVERY_LEASE_TTL
            authorization = (
                EvidenceUploadAuthorization.objects.select_for_update()
                .filter(
                    id=authorization_id,
                    organization=organization,
                    repository_id=repository_id,
                    access_scope_id=access_scope_id,
                )
                .filter(
                    Q(
                        state=EvidenceUploadAuthorization.State.RECEIVING,
                        reserved_at__lt=before,
                    )
                    | Q(
                        state=EvidenceUploadAuthorization.State.RECOVERING,
                        reserved_at__lt=recovery_lease_cutoff,
                    )
                )
                .first()
            )
            if authorization is None:
                continue
            from_state = authorization.state
            authorization.state = EvidenceUploadAuthorization.State.RECOVERING
            authorization.reserved_at = lease_started_at
            authorization.save(update_fields=["state", "reserved_at"])
        try:
            storage = EvidenceObjectStorage()
            object_clean = _cleanup_owned_object(storage, authorization)
        except EvidenceUploadError:
            object_clean = False
        if not object_clean:
            continue
        with transaction.atomic():
            organization = (
                Organization.objects.select_for_update().filter(id=actor.organization_id).first()
            )
            if organization is None:
                continue
            locked = (
                EvidenceUploadAuthorization.objects.select_for_update()
                .filter(
                    id=authorization.id,
                    organization=organization,
                    repository_id=repository_id,
                    access_scope_id=access_scope_id,
                    state=EvidenceUploadAuthorization.State.RECOVERING,
                    reserved_at=lease_started_at,
                )
                .first()
            )
            if locked is None:
                continue
            locked.state = EvidenceUploadAuthorization.State.REJECTED
            locked.failure_code = "UPLOAD_RECEIVING_STALE"
            locked.completed_at = timezone.now()
            locked.save(update_fields=["state", "failure_code", "completed_at"])
            record_transition(
                organization=organization,
                actor=replace(actor, authorization_path=decision.authorization_path),
                target_type="evidenceuploadauthorization",
                target_id=locked.id,
                from_state=from_state,
                to_state=EvidenceUploadAuthorization.State.REJECTED,
                revision=4,
                metadata={"repository_id": str(repository_id)},
            )
            cleaned += 1
    return cleaned


def cleanup_decommissioned_upload_authorizations(
    *,
    organization_id: uuid.UUID,
    authorization_ids: list[uuid.UUID],
) -> tuple[int, int]:
    """System cleanup for upload objects claimed before tenant access was revoked."""
    if len(authorization_ids) > 10_000:
        raise ValueError("Decommission upload cleanup exceeds the 10,000-record bound")
    cleaned = 0
    failed = 0
    for authorization_id in authorization_ids:
        lease_started_at = timezone.now()
        with transaction.atomic():
            organization = (
                Organization.objects.select_for_update()
                .filter(
                    id=organization_id,
                    lifecycle_state=Organization.LifecycleState.DECOMMISSIONED,
                )
                .first()
            )
            if organization is None:
                raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
            authorization = (
                EvidenceUploadAuthorization.objects.select_for_update()
                .filter(
                    id=authorization_id,
                    organization=organization,
                    state=EvidenceUploadAuthorization.State.RECOVERING,
                )
                .first()
            )
            if authorization is None:
                continue
            if (
                authorization.reserved_at is not None
                and lease_started_at <= authorization.reserved_at
            ):
                lease_started_at = authorization.reserved_at + timedelta(microseconds=1)
            authorization.reserved_at = lease_started_at
            authorization.save(update_fields=["state", "reserved_at"])
        try:
            object_clean = _cleanup_owned_object(EvidenceObjectStorage(), authorization)
        except EvidenceUploadError:
            object_clean = False
        if not object_clean:
            failed += 1
            continue
        with transaction.atomic():
            organization = Organization.objects.select_for_update().get(id=organization_id)
            locked = (
                EvidenceUploadAuthorization.objects.select_for_update()
                .filter(
                    id=authorization_id,
                    organization=organization,
                    state=EvidenceUploadAuthorization.State.RECOVERING,
                    reserved_at=lease_started_at,
                )
                .first()
            )
            if locked is None:
                continue
            locked.state = EvidenceUploadAuthorization.State.REJECTED
            locked.failure_code = "UPLOAD_ORGANIZATION_DECOMMISSIONED"
            locked.completed_at = timezone.now()
            locked.save(update_fields=["state", "failure_code", "completed_at"])
            cleaned += 1
    return cleaned, failed
