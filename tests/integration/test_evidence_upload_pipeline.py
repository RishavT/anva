"""Accepted upload orchestration fails closed across API, DB, and object storage."""

from __future__ import annotations

import hashlib
import io
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from typing import IO
from unittest.mock import patch

import pytest
from django.db import IntegrityError, connection, transaction
from django.test import Client
from django.utils import timezone

from anva.core.models import (
    AccessScope,
    EvidenceBlob,
    EvidenceUploadAuthorization,
    Membership,
    Organization,
    PullRequest,
    Repository,
    Role,
    User,
)
from anva.core.services.context import ActorContext
from anva.core.services.evidence_uploads import (
    EvidenceUploadError,
    UploadAuthorizationGrant,
    accept_evidence_upload,
    delete_evidence_blob_bytes,
    issue_upload_authorization,
    recover_stale_upload_authorizations,
    revoke_upload_authorization,
)
from anva.core.services.operations import decommission_organization
from anva.integrations.evidence_object_storage import (
    EvidenceObjectNotFoundError,
    EvidenceObjectOwnershipConflictError,
    EvidenceObjectStorage,
    EvidenceStorageError,
)

pytestmark = [pytest.mark.integration, pytest.mark.django_db(transaction=True)]

HEAD = "a" * 40


@dataclass(frozen=True, slots=True)
class UploadTenant:
    organization: Organization
    repository: Repository
    scope: AccessScope
    pull_request: PullRequest
    actor: ActorContext


@dataclass(slots=True)
class FakeEvidenceStorage:
    objects: dict[str, tuple[bytes, str, str]] = field(default_factory=dict)
    put_error: EvidenceStorageError | None = None
    head_error: EvidenceStorageError | None = None
    get_error: EvidenceStorageError | None = None
    delete_error: EvidenceStorageError | None = None
    force_conflict: bool = False
    put_entered: threading.Event | None = None
    release_put: threading.Event | None = None
    put_calls: int = 0
    delete_calls: int = 0

    def put(
        self,
        *,
        object_key: str,
        stream: IO[bytes],
        size: int,
        sha256: str,
        media_type: str,
        ownership_nonce: str,
    ) -> None:
        del media_type
        self.put_calls += 1
        if self.force_conflict:
            self.objects[object_key] = (b"foreign", hashlib.sha256(b"foreign").hexdigest(), "x")
            raise EvidenceObjectOwnershipConflictError()
        if self.put_error is not None:
            raise self.put_error
        stream.seek(0)
        value = stream.read(size + 1)
        assert len(value) == size
        assert hashlib.sha256(value).hexdigest() == sha256
        self.objects[object_key] = (value, sha256, ownership_nonce)
        if self.put_entered is not None:
            self.put_entered.set()
        if self.release_put is not None:
            assert self.release_put.wait(timeout=10)

    def head(self, *, object_key: str) -> tuple[int, str, str]:
        if self.head_error is not None:
            raise self.head_error
        try:
            value, digest, owner = self.objects[object_key]
        except KeyError:
            raise EvidenceObjectNotFoundError() from None
        return len(value), digest, owner

    def get_digest(self, *, object_key: str, max_bytes: int) -> tuple[int, str]:
        if self.get_error is not None:
            raise self.get_error
        try:
            value, _digest, _owner = self.objects[object_key]
        except KeyError:
            raise EvidenceStorageError("EVIDENCE_STORAGE_GET_FAILED") from None
        if len(value) > max_bytes:
            raise EvidenceStorageError("EVIDENCE_STORAGE_VERIFY_FAILED")
        return len(value), hashlib.sha256(value).hexdigest()

    def delete(self, *, object_key: str) -> None:
        self.delete_calls += 1
        if self.delete_error is not None:
            raise self.delete_error
        self.objects.pop(object_key, None)


def make_tenant(label: str = "upload") -> UploadTenant:
    organization = Organization.objects.create(
        slug=f"evidence-upload-{label}-{uuid.uuid4()}",
        name="Evidence upload test",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:evidence-upload/{uuid.uuid4()}",
        name="Evidence upload repository",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="evidence-upload-visible",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Org admin",
    )
    user = User.objects.create(
        email=f"evidence-upload-{uuid.uuid4()}@example.test",
        display_name="Evidence upload admin",
    )
    Membership.objects.create(organization=organization, user=user, role=role)
    pull_request = PullRequest.objects.create(
        organization=organization,
        repository=repository,
        number=17,
        current_head_commit=HEAD,
    )
    return UploadTenant(
        organization=organization,
        repository=repository,
        scope=scope,
        pull_request=pull_request,
        actor=ActorContext(
            organization_id=organization.id,
            actor_type="USER",
            actor_id=str(user.id),
            authorization_path="test",
            request_id=uuid.uuid4(),
        ),
    )


def evidence_json(*, head: str = HEAD, secret: bool = False) -> bytes:
    check_name = "unit"
    if secret:
        check_name = "ghp_TST007_pipeline_secret_canary_7H2K9M4P"
    return json.dumps(
        {
            "schema_version": 1,
            "head_sha": head,
            "checks": [{"name": check_name, "status": "PASSED"}],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def issue(
    tenant: UploadTenant,
    value: bytes,
    *,
    idempotency_key: str | None = None,
) -> UploadAuthorizationGrant:
    return issue_upload_authorization(
        actor=tenant.actor,
        repository_id=tenant.repository.id,
        access_scope_id=tenant.scope.id,
        pull_request_number=17,
        commit_sha=HEAD,
        filename="evidence.json",
        declared_sha256=hashlib.sha256(value).hexdigest(),
        declared_size=len(value),
        idempotency_key=idempotency_key or f"evidence-upload-{uuid.uuid4()}",
    )


def accept(
    grant: UploadAuthorizationGrant,
    tenant: UploadTenant,
    value: bytes,
) -> EvidenceBlob:
    assert grant.raw_token is not None
    return accept_evidence_upload(
        authorization_id=grant.authorization.id,
        raw_token=grant.raw_token,
        actor=tenant.actor,
        stream=io.BytesIO(value),
        content_length=len(value),
        expected_sha256=hashlib.sha256(value).hexdigest(),
    )


def test_api_success_replay_and_idempotent_authorization_create_one_blob(client: Client) -> None:
    tenant = make_tenant("api-success")
    value = evidence_json()
    digest = hashlib.sha256(value).hexdigest()
    storage = FakeEvidenceStorage()
    path = (
        f"/api/v1/repositories/{tenant.repository.id}/pull-requests/17/"
        "evidence-upload-authorizations"
    )
    payload = {
        "schema_version": "1.0",
        "access_scope_id": str(tenant.scope.id),
        "commit_sha": HEAD,
        "filename": "evidence.json",
        "declared_sha256": digest,
        "declared_size": len(value),
        "idempotency_key": "api-success-upload-0001",
    }
    with patch("anva.core.views._actor", return_value=tenant.actor):
        first = client.post(path, data=json.dumps(payload), content_type="application/json")
        replay = client.post(path, data=json.dumps(payload), content_type="application/json")
    assert first.status_code == 201
    assert replay.status_code == 200
    assert replay.json()["authorization_id"] == first.json()["authorization_id"]
    assert replay.json()["upload_token"] is None
    raw_token = first.json()["upload_token"]
    assert isinstance(raw_token, str)

    upload_path = first.json()["upload_path"]
    with (
        patch("anva.core.views._actor", return_value=tenant.actor),
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
    ):
        accepted = client.put(
            upload_path,
            data=value,
            content_type="application/octet-stream",
            HTTP_X_ANVA_EVIDENCE_UPLOAD_TOKEN=raw_token,
            HTTP_X_ANVA_CONTENT_SHA256=digest,
        )
        consumed = client.put(
            upload_path,
            data=value,
            content_type="application/octet-stream",
            HTTP_X_ANVA_EVIDENCE_UPLOAD_TOKEN=raw_token,
            HTTP_X_ANVA_CONTENT_SHA256=digest,
        )

    assert accepted.status_code == 201
    assert consumed.status_code == 404
    assert consumed.json()["code"] == "UPLOAD_AUTHORIZATION_UNAVAILABLE"
    assert EvidenceBlob.objects.count() == 1
    authorization = EvidenceUploadAuthorization.objects.get(id=first.json()["authorization_id"])
    assert authorization.state == EvidenceUploadAuthorization.State.ACCEPTED
    assert raw_token not in authorization.token_hash
    assert storage.put_calls == 1


@pytest.mark.parametrize(("pull_request_number", "head"), [(18, HEAD), (17, "b" * 40)])
def test_authorization_requires_real_current_pull_request_without_disclosure(
    pull_request_number: int,
    head: str,
) -> None:
    tenant = make_tenant("pr-binding")
    value = evidence_json()

    with pytest.raises(EvidenceUploadError) as raised:
        issue_upload_authorization(
            actor=tenant.actor,
            repository_id=tenant.repository.id,
            access_scope_id=tenant.scope.id,
            pull_request_number=pull_request_number,
            commit_sha=head,
            filename="evidence.json",
            declared_sha256=hashlib.sha256(value).hexdigest(),
            declared_size=len(value),
            idempotency_key=f"pr-binding-{pull_request_number}-{head}",
        )

    assert raised.value.code == "UPLOAD_AUTHORIZATION_UNAVAILABLE"
    assert raised.value.http_status == 404
    assert not EvidenceUploadAuthorization.objects.exists()


def test_pull_request_head_update_wins_lock_before_authorization() -> None:
    tenant = make_tenant("pr-head-race")
    value = evidence_json()
    head_locked = threading.Event()
    release_head = threading.Event()
    issue_started = threading.Event()

    def move_head() -> None:
        try:
            with transaction.atomic():
                pull_request = PullRequest.objects.select_for_update().get(
                    id=tenant.pull_request.id
                )
                pull_request.current_head_commit = "b" * 40
                pull_request.save(update_fields=["current_head_commit", "updated_at"])
                head_locked.set()
                assert release_head.wait(timeout=10)
        finally:
            connection.close()

    def issue_stale_head() -> UploadAuthorizationGrant:
        try:
            issue_started.set()
            return issue(tenant, value)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        moving = executor.submit(move_head)
        assert head_locked.wait(timeout=10)
        issuing = executor.submit(issue_stale_head)
        assert issue_started.wait(timeout=10)
        release_head.set()
        moving.result(timeout=10)
        with pytest.raises(EvidenceUploadError) as raised:
            issuing.result(timeout=10)

    assert raised.value.code == "UPLOAD_AUTHORIZATION_UNAVAILABLE"
    assert not EvidenceUploadAuthorization.objects.exists()


def test_concurrent_token_use_accepts_only_one_upload() -> None:
    tenant = make_tenant("race")
    value = evidence_json()
    grant = issue(tenant, value)
    entered = threading.Event()
    release = threading.Event()
    storage = FakeEvidenceStorage(put_entered=entered, release_put=release)

    def first_upload() -> EvidenceBlob:
        try:
            return accept(grant, tenant, value)
        finally:
            connection.close()

    with patch(
        "anva.core.services.evidence_uploads.EvidenceObjectStorage",
        return_value=storage,
    ):
        with ThreadPoolExecutor(max_workers=1) as executor:
            winner = executor.submit(first_upload)
            assert entered.wait(timeout=10)
            with pytest.raises(EvidenceUploadError) as loser:
                accept(grant, tenant, value)
            release.set()
            blob = winner.result(timeout=10)

    assert loser.value.code == "UPLOAD_AUTHORIZATION_UNAVAILABLE"
    assert EvidenceBlob.objects.filter(id=blob.id).count() == 1
    assert storage.put_calls == 1


def test_revoke_is_terminal_and_never_reaches_object_storage() -> None:
    tenant = make_tenant("revoke")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = FakeEvidenceStorage()

    revoked = revoke_upload_authorization(
        authorization_id=grant.authorization.id,
        actor=tenant.actor,
    )
    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        pytest.raises(EvidenceUploadError) as raised,
    ):
        accept(grant, tenant, value)

    assert revoked.state == EvidenceUploadAuthorization.State.REVOKED
    assert raised.value.code == "UPLOAD_AUTHORIZATION_UNAVAILABLE"
    assert storage.put_calls == 0
    assert not EvidenceBlob.objects.exists()


class DisconnectingStream:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, size: int = -1) -> bytes:
        del size
        self.calls += 1
        if self.calls == 1:
            return b"{"
        raise OSError("client disconnected")


def test_client_disconnect_is_terminal_without_object_or_blob() -> None:
    tenant = make_tenant("disconnect")
    value = evidence_json()
    grant = issue(tenant, value)
    assert grant.raw_token is not None
    storage = FakeEvidenceStorage()

    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        pytest.raises(EvidenceUploadError) as raised,
    ):
        accept_evidence_upload(
            authorization_id=grant.authorization.id,
            raw_token=grant.raw_token,
            actor=tenant.actor,
            stream=DisconnectingStream(),  # type: ignore[arg-type]
            content_length=len(value),
            expected_sha256=hashlib.sha256(value).hexdigest(),
        )

    grant.authorization.refresh_from_db()
    assert raised.value.code == "UPLOAD_STREAM_FAILED"
    assert grant.authorization.state == EvidenceUploadAuthorization.State.REJECTED
    assert storage.put_calls == 0
    assert not EvidenceBlob.objects.exists()


@pytest.mark.parametrize("failure_point", ["put", "head"])
def test_object_store_failure_never_claims_acceptance(failure_point: str) -> None:
    tenant = make_tenant(f"storage-{failure_point}")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = FakeEvidenceStorage()
    if failure_point == "put":
        storage.put_error = EvidenceStorageError("EVIDENCE_STORAGE_PUT_FAILED")
    else:
        storage.head_error = EvidenceStorageError("EVIDENCE_STORAGE_HEAD_FAILED")

    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        pytest.raises(EvidenceStorageError),
    ):
        accept(grant, tenant, value)

    grant.authorization.refresh_from_db()
    expected_state = (
        EvidenceUploadAuthorization.State.REJECTED
        if failure_point == "put"
        else EvidenceUploadAuthorization.State.RECEIVING
    )
    assert grant.authorization.state == expected_state
    assert bool(storage.objects) is (failure_point == "head")
    assert not EvidenceBlob.objects.exists()


def test_preexisting_foreign_object_conflict_is_never_deleted() -> None:
    tenant = make_tenant("foreign-object")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = FakeEvidenceStorage(force_conflict=True)

    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        pytest.raises(EvidenceObjectOwnershipConflictError),
    ):
        accept(grant, tenant, value)

    grant.authorization.refresh_from_db()
    assert grant.authorization.state == EvidenceUploadAuthorization.State.REJECTED
    assert grant.authorization.failure_code == "EVIDENCE_STORAGE_OBJECT_EXISTS"
    assert len(storage.objects) == 1
    assert storage.delete_calls == 0
    assert not EvidenceBlob.objects.exists()


def test_database_failure_after_object_success_deletes_only_owned_bytes() -> None:
    tenant = make_tenant("database-failure")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = FakeEvidenceStorage()

    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        patch.object(EvidenceBlob.objects, "create", side_effect=IntegrityError("forced")),
        pytest.raises(EvidenceUploadError) as raised,
    ):
        accept(grant, tenant, value)

    grant.authorization.refresh_from_db()
    assert raised.value.code == "UPLOAD_FINALIZATION_FAILED"
    assert grant.authorization.state == EvidenceUploadAuthorization.State.REJECTED
    assert grant.authorization.failure_code == "UPLOAD_FINALIZATION_FAILED"
    assert not storage.objects
    assert storage.delete_calls == 1
    assert not EvidenceBlob.objects.exists()


def test_cleanup_failure_stays_retryable_until_owned_bytes_are_deleted() -> None:
    tenant = make_tenant("cleanup-retry")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = FakeEvidenceStorage(
        get_error=EvidenceStorageError("EVIDENCE_STORAGE_GET_FAILED"),
        delete_error=EvidenceStorageError("EVIDENCE_STORAGE_DELETE_FAILED"),
    )

    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        pytest.raises(EvidenceStorageError),
    ):
        accept(grant, tenant, value)

    grant.authorization.refresh_from_db()
    assert grant.authorization.state == EvidenceUploadAuthorization.State.RECEIVING
    assert len(storage.objects) == 1
    assert not EvidenceBlob.objects.exists()

    storage.delete_error = None
    with patch(
        "anva.core.services.evidence_uploads.EvidenceObjectStorage",
        return_value=storage,
    ):
        cleaned = recover_stale_upload_authorizations(
            actor=tenant.actor,
            repository_id=tenant.repository.id,
            access_scope_id=tenant.scope.id,
            before=timezone.now() + timedelta(seconds=1),
            limit=10,
        )

    grant.authorization.refresh_from_db()
    assert cleaned == 1
    assert grant.authorization.state == EvidenceUploadAuthorization.State.REJECTED
    assert grant.authorization.failure_code == "UPLOAD_RECEIVING_STALE"
    assert not storage.objects


def test_recovery_claim_wins_against_inflight_finalizer_without_accepting_bytes() -> None:
    tenant = make_tenant("recovery-finalizer-race")
    value = evidence_json()
    grant = issue(tenant, value)
    entered = threading.Event()
    release = threading.Event()
    storage = FakeEvidenceStorage(put_entered=entered, release_put=release)

    def upload() -> EvidenceBlob:
        try:
            return accept(grant, tenant, value)
        finally:
            connection.close()

    with patch(
        "anva.core.services.evidence_uploads.EvidenceObjectStorage",
        return_value=storage,
    ):
        with ThreadPoolExecutor(max_workers=1) as executor:
            finalizer = executor.submit(upload)
            assert entered.wait(timeout=10)
            cleaned = recover_stale_upload_authorizations(
                actor=tenant.actor,
                repository_id=tenant.repository.id,
                access_scope_id=tenant.scope.id,
                before=timezone.now() + timedelta(seconds=1),
                limit=10,
            )
            release.set()
            with pytest.raises(EvidenceStorageError):
                finalizer.result(timeout=10)

    grant.authorization.refresh_from_db()
    assert cleaned == 1
    assert grant.authorization.state == EvidenceUploadAuthorization.State.REJECTED
    assert not storage.objects
    assert not EvidenceBlob.objects.exists()


def test_recovery_scope_cannot_delete_another_repository_upload() -> None:
    tenant = make_tenant("recovery-boundary")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = FakeEvidenceStorage(
        get_error=EvidenceStorageError("EVIDENCE_STORAGE_GET_FAILED"),
        delete_error=EvidenceStorageError("EVIDENCE_STORAGE_DELETE_FAILED"),
    )
    with (
        patch(
            "anva.core.services.evidence_uploads.EvidenceObjectStorage",
            return_value=storage,
        ),
        pytest.raises(EvidenceStorageError),
    ):
        accept(grant, tenant, value)

    other_repository = Repository.objects.create(
        organization=tenant.organization,
        external_id=f"github:recovery-boundary/{uuid.uuid4()}",
        name="Other repository",
    )
    other_scope = AccessScope.objects.create(
        organization=tenant.organization,
        name="other-scope",
        all_memberships=True,
        all_repositories=True,
    )
    storage.delete_error = None
    with patch(
        "anva.core.services.evidence_uploads.EvidenceObjectStorage",
        return_value=storage,
    ):
        cleaned = recover_stale_upload_authorizations(
            actor=tenant.actor,
            repository_id=other_repository.id,
            access_scope_id=other_scope.id,
            before=timezone.now() + timedelta(seconds=1),
            limit=10,
        )

    grant.authorization.refresh_from_db()
    assert cleaned == 0
    assert grant.authorization.state == EvidenceUploadAuthorization.State.RECEIVING
    assert storage.objects
    assert storage.delete_calls == 1


def test_decommission_claims_inflight_upload_before_finalizer_can_accept() -> None:
    tenant = make_tenant("decommission-finalizer-race")
    value = evidence_json()
    grant = issue(tenant, value)
    entered = threading.Event()
    release = threading.Event()
    storage = FakeEvidenceStorage(put_entered=entered, release_put=release)

    def upload() -> EvidenceBlob:
        try:
            return accept(grant, tenant, value)
        finally:
            connection.close()

    with patch(
        "anva.core.services.evidence_uploads.EvidenceObjectStorage",
        return_value=storage,
    ):
        with ThreadPoolExecutor(max_workers=1) as executor:
            finalizer = executor.submit(upload)
            assert entered.wait(timeout=10)
            run = decommission_organization(
                actor=tenant.actor,
                confirmation=tenant.organization.slug,
                acknowledgement=f"DECOMMISSION {tenant.organization.slug}",
            )
            release.set()
            with pytest.raises(EvidenceStorageError):
                finalizer.result(timeout=10)

    grant.authorization.refresh_from_db()
    tenant.organization.refresh_from_db()
    assert run.state == "COMPLETED"
    assert tenant.organization.lifecycle_state == Organization.LifecycleState.DECOMMISSIONED
    assert grant.authorization.state == EvidenceUploadAuthorization.State.REJECTED
    assert grant.authorization.failure_code == "UPLOAD_ORGANIZATION_DECOMMISSIONED"
    assert not storage.objects
    assert not EvidenceBlob.objects.exists()


def test_secret_canary_and_upload_token_never_reach_response_or_logs(
    client: Client,
    caplog: pytest.LogCaptureFixture,
) -> None:
    tenant = make_tenant("secret-log")
    value = evidence_json(secret=True)
    digest = hashlib.sha256(value).hexdigest()
    payload = {
        "schema_version": "1.0",
        "access_scope_id": str(tenant.scope.id),
        "commit_sha": HEAD,
        "filename": "evidence.json",
        "declared_sha256": digest,
        "declared_size": len(value),
        "idempotency_key": "api-secret-upload-0001",
    }
    path = (
        f"/api/v1/repositories/{tenant.repository.id}/pull-requests/17/"
        "evidence-upload-authorizations"
    )
    with patch("anva.core.views._actor", return_value=tenant.actor):
        grant_response = client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
        )
        raw_token = grant_response.json()["upload_token"]
        caplog.set_level("DEBUG")
        rejection = client.put(
            grant_response.json()["upload_path"],
            data=value,
            content_type="application/octet-stream",
            HTTP_X_ANVA_EVIDENCE_UPLOAD_TOKEN=raw_token,
            HTTP_X_ANVA_CONTENT_SHA256=digest,
        )

    canary = "ghp_TST007_pipeline_secret_canary_7H2K9M4P"
    rendered_logs = "\n".join(record.getMessage() for record in caplog.records)
    assert grant_response.status_code == 201
    assert rejection.status_code == 422
    assert rejection.json()["code"] == "SECRET_PATTERN_DETECTED"
    assert canary not in rejection.content.decode()
    assert raw_token not in rejection.content.decode()
    assert canary not in rendered_logs
    assert raw_token not in rendered_logs
    assert not EvidenceBlob.objects.exists()


def test_live_minio_upload_verifies_and_deletes_exact_owned_bytes() -> None:
    tenant = make_tenant("live-minio")
    value = evidence_json()
    grant = issue(tenant, value)
    storage = EvidenceObjectStorage()
    object_key = ""
    try:
        blob = accept(grant, tenant, value)
        object_key = blob.object_key
        stored_size, stored_hash, stored_owner = storage.head(object_key=object_key)
        read_size, read_hash = storage.get_digest(object_key=object_key, max_bytes=4_096)

        assert stored_size == read_size == len(value)
        assert stored_hash == read_hash == hashlib.sha256(value).hexdigest()
        assert stored_owner

        deleted = delete_evidence_blob_bytes(
            organization_id=tenant.organization.id,
            blob_id=blob.id,
            reason="integration_cleanup",
        )
        assert deleted.storage_state == EvidenceBlob.StorageState.DELETED
        assert EvidenceBlob.objects.filter(id=blob.id).exists()
        with pytest.raises(EvidenceObjectNotFoundError):
            storage.head(object_key=object_key)
    finally:
        if object_key:
            storage.delete(object_key=object_key)
