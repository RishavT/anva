"""Immutable evidence records may link only exact-context accepted blobs."""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from anva.contracts.catalog import EXAMPLES
from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    Evidence,
    EvidenceBlob,
    EvidenceUploadAuthorization,
    Membership,
    Organization,
    Repository,
    Role,
    User,
    content_hash,
)
from anva.core.services.context import ActorContext
from anva.core.services.evidence import submit_evidence_manifest

pytestmark = [pytest.mark.integration, pytest.mark.django_db]


def test_upload_authorization_cannot_be_inserted_as_accepted() -> None:
    organization, repository, scope, _actor = tenant("insert-accepted")
    now = timezone.now()
    marker = uuid.uuid4().hex
    with pytest.raises(IntegrityError), transaction.atomic():
        EvidenceUploadAuthorization.objects.create(
            organization=organization,
            repository=repository,
            access_scope=scope,
            pull_request_number=17,
            commit_sha="a" * 40,
            filename="evidence.json",
            declared_sha256="c" * 64,
            declared_size=128,
            token_hash=content_hash({"token": marker}),
            idempotency_hash=content_hash({"idempotency": marker}),
            request_hash=content_hash({"request": marker}),
            actor_type="USER",
            actor_id=marker,
            state=EvidenceUploadAuthorization.State.ACCEPTED,
            object_key=f"evidence/{organization.id}/{marker}",
            ownership_nonce_hash=content_hash({"owner": marker}),
            expires_at=now + timedelta(minutes=5),
            reserved_at=now,
            completed_at=now,
        )
    assert not EvidenceBlob.objects.filter(organization=organization).exists()


def tenant(label: str) -> tuple[Organization, Repository, AccessScope, ActorContext]:
    organization = Organization.objects.create(
        slug=f"evidence-blob-{label}-{uuid.uuid4()}",
        name="Evidence blob test",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:evidence-blob/{uuid.uuid4()}",
        name="Evidence blob repository",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="evidence-blob-visible",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Org admin",
    )
    user = User.objects.create(
        email=f"evidence-blob-{uuid.uuid4()}@example.test",
        display_name="Evidence blob admin",
    )
    Membership.objects.create(organization=organization, user=user, role=role)
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="test",
        request_id=uuid.uuid4(),
    )
    return organization, repository, scope, actor


def accepted_blob(
    *,
    organization: Organization,
    repository: Repository,
    scope: AccessScope,
    pull_request_number: int = 17,
    commit_sha: str = "a" * 40,
    storage_state: str = EvidenceBlob.StorageState.AVAILABLE,
) -> EvidenceBlob:
    now = timezone.now()
    marker = uuid.uuid4().hex
    object_key = f"evidence/{organization.id}/{marker}"
    authorization = EvidenceUploadAuthorization.objects.create(
        organization=organization,
        repository=repository,
        access_scope=scope,
        pull_request_number=pull_request_number,
        commit_sha=commit_sha,
        filename="evidence.json",
        declared_sha256="c" * 64,
        declared_size=128,
        token_hash=content_hash({"token": marker}),
        idempotency_hash=content_hash({"idempotency": marker}),
        request_hash=content_hash({"request": marker}),
        actor_type="USER",
        actor_id=marker,
        expires_at=now + timedelta(minutes=5),
    )
    authorization.state = EvidenceUploadAuthorization.State.RECEIVING
    authorization.object_key = object_key
    authorization.ownership_nonce_hash = content_hash({"owner": marker})
    authorization.reserved_at = now
    authorization.save(update_fields=["state", "object_key", "ownership_nonce_hash", "reserved_at"])
    authorization.state = EvidenceUploadAuthorization.State.ACCEPTED
    authorization.completed_at = now
    authorization.save(update_fields=["state", "completed_at"])
    deleted = storage_state == EvidenceBlob.StorageState.DELETED
    return EvidenceBlob.objects.create(
        organization=organization,
        repository=repository,
        access_scope=scope,
        upload_authorization=authorization,
        object_key=object_key,
        content_hash="c" * 64,
        verified_size=128,
        detected_media_type=EvidenceBlob.MediaType.JSON,
        archive_summary={"format": "json", "member_count": 0},
        inspection_version="evidence-artifact-v1",
        storage_state=storage_state,
        deletion_reason="retention" if deleted else "",
        deleted_at=now if deleted else None,
    )


def manifest_payload(
    *,
    organization: Organization,
    repository: Repository,
    scope: AccessScope,
    blob: EvidenceBlob,
) -> dict[str, object]:
    payload = deepcopy(EXAMPLES["evidence-manifest"])
    payload.update(
        {
            "manifest_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "pull_request_number": 17,
            "commit_sha": "a" * 40,
        }
    )
    entry = payload["entries"][0]  # type: ignore[index]
    entry["evidence_id"] = str(uuid.uuid4())
    entry["artifact_blob_id"] = str(blob.id)
    entry["content_hash"] = blob.content_hash
    return payload


@pytest.mark.integration
def test_manifest_links_available_exact_context_blob_only_at_evidence_insert() -> None:
    organization, repository, scope, actor = tenant("exact")
    blob = accepted_blob(
        organization=organization,
        repository=repository,
        scope=scope,
    )

    result = submit_evidence_manifest(
        actor=actor,
        repository_id=repository.id,
        pull_request_number=17,
        payload=manifest_payload(
            organization=organization,
            repository=repository,
            scope=scope,
            blob=blob,
        ),
    )

    assert result.created is True
    assert Evidence.objects.get(id=result.evidence[0].id).artifact_blob_id == blob.id


@pytest.mark.integration
@pytest.mark.parametrize(
    "mismatch",
    ["tenant", "repository", "scope", "pull_request", "commit", "deleted"],
)
def test_manifest_hides_and_rejects_unavailable_or_cross_context_blob(mismatch: str) -> None:
    organization, repository, scope, actor = tenant(f"target-{mismatch}")
    blob_organization = organization
    blob_repository = repository
    blob_scope = scope
    pull_request_number = 17
    commit_sha = "a" * 40
    storage_state = EvidenceBlob.StorageState.AVAILABLE
    if mismatch == "tenant":
        blob_organization, blob_repository, blob_scope, _foreign_actor = tenant("foreign")
    elif mismatch == "repository":
        blob_repository = Repository.objects.create(
            organization=organization,
            external_id=f"github:evidence-blob/{uuid.uuid4()}",
            name="Other repository",
        )
    elif mismatch == "scope":
        blob_scope = AccessScope.objects.create(
            organization=organization,
            name="other-scope",
            all_memberships=True,
            all_repositories=True,
        )
    elif mismatch == "pull_request":
        pull_request_number = 18
    elif mismatch == "commit":
        commit_sha = "d" * 40
    else:
        storage_state = EvidenceBlob.StorageState.DELETED
    blob = accepted_blob(
        organization=blob_organization,
        repository=blob_repository,
        scope=blob_scope,
        pull_request_number=pull_request_number,
        commit_sha=commit_sha,
        storage_state=storage_state,
    )
    payload = manifest_payload(
        organization=organization,
        repository=repository,
        scope=scope,
        blob=blob,
    )

    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        submit_evidence_manifest(
            actor=actor,
            repository_id=repository.id,
            pull_request_number=17,
            payload=payload,
        )

    evidence_id = uuid.UUID(payload["entries"][0]["evidence_id"])  # type: ignore[index]
    assert not Evidence.objects.filter(id=evidence_id).exists()
