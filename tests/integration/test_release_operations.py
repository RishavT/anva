"""Persistence coverage for MVP-013 rate limits, retention, and decommissioning."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from django.contrib.sessions.backends.db import SessionStore
from django.test import Client, RequestFactory
from django.utils import timezone

from anva.core.exceptions import (
    AuthenticationError,
    RateLimitExceededError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AccessScope,
    AuditEvent,
    Evidence,
    EvidenceManifest,
    EvidenceRetentionEvent,
    ImmutableArtifact,
    Membership,
    Organization,
    OrganizationProductSettings,
    RateLimitBucket,
    Repository,
    RetentionRun,
    Role,
    ServiceIdentity,
    SourceConnection,
    User,
    content_hash,
)
from anva.core.services.authorization import Action, authorize_action
from anva.core.services.context import ActorContext
from anva.core.services.operations import (
    decommission_organization,
    enforce_pre_auth_rate_limit,
    enforce_rate_limit,
    purge_expired_pre_auth_rate_buckets,
    run_retention,
)
from anva.core.services.tokens import authenticate_bearer, issue_bootstrap_repository_token
from anva.core.services.web_auth import (
    WEB_AUTHENTICATED_AT_SESSION_KEY,
    WEB_ORGANIZATION_SESSION_KEY,
    WEB_USER_SESSION_KEY,
    resolve_web_principal,
)


@dataclass(frozen=True, slots=True)
class OperationsTenant:
    organization: Organization
    repository: Repository
    scope: AccessScope
    actor: ActorContext
    membership: Membership
    service: ServiceIdentity


def _operations_tenant(label: str) -> OperationsTenant:
    marker = uuid.uuid4()
    organization = Organization.objects.create(
        slug=f"{label}-{marker}",
        name=f"{label} operations tenant",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:{label}/{marker}",
        name=f"{label} repository",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name=f"{label} scope",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Organization administrator",
    )
    user = User.objects.create(
        email=f"{label}-{marker}@example.test",
        display_name=f"{label} administrator",
    )
    membership = Membership.objects.create(
        organization=organization,
        user=user,
        role=role,
    )
    service = ServiceIdentity.objects.create(
        organization=organization,
        name=f"{label} service",
        issuer="anva-test",
        audience="anva-test-api",
    )
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="untrusted-test-claim",
        request_id=uuid.uuid4(),
        repository_id=repository.id,
    )
    return OperationsTenant(
        organization,
        repository,
        scope,
        actor,
        membership,
        service,
    )


def _evidence_manifest(tenant: OperationsTenant) -> EvidenceManifest:
    marker = str(uuid.uuid4())
    artifact = ImmutableArtifact.objects.create(
        organization=tenant.organization,
        access_scope=tenant.scope,
        kind=ImmutableArtifact.Kind.EVIDENCE_MANIFEST,
        schema_name="anva.evidence-manifest",
        schema_version="1.0",
        payload={"test_manifest": marker},
    )
    return EvidenceManifest.objects.create(
        organization=tenant.organization,
        repository=tenant.repository,
        access_scope=tenant.scope,
        artifact=artifact,
        pull_request_number=1,
        commit_sha="a" * 40,
        schema_version="1.0",
        producer="release-operations-test",
        producer_version="1.0",
        producer_mode=EvidenceManifest.ProducerMode.CI,
        payload_hash=content_hash({"test_manifest": marker}),
        payload_size=128,
    )


def _evidence(
    tenant: OperationsTenant,
    manifest: EvidenceManifest,
    *,
    expires_at: datetime,
    name: str,
    active_at: datetime,
) -> Evidence:
    evidence = Evidence.objects.create(
        organization=tenant.organization,
        manifest=manifest,
        commit_sha=manifest.commit_sha,
        kind=Evidence.Kind.TEST_RESULT,
        name=name,
        producer="release-operations-test",
        producer_version="1.0",
        status=Evidence.Status.PASSED,
        completed_at=active_at,
        content_hash=content_hash({"evidence": name}),
        limitations=[],
        criterion_codes=["TESTS_PASS"],
        retention_class="default",
        retention_expires_at=expires_at,
    )
    EvidenceRetentionEvent.objects.create(
        organization=tenant.organization,
        evidence=evidence,
        state=Evidence.RetentionState.ACTIVE,
        reason="manifest_ingested",
        actor_type="SERVICE",
        actor_id="release-operations-test",
        occurred_at=active_at,
    )
    return evidence


@pytest.mark.integration
@pytest.mark.django_db
def test_fixed_window_rate_limit_retries_resets_and_isolates_principals(
    settings: object,
) -> None:
    settings.ANVA_RATE_LIMIT_ENABLED = True  # type: ignore[attr-defined]
    settings.ANVA_RATE_LIMIT_WINDOW_SECONDS = 60  # type: ignore[attr-defined]
    settings.ANVA_RATE_LIMIT_API_REQUESTS = 2  # type: ignore[attr-defined]
    first = _operations_tenant("rate-first")
    second = _operations_tenant("rate-second")
    other_principal = ActorContext(
        organization_id=first.organization.id,
        actor_type="USER",
        actor_id=str(uuid.uuid4()),
        authorization_path="untrusted-test-claim",
        request_id=uuid.uuid4(),
        repository_id=first.repository.id,
    )
    current = datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC)

    assert enforce_rate_limit(actor=first.actor, channel="api", now=current).remaining == 1
    assert enforce_rate_limit(actor=first.actor, channel="api", now=current).remaining == 0
    with pytest.raises(RateLimitExceededError) as denied:
        enforce_rate_limit(actor=first.actor, channel="api", now=current)

    assert denied.value.retry_after_seconds == 55
    assert enforce_rate_limit(actor=other_principal, channel="api", now=current).remaining == 1
    assert enforce_rate_limit(actor=second.actor, channel="api", now=current).remaining == 1
    reset = enforce_rate_limit(
        actor=first.actor,
        channel="api",
        now=current + timedelta(seconds=55),
    )
    assert reset.remaining == 1

    first_buckets = RateLimitBucket.objects.filter(organization=first.organization)
    assert first_buckets.count() == 3
    exhausted = first_buckets.get(
        window_started_at=current.replace(second=0),
        request_count=3,
    )
    assert exhausted.request_count == 3
    assert exhausted.denied_count == 1
    assert all(len(value) == 64 for value in first_buckets.values_list("identity_hash", flat=True))
    assert not first_buckets.filter(identity_hash=first.actor.actor_id).exists()


@pytest.mark.integration
@pytest.mark.django_db
def test_pre_auth_rate_limit_hashes_identity_and_cleanup_is_bounded_system_only(
    settings: object,
) -> None:
    settings.ANVA_RATE_LIMIT_ENABLED = True  # type: ignore[attr-defined]
    settings.ANVA_RATE_LIMIT_WINDOW_SECONDS = 60  # type: ignore[attr-defined]
    settings.ANVA_RATE_LIMIT_PREAUTH_REQUESTS = 3  # type: ignore[attr-defined]
    reference_time = datetime(2026, 8, 4, 12, 0, 5, tzinfo=UTC)
    client_canary = "198.51.100.42|RAW_CLIENT_KEY_MUST_NOT_PERSIST"

    enforce_pre_auth_rate_limit(client_key=client_canary, now=reference_time)
    current = RateLimitBucket.objects.get(organization__isnull=True, channel="preauth")
    assert len(current.identity_hash) == 64
    assert current.identity_hash != client_canary
    assert "198.51.100.42" not in current.identity_hash

    tenant = _operations_tenant("preauth-cleanup-tenant")
    tenant_bucket = RateLimitBucket.objects.create(
        organization=tenant.organization,
        identity_hash="e" * 64,
        channel="api",
        window_started_at=reference_time - timedelta(minutes=10),
        request_count=1,
        expires_at=reference_time - timedelta(minutes=5),
    )
    global_non_preauth_bucket = RateLimitBucket.objects.create(
        organization=None,
        identity_hash="d" * 64,
        channel="api",
        window_started_at=reference_time - timedelta(minutes=10),
        request_count=1,
        expires_at=reference_time - timedelta(minutes=5),
    )
    expired: list[RateLimitBucket] = []
    for index, minutes in enumerate((5, 4, 3)):
        expires_at = reference_time - timedelta(minutes=minutes)
        expired.append(
            RateLimitBucket.objects.create(
                organization=None,
                identity_hash=f"{index + 1:064x}",
                channel="preauth",
                window_started_at=expires_at - timedelta(minutes=2),
                request_count=1,
                expires_at=expires_at,
            )
        )
    future = RateLimitBucket.objects.create(
        organization=None,
        identity_hash="f" * 64,
        channel="preauth",
        window_started_at=reference_time,
        request_count=1,
        expires_at=reference_time + timedelta(minutes=2),
    )

    assert purge_expired_pre_auth_rate_buckets(now=reference_time, limit=2) == 2
    assert not RateLimitBucket.objects.filter(id__in=[expired[0].id, expired[1].id]).exists()
    assert RateLimitBucket.objects.filter(id=expired[2].id).exists()
    assert RateLimitBucket.objects.filter(id=tenant_bucket.id).exists()
    assert RateLimitBucket.objects.filter(id=global_non_preauth_bucket.id).exists()
    assert RateLimitBucket.objects.filter(id=current.id).exists()
    assert RateLimitBucket.objects.filter(id=future.id).exists()

    assert purge_expired_pre_auth_rate_buckets(now=reference_time, limit=2) == 1
    assert purge_expired_pre_auth_rate_buckets(now=reference_time, limit=2) == 0
    assert RateLimitBucket.objects.filter(id=tenant_bucket.id).exists()
    assert RateLimitBucket.objects.filter(id=global_non_preauth_bucket.id).exists()
    assert RateLimitBucket.objects.filter(id=current.id).exists()
    assert RateLimitBucket.objects.filter(id=future.id).exists()


@pytest.mark.integration
@pytest.mark.django_db
@pytest.mark.parametrize("limit", [0, 1_001, True])
def test_pre_auth_cleanup_rejects_unbounded_batches(limit: int) -> None:
    with pytest.raises(ValueError, match="between 1 and 1000"):
        purge_expired_pre_auth_rate_buckets(limit=limit)


@pytest.mark.integration
@pytest.mark.django_db
def test_retention_dry_run_is_idempotent_then_live_run_expires_only_due_evidence(
    settings: object,
) -> None:
    settings.ANVA_RATE_LIMIT_ENABLED = True  # type: ignore[attr-defined]
    tenant = _operations_tenant("retention")
    OrganizationProductSettings.objects.create(
        organization=tenant.organization,
        retention_days=30,
    )
    reference_time = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    manifest = _evidence_manifest(tenant)
    due = _evidence(
        tenant,
        manifest,
        expires_at=reference_time,
        name="due evidence",
        active_at=reference_time - timedelta(days=31),
    )
    future = _evidence(
        tenant,
        manifest,
        expires_at=reference_time + timedelta(seconds=1),
        name="future evidence",
        active_at=reference_time - timedelta(days=31),
    )
    too_young = _evidence(
        tenant,
        manifest,
        expires_at=reference_time,
        name="minimum retention not elapsed",
        active_at=reference_time - timedelta(days=29),
    )
    RateLimitBucket.objects.create(
        organization=tenant.organization,
        identity_hash="d" * 64,
        channel="api",
        window_started_at=reference_time - timedelta(minutes=2),
        request_count=3,
        denied_count=1,
        expires_at=reference_time - timedelta(seconds=1),
    )
    other_tenant = _operations_tenant("retention-other")
    other_bucket = RateLimitBucket.objects.create(
        organization=other_tenant.organization,
        identity_hash="e" * 64,
        channel="api",
        window_started_at=reference_time - timedelta(minutes=2),
        request_count=4,
        denied_count=2,
        expires_at=reference_time - timedelta(seconds=1),
    )

    dry_run = run_retention(
        actor=tenant.actor,
        reference_time=reference_time,
        dry_run=True,
    )
    replay = run_retention(
        actor=tenant.actor,
        reference_time=reference_time,
        dry_run=True,
    )

    assert replay.id == dry_run.id
    assert dry_run.cutoff_at == reference_time - timedelta(days=30)
    assert dry_run.summary == {
        "evidence_expired": 1,
        "rate_buckets_deleted": 1,
        "governed_history_retained": True,
        "source_content_deleted": 0,
    }
    assert EvidenceRetentionEvent.objects.filter(evidence=due).count() == 1
    assert RateLimitBucket.objects.filter(organization=tenant.organization).exists()

    applied = run_retention(
        actor=tenant.actor,
        reference_time=reference_time,
        dry_run=False,
    )

    assert applied.id != dry_run.id
    assert applied.state == RetentionRun.State.COMPLETED
    assert applied.summary["evidence_expired"] == 1
    assert applied.summary["rate_buckets_deleted"] == 1
    assert not RateLimitBucket.objects.filter(organization=tenant.organization).exists()
    assert RateLimitBucket.objects.filter(id=other_bucket.id).exists()
    assert (
        EvidenceRetentionEvent.objects.filter(evidence=due).latest("occurred_at", "id").state
        == Evidence.RetentionState.EXPIRED
    )
    assert (
        EvidenceRetentionEvent.objects.filter(evidence=future).latest("occurred_at", "id").state
        == Evidence.RetentionState.ACTIVE
    )
    assert (
        EvidenceRetentionEvent.objects.filter(evidence=too_young).latest("occurred_at", "id").state
        == Evidence.RetentionState.ACTIVE
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_retention_uses_latest_availability_event_when_expiring_evidence() -> None:
    tenant = _operations_tenant("retention-latest")
    reference_time = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)
    manifest = _evidence_manifest(tenant)
    evidence = _evidence(
        tenant,
        manifest,
        expires_at=reference_time - timedelta(days=1),
        name="reactivated evidence",
        active_at=reference_time - timedelta(days=366),
    )
    EvidenceRetentionEvent.objects.create(
        organization=tenant.organization,
        evidence=evidence,
        state=Evidence.RetentionState.EXPIRED,
        reason="historical expiry",
        actor_type="USER",
        actor_id=tenant.actor.actor_id,
        occurred_at=reference_time - timedelta(days=3),
    )
    EvidenceRetentionEvent.objects.create(
        organization=tenant.organization,
        evidence=evidence,
        state=Evidence.RetentionState.ACTIVE,
        reason="operator restoration",
        actor_type="USER",
        actor_id=tenant.actor.actor_id,
        occurred_at=reference_time - timedelta(days=2),
    )

    run = run_retention(actor=tenant.actor, reference_time=reference_time)

    assert run.summary["evidence_expired"] == 1
    assert (
        EvidenceRetentionEvent.objects.filter(evidence=evidence).latest("occurred_at", "id").state
        == Evidence.RetentionState.EXPIRED
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_decommission_requires_exact_confirmation_and_fails_closed_for_all_access() -> None:
    tenant = _operations_tenant("decommission")
    source = SourceConnection.objects.create(
        organization=tenant.organization,
        repository=tenant.repository,
        access_scope=tenant.scope,
        external_key=f"github:decommission/{uuid.uuid4()}",
        display_name="Decommissioned source",
        state=SourceConnection.State.ACTIVE,
    )
    issued = issue_bootstrap_repository_token(
        organization=tenant.organization,
        repository=tenant.repository,
        service_identity=tenant.service,
        actions=frozenset({Action.ORG_VIEW}),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    assert authenticate_bearer(f"Bearer {issued.plaintext}").organization_id == (
        tenant.organization.id
    )

    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        decommission_organization(
            actor=tenant.actor,
            confirmation=f"{tenant.organization.slug} ",
            acknowledgement=f"DECOMMISSION {tenant.organization.slug} ",
        )

    tenant.organization.refresh_from_db()
    assert tenant.organization.lifecycle_state == Organization.LifecycleState.ACTIVE
    assert not RetentionRun.objects.filter(organization=tenant.organization).exists()

    service_actor = ActorContext(
        organization_id=tenant.organization.id,
        actor_type="SERVICE",
        actor_id=str(tenant.service.id),
        authorization_path="credential:test",
        request_id=uuid.uuid4(),
        repository_id=tenant.repository.id,
        credential_id=uuid.uuid4(),
        credential_actions=frozenset({Action.RETENTION_MANAGE}),
    )
    with pytest.raises(ResourceNotFoundError, match="Governed record was not found"):
        decommission_organization(
            actor=service_actor,
            confirmation=tenant.organization.slug,
            acknowledgement=f"DECOMMISSION {tenant.organization.slug}",
        )

    tenant.organization.refresh_from_db()
    assert tenant.organization.lifecycle_state == Organization.LifecycleState.ACTIVE
    assert not RetentionRun.objects.filter(organization=tenant.organization).exists()

    run = decommission_organization(
        actor=tenant.actor,
        confirmation=tenant.organization.slug,
        acknowledgement=f"DECOMMISSION {tenant.organization.slug}",
    )

    tenant.organization.refresh_from_db()
    tenant.membership.refresh_from_db()
    tenant.repository.refresh_from_db()
    tenant.service.refresh_from_db()
    tenant.scope.refresh_from_db()
    source.refresh_from_db()
    issued.record.refresh_from_db()
    assert run.state == RetentionRun.State.COMPLETED
    assert tenant.organization.lifecycle_state == Organization.LifecycleState.DECOMMISSIONED
    assert tenant.organization.deletion_requested_at is not None
    assert tenant.organization.decommissioned_at is not None
    assert not tenant.membership.is_active
    assert not tenant.repository.is_active
    assert not tenant.service.is_active
    assert not tenant.scope.is_active
    assert source.state == SourceConnection.State.REVOKED
    assert issued.record.revoked_at is not None
    assert AuditEvent.objects.filter(organization=tenant.organization).exists()

    with pytest.raises(AuthenticationError, match="Credential is invalid or expired"):
        authenticate_bearer(f"Bearer {issued.plaintext}")
    with pytest.raises(AuthenticationError, match="Credential is invalid or expired"):
        authorize_action(
            actor=tenant.actor,
            action=Action.ORG_VIEW,
            repository_id=tenant.repository.id,
        )

    request = RequestFactory().get("/app", REMOTE_ADDR="203.0.113.5")
    request.session = SessionStore()
    request.session[WEB_USER_SESSION_KEY] = str(tenant.membership.user_id)
    request.session[WEB_ORGANIZATION_SESSION_KEY] = str(tenant.organization.id)
    with pytest.raises(AuthenticationError, match="Credential is invalid or expired"):
        resolve_web_principal(request)


@pytest.mark.integration
@pytest.mark.django_db
def test_decommission_http_requires_recent_human_session_csrf_and_two_confirmations() -> None:
    tenant = _operations_tenant("decommission-http")
    issued = issue_bootstrap_repository_token(
        organization=tenant.organization,
        repository=tenant.repository,
        service_identity=tenant.service,
        actions=frozenset({Action.RETENTION_MANAGE}),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    client = Client(enforce_csrf_checks=True)
    csrf_token = "a" * 32
    client.cookies["csrftoken"] = csrf_token
    path = f"/api/v1/organizations/{tenant.organization.id}/decommission"
    payload = {
        "confirmation": tenant.organization.slug,
        "acknowledgement": f"DECOMMISSION {tenant.organization.slug}",
    }

    bearer_response = client.post(
        path,
        data=payload,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {issued.plaintext}",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert bearer_response.status_code == 401

    session = client.session
    session[WEB_USER_SESSION_KEY] = str(tenant.membership.user_id)
    session[WEB_ORGANIZATION_SESSION_KEY] = str(tenant.organization.id)
    session[WEB_AUTHENTICATED_AT_SESSION_KEY] = int(time.time()) - 901
    session.save()
    stale_response = client.post(
        path,
        data=payload,
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert stale_response.status_code == 401

    session = client.session
    session[WEB_USER_SESSION_KEY] = str(tenant.membership.user_id)
    session[WEB_ORGANIZATION_SESSION_KEY] = str(tenant.organization.id)
    session[WEB_AUTHENTICATED_AT_SESSION_KEY] = int(time.time())
    session.save()
    wrong_acknowledgement = client.post(
        path,
        data={**payload, "acknowledgement": f"DECOMMISSION {tenant.organization.slug} "},
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert wrong_acknowledgement.status_code == 404

    accepted = client.post(
        path,
        data=payload,
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert accepted.status_code == 202
    tenant.organization.refresh_from_db()
    assert tenant.organization.lifecycle_state == Organization.LifecycleState.DECOMMISSIONED
