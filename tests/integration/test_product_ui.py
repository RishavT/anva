"""End-to-end HTTP coverage for the server-rendered product surface."""

from __future__ import annotations

import uuid

import pytest
from django.db import IntegrityError, connection, transaction
from django.test import Client
from django.utils import timezone

from anva.core.models import (
    AccessScope,
    AssuranceCheck,
    AssuranceRun,
    AuditEvent,
    Finding,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeProposalScope,
    Membership,
    Organization,
    OrganizationProductSettings,
    PullRequest,
    Repository,
    RepositoryProfile,
    Role,
    SourceConnection,
    SyncRun,
    User,
)
from anva.core.services.bootstrap import bootstrap_local_organization


def _signed_in_client() -> tuple[Client, Repository]:
    result = bootstrap_local_organization(
        supplied_secret="test-only-bootstrap-secret",
        organization_slug="northstar",
        organization_name="Northstar Systems",
        admin_email="admin@northstar.test",
        admin_display_name="Ada Morgan",
        repository_external_id="github:northstar/payments",
        repository_name="payments",
    )
    client = Client()
    session = client.session
    session["anva_web_user_id"] = str(result.user.id)
    session["anva_web_organization_id"] = str(result.organization.id)
    session.save()
    return client, result.repository


@pytest.mark.integration
@pytest.mark.django_db
def test_bootstrap_form_creates_workspace_and_starts_redacted_session() -> None:
    client = Client()

    response = client.post(
        "/setup",
        {
            "bootstrap_secret": "test-only-bootstrap-secret",
            "organization_name": "Northstar Systems",
            "organization_slug": "northstar",
            "admin_name": "Ada Morgan",
            "admin_email": "admin@northstar.test",
            "repository_name": "payments",
            "repository_external_id": "github:northstar/payments",
            "retention_days": "365",
            "model_processing": "REDACTED_ONLY",
            "skill_distribution": "MANAGED",
            "assurance_mode": "OBSERVE",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/app/onboarding"
    assert Organization.objects.filter(slug="northstar").exists()
    product_settings = OrganizationProductSettings.objects.get(organization__slug="northstar")
    assert product_settings.retention_days == 365
    assert product_settings.model_processing == "REDACTED_ONLY"
    assert product_settings.skill_distribution == "MANAGED"
    assert product_settings.assurance_mode == "OBSERVE"
    session = client.session
    assert session["anva_web_user_id"]
    assert session["anva_web_organization_id"]
    assert "anva_web_credential_id" not in session
    assert "bootstrap_secret" not in session
    assert "token" not in " ".join(session.keys()).lower()


@pytest.mark.integration
@pytest.mark.django_db
def test_attention_home_and_every_primary_surface_render_for_authorized_actor() -> None:
    client, repository = _signed_in_client()
    routes = (
        "/app",
        "/app/onboarding",
        "/app/explorer",
        f"/app/repositories/{repository.id}",
        "/app/sources",
        "/app/review",
        "/app/work",
        "/app/policies",
        "/app/assurance",
        "/app/skills",
        "/app/audit",
    )

    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, route
        content = response.content.decode()
        assert "<main" in content
        assert 'href="#main-content"' in content
        assert "<nav" in content
        assert "Access token" not in content


@pytest.mark.integration
@pytest.mark.django_db
def test_entity_deep_link_does_not_disclose_foreign_tenant_record() -> None:
    client, _repository = _signed_in_client()
    foreign = Organization.objects.create(slug="foreign", name="Foreign")
    foreign_scope = AccessScope.objects.create(
        organization=foreign,
        name="Foreign",
        all_memberships=True,
        all_repositories=True,
    )
    from anva.core.models import KnowledgeEntity

    entity = KnowledgeEntity.objects.create(
        organization=foreign,
        access_scope=foreign_scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="system:hidden",
        display_name="Hidden system",
        attributes={},
    )

    response = client.get(f"/app/explorer/entities/{entity.id}")

    assert response.status_code == 404
    assert "Hidden system" not in response.content.decode()
    assert "not available" in response.content.decode().lower()


@pytest.mark.integration
@pytest.mark.django_db
def test_service_bearer_cannot_sign_into_human_ui() -> None:
    result = bootstrap_local_organization(
        supplied_secret="test-only-bootstrap-secret",
        organization_slug="machine",
        organization_name="Machine",
        admin_email="admin@machine.test",
        admin_display_name="Machine Admin",
        repository_external_id="github:machine/repository",
        repository_name="repository",
    )

    response = Client().get(
        "/app",
        HTTP_AUTHORIZATION=f"Bearer {result.issued_token.plaintext}",
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/access")


@pytest.mark.integration
@pytest.mark.django_db
def test_deactivated_membership_invalidates_existing_web_session_immediately() -> None:
    client, repository = _signed_in_client()
    Membership.objects.filter(organization=repository.organization).update(is_active=False)

    response = client.get("/app")

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/access")


@pytest.mark.integration
@pytest.mark.django_db
def test_review_confirmation_uses_governed_transition_and_rejects_stale_form() -> None:
    client, repository = _signed_in_client()
    scope = AccessScope.objects.get(organization=repository.organization)
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key="system:payments",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        confidence=0.82,
        observed_at=timezone.now(),
    )

    response = client.post(
        f"/app/review/{assertion.id}",
        {
            "decision": "CONFIRM",
            "expected_revision": "1",
            "repository_id": str(repository.id),
        },
    )

    assert response.status_code == 302
    assertion.refresh_from_db()
    assert assertion.review_state == KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED
    review_event = AuditEvent.objects.get(
        organization=repository.organization,
        target_type="knowledgeassertion",
        target_id=assertion.id,
        to_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
    )
    assert review_event.actor_type == "USER"
    assert review_event.actor_id != ""
    assert "credential:" not in review_event.authorization_path

    stale = client.post(
        f"/app/review/{assertion.id}",
        {
            "decision": "REJECT",
            "expected_revision": "1",
            "repository_id": str(repository.id),
        },
    )
    assert stale.status_code == 409
    assertion.refresh_from_db()
    assert assertion.review_state == KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED


@pytest.mark.integration
@pytest.mark.django_db
def test_web_mutations_require_csrf_and_responses_apply_browser_hardening() -> None:
    client, repository = _signed_in_client()
    scope = AccessScope.objects.get(organization=repository.organization)
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key="system:payments",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        confidence=0.82,
        observed_at=timezone.now(),
    )
    protected_client = Client(enforce_csrf_checks=True)
    session = protected_client.session
    session["anva_web_user_id"] = client.session["anva_web_user_id"]
    session["anva_web_organization_id"] = client.session["anva_web_organization_id"]
    session.save()

    response = protected_client.post(
        f"/app/review/{assertion.id}",
        {
            "decision": "CONFIRM",
            "expected_revision": "1",
            "repository_id": str(repository.id),
        },
    )

    assert response.status_code == 403
    assertion.refresh_from_db()
    assert assertion.review_state == KnowledgeAssertion.ReviewState.UNREVIEWED

    page = protected_client.get("/app")
    assert page.status_code == 200
    assert "default-src 'self'" in page.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
    assert page.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    session_cookie = protected_client.cookies["sessionid"]
    assert session_cookie["httponly"] is True
    assert session_cookie["samesite"] == "Lax"


@pytest.mark.integration
@pytest.mark.django_db
def test_viewer_cannot_forge_a_human_review_identity_in_form_data() -> None:
    admin_client, repository = _signed_in_client()
    viewer = User.objects.create(
        email="viewer@northstar.test",
        display_name="Vera Viewer",
    )
    role = Role.objects.get(
        organization=repository.organization,
        code=Role.Code.VIEWER,
    )
    Membership.objects.create(
        organization=repository.organization,
        user=viewer,
        role=role,
    )
    scope = AccessScope.objects.get(organization=repository.organization)
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key="system:payments",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        confidence=0.82,
        observed_at=timezone.now(),
    )
    viewer_client = Client()
    session = viewer_client.session
    session["anva_web_user_id"] = str(viewer.id)
    session["anva_web_organization_id"] = str(repository.organization_id)
    session.save()

    page = viewer_client.get("/app/review")

    assert page.status_code == 200
    assert b'href="/app/audit"' not in page.content
    assert b'value="CONFIRM" class="button button--primary" type="submit" disabled' in page.content

    response = viewer_client.post(
        f"/app/review/{assertion.id}",
        {
            "decision": "CONFIRM",
            "expected_revision": "1",
            "repository_id": str(repository.id),
            "actor_id": admin_client.session["anva_web_user_id"],
            "actor_type": "SERVICE",
            "role": Role.Code.ORG_ADMIN,
        },
    )

    assert response.status_code == 404
    assertion.refresh_from_db()
    assert assertion.review_state == KnowledgeAssertion.ReviewState.UNREVIEWED
    assert not AuditEvent.objects.filter(
        organization=repository.organization,
        target_type="knowledgeassertion",
        target_id=assertion.id,
    ).exists()


@pytest.mark.integration
@pytest.mark.django_db
def test_entity_correction_profile_and_source_lifecycle_render_governed_state() -> None:
    client, repository = _signed_in_client()
    scope = AccessScope.objects.get(organization=repository.organization)
    entity = KnowledgeEntity.objects.create(
        organization=repository.organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:payments",
        display_name="Payments service",
        attributes={"tier": "critical"},
    )
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key=entity.canonical_key,
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        confidence=0.82,
        observed_at=timezone.now(),
    )
    source = SourceConnection.objects.create(
        organization=repository.organization,
        external_key="filesystem:payments-docs",
        display_name="Payments docs",
        repository=repository,
        access_scope=scope,
        state=SourceConnection.State.ACTIVE,
    )

    entity_page = client.get(f"/app/explorer/entities/{entity.id}?repository={repository.id}")
    assert entity_page.status_code == 200
    assert "Payments service" in entity_page.content.decode()
    assert "Source-backed" in entity_page.content.decode()

    correction = client.post(
        f"/app/review/{assertion.id}",
        {
            "decision": "CORRECT",
            "expected_revision": str(assertion.revision),
            "repository_id": str(repository.id),
            "correction": "Owned by the Payments Platform team.",
        },
    )
    assert correction.status_code == 302
    proposal_scope = KnowledgeProposalScope.objects.get(assertion=assertion)
    assert proposal_scope.repository == repository
    proposed_change = proposal_scope.knowledge_proposal.proposed_changes[0]
    assert proposed_change["current_value_hash"]
    assert proposed_change["proposed_value"] == "Owned by the Payments Platform team."

    profile = RepositoryProfile.objects.create(
        organization=repository.organization,
        repository=repository,
    )
    profile_update = client.post(
        f"/app/repositories/{repository.id}/profile",
        {
            "expected_revision": str(profile.revision),
            "purpose": "Processes customer payments.",
            "owning_team": "Payments Platform",
            "setup_commands": "uv sync\npython -m anva.manage check",
            "required_checks": "pytest\nruff check",
            "sensitive_paths": "src/payments/secrets.py",
        },
    )
    assert profile_update.status_code == 302
    profile.refresh_from_db()
    assert profile.status == RepositoryProfile.Status.CONFIRMED
    assert profile.setup_commands == ["uv sync", "python -m anva.manage check"]

    source_page = client.get(f"/app/sources/{source.id}")
    assert source_page.status_code == 200
    assert "Payments docs" in source_page.content.decode()
    sync = client.post(
        f"/app/sources/{source.id}/sync",
        {"scan_mode": SyncRun.ScanMode.INCREMENTAL},
    )
    assert sync.status_code == 302
    assert SyncRun.objects.filter(source_connection=source).exists()
    revoke = client.post(
        f"/app/sources/{source.id}/revoke",
        {
            "confirmation": "REVOKE",
            "expected_revision": str(source.revision),
        },
    )
    assert revoke.status_code == 302
    source.refresh_from_db()
    assert source.state == SourceConnection.State.REVOKED


@pytest.mark.integration
@pytest.mark.django_db
def test_assurance_detail_and_audit_filters_present_exact_bounded_evidence() -> None:
    client, repository = _signed_in_client()
    pull_request = PullRequest.objects.create(
        organization=repository.organization,
        repository=repository,
        number=42,
        current_head_commit="e" * 40,
    )
    run = AssuranceRun.objects.create(
        organization=repository.organization,
        repository=repository,
        repository_external_id=repository.external_id,
        pull_request_number=pull_request.number,
        head_commit=pull_request.current_head_commit,
        evaluated_commit=pull_request.current_head_commit,
        report_commit=pull_request.current_head_commit,
        policy_version=3,
        input_hash="b" * 64,
        requirements_hash="c" * 64,
        policy_bundle_hash="d" * 64,
        evidence_bundle_hash="f" * 64,
        evaluator_version="integration-v1",
        prompt_version="none",
        limitations=["No exact-commit criterion evidence was supplied."],
        readiness="BLOCKED",
        state=AssuranceRun.State.COMPLETED,
        completed_at=timezone.now(),
    )
    AssuranceCheck.objects.create(
        organization=repository.organization,
        assurance_run=run,
        position=1,
        code="REQUIRED_TEST_EVIDENCE",
        status=AssuranceCheck.Status.FAILED,
        blocking=True,
        summary="Required test evidence is unavailable.",
        evidence_ids=[],
        input_hash="a" * 64,
    )
    finding = Finding.objects.create(
        organization=repository.organization,
        pull_request=pull_request,
        first_run=run,
        latest_run=run,
        fingerprint="9" * 64,
        code="TEST_EVIDENCE_GAP",
        kind=Finding.Kind.DETERMINISTIC,
        severity=Finding.Severity.BLOCKING,
        confidence=Finding.Confidence.PROVEN,
        title="Required test evidence is missing",
        explanation="No exact-head evidence manifest proves the test command passed.",
        uncertainty="The command may have run elsewhere.",
        suggested_resolution="Publish a commit-bound evidence manifest.",
    )

    response = client.get(f"/app/assurance/{run.id}")
    content = response.content.decode()
    assert response.status_code == 200
    assert "Required test evidence is missing" in content
    assert run.head_commit in content
    assert "No exact-commit criterion evidence was supplied." in content

    audit = client.get(
        "/app/audit",
        {
            "actor": str(client.session["anva_web_user_id"]),
            "action": "state",
            "target": "finding",
            "request_id": str(uuid.uuid4()),
            "date_from": timezone.now().date().isoformat(),
        },
    )
    assert audit.status_code == 200
    assert "No event matches these filters" in audit.content.decode()
    unfiltered_audit = client.get("/app/audit")
    assert unfiltered_audit.status_code == 200
    assert "Permission-restricted organization audit history" in unfiltered_audit.content.decode()
    assert finding.id


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_product_records_reject_cross_tenant_relationship_grafts() -> None:
    _client, repository = _signed_in_client()
    proposal = KnowledgeProposal.objects.create(
        organization=repository.organization,
        summary="Scoped correction",
        proposed_changes=[{"operation": "CORRECT"}],
        anva_sources=[{"source_id": str(uuid.uuid4())}],
    )
    foreign = Organization.objects.create(slug="foreign-product", name="Foreign Product")
    foreign_repository = Repository.objects.create(
        organization=foreign,
        external_id="github:foreign/product",
        name="product",
    )
    foreign_scope = AccessScope.objects.create(
        organization=foreign,
        name="Foreign scope",
        all_memberships=True,
        all_repositories=True,
    )

    with pytest.raises(IntegrityError), transaction.atomic():
        KnowledgeProposalScope.objects.create(
            organization=repository.organization,
            knowledge_proposal=proposal,
            repository=foreign_repository,
            access_scope=foreign_scope,
        )
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    with pytest.raises(IntegrityError), transaction.atomic():
        RepositoryProfile.objects.create(
            organization=repository.organization,
            repository=foreign_repository,
        )
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
