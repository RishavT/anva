"""End-to-end HTTP coverage for the server-rendered product surface."""

from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import IntegrityError, close_old_connections, connection, connections, transaction
from django.test import Client, override_settings
from django.utils import timezone

from anva.core.models import (
    AccessScope,
    AccessScopeMembership,
    AssuranceCheck,
    AssuranceRun,
    AuditEvent,
    ContextPacketRecord,
    Evidence,
    EvidenceManifest,
    Finding,
    GitHubInstallation,
    GitHubRepositoryBinding,
    ImmutableArtifact,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeProposalScope,
    Membership,
    Organization,
    OrganizationProductSettings,
    OutboxEvent,
    PullRequest,
    Repository,
    RepositoryProfile,
    Role,
    ServiceIdentity,
    SourceConnection,
    SyncRun,
    User,
    content_hash,
)
from anva.core.services.bootstrap import bootstrap_local_organization
from anva.core.services.context import ActorContext
from anva.core.services.product_ui import ProductUIFacade
from anva.core.services.scopes import derive_scope_intersection
from anva.entrypoints.cli import main as cli_main


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


def _onboarding_item(rendered: str, name: str) -> str:
    heading = rendered.index(f"<h3>{name}</h3>")
    start = rendered.rindex('<li class="progress-item', 0, heading)
    end = rendered.index("</li>", heading) + len("</li>")
    return rendered[start:end]


def _create_github_binding(
    *,
    repository: Repository,
    access_scope: AccessScope,
    full_name: str,
) -> GitHubRepositoryBinding:
    organization = repository.organization
    service_identity = ServiceIdentity.objects.get(organization=organization)
    installation = GitHubInstallation.objects.create(
        organization=organization,
        external_id=uuid.uuid4().int % 9_000_000_000,
        account_id=uuid.uuid4().int % 9_000_000_000,
        account_login="product-ui-test",
        account_type="Organization",
        repository_selection="selected",
        permissions={"metadata": "read"},
        service_identity=service_identity,
    )
    return GitHubRepositoryBinding.objects.create(
        organization=organization,
        installation=installation,
        repository=repository,
        access_scope=access_scope,
        external_repository_id=uuid.uuid4().int % 9_000_000_000,
        full_name=full_name,
        default_branch="main",
    )


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
@pytest.mark.contract
@pytest.mark.django_db
def test_demo_cli_returns_the_authoritative_repository_access_scope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = cli_main(
        [
            "demo",
            "--organization-slug",
            "scope-discovery",
            "--repository-external-id",
            "RishavT/anva-test",
        ]
    )

    assert result == 0
    response = json.loads(capsys.readouterr().out)
    scope = AccessScope.objects.get(id=response["access_scope_id"])
    repository = Repository.objects.get(id=response["repository_id"])
    service_identity = ServiceIdentity.objects.get(id=response["service_identity_id"])
    assert scope.organization_id == uuid.UUID(response["organization_id"])
    assert repository.organization_id == scope.organization_id
    assert service_identity.organization_id == scope.organization_id
    assert scope.all_repositories is True
    assert scope.all_service_identities is True
    assert response["token"]


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
        initiated_by_actor_type="SYSTEM",
        initiated_by_actor_id="test-fixture",
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


@pytest.mark.integration
@pytest.mark.django_db
def test_product_pages_filter_hidden_revoked_source_packet_proposal_audit_and_evidence() -> None:
    client, repository = _signed_in_client()
    organization = repository.organization
    visible_scope = AccessScope.objects.get(organization=organization)
    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="CANARY-HIDDEN-SCOPE",
        all_memberships=False,
        all_repositories=True,
    )
    visible_source = SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=visible_scope,
        external_key="filesystem:visible",
        display_name="Visible source",
        state=SourceConnection.State.ACTIVE,
        last_successful_sync_at=timezone.now(),
    )
    hidden_source = SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=hidden_scope,
        external_key="filesystem:hidden",
        display_name="CANARY-HIDDEN-SOURCE",
        state=SourceConnection.State.FAILED,
        last_error_code="CANARY-HIDDEN-ERROR",
    )
    revoked_source = SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=visible_scope,
        external_key="filesystem:revoked",
        display_name="CANARY-REVOKED-SOURCE",
        state=SourceConnection.State.REVOKED,
    )
    hidden_packet_scope = derive_scope_intersection(
        actor=ActorContext(
            actor_type="USER",
            actor_id=str(client.session["anva_web_user_id"]),
            organization_id=organization.id,
            authorization_path="session:untrusted",
            repository_id=repository.id,
            request_id=uuid.uuid4(),
        ),
        source_scope_ids=[hidden_scope.id],
        name="CANARY-HIDDEN-PACKET-SCOPE",
    )
    packet_artifact = ImmutableArtifact.objects.create(
        organization=organization,
        access_scope=hidden_packet_scope,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload={"canary": "CANARY-HIDDEN-PACKET"},
    )
    hidden_packet = ContextPacketRecord.objects.create(
        organization=organization,
        artifact=packet_artifact,
        repository=repository,
        access_scope=hidden_packet_scope,
        actor_type="USER",
        actor_id=str(client.session["anva_web_user_id"]),
        phase=ContextPacketRecord.Phase.PREPARE,
        normalized_request={"task": "CANARY-HIDDEN-PACKET"},
        request_hash="1" * 64,
        authorization_hash="2" * 64,
        selection_hash="3" * 64,
        retrieval_watermark=1,
        retrieval_algorithm_version="test",
        index_version="test",
        embedding_version="test",
        budget_max_items=10,
        budget_max_tokens=100,
        budget_max_bytes=1000,
        budget_max_citations=10,
        selected_items=1,
        selected_tokens=1,
        selected_bytes=1,
        selected_citations=1,
        limitations=["CANARY-HIDDEN-PACKET-LIMIT"],
        cache_key="4" * 64,
    )
    hidden_assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        subject_key="CANARY-HIDDEN-ASSERTION",
        predicate="owned_by",
        value={"owner": "CANARY-HIDDEN-OWNER"},
        provenance=[{"source_id": str(hidden_source.id)}],
        observed_at=timezone.now(),
    )
    hidden_proposal = KnowledgeProposal.objects.create(
        organization=organization,
        summary="CANARY-HIDDEN-PROPOSAL",
        proposed_changes=[{"operation": "CORRECT"}],
        anva_sources=[{"source_id": str(hidden_source.id)}],
    )
    KnowledgeProposalScope.objects.create(
        organization=organization,
        knowledge_proposal=hidden_proposal,
        repository=repository,
        access_scope=hidden_scope,
        assertion=hidden_assertion,
    )
    AuditEvent.objects.create(
        organization=organization,
        actor_type="USER",
        actor_id=str(client.session["anva_web_user_id"]),
        action="CANARY-HIDDEN-AUDIT",
        target_type="sourceconnection",
        target_id=hidden_source.id,
        from_state="ACTIVE",
        to_state="FAILED",
        authorization_path="role:ORG_ADMIN",
        request_id=uuid.uuid4(),
    )
    hidden_run = AssuranceRun.objects.create(
        organization=organization,
        initiated_by_actor_type="SYSTEM",
        initiated_by_actor_id="test-fixture",
        repository=repository,
        repository_external_id=repository.external_id,
        pull_request_number=77,
        head_commit="7" * 40,
        policy_version=1,
        context_packet=hidden_packet,
    )
    visible_run = AssuranceRun.objects.create(
        organization=organization,
        initiated_by_actor_type="SYSTEM",
        initiated_by_actor_id="test-fixture",
        repository=repository,
        repository_external_id=repository.external_id,
        pull_request_number=78,
        head_commit="8" * 40,
        evaluated_commit="8" * 40,
        report_commit="8" * 40,
        policy_version=1,
        readiness=AssuranceRun.State.FAILED,
        state=AssuranceRun.State.FAILED,
        completed_at=timezone.now(),
    )
    manifest_artifact = ImmutableArtifact.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        kind=ImmutableArtifact.Kind.EVIDENCE_MANIFEST,
        schema_name="evidence-manifest",
        schema_version="1.0",
        payload={"canary": "CANARY-HIDDEN-EVIDENCE-MANIFEST"},
    )
    manifest = EvidenceManifest.objects.create(
        organization=organization,
        repository=repository,
        access_scope=hidden_scope,
        artifact=manifest_artifact,
        pull_request_number=visible_run.pull_request_number,
        commit_sha=visible_run.head_commit,
        schema_version="1.0",
        producer="CANARY-HIDDEN-PRODUCER",
        producer_version="secret",
        producer_mode=EvidenceManifest.ProducerMode.CI,
        payload_hash=manifest_artifact.content_hash,
        payload_size=1,
    )
    Evidence.objects.create(
        organization=organization,
        manifest=manifest,
        commit_sha=visible_run.head_commit,
        kind=Evidence.Kind.TEST_RESULT,
        name="CANARY-HIDDEN-EVIDENCE",
        producer="CANARY-HIDDEN-PRODUCER",
        producer_version="secret",
        status=Evidence.Status.FAILED,
        completed_at=timezone.now(),
        content_hash=content_hash({"evidence": str(uuid.uuid4())}),
        limitations=["CANARY-HIDDEN-EVIDENCE-LIMIT"],
        retention_class="test",
    )

    routes = (
        "/app",
        "/app/onboarding",
        "/app/sources",
        f"/app/repositories/{repository.id}",
        "/app/review",
        "/app/assurance",
        f"/app/assurance/{visible_run.id}",
        "/app/skills",
        "/app/audit",
    )
    prohibited = (
        "CANARY-HIDDEN",
        "CANARY-REVOKED",
        str(hidden_source.id),
        str(hidden_source.id)[:12],
        str(hidden_packet.id),
        str(hidden_packet.id)[:12],
        str(hidden_proposal.id),
        str(hidden_proposal.id)[:12],
    )
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, route
        rendered = response.content.decode()
        for value in prohibited:
            assert value not in rendered, (route, value)
    home = client.get("/app").content.decode()
    assert "1 of 1" in home
    assert "1/1" in home
    onboarding = client.get("/app/onboarding").content.decode()
    assert "1 source connection" in onboarding
    assert "No successful context packet is visible." in onboarding

    foreign = Organization.objects.create(slug="source-foreign", name="Source Foreign")
    foreign_repository = Repository.objects.create(
        organization=foreign,
        external_id="github:foreign/source",
        name="source",
    )
    foreign_source = SourceConnection.objects.create(
        organization=foreign,
        repository=foreign_repository,
        external_key="filesystem:foreign",
        display_name="CANARY-FOREIGN-SOURCE",
    )
    correlation = str(uuid.uuid4())
    unavailable = [
        client.get(
            f"/app/sources/{source_id}",
            HTTP_X_CORRELATION_ID=correlation,
        )
        for source_id in (
            hidden_source.id,
            revoked_source.id,
            foreign_source.id,
            uuid.uuid4(),
        )
    ]
    assert {response.status_code for response in unavailable} == {404}
    assert len({response.content for response in unavailable}) == 1
    hidden_assurance = client.get(
        f"/app/assurance/{hidden_run.id}",
        HTTP_X_CORRELATION_ID=correlation,
    )
    assert hidden_assurance.status_code == 404
    assert hidden_assurance.content == unavailable[0].content
    assert visible_source.id


@pytest.mark.integration
@pytest.mark.django_db
def test_github_binding_status_is_scope_authorized_and_recomputed_immediately() -> None:
    client, repository = _signed_in_client()
    organization = repository.organization
    membership = Membership.objects.get(
        organization=organization,
        user_id=uuid.UUID(client.session["anva_web_user_id"]),
    )
    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="CANARY-HIDDEN-GITHUB-SCOPE",
        all_memberships=False,
        all_repositories=True,
    )
    binding = _create_github_binding(
        repository=repository,
        access_scope=hidden_scope,
        full_name="CANARY-HIDDEN-GITHUB-BINDING",
    )

    hidden_onboarding = client.get("/app/onboarding").content.decode()
    hidden_binding_item = _onboarding_item(hidden_onboarding, "GitHub App binding")
    hidden_repository = client.get(f"/app/repositories/{repository.id}").content.decode()

    assert "progress-item--unavailable" in hidden_binding_item
    assert "Operator-assisted GitHub App installation is required." in hidden_binding_item
    assert "active installation binding" not in hidden_binding_item
    assert "GitHub binding unavailable" in hidden_repository
    assert "GitHub bound" not in hidden_repository
    for rendered in (hidden_onboarding, hidden_repository):
        assert binding.full_name not in rendered
        assert str(binding.id) not in rendered
        assert str(binding.installation_id) not in rendered

    scope_membership = AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        membership=membership,
    )
    visible_onboarding = client.get("/app/onboarding").content.decode()
    visible_binding_item = _onboarding_item(visible_onboarding, "GitHub App binding")
    visible_repository = client.get(f"/app/repositories/{repository.id}").content.decode()
    assert "progress-item--done" in visible_binding_item
    assert "1 active installation binding" in visible_binding_item
    assert "GitHub bound" in visible_repository

    scope_membership.delete()
    membership.role = Role.objects.get(
        organization=organization,
        code=Role.Code.DEVELOPER,
    )
    membership.save(update_fields=["role", "updated_at"])
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=hidden_scope,
        membership=membership,
    )
    role_changed_onboarding = client.get("/app/onboarding").content.decode()
    role_changed_repository = client.get(f"/app/repositories/{repository.id}").content.decode()
    assert "progress-item--unavailable" in _onboarding_item(
        role_changed_onboarding,
        "GitHub App binding",
    )
    assert "GitHub binding unavailable" in role_changed_repository
    assert "GitHub bound" not in role_changed_repository

    membership.role = Role.objects.get(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
    )
    membership.save(update_fields=["role", "updated_at"])
    binding.is_active = False
    binding.revoked_at = timezone.now()
    binding.save(update_fields=["is_active", "revoked_at", "updated_at"])
    revoked_onboarding = client.get("/app/onboarding").content.decode()
    revoked_repository = client.get(f"/app/repositories/{repository.id}").content.decode()
    assert "progress-item--unavailable" in _onboarding_item(
        revoked_onboarding,
        "GitHub App binding",
    )
    assert "GitHub binding unavailable" in revoked_repository
    assert "GitHub bound" not in revoked_repository


@pytest.mark.integration
@pytest.mark.django_db
def test_onboarding_revocation_aggregate_is_scope_safe_and_identity_free() -> None:
    client, repository = _signed_in_client()
    organization = repository.organization
    visible_scope = AccessScope.objects.get(organization=organization)

    empty_onboarding = client.get("/app/onboarding").content.decode()
    empty_indexing = _onboarding_item(empty_onboarding, "Sources indexed with provenance")
    empty_revocation = _onboarding_item(empty_onboarding, "Source revocation exercise")
    assert "progress-item--needs_attention" in empty_indexing
    assert "0 source connections" in empty_indexing
    assert "progress-item--needs_attention" in empty_revocation
    assert (
        "No authorized source revocation has been observed. "
        "Revoke a test source to verify future retrieval is denied."
    ) in empty_revocation

    SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=visible_scope,
        external_key="filesystem:active-finalfix",
        display_name="Active final-fix source",
        state=SourceConnection.State.ACTIVE,
        last_successful_sync_at=timezone.now(),
    )
    SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=visible_scope,
        external_key="filesystem:failed-finalfix",
        display_name="Failed final-fix source",
        state=SourceConnection.State.FAILED,
    )
    mixed_onboarding = client.get("/app/onboarding").content.decode()
    mixed_indexing = _onboarding_item(mixed_onboarding, "Sources indexed with provenance")
    mixed_revocation = _onboarding_item(mixed_onboarding, "Source revocation exercise")
    assert "progress-item--done" in mixed_indexing
    assert "2 source connections" in mixed_indexing
    assert mixed_revocation == empty_revocation

    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="CANARY-HIDDEN-REVOKED-SCOPE",
        all_memberships=False,
        all_repositories=True,
        is_active=False,
    )
    hidden_revoked = SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=hidden_scope,
        external_key="filesystem:hidden-revoked-finalfix",
        display_name="CANARY-HIDDEN-REVOKED-SOURCE",
        state=SourceConnection.State.REVOKED,
    )
    hidden_onboarding = client.get("/app/onboarding").content.decode()
    assert _onboarding_item(hidden_onboarding, "Source revocation exercise") == empty_revocation
    assert "CANARY-HIDDEN-REVOKED" not in hidden_onboarding

    revoked_scope = AccessScope.objects.create(
        organization=organization,
        name="Visible revoked source health",
        all_memberships=True,
        all_repositories=True,
        is_active=False,
    )
    visible_revoked = SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=revoked_scope,
        external_key="filesystem:visible-revoked-finalfix",
        display_name="CANARY-VISIBLE-REVOKED-SOURCE",
        state=SourceConnection.State.REVOKED,
    )
    revoked_onboarding = client.get("/app/onboarding").content.decode()
    revoked_indexing = _onboarding_item(revoked_onboarding, "Sources indexed with provenance")
    revoked_exercise = _onboarding_item(revoked_onboarding, "Source revocation exercise")
    assert "progress-item--done" in revoked_indexing
    assert "2 source connections" in revoked_indexing
    assert "progress-item--done" in revoked_exercise
    assert (
        "Revocation verified for 1 authorized source; reconnect or replace it "
        "before ingestion resumes."
    ) in revoked_exercise
    assert "CANARY-VISIBLE-REVOKED" not in revoked_onboarding

    correlation = str(uuid.uuid4())
    unavailable = [
        client.get(
            f"/app/sources/{source_id}",
            HTTP_X_CORRELATION_ID=correlation,
        )
        for source_id in (hidden_revoked.id, visible_revoked.id, uuid.uuid4())
    ]
    assert {response.status_code for response in unavailable} == {404}
    assert len({response.content for response in unavailable}) == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_correction_is_revision_checked_and_canonical_retry_idempotent() -> None:
    client, repository = _signed_in_client()
    scope = AccessScope.objects.get(organization=repository.organization)
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key="system:payments",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        observed_at=timezone.now(),
    )
    path = f"/app/review/{assertion.id}"
    payload = {
        "decision": "CORRECT",
        "expected_revision": str(assertion.revision),
        "repository_id": str(repository.id),
        "correction": "Owned by Payments Platform.",
    }

    first = client.post(path, payload)
    proposal = KnowledgeProposal.objects.get()
    first_counts = (
        KnowledgeProposal.objects.count(),
        KnowledgeProposalScope.objects.count(),
        AuditEvent.objects.filter(target_type="knowledgeproposal").count(),
        OutboxEvent.objects.filter(aggregate_type="knowledgeproposal").count(),
    )
    replay = client.post(path, payload)
    replay_scope = KnowledgeProposalScope.objects.get()

    assert first.status_code == 302
    assert replay.status_code == 302
    assert replay_scope.knowledge_proposal_id == proposal.id
    assert (
        (
            KnowledgeProposal.objects.count(),
            KnowledgeProposalScope.objects.count(),
            AuditEvent.objects.filter(target_type="knowledgeproposal").count(),
            OutboxEvent.objects.filter(aggregate_type="knowledgeproposal").count(),
        )
        == first_counts
        == (1, 1, 1, 1)
    )
    audit = AuditEvent.objects.get(target_type="knowledgeproposal")
    assert audit.actor_type == "USER"
    assert audit.authorization_path.startswith("role:ORG_ADMIN")
    assert "web-session" not in audit.authorization_path

    changed_payload = {**payload, "correction": "Owned by a different team."}
    changed = client.post(path, changed_payload)
    assert changed.status_code == 409
    assert (
        KnowledgeProposal.objects.count(),
        KnowledgeProposalScope.objects.count(),
        AuditEvent.objects.filter(target_type="knowledgeproposal").count(),
        OutboxEvent.objects.filter(aggregate_type="knowledgeproposal").count(),
    ) == first_counts

    KnowledgeAssertion.objects.filter(id=assertion.id).update(revision=assertion.revision + 1)
    stale = client.post(path, payload)
    assert stale.status_code == 409
    assert (
        KnowledgeProposal.objects.count(),
        KnowledgeProposalScope.objects.count(),
        AuditEvent.objects.filter(target_type="knowledgeproposal").count(),
        OutboxEvent.objects.filter(aggregate_type="knowledgeproposal").count(),
    ) == first_counts


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(
    ANVA_MCP_URL="http://missing.invalid/mcp",
    ANVA_MCP_ALLOWED_HOSTS=("missing.invalid",),
)
def test_skills_reports_configured_mcp_dns_failure_without_claiming_compatibility() -> None:
    client, _repository = _signed_in_client()

    response = client.get("/app/skills")
    content = response.content.decode()

    assert response.status_code == 200
    assert "DNS unavailable" in content
    assert "Compatible" not in content


@pytest.mark.integration
@pytest.mark.django_db
def test_stale_correction_creates_no_proposal_audit_or_outbox() -> None:
    client, repository = _signed_in_client()
    scope = AccessScope.objects.get(organization=repository.organization)
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key="system:stale",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        observed_at=timezone.now(),
    )
    KnowledgeAssertion.objects.filter(id=assertion.id).update(revision=2)

    response = client.post(
        f"/app/review/{assertion.id}",
        {
            "decision": "CORRECT",
            "expected_revision": "1",
            "repository_id": str(repository.id),
            "correction": "Owned by Payments Platform.",
        },
    )

    assert response.status_code == 409
    assert KnowledgeProposal.objects.count() == 0
    assert KnowledgeProposalScope.objects.count() == 0
    assert AuditEvent.objects.filter(target_type="knowledgeproposal").count() == 0
    assert OutboxEvent.objects.filter(aggregate_type="knowledgeproposal").count() == 0


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_concurrent_exact_correction_retries_create_one_canonical_proposal() -> None:
    client, repository = _signed_in_client()
    scope = AccessScope.objects.get(organization=repository.organization)
    assertion = KnowledgeAssertion.objects.create(
        organization=repository.organization,
        access_scope=scope,
        subject_key="system:concurrent",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
        observed_at=timezone.now(),
    )
    user_id = str(client.session["anva_web_user_id"])
    barrier = threading.Barrier(2)

    def propose() -> uuid.UUID:
        close_old_connections()
        try:
            actor = ActorContext(
                organization_id=repository.organization_id,
                actor_type="USER",
                actor_id=user_id,
                authorization_path="session:untrusted",
                request_id=uuid.uuid4(),
            )
            barrier.wait()
            result = ProductUIFacade(actor).review_assertion(
                repository_id=repository.id,
                assertion_id=assertion.id,
                decision="CORRECT",
                expected_revision=1,
                correction="Owned by Payments Platform.",
            )
            return result.id
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        proposal_ids = {future.result() for future in [executor.submit(propose) for _ in range(2)]}

    assert len(proposal_ids) == 1
    assert KnowledgeProposal.objects.count() == 1
    assert KnowledgeProposalScope.objects.count() == 1
    assert AuditEvent.objects.filter(target_type="knowledgeproposal").count() == 1
    assert OutboxEvent.objects.filter(aggregate_type="knowledgeproposal").count() == 1
