"""End-to-end tenancy, scope, credential, and non-disclosure security tests."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

import pytest
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import Client
from django.utils import timezone

from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    AccessSnapshot,
    AssuranceRun,
    AuditEvent,
    ImmutableArtifact,
    KnowledgeAssertion,
    Membership,
    Organization,
    OutboxEvent,
    Repository,
    RepositoryAccessToken,
    Role,
    ServiceIdentity,
    SourceConnection,
    SyncRun,
    Team,
    TeamMembership,
    User,
)
from anva.core.services.artifacts import create_artifact
from anva.core.services.authorization import (
    INVALID_CREDENTIAL_MESSAGE,
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
)
from anva.core.services.context import ActorContext
from anva.core.services.creation import (
    create_assertion,
    request_assurance_run,
    request_sync_run,
)
from anva.core.services.events import record_transition
from anva.core.services.retrieval import get_authorized_assertion
from anva.core.services.scopes import (
    create_access_snapshot,
    derive_scope_intersection,
    revoke_source_connection,
)
from anva.core.services.secured_operations import execute_assurance_transition
from anva.core.services.tokens import (
    authenticate_bearer,
    issue_bootstrap_repository_token,
    issue_repository_token,
    revoke_repository_token,
    rotate_repository_token,
)


@dataclass(frozen=True)
class ServiceTenant:
    organization: Organization
    repository: Repository
    service: ServiceIdentity
    scope: AccessScope
    plaintext_token: str


def service_tenant(slug: str, actions: frozenset[Action]) -> ServiceTenant:
    organization = Organization.objects.create(slug=slug, name=f"{slug} organization")
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:{slug}/repository",
        name=f"{slug} repository",
    )
    service = ServiceIdentity.objects.create(
        organization=organization,
        name="test-service",
        issuer="anva-test",
        audience="anva-test-api",
    )
    AccessGrant.objects.bulk_create(
        [
            AccessGrant(
                organization=organization,
                service_identity=service,
                repository=repository,
                action=action.value,
            )
            for action in actions
        ]
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="service-visible",
        all_service_identities=True,
        all_repositories=True,
    )
    issued = issue_bootstrap_repository_token(
        organization=organization,
        repository=repository,
        service_identity=service,
        actions=actions,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return ServiceTenant(organization, repository, service, scope, issued.plaintext)


def user_actor(
    organization: Organization,
    role_code: str,
    *,
    label: str,
    repository: Repository | None = None,
) -> tuple[ActorContext, Membership]:
    role, _ = Role.objects.get_or_create(
        organization=organization,
        code=role_code,
        defaults={"name": role_code.title()},
    )
    user = User.objects.create(
        email=f"{label}-{uuid.uuid4()}@example.test",
        display_name=label,
    )
    membership = Membership.objects.create(
        organization=organization,
        user=user,
        role=role,
    )
    return (
        ActorContext(
            organization_id=organization.id,
            actor_type="USER",
            actor_id=str(user.id),
            authorization_path="untrusted-caller-claim",
            request_id=uuid.uuid4(),
            repository_id=repository.id if repository else None,
        ),
        membership,
    )


def assert_hidden(operation: Callable[[], object]) -> None:
    with pytest.raises(ResourceNotFoundError) as captured:
        operation()
    assert captured.value.code == "resource_not_found"
    assert str(captured.value) == NOT_FOUND_MESSAGE


@pytest.mark.integration
@pytest.mark.django_db
@pytest.mark.parametrize(
    ("role_code", "action", "allowed"),
    [
        (Role.Code.ORG_ADMIN, Action.TOKEN_MANAGE, True),
        (Role.Code.KNOWLEDGE_ADMIN, Action.SCOPE_MANAGE, True),
        (Role.Code.TECHNICAL_OWNER, Action.ASSURANCE_EXECUTE, True),
        (Role.Code.PRODUCT_OWNER, Action.KNOWLEDGE_REVIEW, True),
        (Role.Code.DEVELOPER, Action.ASSURANCE_EXECUTE, True),
        (Role.Code.REVIEWER, Action.KNOWLEDGE_REVIEW, True),
        (Role.Code.SECURITY_REVIEWER, Action.FINDING_DISMISS, True),
        (Role.Code.VIEWER, Action.SEARCH, True),
        (Role.Code.VIEWER, Action.POLICY_VIEW, True),
        (Role.Code.VIEWER, Action.EVIDENCE_VIEW, True),
        (Role.Code.VIEWER, Action.KNOWLEDGE_PROPOSE, False),
        (Role.Code.VIEWER, Action.KNOWLEDGE_REVIEW, False),
        (Role.Code.VIEWER, Action.ASSURANCE_EXECUTE, False),
        (Role.Code.KNOWLEDGE_ADMIN, Action.WORK_MANAGE, True),
        (Role.Code.KNOWLEDGE_ADMIN, Action.WORK_APPROVE, False),
        (Role.Code.TECHNICAL_OWNER, Action.POLICY_MANAGE, True),
        (Role.Code.TECHNICAL_OWNER, Action.EVIDENCE_SUBMIT, True),
        (Role.Code.TECHNICAL_OWNER, Action.WORK_APPROVE, False),
        (Role.Code.PRODUCT_OWNER, Action.WORK_APPROVE, True),
        (Role.Code.PRODUCT_OWNER, Action.POLICY_MANAGE, False),
        (Role.Code.SECURITY_REVIEWER, Action.POLICY_OVERRIDE, True),
        (Role.Code.SECURITY_REVIEWER, Action.ASSURANCE_EXECUTE, False),
        (Role.Code.DEVELOPER, Action.POLICY_OVERRIDE, False),
        (Role.Code.REVIEWER, Action.TOKEN_MANAGE, False),
    ],
)
def test_role_action_matrix(role_code: str, action: Action, allowed: bool) -> None:
    organization = Organization.objects.create(
        slug=f"role-{uuid.uuid4()}",
        name="Role matrix",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:role/{uuid.uuid4()}",
        name="Role repository",
    )
    actor, _membership = user_actor(
        organization,
        role_code,
        label="matrix",
    )

    if allowed:
        decision = authorize_action(actor=actor, action=action, repository_id=repository.id)
        assert decision.action == action
        assert decision.authorization_path.startswith(f"role:{role_code}")
    else:
        assert_hidden(
            lambda: authorize_action(actor=actor, action=action, repository_id=repository.id)
        )


@pytest.mark.integration
@pytest.mark.django_db
def test_creation_paths_authorize_before_idempotency_and_persist_scopes() -> None:
    organization = Organization.objects.create(slug="creation-auth", name="Creation auth")
    repository = Repository.objects.create(
        organization=organization,
        external_id="github:creation/auth",
        name="Creation auth",
    )
    source = SourceConnection.objects.create(
        organization=organization,
        external_key="github:creation/auth",
        state=SourceConnection.State.ACTIVE,
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="creation scope",
        all_memberships=True,
        all_repositories=True,
    )
    admin, _admin_membership = user_actor(
        organization,
        Role.Code.ORG_ADMIN,
        label="creation-admin",
    )
    viewer, _viewer_membership = user_actor(
        organization,
        Role.Code.VIEWER,
        label="creation-viewer",
    )
    request_sync_run(actor=admin, source_connection_id=source.id)
    request_assurance_run(
        actor=admin,
        repository_id=repository.id,
        pull_request_number=8,
        head_commit="a" * 40,
        policy_version=1,
    )

    initial_counts = (
        SyncRun.objects.count(),
        AssuranceRun.objects.count(),
        KnowledgeAssertion.objects.count(),
        ImmutableArtifact.objects.count(),
        AuditEvent.objects.count(),
        OutboxEvent.objects.count(),
    )
    denied_operations: list[Callable[[], object]] = [
        lambda: request_sync_run(actor=viewer, source_connection_id=source.id),
        lambda: request_assurance_run(
            actor=viewer,
            repository_id=repository.id,
            pull_request_number=8,
            head_commit="a" * 40,
            policy_version=1,
        ),
        lambda: create_assertion(
            actor=viewer,
            repository_id=repository.id,
            access_scope_id=scope.id,
            subject_key="CANARY-UNAUTHORIZED",
            predicate="contains",
            value=True,
            provenance=[{"source_id": str(source.id)}],
        ),
        lambda: create_artifact(
            actor=viewer,
            repository_id=repository.id,
            access_scope_id=scope.id,
            kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
            schema_name="unknown-before-authorization",
            schema_version="1.0",
            payload={},
        ),
    ]
    for operation in denied_operations:
        assert_hidden(operation)
    assert (
        SyncRun.objects.count(),
        AssuranceRun.objects.count(),
        KnowledgeAssertion.objects.count(),
        ImmutableArtifact.objects.count(),
        AuditEvent.objects.count(),
        OutboxEvent.objects.count(),
    ) == initial_counts

    foreign_organization = Organization.objects.create(
        slug="creation-foreign",
        name="Creation foreign",
    )
    foreign_repository = Repository.objects.create(
        organization=foreign_organization,
        external_id="github:creation/foreign",
        name="Foreign",
    )
    foreign_source = SourceConnection.objects.create(
        organization=foreign_organization,
        external_key="github:creation/foreign",
    )
    foreign_scope = AccessScope.objects.create(
        organization=foreign_organization,
        name="foreign",
        all_memberships=True,
        all_repositories=True,
    )
    missing_source_id = uuid.uuid4()
    for operation in [
        lambda: request_sync_run(actor=admin, source_connection_id=foreign_source.id),
        lambda: request_sync_run(actor=admin, source_connection_id=missing_source_id),
        lambda: request_assurance_run(
            actor=admin,
            repository_id=foreign_repository.id,
            pull_request_number=1,
            head_commit="b" * 40,
            policy_version=1,
        ),
        lambda: request_assurance_run(
            actor=admin,
            repository_id=uuid.uuid4(),
            pull_request_number=1,
            head_commit="b" * 40,
            policy_version=1,
        ),
        lambda: create_assertion(
            actor=admin,
            repository_id=repository.id,
            access_scope_id=foreign_scope.id,
            subject_key="CANARY-FOREIGN",
            predicate="contains",
            value=True,
            provenance=[{"source_id": str(foreign_source.id)}],
        ),
        lambda: create_assertion(
            actor=admin,
            repository_id=foreign_repository.id,
            access_scope_id=scope.id,
            subject_key="CANARY-FOREIGN-REPOSITORY",
            predicate="contains",
            value=True,
            provenance=[{"source_id": str(source.id)}],
        ),
        lambda: create_artifact(
            actor=admin,
            repository_id=repository.id,
            access_scope_id=uuid.uuid4(),
            kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
            schema_name="unknown-before-authorization",
            schema_version="1.0",
            payload={},
        ),
        lambda: create_artifact(
            actor=admin,
            repository_id=uuid.uuid4(),
            access_scope_id=scope.id,
            kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
            schema_name="unknown-before-authorization",
            schema_version="1.0",
            payload={},
        ),
    ]:
        assert_hidden(operation)
    assert (
        SyncRun.objects.count(),
        AssuranceRun.objects.count(),
        KnowledgeAssertion.objects.count(),
        ImmutableArtifact.objects.count(),
        AuditEvent.objects.count(),
        OutboxEvent.objects.count(),
    ) == initial_counts

    assertion = create_assertion(
        actor=admin,
        repository_id=repository.id,
        access_scope_id=scope.id,
        subject_key="service:creation",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(source.id)}],
    )
    assert assertion.access_scope_id == scope.id


@pytest.mark.integration
@pytest.mark.django_db
def test_grants_intersect_principal_action_repository_source_and_lifetime() -> None:
    tenant = service_tenant("grant-matrix", frozenset({Action.SEARCH}))
    second_repository = Repository.objects.create(
        organization=tenant.organization,
        external_id="github:grant/second",
        name="Second",
    )
    first_source = SourceConnection.objects.create(
        organization=tenant.organization,
        external_key="source:first",
        state=SourceConnection.State.ACTIVE,
    )
    second_source = SourceConnection.objects.create(
        organization=tenant.organization,
        external_key="source:second",
        state=SourceConnection.State.ACTIVE,
    )
    AccessGrant.objects.filter(
        organization=tenant.organization,
        service_identity=tenant.service,
    ).delete()
    grant = AccessGrant.objects.create(
        organization=tenant.organization,
        service_identity=tenant.service,
        repository=tenant.repository,
        source_connection=first_source,
        action=Action.SOURCE_SYNC.value,
    )
    actor = authenticate_bearer(f"Bearer {tenant.plaintext_token}")

    # Credential capabilities are intersected with grants, never unioned with them.
    assert_hidden(
        lambda: authorize_action(
            actor=actor,
            action=Action.SOURCE_SYNC,
            repository_id=tenant.repository.id,
            source_connection_id=first_source.id,
        )
    )
    unrestricted_actor = ActorContext(
        organization_id=tenant.organization.id,
        actor_type="SERVICE",
        actor_id=str(tenant.service.id),
        authorization_path="service",
        request_id=uuid.uuid4(),
    )
    authorize_action(
        actor=unrestricted_actor,
        action=Action.SOURCE_SYNC,
        repository_id=tenant.repository.id,
        source_connection_id=first_source.id,
    )
    for repository_id, source_id in [
        (second_repository.id, first_source.id),
        (tenant.repository.id, second_source.id),
    ]:
        with pytest.raises(ResourceNotFoundError, match=NOT_FOUND_MESSAGE):
            authorize_action(
                actor=unrestricted_actor,
                action=Action.SOURCE_SYNC,
                repository_id=repository_id,
                source_connection_id=source_id,
            )
    grant.revoked_at = timezone.now()
    grant.save(update_fields=["revoked_at"])
    assert_hidden(
        lambda: authorize_action(
            actor=unrestricted_actor,
            action=Action.SOURCE_SYNC,
            repository_id=tenant.repository.id,
            source_connection_id=first_source.id,
        )
    )
    grant.revoked_at = None
    grant.expires_at = timezone.now() - timedelta(seconds=1)
    grant.save(update_fields=["revoked_at", "expires_at"])
    assert_hidden(
        lambda: authorize_action(
            actor=unrestricted_actor,
            action=Action.SOURCE_SYNC,
            repository_id=tenant.repository.id,
            source_connection_id=first_source.id,
        )
    )


@pytest.mark.integration
@pytest.mark.django_db
def test_derived_scope_is_exact_intersection_and_source_revocation_propagates() -> None:
    organization = Organization.objects.create(slug="derived", name="Derived")
    repository_a = Repository.objects.create(
        organization=organization,
        external_id="github:derived/a",
        name="A",
    )
    repository_b = Repository.objects.create(
        organization=organization,
        external_id="github:derived/b",
        name="B",
    )
    admin, admin_membership = user_actor(
        organization,
        Role.Code.ORG_ADMIN,
        label="admin",
    )
    viewer, viewer_membership = user_actor(
        organization,
        Role.Code.VIEWER,
        label="viewer",
    )
    other, other_membership = user_actor(
        organization,
        Role.Code.VIEWER,
        label="other",
    )
    del other
    source = SourceConnection.objects.create(
        organization=organization,
        external_key="github:derived/source",
        state=SourceConnection.State.ACTIVE,
    )
    included_service = ServiceIdentity.objects.create(
        organization=organization,
        name="derived-included-service",
        issuer="test",
        audience="test",
    )
    excluded_service = ServiceIdentity.objects.create(
        organization=organization,
        name="derived-excluded-service",
        issuer="test",
        audience="test",
    )
    broad = AccessScope.objects.create(
        organization=organization,
        name="broad",
    )
    narrow = AccessScope.objects.create(
        organization=organization,
        name="narrow",
    )
    AccessScopeMembership.objects.bulk_create(
        [
            AccessScopeMembership(
                organization=organization,
                access_scope=broad,
                membership=viewer_membership,
            ),
            AccessScopeMembership(
                organization=organization,
                access_scope=broad,
                membership=other_membership,
            ),
            AccessScopeMembership(
                organization=organization,
                access_scope=narrow,
                membership=viewer_membership,
            ),
        ]
    )
    AccessScopeRepository.objects.bulk_create(
        [
            AccessScopeRepository(
                organization=organization,
                access_scope=broad,
                repository=repository_a,
            ),
            AccessScopeRepository(
                organization=organization,
                access_scope=broad,
                repository=repository_b,
            ),
            AccessScopeRepository(
                organization=organization,
                access_scope=narrow,
                repository=repository_b,
            ),
        ]
    )
    AccessScopeServiceIdentity.objects.bulk_create(
        [
            AccessScopeServiceIdentity(
                organization=organization,
                access_scope=broad,
                service_identity=included_service,
            ),
            AccessScopeServiceIdentity(
                organization=organization,
                access_scope=narrow,
                service_identity=included_service,
            ),
        ]
    )
    AccessScopeSource.objects.create(
        organization=organization,
        access_scope=broad,
        source_connection=source,
    )

    derived = derive_scope_intersection(
        actor=admin,
        source_scope_ids=[broad.id, narrow.id],
        name="intersection",
    )

    assert set(
        AccessScopeMembership.objects.filter(access_scope=derived).values_list(
            "membership_id", flat=True
        )
    ) == {viewer_membership.id}
    assert set(
        AccessScopeRepository.objects.filter(access_scope=derived).values_list(
            "repository_id", flat=True
        )
    ) == {repository_b.id}
    assert set(
        AccessScopeServiceIdentity.objects.filter(access_scope=derived).values_list(
            "service_identity_id", flat=True
        )
    ) == {included_service.id}
    assert set(derived.derived_from.values_list("id", flat=True)) == {broad.id, narrow.id}
    assert derived.is_derived
    assert derived.boundary_sealed_at is not None
    assert AccessScopeSource.objects.filter(
        access_scope=derived,
        source_connection=source,
    ).exists()
    decoy = AccessScope.objects.create(
        organization=organization,
        name="ordinary-decoy",
    )

    outbound_moves = [
        ("UPDATE core_accessscopemembership SET access_scope_id = %s WHERE access_scope_id = %s"),
        (
            "UPDATE core_accessscopeserviceidentity "
            "SET access_scope_id = %s WHERE access_scope_id = %s"
        ),
        ("UPDATE core_accessscoperepository SET access_scope_id = %s WHERE access_scope_id = %s"),
        ("UPDATE core_accessscopesource SET access_scope_id = %s WHERE access_scope_id = %s"),
        (
            "UPDATE core_accessscope_derived_from "
            "SET from_accessscope_id = %s WHERE from_accessscope_id = %s"
        ),
    ]
    for statement in outbound_moves:
        with pytest.raises(DatabaseError, match="derived access scope relations"):
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(statement, [decoy.id, derived.id])

    assert set(
        AccessScopeMembership.objects.filter(access_scope=derived).values_list(
            "membership_id", flat=True
        )
    ) == {viewer_membership.id}
    assert set(
        AccessScopeServiceIdentity.objects.filter(access_scope=derived).values_list(
            "service_identity_id", flat=True
        )
    ) == {included_service.id}
    assert set(
        AccessScopeRepository.objects.filter(access_scope=derived).values_list(
            "repository_id", flat=True
        )
    ) == {repository_b.id}
    assert AccessScopeSource.objects.filter(
        access_scope=derived,
        source_connection=source,
    ).exists()
    assert set(derived.derived_from.values_list("id", flat=True)) == {broad.id, narrow.id}

    def widen_with_direct_sql() -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE core_accessscope SET all_memberships = TRUE WHERE id = %s",
                [derived.id],
            )

    mutations: list[Callable[[], object]] = [
        widen_with_direct_sql,
        lambda: AccessScope.objects.filter(id=derived.id).update(is_derived=False),
        lambda: AccessScopeMembership.objects.filter(access_scope=derived).delete(),
        lambda: AccessScopeRepository.objects.create(
            organization=organization,
            access_scope=derived,
            repository=repository_a,
        ),
        lambda: derived.derived_from.remove(broad),
    ]
    for mutation in mutations:
        with pytest.raises(DatabaseError, match="derived access scope"):
            with transaction.atomic():
                mutation()

    with pytest.raises(DatabaseError, match="derived access scope"):
        with transaction.atomic():
            AccessScopeServiceIdentity.objects.create(
                organization=organization,
                access_scope=derived,
                service_identity=excluded_service,
            )

    # Ordinary administrator-owned scopes retain their legitimate lifecycle.
    AccessScope.objects.filter(id=broad.id).update(name="broad-renamed")
    broad.refresh_from_db()
    assert broad.name == "broad-renamed"
    assert_hidden(
        lambda: authorize_action(
            actor=viewer,
            action=Action.KNOWLEDGE_VIEW,
            access_scope_id=derived.id,
        )
    )

    assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=derived,
        subject_key="CANARY-DERIVED",
        predicate="owned_by",
        value={"team": "visible"},
        provenance=[{"source_id": str(source.id)}],
    )
    visible = get_authorized_assertion(
        actor=viewer,
        repository_id=repository_b.id,
        assertion_id=assertion.id,
        action=Action.KNOWLEDGE_VIEW,
    )
    assert visible.id == assertion.id
    assert_hidden(
        lambda: get_authorized_assertion(
            actor=viewer,
            repository_id=repository_a.id,
            assertion_id=assertion.id,
            action=Action.KNOWLEDGE_VIEW,
        )
    )

    snapshot = create_access_snapshot(
        actor=admin,
        source_connection_id=source.id,
        access_scope_id=broad.id,
    )
    assert snapshot.payload["source_connection_id"] == str(source.id)
    revoke_source_connection(
        actor=admin,
        source_connection_id=source.id,
        expected_revision=source.revision,
    )
    derived.refresh_from_db()
    snapshot.refresh_from_db()
    assert not derived.is_active
    assert snapshot.revoked_at is not None
    assert_hidden(
        lambda: get_authorized_assertion(
            actor=viewer,
            repository_id=repository_b.id,
            assertion_id=assertion.id,
            action=Action.KNOWLEDGE_VIEW,
        )
    )
    assert AuditEvent.objects.filter(
        organization=organization,
        target_type="sourceconnection",
        authorization_path__startswith="role:ORG_ADMIN",
    ).exists()
    assert admin_membership.is_active


@pytest.mark.integration
@pytest.mark.django_db
def test_tokens_are_hashed_one_time_bounded_rotatable_and_immediately_revocable() -> None:
    organization = Organization.objects.create(slug="tokens", name="Tokens")
    repository = Repository.objects.create(
        organization=organization,
        external_id="github:tokens/repository",
        name="Tokens",
    )
    service = ServiceIdentity.objects.create(
        organization=organization,
        name="ci",
        issuer="anva-test",
        audience="anva-test-api",
    )
    admin, _membership = user_actor(organization, Role.Code.ORG_ADMIN, label="token-admin")
    issued = issue_repository_token(
        actor=admin,
        repository_id=repository.id,
        service_identity_id=service.id,
        actions=frozenset({Action.SEARCH, Action.TOKEN_MANAGE}),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    stored = RepositoryAccessToken.objects.get(id=issued.record.id)
    assert issued.plaintext not in stored.token_hash
    assert len(stored.token_hash) == 64
    assert "plaintext" not in str(stored.__dict__).lower()

    authenticated = authenticate_bearer(f"Bearer {issued.plaintext}")
    stored.refresh_from_db()
    assert authenticated.repository_id == repository.id
    assert stored.last_used_at is not None

    replacement = rotate_repository_token(
        actor=admin,
        token_id=stored.id,
        expires_at=timezone.now() + timedelta(hours=2),
    )
    with pytest.raises(AuthenticationError, match=INVALID_CREDENTIAL_MESSAGE):
        authenticate_bearer(f"Bearer {issued.plaintext}")
    with pytest.raises(AuthenticationError, match=INVALID_CREDENTIAL_MESSAGE):
        authorize_action(
            actor=authenticated,
            action=Action.SEARCH,
            repository_id=repository.id,
        )
    assert authenticate_bearer(f"Bearer {replacement.plaintext}").credential_id == (
        replacement.record.id
    )

    revoke_repository_token(actor=admin, token_id=replacement.record.id)
    with pytest.raises(AuthenticationError, match=INVALID_CREDENTIAL_MESSAGE):
        authenticate_bearer(f"Bearer {replacement.plaintext}")

    expired = issue_repository_token(
        actor=admin,
        repository_id=repository.id,
        service_identity_id=service.id,
        actions=frozenset({Action.SEARCH}),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    RepositoryAccessToken.objects.filter(id=expired.record.id).update(
        issued_at=timezone.now() - timedelta(hours=2),
        expires_at=timezone.now() - timedelta(hours=1),
    )
    failures = []
    for header in [
        f"Bearer {expired.plaintext}",
        "Bearer anva_v1.00000000-0000-4000-8000-000000000000.unknown",
        "Bearer malformed",
    ]:
        with pytest.raises(AuthenticationError) as captured:
            authenticate_bearer(header)
        failures.append((captured.value.code, str(captured.value)))
    assert len(set(failures)) == 1

    serialized_audit = json.dumps(
        list(AuditEvent.objects.filter(organization=organization).values()),
        default=str,
    )
    for plaintext in [issued.plaintext, replacement.plaintext, expired.plaintext]:
        assert plaintext not in serialized_audit
    audit_count = AuditEvent.objects.filter(organization=organization).count()
    outbox_count = OutboxEvent.objects.filter(organization=organization).count()
    unsafe_metadata: list[dict[str, object]] = [
        {"authorization": f"Bearer {expired.plaintext}"},
        {"api_key": "sk_live_AUDITLEAK012345"},
        {"kind": {"kind": {"password": "nested-password"}}},
        {"kind": "upstream returned sk_live_EMBEDDED012345"},
    ]
    for metadata in unsafe_metadata:
        with pytest.raises(ValueError, match="secret field|credential material"):
            record_transition(
                organization=organization,
                actor=admin,
                target_type="securitytest",
                target_id=uuid.uuid4(),
                from_state="",
                to_state="REJECTED",
                revision=1,
                metadata=metadata,
            )
    assert AuditEvent.objects.filter(organization=organization).count() == audit_count
    assert OutboxEvent.objects.filter(organization=organization).count() == outbox_count


@pytest.mark.integration
@pytest.mark.django_db
def test_api_filters_before_search_and_hides_foreign_ids_on_every_read_surface() -> None:
    caller = service_tenant(
        "api-caller",
        frozenset(
            {
                Action.ORG_VIEW,
                Action.SEARCH,
                Action.CANVAS_VIEW,
                Action.MCP_CONTEXT,
                Action.ARTIFACT_VIEW,
            }
        ),
    )
    foreign = service_tenant("api-foreign", frozenset({Action.SEARCH}))
    foreign_assertion = KnowledgeAssertion.objects.create(
        organization=foreign.organization,
        access_scope=foreign.scope,
        subject_key="CANARY-FOREIGN-ASSERTION-TITLE",
        predicate="contains_CANARY_SECRET",
        value={"secret": "CANARY-VALUE"},
        provenance=[{"source_id": str(uuid.uuid4())}],
    )
    foreign_artifact = ImmutableArtifact.objects.create(
        organization=foreign.organization,
        access_scope=foreign.scope,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="canary",
        schema_version="1",
        payload={"title": "CANARY-FOREIGN-ARTIFACT-TITLE"},
    )
    correlation = str(uuid.uuid4())
    client = Client(
        HTTP_AUTHORIZATION=f"Bearer {caller.plaintext_token}",
        HTTP_X_CORRELATION_ID=correlation,
    )
    missing_id = uuid.uuid4()

    organization_foreign = client.get(
        f"/api/v1/organizations/{foreign.organization.id}",
    )
    organization_missing = client.get(f"/api/v1/organizations/{missing_id}")
    assert organization_foreign.status_code == organization_missing.status_code == 404
    assert organization_foreign.json() == organization_missing.json()

    for foreign_url, missing_url in [
        (
            f"/api/v1/canvas/assertions/{foreign_assertion.id}"
            f"?repository_id={caller.repository.id}",
            f"/api/v1/canvas/assertions/{missing_id}?repository_id={caller.repository.id}",
        ),
        (
            f"/api/v1/artifacts/{foreign_artifact.id}?repository_id={caller.repository.id}",
            f"/api/v1/artifacts/{missing_id}?repository_id={caller.repository.id}",
        ),
    ]:
        foreign_response = client.get(foreign_url)
        missing_response = client.get(missing_url)
        assert foreign_response.status_code == missing_response.status_code == 404
        assert foreign_response.json() == missing_response.json()
        assert "CANARY" not in foreign_response.content.decode()

    foreign_mcp = client.post(
        "/api/v1/mcp/context",
        data=json.dumps(
            {
                "repository_id": str(caller.repository.id),
                "assertion_id": str(foreign_assertion.id),
            }
        ),
        content_type="application/json",
    )
    missing_mcp = client.post(
        "/api/v1/mcp/context",
        data=json.dumps(
            {
                "repository_id": str(caller.repository.id),
                "assertion_id": str(missing_id),
            }
        ),
        content_type="application/json",
    )
    assert foreign_mcp.status_code == missing_mcp.status_code == 200
    assert foreign_mcp.json() == missing_mcp.json()
    assert "CANARY" not in foreign_mcp.content.decode()

    search = client.post(
        "/api/v1/search",
        data=json.dumps({"repository_id": str(caller.repository.id), "query": "CANARY"}),
        content_type="application/json",
    )
    assert search.status_code == 200
    assert search.json() == {"results": []}


@pytest.mark.integration
@pytest.mark.django_db
def test_unauthorized_actor_cannot_review_dismiss_or_override() -> None:
    tenant = service_tenant("sensitive", frozenset({Action.KNOWLEDGE_VIEW}))
    assertion = KnowledgeAssertion.objects.create(
        organization=tenant.organization,
        access_scope=tenant.scope,
        subject_key="sensitive",
        predicate="owned_by",
        value={"team": "security"},
        provenance=[{"source_id": str(uuid.uuid4())}],
    )
    assurance = AssuranceRun.objects.create(
        organization=tenant.organization,
        repository_external_id=tenant.repository.external_id,
        pull_request_number=17,
        head_commit="a" * 40,
        policy_version=1,
    )
    client = Client(
        HTTP_AUTHORIZATION=f"Bearer {tenant.plaintext_token}",
        HTTP_X_CORRELATION_ID=str(uuid.uuid4()),
    )
    requests = [
        client.post(
            f"/api/v1/knowledge/assertions/{assertion.id}/review",
            data=json.dumps(
                {
                    "repository_id": str(tenant.repository.id),
                    "target_state": KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
                    "expected_revision": 1,
                }
            ),
            content_type="application/json",
        ),
        client.post(
            f"/api/v1/findings/{uuid.uuid4()}/dismiss",
            data=json.dumps({"repository_id": str(tenant.repository.id)}),
            content_type="application/json",
        ),
        client.post(
            f"/api/v1/policies/{uuid.uuid4()}/override",
            data=json.dumps({"repository_id": str(tenant.repository.id)}),
            content_type="application/json",
        ),
        client.post(
            f"/api/v1/assurance-runs/{assurance.id}/transition",
            data=json.dumps(
                {
                    "target_state": AssuranceRun.State.DEBOUNCING,
                    "expected_revision": 1,
                }
            ),
            content_type="application/json",
        ),
    ]
    assert [response.status_code for response in requests] == [404, 404, 404, 404]
    assert {response.json()["message"] for response in requests} == {NOT_FOUND_MESSAGE}
    assertion.refresh_from_db()
    assert assertion.review_state == KnowledgeAssertion.ReviewState.UNREVIEWED
    assurance.refresh_from_db()
    assert assurance.state == AssuranceRun.State.REQUESTED

    developer, _membership = user_actor(
        tenant.organization,
        Role.Code.DEVELOPER,
        label="assurance-developer",
    )
    transitioned = execute_assurance_transition(
        actor=developer,
        run_id=assurance.id,
        target_state=AssuranceRun.State.DEBOUNCING,
        expected_revision=1,
    )
    assert transitioned.state == AssuranceRun.State.DEBOUNCING
    assert AuditEvent.objects.filter(
        target_type="assurancerun",
        target_id=assurance.id,
        authorization_path__startswith="role:DEVELOPER",
    ).exists()


@pytest.mark.integration
@pytest.mark.django_db
@pytest.mark.parametrize(
    ("initial_state", "target_state", "attach_existing", "supply_artifact"),
    [
        (
            AssuranceRun.State.REQUESTED,
            AssuranceRun.State.DEBOUNCING,
            False,
            True,
        ),
        (
            AssuranceRun.State.REQUESTED,
            AssuranceRun.State.DEBOUNCING,
            True,
            False,
        ),
        (
            AssuranceRun.State.COMPLETED,
            AssuranceRun.State.COMPLETED,
            True,
            False,
        ),
    ],
)
def test_assurance_transition_reauthorizes_every_attached_artifact(
    initial_state: str,
    target_state: str,
    attach_existing: bool,
    supply_artifact: bool,
) -> None:
    tenant = service_tenant(
        f"artifact-canary-{uuid.uuid4()}",
        frozenset({Action.ASSURANCE_EXECUTE}),
    )
    hidden_scope = AccessScope.objects.create(
        organization=tenant.organization,
        name="same-tenant-hidden",
        all_repositories=True,
    )
    hidden_artifact = ImmutableArtifact.objects.create(
        organization=tenant.organization,
        access_scope=hidden_scope,
        kind=ImmutableArtifact.Kind.CONTEXT_PACKET,
        schema_name="context-packet",
        schema_version="1.0",
        payload={"schema_version": "1.0", "canary": "OUT-OF-SCOPE"},
    )
    run = AssuranceRun.objects.create(
        organization=tenant.organization,
        repository_external_id=tenant.repository.external_id,
        pull_request_number=91,
        head_commit="d" * 40,
        evaluated_commit="d" * 40 if initial_state == AssuranceRun.State.COMPLETED else "",
        report_commit="d" * 40 if initial_state == AssuranceRun.State.COMPLETED else "",
        policy_version=1,
        state=initial_state,
        completed_at=timezone.now() if initial_state == AssuranceRun.State.COMPLETED else None,
        context_artifact=hidden_artifact if attach_existing else None,
    )
    actor = authenticate_bearer(f"Bearer {tenant.plaintext_token}")
    audit_count = AuditEvent.objects.count()
    outbox_count = OutboxEvent.objects.count()

    assert_hidden(
        lambda: execute_assurance_transition(
            actor=actor,
            run_id=run.id,
            target_state=target_state,
            expected_revision=run.revision,
            context_artifact_id=hidden_artifact.id if supply_artifact else None,
        )
    )

    run.refresh_from_db()
    assert run.state == initial_state
    assert AuditEvent.objects.count() == audit_count
    assert OutboxEvent.objects.count() == outbox_count


@pytest.mark.integration
@pytest.mark.django_db
def test_bootstrap_is_one_time_and_never_persists_issued_secret() -> None:
    client = Client(HTTP_X_ANVA_BOOTSTRAP_SECRET="test-only-bootstrap-secret")
    payload = {
        "organization_slug": "bootstrap",
        "organization_name": "Bootstrap",
        "admin_email": "admin@bootstrap.test",
        "admin_display_name": "Admin",
        "repository_external_id": "github:bootstrap/repository",
        "repository_name": "Bootstrap",
    }
    first = client.post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert first.status_code == 201
    plaintext = first.json()["token"]
    assert authenticate_bearer(f"Bearer {plaintext}").organization_id == (
        uuid.UUID(first.json()["organization_id"])
    )
    stored = RepositoryAccessToken.objects.get(id=first.json()["token_id"])
    assert plaintext not in stored.token_hash
    assert Role.objects.filter(organization=stored.organization).count() == len(Role.Code.values)

    authenticated_client = Client(
        HTTP_AUTHORIZATION=f"Bearer {plaintext}",
        HTTP_X_CORRELATION_ID=str(uuid.uuid4()),
    )
    membership_created = authenticated_client.post(
        f"/api/v1/organizations/{stored.organization_id}/members",
        data=json.dumps(
            {
                "email": "viewer@bootstrap.test",
                "display_name": "Viewer",
                "role": Role.Code.VIEWER,
            }
        ),
        content_type="application/json",
    )
    assert membership_created.status_code == 201
    membership_id = membership_created.json()["id"]
    membership_updated = authenticated_client.patch(
        f"/api/v1/organizations/{stored.organization_id}/members/{membership_id}",
        data=json.dumps({"role": Role.Code.REVIEWER, "expected_revision": 1}),
        content_type="application/json",
    )
    assert membership_updated.status_code == 200
    assert membership_updated.json()["role"] == Role.Code.REVIEWER
    membership_deleted = authenticated_client.delete(
        f"/api/v1/organizations/{stored.organization_id}/members/{membership_id}",
        data=json.dumps({"expected_revision": 2}),
        content_type="application/json",
    )
    assert membership_deleted.status_code == 200
    assert not membership_deleted.json()["active"]

    second = client.post(
        "/api/v1/bootstrap",
        data=json.dumps({**payload, "organization_slug": "second"}),
        content_type="application/json",
    )
    assert second.status_code == 404
    audit = AuditEvent.objects.get(target_type="organization")
    assert plaintext not in json.dumps(audit.metadata)
    assert "test-only-bootstrap-secret" not in json.dumps(audit.metadata)


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_database_rejects_cross_tenant_relations_and_snapshot_rewrites() -> None:
    owner = Organization.objects.create(slug="db-owner", name="Owner")
    foreign = Organization.objects.create(slug="db-foreign", name="Foreign")
    owner_role = Role.objects.create(
        organization=owner,
        code=Role.Code.VIEWER,
        name="Viewer",
    )
    foreign_user = User.objects.create(email="foreign@db.test", display_name="Foreign")
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Membership.objects.create(
                organization=foreign,
                user=foreign_user,
                role=owner_role,
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    foreign_role = Role.objects.create(
        organization=foreign,
        code=Role.Code.VIEWER,
        name="Viewer",
    )
    foreign_membership = Membership.objects.create(
        organization=foreign,
        user=foreign_user,
        role=foreign_role,
    )
    owner_user = User.objects.create(email="owner@db.test", display_name="Owner")
    owner_membership = Membership.objects.create(
        organization=owner,
        user=owner_user,
        role=owner_role,
    )
    team = Team.objects.create(organization=owner, name="Platform", slug="platform")
    TeamMembership.objects.create(
        organization=owner,
        team=team,
        membership=owner_membership,
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            TeamMembership.objects.create(
                organization=owner,
                team=team,
                membership=foreign_membership,
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    source = SourceConnection.objects.create(
        organization=owner,
        external_key="db-source",
        state=SourceConnection.State.ACTIVE,
    )
    scope = AccessScope.objects.create(
        organization=owner,
        name="db-scope",
        all_memberships=True,
        all_repositories=True,
    )
    snapshot = AccessSnapshot.objects.create(
        organization=owner,
        source_connection=source,
        access_scope=scope,
        scope_revision=scope.revision,
        payload={"boundary": "original"},
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            AccessSnapshot.objects.filter(id=snapshot.id).update(payload={"boundary": "changed"})
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            AccessSnapshot.objects.filter(id=snapshot.id).delete()
