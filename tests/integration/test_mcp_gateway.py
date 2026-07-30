"""Persistence and security tests for the canonical MCP/HTTP domain facade."""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from django.conf import settings
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import Client
from django.utils import timezone

from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AuditEvent,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    MCPProposalSubmission,
    MCPToolInvocation,
    Organization,
    OutboxEvent,
    Repository,
    RepositoryAccessToken,
    ServiceIdentity,
    SourceConnection,
)
from anva.core.services.authorization import NOT_FOUND_MESSAGE, Action
from anva.core.services.mcp_gateway import (
    MCPGatewayError,
    _decode_cursor,
    _encode_cursor,
    dispatch_tool,
)
from anva.core.services.tokens import (
    authenticate_bearer,
    issue_bootstrap_repository_token,
)
from anva.core.services.transitions import transition_knowledge_proposal


def _gateway_tenant(label: str) -> tuple[Organization, Repository, AccessScope, str]:
    organization = Organization.objects.create(slug=label, name=label.title())
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:{label}/repository",
        name=label.title(),
    )
    service = ServiceIdentity.objects.create(
        organization=organization,
        name=f"{label}-mcp",
        issuer=settings.TOKEN_ISSUER,
        audience=settings.TOKEN_AUDIENCE,
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name=f"{label}-scope",
        all_service_identities=True,
        all_repositories=True,
    )
    actions = frozenset(
        {
            Action.REPOSITORY_VIEW,
            Action.KNOWLEDGE_VIEW,
            Action.KNOWLEDGE_PROPOSE,
        }
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
    issued = issue_bootstrap_repository_token(
        organization=organization,
        repository=repository,
        service_identity=service,
        actions=actions,
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return organization, repository, scope, issued.plaintext


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_proposal_tools_are_idempotent_review_only_scoped_and_audited() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-proposal")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    source = KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:source",
        display_name="Source",
    )
    target = KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.TEAM,
        canonical_key="team:target",
        display_name="Target",
    )
    arguments: dict[str, object] = {
        "contract_version": "1",
        "repository_id": str(repository.id),
        "access_scope_id": str(scope.id),
        "summary": "Record newly discovered ownership for human review.",
        "source_references": [{"kind": "ENTITY", "id": str(source.id)}],
        "idempotency_key": "mcp-proposal-idempotency",
        "source_entity_id": str(source.id),
        "target_entity_id": str(target.id),
        "relationship_type": "OWNED_BY",
        "rationale": "Observed during implementation.",
    }
    first = dispatch_tool(
        actor=actor,
        tool_name="anva.propose_relationship",
        arguments=arguments,
        transport="MCP",
    )
    first_data = first["data"]
    assert isinstance(first_data, dict)
    assert first_data["review_state"] == "PROPOSED"
    assert first_data["approved"] is False
    assert first_data["review_required"] is True
    assert first_data["created"] is True

    replay = dispatch_tool(
        actor=replace(actor, request_id=uuid.uuid4()),
        tool_name="anva.propose_relationship",
        arguments=arguments,
        transport="HTTP",
    )
    replay_data = replay["data"]
    assert isinstance(replay_data, dict)
    assert replay_data["proposal_id"] == first_data["proposal_id"]
    assert replay_data["created"] is False
    proposal = KnowledgeProposal.objects.get(id=first_data["proposal_id"])
    submission = MCPProposalSubmission.objects.get(knowledge_proposal=proposal)
    assert proposal.state == KnowledgeProposal.State.PROPOSED
    assert proposal.decided_at is None
    assert submission.organization_id == organization.id
    assert submission.repository_id == repository.id
    assert submission.access_scope_id == scope.id
    assert submission.actor_id == actor.actor_id
    assert submission.payload_hash
    assert submission.idempotency_hash
    assert (
        MCPToolInvocation.objects.filter(
            organization=organization,
            repository=repository,
            tool_name="anva.propose_relationship",
            outcome=MCPToolInvocation.Outcome.SUCCEEDED,
        ).count()
        == 2
    )
    audit_columns = {field.name for field in MCPToolInvocation._meta.fields}
    assert not audit_columns & {"arguments", "source_text", "token", "authorization"}
    assert plaintext not in str(MCPToolInvocation.objects.values().first())

    alternate_repository = Repository.objects.create(
        organization=organization,
        external_id="github:mcp-proposal/alternate",
        name="Alternate",
    )
    alternate_scope = AccessScope.objects.create(
        organization=organization,
        name="alternate-scope",
    )
    for immutable_submission_update in (
        {"organization_id": uuid.uuid4()},
        {"repository_id": alternate_repository.id},
        {"access_scope_id": alternate_scope.id},
        {"proposal_kind": MCPProposalSubmission.Kind.CORRECTION},
        {"actor_type": "USER"},
        {"actor_id": "tampered"},
        {"payload_hash": "c" * 64},
        {"idempotency_hash": "d" * 64},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            MCPProposalSubmission.objects.filter(id=submission.id).update(
                **immutable_submission_update
            )

    for immutable_update in (
        {"summary": "tampered"},
        {"proposed_changes": [{"operation": "DELETE"}]},
        {"anva_sources": [{"type": "DOCUMENT", "id": str(uuid.uuid4())}]},
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            KnowledgeProposal.objects.filter(id=proposal.id).update(**immutable_update)
    with pytest.raises(DatabaseError), transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "UPDATE core_knowledgeproposal SET summary = %s WHERE id = %s",
            ["raw SQL tamper", proposal.id],
        )
    with pytest.raises(DatabaseError), transaction.atomic():
        KnowledgeProposal.objects.filter(id=proposal.id).update(
            state=KnowledgeProposal.State.VALIDATING,
            revision=2,
        )
    proposal.refresh_from_db()
    transitioned = transition_knowledge_proposal(
        actor=replace(actor, request_id=uuid.uuid4()),
        proposal_id=proposal.id,
        target_state=KnowledgeProposal.State.VALIDATING,
        expected_revision=proposal.revision,
    )
    assert transitioned.state == KnowledgeProposal.State.VALIDATING


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_knowledge_proposal_content_and_lifecycle_are_database_governed() -> None:
    organization, _repository, _scope, _plaintext = _gateway_tenant("mcp-immutable")
    proposal = KnowledgeProposal.objects.create(
        organization=organization,
        summary="Immutable content fixture.",
        proposed_changes=[{"operation": "ADD"}],
        anva_sources=[{"source_type": "DOCUMENT"}],
    )
    for immutable_update in (
        {"summary": "tampered"},
        {"proposed_changes": [{"operation": "DELETE"}]},
        {"anva_sources": [{"source_type": "HUMAN_APPROVAL"}]},
        {
            "state": KnowledgeProposal.State.VALIDATING,
            "revision": proposal.revision + 1,
        },
    ):
        with pytest.raises(DatabaseError), transaction.atomic():
            KnowledgeProposal.objects.filter(id=proposal.id).update(**immutable_update)


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_secret_bearing_proposal_is_rejected_before_any_persistence() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-secret")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=scope,
        subject_key="service:secret-source",
        predicate="service.owner",
        value={"team": "platform"},
        provenance=[{"fixture": "secret-rejection"}],
    )
    secret = f"ghp_{'A' * 36}"
    before = {
        "proposals": KnowledgeProposal.objects.count(),
        "submissions": MCPProposalSubmission.objects.count(),
        "invocations": MCPToolInvocation.objects.count(),
        "audits": AuditEvent.objects.count(),
        "outbox": OutboxEvent.objects.count(),
    }
    with pytest.raises(MCPGatewayError) as rejected:
        dispatch_tool(
            actor=actor,
            tool_name="anva.propose_correction",
            arguments={
                "contract_version": "1",
                "repository_id": str(repository.id),
                "access_scope_id": str(scope.id),
                "summary": "Must never persist credential material.",
                "source_references": [{"kind": "ASSERTION", "id": str(assertion.id)}],
                "idempotency_key": "secret-rejection-idempotency",
                "assertion_id": str(assertion.id),
                "correction": {"nested": [{"value": secret}]},
            },
            transport="MCP",
        )
    assert rejected.value.code == "secret_material_rejected"
    assert secret not in str(rejected.value)
    assert before == {
        "proposals": KnowledgeProposal.objects.count(),
        "submissions": MCPProposalSubmission.objects.count(),
        "invocations": MCPToolInvocation.objects.count(),
        "audits": AuditEvent.objects.count(),
        "outbox": OutboxEvent.objects.count(),
    }


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_unknown_and_validation_failures_have_one_content_free_stable_audit() -> None:
    organization, repository, _scope, plaintext = _gateway_tenant("mcp-failure-audit")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    unknown_name = "anva.canary-unknown-tool"
    canary = "CANARY_ARGUMENT_MUST_NOT_PERSIST"
    with pytest.raises(MCPGatewayError) as unknown:
        dispatch_tool(
            actor=actor,
            tool_name=unknown_name,
            arguments={
                "contract_version": "1",
                "repository_id": str(repository.id),
                "opaque": canary,
            },
            transport="MCP",
        )
    assert unknown.value.code == "capability_unavailable"
    assert unknown_name not in str(unknown.value)
    unknown_audits = MCPToolInvocation.objects.filter(request_id=actor.request_id)
    assert unknown_audits.count() == 1
    unknown_audit = unknown_audits.get()
    assert unknown_audit.tool_name == "unrecognized"
    assert unknown_audit.required_action == "unrecognized"
    assert unknown_name not in str(MCPToolInvocation.objects.values().get(id=unknown_audit.id))
    assert canary not in str(MCPToolInvocation.objects.values().get(id=unknown_audit.id))

    validation_actor = replace(actor, request_id=uuid.uuid4())
    invalid_value = "ghp_CANARY_INVALID_ENUM_MUST_NOT_ECHO"
    with pytest.raises(MCPGatewayError) as invalid:
        dispatch_tool(
            actor=validation_actor,
            tool_name="anva.search",
            arguments={
                "contract_version": "1",
                "repository_id": str(repository.id),
                "query": "bounded",
                "phase": invalid_value,
            },
            transport="HTTP",
        )
    assert invalid.value.code == "invalid_tool_input"
    assert invalid.value.path == "$.phase"
    assert invalid.value.reason == "allowed_value"
    assert invalid_value not in str(invalid.value)
    validation_audits = MCPToolInvocation.objects.filter(request_id=validation_actor.request_id)
    assert validation_audits.count() == 1
    assert validation_audits.get().error_code == "invalid_tool_input"
    assert invalid_value not in str(
        MCPToolInvocation.objects.values().get(id=validation_audits.get().id)
    )

    before_unauthenticated = MCPToolInvocation.objects.count()
    unauthenticated = Client().post(
        "/api/v1/mcp/tools/anva.canary-unauthenticated",
        data=json.dumps(
            {
                "contract_version": "1",
                "repository_id": str(repository.id),
                "opaque": canary,
            }
        ),
        content_type="application/json",
    )
    assert unauthenticated.status_code == 401
    assert MCPToolInvocation.objects.count() == before_unauthenticated
    assert canary not in unauthenticated.content.decode()


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_cursor_rechecks_source_grant_and_credential_watermarks() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-cursor")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    source = SourceConnection.objects.create(
        organization=organization,
        repository=repository,
        access_scope=scope,
        external_key="mcp-cursor-source",
        display_name="MCP cursor source",
    )
    arguments: dict[str, object] = {
        "contract_version": "1",
        "repository_id": str(repository.id),
        "entity_id": str(uuid.uuid4()),
        "limit": 20,
    }
    cursor = _encode_cursor(
        actor=actor,
        tool_name="anva.get_relationships",
        arguments=arguments,
        offset=20,
    )
    assert (
        _decode_cursor(
            actor=actor,
            tool_name="anva.get_relationships",
            arguments={**arguments, "cursor": cursor},
        )
        == 20
    )

    SourceConnection.objects.filter(id=source.id).update(
        state=SourceConnection.State.ACTIVE,
        revision=source.revision + 1,
    )
    with pytest.raises(MCPGatewayError, match="invalid"):
        _decode_cursor(
            actor=actor,
            tool_name="anva.get_relationships",
            arguments={**arguments, "cursor": cursor},
        )

    grant_cursor = _encode_cursor(
        actor=actor,
        tool_name="anva.get_relationships",
        arguments=arguments,
        offset=20,
    )
    knowledge_grant = AccessGrant.objects.get(
        organization=organization,
        repository=repository,
        action=Action.KNOWLEDGE_VIEW.value,
    )
    AccessGrant.objects.filter(id=knowledge_grant.id).update(revoked_at=timezone.now())
    with pytest.raises(ResourceNotFoundError, match=NOT_FOUND_MESSAGE):
        _decode_cursor(
            actor=actor,
            tool_name="anva.get_relationships",
            arguments={**arguments, "cursor": grant_cursor},
        )

    AccessGrant.objects.filter(id=knowledge_grant.id).update(revoked_at=None)
    credential_cursor = _encode_cursor(
        actor=actor,
        tool_name="anva.get_relationships",
        arguments=arguments,
        offset=20,
    )
    assert actor.credential_id is not None
    RepositoryAccessToken.objects.filter(id=actor.credential_id).update(revoked_at=timezone.now())
    with pytest.raises(AuthenticationError, match="Credential is invalid or expired"):
        _decode_cursor(
            actor=actor,
            tool_name="anva.get_relationships",
            arguments={**arguments, "cursor": credential_cursor},
        )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_cross_tenant_and_missing_targets_share_hidden_contract_and_composite_fk() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-own")
    foreign_organization, foreign_repository, _foreign_scope, _foreign_token = _gateway_tenant(
        "mcp-foreign"
    )
    actor = authenticate_bearer(f"Bearer {plaintext}")
    messages: list[str] = []
    for repository_id in (foreign_repository.id, uuid.uuid4()):
        with pytest.raises(ResourceNotFoundError) as error:
            dispatch_tool(
                actor=replace(actor, request_id=uuid.uuid4()),
                tool_name="anva.resolve_repository",
                arguments={
                    "contract_version": "1",
                    "repository_id": str(repository_id),
                },
                transport="MCP",
            )
        messages.append(str(error.value))
    assert messages == [NOT_FOUND_MESSAGE, NOT_FOUND_MESSAGE]
    assert (
        MCPToolInvocation.objects.filter(
            organization=organization,
            repository=repository,
            tool_name="anva.resolve_repository",
            outcome=MCPToolInvocation.Outcome.FAILED,
            error_code="resource_not_found",
        ).count()
        == 2
    )

    own_source = KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:composite",
        display_name="Composite",
    )
    own_target = KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.TEAM,
        canonical_key="team:composite",
        display_name="Composite",
    )
    created = dispatch_tool(
        actor=replace(actor, request_id=uuid.uuid4()),
        tool_name="anva.propose_relationship",
        arguments={
            "contract_version": "1",
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "summary": "Composite constraint fixture.",
            "source_references": [{"kind": "ENTITY", "id": str(own_source.id)}],
            "idempotency_key": "composite-original",
            "source_entity_id": str(own_source.id),
            "target_entity_id": str(own_target.id),
            "relationship_type": "OWNED_BY",
            "rationale": "Exercise tenant constraint.",
        },
        transport="MCP",
    )
    data = created["data"]
    assert isinstance(data, dict)
    original = MCPProposalSubmission.objects.get(id=data["submission_id"])
    second_proposal = KnowledgeProposal.objects.create(
        organization=organization,
        summary="Must fail cross-tenant composition.",
        proposed_changes=[{"invalid": "database fixture"}],
        anva_sources=[{"invalid": "database fixture"}],
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        MCPProposalSubmission.objects.create(
            organization=organization,
            repository=foreign_repository,
            access_scope=scope,
            knowledge_proposal=second_proposal,
            credential=original.credential,
            proposal_kind=MCPProposalSubmission.Kind.RELATIONSHIP,
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
            payload_hash="a" * 64,
            idempotency_hash="b" * 64,
        )
    assert foreign_organization.id != organization.id


@pytest.mark.integration
@pytest.mark.django_db
def test_read_only_and_unsupported_contract_fail_safely() -> None:
    _organization, repository, scope, plaintext = _gateway_tenant("mcp-safe")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    with pytest.raises(MCPGatewayError, match="supported versions: 1") as unsupported:
        dispatch_tool(
            actor=actor,
            tool_name="anva.resolve_repository",
            arguments={
                "contract_version": "999",
                "repository_id": str(repository.id),
            },
            transport="MCP",
        )
    assert unsupported.value.code == "unsupported_contract_version"

    with pytest.raises(MCPGatewayError, match="read-only") as read_only:
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(settings, "ANVA_MCP_READ_ONLY", True)
            dispatch_tool(
                actor=replace(actor, request_id=uuid.uuid4()),
                tool_name="anva.propose_correction",
                arguments={
                    "contract_version": "1",
                    "repository_id": str(repository.id),
                    "access_scope_id": str(scope.id),
                    "summary": "Read-only rejects before target lookup.",
                    "source_references": [{"kind": "ASSERTION", "id": str(uuid.uuid4())}],
                    "idempotency_key": "read-only-domain",
                    "assertion_id": str(uuid.uuid4()),
                    "correction": {"value": "ignored"},
                },
                transport="MCP",
            )
    assert read_only.value.code == "read_only_mode"
