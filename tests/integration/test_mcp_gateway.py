"""Persistence and security tests for the canonical MCP/HTTP domain facade."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.utils import timezone

from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    KnowledgeEntity,
    KnowledgeProposal,
    MCPProposalSubmission,
    MCPToolInvocation,
    Organization,
    Repository,
    ServiceIdentity,
)
from anva.core.services.authorization import NOT_FOUND_MESSAGE, Action
from anva.core.services.mcp_gateway import MCPGatewayError, dispatch_tool
from anva.core.services.tokens import (
    authenticate_bearer,
    issue_bootstrap_repository_token,
)


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

    with pytest.raises(DatabaseError), transaction.atomic():
        MCPProposalSubmission.objects.filter(id=submission.id).update(actor_id="tampered")


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
