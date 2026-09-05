"""Persistence and security tests for the canonical MCP/HTTP domain facade."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest
from django.conf import settings
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import Client
from django.utils import timezone

from anva.contracts.catalog import EXAMPLES
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
from anva.core.services import mcp_gateway
from anva.core.services.authorization import NOT_FOUND_MESSAGE, Action
from anva.core.services.context import ActorContext
from anva.core.services.intent import import_work_item
from anva.core.services.mcp_gateway import (
    MCPGatewayError,
    _decode_cursor,
    _encode_cursor,
    dispatch_tool,
)
from anva.core.services.ranking import RankingExplanation
from anva.core.services.search import SearchResponse, SearchResult
from anva.core.services.tokens import (
    authenticate_bearer,
    issue_bootstrap_repository_token,
)
from anva.core.services.transitions import transition_knowledge_proposal
from anva.mcp.contracts import validate_tool_output


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
            Action.ARTIFACT_CREATE,
            Action.ARTIFACT_VIEW,
            Action.MCP_CONTEXT,
            Action.REPOSITORY_VIEW,
            Action.SEARCH,
            Action.KNOWLEDGE_VIEW,
            Action.KNOWLEDGE_PROPOSE,
            Action.WORK_MANAGE,
            Action.WORK_VIEW,
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


def _assertion_packet(
    *,
    organization: Organization,
    repository: Repository,
    assertion: KnowledgeAssertion,
) -> dict[str, object]:
    packet = deepcopy(EXAMPLES["context-packet"])
    packet.update(
        {
            "packet_id": str(uuid.uuid4()),
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "work_item_id": None,
            "phase": "PREPARE",
            "request": {
                "task": "Read persisted structured assertion context",
                "phase": "PREPARE",
                "budget": {
                    "max_items": 50,
                    "max_tokens": 8_000,
                    "max_bytes": 100_000,
                    "max_citations": 100,
                },
            },
            "items": [
                {
                    "item_id": str(uuid.uuid4()),
                    "kind": "ASSERTION",
                    "item_key": f"assertion:{assertion.id}",
                    "summary": "The checkout service depends on payments.",
                    "freshness": "CURRENT",
                    "is_inferred": False,
                    "selection_reason": "Authorized governed assertion",
                    "rank_score": 1.0,
                    "payload": {
                        "assertion_id": str(assertion.id),
                        "subject_key": assertion.subject_key,
                        "predicate": assertion.predicate,
                        "value": assertion.value,
                        "review_state": assertion.review_state,
                        "staleness_state": assertion.staleness_state,
                        "confidence": assertion.confidence,
                    },
                    "anva_sources": [
                        {
                            "source_location_id": str(uuid.uuid4()),
                            "source_observation_id": str(uuid.uuid4()),
                            "access_snapshot_id": str(uuid.uuid4()),
                            "canonical_url": "https://example.test/services/checkout.json",
                            "locator": "/dependencies",
                            "source_content_hash": "a" * 64,
                            "observed_at": "2026-08-22T00:00:00Z",
                        }
                    ],
                }
            ],
        }
    )
    packet_budget = packet["budget"]
    assert isinstance(packet_budget, dict)
    packet_budget.update(
        {
            "selected_items": 1,
            "selected_tokens": 10,
            "selected_bytes": 100,
            "selected_citations": 1,
        }
    )
    return packet


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_codex_and_claude_workflow_traces_share_exact_authorized_packet() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-host-parity")
    base_actor = authenticate_bearer(f"Bearer {plaintext}")
    work_payload = deepcopy(EXAMPLES["work-item-import"])
    work_payload.update(
        {
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_id": str(uuid.uuid4()),
            "external_key": "ANVA-HOST-10",
            "title": "Host-neutral workflow parity",
            "summary": "Retrieve the same bounded context from each supported host.",
            "status": "READY",
        }
    )
    imported = import_work_item(actor=base_actor, payload=work_payload)
    work_item = imported.work_item
    task = "Implement ANVA-HOST-10 without changing unrelated services"
    repository_arguments: dict[str, object] = {
        "contract_version": "1",
        "repository_id": str(repository.id),
    }
    work_arguments: dict[str, object] = {
        **repository_arguments,
        "external_key": work_item.external_key,
    }
    context_arguments: dict[str, object] = {
        **repository_arguments,
        "task": task,
        "phase": "PREPARE",
    }

    def invoke(
        actor: ActorContext,
    ) -> tuple[list[dict[str, object]], dict[str, object], list[uuid.UUID]]:
        trace: list[dict[str, object]] = []
        request_ids: list[uuid.UUID] = []
        for tool_name, arguments in (
            ("anva.resolve_repository", repository_arguments),
            ("anva.resolve_work_item", work_arguments),
            ("anva.get_context_packet", context_arguments),
        ):
            request_id = uuid.uuid4()
            request_ids.append(request_id)
            trace.append(
                dispatch_tool(
                    actor=replace(actor, request_id=request_id),
                    tool_name=tool_name,
                    arguments=arguments,
                    transport="MCP",
                )
            )
        return trace, trace[-1], request_ids

    codex_trace, codex_context, codex_request_ids = invoke(base_actor)
    claude_trace, claude_context, claude_request_ids = invoke(base_actor)

    assert codex_trace[:2] == claude_trace[:2]
    codex_data = codex_context["data"]
    claude_data = claude_context["data"]
    assert isinstance(codex_data, dict)
    assert isinstance(claude_data, dict)
    assert codex_data["packet_id"] == claude_data["packet_id"]
    codex_packet = codex_data["packet"]
    claude_packet = claude_data["packet"]
    assert isinstance(codex_packet, dict)
    assert isinstance(claude_packet, dict)
    assert codex_packet["content_hash"] == claude_packet["content_hash"]
    assert codex_packet["items"] == claude_packet["items"]
    assert codex_packet["limitations"] == claude_packet["limitations"]
    assert codex_data["created"] is True
    assert claude_data["created"] is False
    validate_tool_output("anva.get_context_packet", codex_context)
    validate_tool_output("anva.get_context_packet", claude_context)
    search_result = dispatch_tool(
        actor=replace(base_actor, request_id=uuid.uuid4()),
        tool_name="anva.search",
        arguments={
            **repository_arguments,
            "query": "Host-neutral workflow parity",
            "phase": "PREPARE",
            "limit": 20,
        },
        transport="MCP",
    )
    validate_tool_output("anva.search", search_result)
    for request_ids in (codex_request_ids, claude_request_ids):
        assert [
            MCPToolInvocation.objects.get(request_id=request_id).tool_name
            for request_id in request_ids
        ] == ["anva.resolve_repository", "anva.resolve_work_item", "anva.get_context_packet"]


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_persisted_nested_assertion_value_returns_schema_valid_public_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-structured-value")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    structured_value = {
        "dependencies": [
            {"tier": 1, "name": "payments"},
            {"name": "ledger", "tier": 2},
        ]
    }
    assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=scope,
        subject_key="service:checkout",
        predicate="service.dependencies",
        value=structured_value,
        provenance=[{"extractor": "structured-json"}],
    )
    packet = _assertion_packet(
        organization=organization,
        repository=repository,
        assertion=assertion,
    )
    monkeypatch.setattr(
        mcp_gateway,
        "get_context_packet",
        lambda **_kwargs: deepcopy(packet),
    )

    response = dispatch_tool(
        actor=actor,
        tool_name="anva.get_context_packet",
        arguments={
            "contract_version": "1",
            "repository_id": str(repository.id),
            "packet_id": packet["packet_id"],
        },
        transport="MCP",
    )

    validate_tool_output("anva.get_context_packet", response)
    data = response["data"]
    assert isinstance(data, dict)
    public_packet = data["packet"]
    assert isinstance(public_packet, dict)
    items = public_packet["items"]
    assert isinstance(items, list)
    payload = items[0]["payload"]
    assert isinstance(payload, dict)
    assert payload["value"] == {
        "format": "CANONICAL_JSON",
        "json": ('{"dependencies":[{"name":"payments","tier":1},{"name":"ledger","tier":2}]}'),
    }
    assertion.refresh_from_db()
    assert assertion.value == structured_value
    invocation = MCPToolInvocation.objects.get(request_id=actor.request_id)
    assert invocation.outcome == MCPToolInvocation.Outcome.SUCCEEDED


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_nested_assertion_control_and_credentials_fail_before_success_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-nested-rejection")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    base_value: dict[str, object] = {
        "dependencies": [
            {
                "name": "payments",
                "metadata": {"tier": 1},
            }
        ],
        "owners": [{"name": "platform"}],
    }

    def object_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
        paths: list[tuple[object, ...]] = []
        if isinstance(value, dict):
            paths.append(path)
            for key, child in value.items():
                paths.extend(object_paths(child, (*path, key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                paths.extend(object_paths(child, (*path, index)))
        return paths

    def scalar_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
        if isinstance(value, dict):
            return [
                child_path
                for key, child in value.items()
                for child_path in scalar_paths(child, (*path, key))
            ]
        if isinstance(value, list):
            return [
                child_path
                for index, child in enumerate(value)
                for child_path in scalar_paths(child, (*path, index))
            ]
        return [path]

    def target_at(value: object, path: tuple[object, ...]) -> object:
        target = value
        for part in path:
            if isinstance(part, str):
                assert isinstance(target, dict)
                target = target[part]
            else:
                assert isinstance(part, int)
                assert isinstance(target, list)
                target = target[part]
        return target

    private_canary = "PRIVATE_NESTED_ASSERTION_MUST_NOT_ESCAPE"
    rejected_values: list[tuple[dict[str, object], str, str]] = []
    for path in object_paths(base_value):
        injected = deepcopy(base_value)
        target = target_at(injected, path)
        assert isinstance(target, dict)
        target["privateOracle"] = {"verdict": private_canary}
        rejected_values.append((injected, "private_control_material", private_canary))
    secret = f"ghp_{'A' * 36}"
    for path in scalar_paths(base_value):
        injected = deepcopy(base_value)
        if len(path) == 1:
            injected[str(path[0])] = secret
        else:
            parent = target_at(injected, path[:-1])
            leaf = path[-1]
            if isinstance(leaf, str):
                assert isinstance(parent, dict)
                parent[leaf] = secret
            else:
                assert isinstance(leaf, int)
                assert isinstance(parent, list)
                parent[leaf] = secret
        rejected_values.append((injected, "secret_material", secret))
    secret_key = f"ghp_{'B' * 36}"
    for path in object_paths(base_value):
        injected = deepcopy(base_value)
        target = target_at(injected, path)
        assert isinstance(target, dict)
        target[secret_key] = "must-not-cross-public-boundary"
        rejected_values.append((injected, "secret_material", secret_key))

    for index, (value, reason, canary) in enumerate(rejected_values):
        assertion = KnowledgeAssertion.objects.create(
            organization=organization,
            access_scope=scope,
            subject_key=f"service:checkout:{index}",
            predicate="service.dependencies",
            value=value,
            provenance=[{"extractor": "structured-json"}],
        )
        packet = _assertion_packet(
            organization=organization,
            repository=repository,
            assertion=assertion,
        )
        monkeypatch.setattr(
            mcp_gateway,
            "get_context_packet",
            lambda packet=packet, **_kwargs: deepcopy(packet),
        )
        request_actor = replace(actor, request_id=uuid.uuid4())

        with pytest.raises(MCPGatewayError) as rejected:
            dispatch_tool(
                actor=request_actor,
                tool_name="anva.get_context_packet",
                arguments={
                    "contract_version": "1",
                    "repository_id": str(repository.id),
                    "packet_id": packet["packet_id"],
                },
                transport="MCP",
            )

        assert rejected.value.code == "invalid_tool_output"
        assert rejected.value.reason == reason
        assert canary not in str(rejected.value)
        invocations = MCPToolInvocation.objects.filter(request_id=request_actor.request_id)
        assert invocations.count() == 1
        invocation = invocations.get()
        assert invocation.outcome == MCPToolInvocation.Outcome.FAILED
        assert invocation.error_code == "invalid_tool_output"
        assert not invocations.filter(outcome=MCPToolInvocation.Outcome.SUCCEEDED).exists()
        persisted_audit = json.dumps(
            MCPToolInvocation.objects.values().get(id=invocation.id),
            default=str,
            sort_keys=True,
        )
        assert canary not in persisted_audit


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
def test_closed_proposal_shapes_dispatch_and_private_fields_fail_before_persistence() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-closed-proposals")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    assertion = KnowledgeAssertion.objects.create(
        organization=organization,
        access_scope=scope,
        subject_key="service:checkout",
        predicate="service.owner",
        value={"team": "platform"},
        provenance=[{"fixture": "closed-proposal-shapes"}],
    )
    work_payload = deepcopy(EXAMPLES["work-item-import"])
    work_payload.update(
        {
            "organization_id": str(organization.id),
            "repository_id": str(repository.id),
            "access_scope_id": str(scope.id),
            "work_item_id": str(uuid.uuid4()),
            "external_key": "ANVA-CLOSED-35",
            "title": "Close public proposal inputs",
            "summary": "Reject undocumented nested proposal content.",
            "status": "READY",
        }
    )
    work_item = import_work_item(actor=actor, payload=work_payload).work_item
    common: dict[str, object] = {
        "contract_version": "1",
        "repository_id": str(repository.id),
        "access_scope_id": str(scope.id),
        "summary": "Public review-only proposal.",
        "source_references": [{"kind": "ASSERTION", "id": str(assertion.id)}],
    }
    valid_cases: tuple[tuple[str, str, dict[str, object], dict[str, object]], ...] = (
        (
            "anva.propose_correction",
            MCPProposalSubmission.Kind.CORRECTION,
            {
                **common,
                "idempotency_key": "closed-correction-proposal",
                "assertion_id": str(assertion.id),
                "correction": {"value": "payments-platform"},
            },
            {"value": "payments-platform"},
        ),
        (
            "anva.submit_work_summary",
            MCPProposalSubmission.Kind.WORK_SUMMARY,
            {
                **common,
                "idempotency_key": "closed-work-summary-proposal",
                "work_item_id": str(work_item.id),
                "summary_data": {"status": "complete"},
            },
            {"status": "complete"},
        ),
        (
            "anva.submit_preflight_summary",
            MCPProposalSubmission.Kind.PREFLIGHT_SUMMARY,
            {
                **common,
                "idempotency_key": "closed-preflight-proposal",
                "work_item_id": str(work_item.id),
                "commit_sha": "a" * 40,
                "checks": [{"name": "contract-tests", "passed": True}],
                "limitations": ["Human review is still required."],
            },
            {
                "commit_sha": "a" * 40,
                "checks": [{"name": "contract-tests", "passed": True}],
                "limitations": ["Human review is still required."],
                "advisory": True,
            },
        ),
    )
    for tool_name, proposal_kind, arguments, expected_value in valid_cases:
        response = dispatch_tool(
            actor=replace(actor, request_id=uuid.uuid4()),
            tool_name=tool_name,
            arguments=arguments,
            transport="MCP",
        )
        data = response["data"]
        assert isinstance(data, dict)
        assert data["proposal_kind"] == proposal_kind
        proposal = KnowledgeProposal.objects.get(id=data["proposal_id"])
        assert proposal.proposed_changes[0]["value"] == expected_value

    invalid_cases = (
        (
            valid_cases[0][0],
            {
                **valid_cases[0][2],
                "idempotency_key": "invalid-closed-correction",
                "correction": {
                    "value": "payments-platform",
                    "private_oracle_payload": {"verdict": "BLOCKED"},
                },
            },
        ),
        (
            valid_cases[1][0],
            {
                **valid_cases[1][2],
                "idempotency_key": "invalid-closed-work-summary",
                "summary_data": {"status": "complete", "private": {"verdict": "BLOCKED"}},
            },
        ),
        (
            valid_cases[2][0],
            {
                **valid_cases[2][2],
                "idempotency_key": "invalid-closed-preflight",
                "checks": [
                    {
                        "name": "contract-tests",
                        "passed": True,
                        "oracle": {"verdict": "BLOCKED"},
                    }
                ],
            },
        ),
    )
    for tool_name, arguments in invalid_cases:
        before = {
            "proposals": KnowledgeProposal.objects.count(),
            "submissions": MCPProposalSubmission.objects.count(),
            "outbox": OutboxEvent.objects.count(),
        }
        with pytest.raises(MCPGatewayError) as rejected:
            dispatch_tool(
                actor=replace(actor, request_id=uuid.uuid4()),
                tool_name=tool_name,
                arguments=arguments,
                transport="MCP",
            )
        assert rejected.value.code == "invalid_tool_input"
        assert KnowledgeProposal.objects.count() == before["proposals"]
        assert MCPProposalSubmission.objects.count() == before["submissions"]
        assert OutboxEvent.objects.count() == before["outbox"]


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
                "correction": {"value": secret},
            },
            transport="MCP",
        )
    assert rejected.value.code == "secret_material_rejected"
    rendered_error = str(rejected.value)
    assert KnowledgeProposal.objects.count() == before["proposals"]
    assert MCPProposalSubmission.objects.count() == before["submissions"]
    assert AuditEvent.objects.count() == before["audits"]
    assert OutboxEvent.objects.count() == before["outbox"]
    assert MCPToolInvocation.objects.count() == before["invocations"] + 1

    invocations = MCPToolInvocation.objects.filter(request_id=actor.request_id)
    assert invocations.count() == 1
    invocation = invocations.get()
    assert invocation.tool_name == "anva.propose_correction"
    assert invocation.required_action == Action.KNOWLEDGE_PROPOSE.value
    assert invocation.outcome == MCPToolInvocation.Outcome.FAILED
    assert invocation.error_code == "secret_material_rejected"
    assert len(invocation.arguments_hash) == 64
    persisted_audit = json.dumps(
        MCPToolInvocation.objects.values().get(id=invocation.id),
        default=str,
        sort_keys=True,
    )
    for prohibited in (
        secret,
        plaintext,
        "Must never persist credential material.",
        "secret-rejection-idempotency",
        str(assertion.id),
        '"correction"',
        '"value"',
    ):
        assert prohibited not in rendered_error
        assert prohibited not in persisted_audit


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_persisted_private_entity_output_fails_closed_before_success_audit() -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-private-output")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    canary = "PRIVATE_ORACLE_OUTPUT_MUST_NOT_ESCAPE"
    entity = KnowledgeEntity.objects.create(
        organization=organization,
        access_scope=scope,
        entity_type=KnowledgeEntity.EntityType.SERVICE,
        canonical_key="service:private-output",
        display_name="Private output canary",
        attributes={
            "owner": "platform",
            "privateOracle": {"verdict": canary},
        },
    )

    with pytest.raises(MCPGatewayError) as rejected:
        dispatch_tool(
            actor=actor,
            tool_name="anva.get_entity",
            arguments={
                "contract_version": "1",
                "repository_id": str(repository.id),
                "entity_id": str(entity.id),
            },
            transport="MCP",
        )

    assert rejected.value.code == "invalid_tool_output"
    assert rejected.value.reason == "private_control_material"
    assert canary not in str(rejected.value)
    invocation = MCPToolInvocation.objects.get(request_id=actor.request_id)
    assert invocation.outcome == MCPToolInvocation.Outcome.FAILED
    assert invocation.error_code == "invalid_tool_output"
    persisted_audit = json.dumps(
        MCPToolInvocation.objects.values().get(id=invocation.id),
        default=str,
        sort_keys=True,
    )
    assert canary not in persisted_audit


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_search_preserves_public_bearer_prose_at_canonical_mcp_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization, repository, scope, plaintext = _gateway_tenant("mcp-public-bearer-prose")
    actor = authenticate_bearer(f"Bearer {plaintext}")
    sentence = "The first operator sample used a long-lived shared bearer token in a shell script."
    normalized_document = {
        "headings": [{"level": 1, "line": 12, "text": "Shared token integration sample"}],
        "links": [],
        "text": (
            f"---\nclaim:\n  object:\n    value: {sentence}\n"
            f"  statement: {sentence}\n---\n\n# Claim\n\n{sentence}\n\n"
            + ("Public historical context remained unapproved. " * 100)
        ),
    }
    public_text = json.dumps(
        normalized_document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )[:4_000]
    assert len(public_text) == 4_000
    content_hash = "b4fe2b839d8b2be96656b319a6cf8512c332ded3fa07d18c2ad48a6c26a9ef64"
    result = SearchResult(
        chunk_id=uuid.uuid4(),
        text=public_text,
        content_hash=content_hash,
        pointer="archive/archive-shared-token-sample/r001.md#L1-L8",
        canonical_url="https://github.com/RishavT/anva-test/blob/main/archive/r001.md",
        access_scope_id=scope.id,
        source_location_id=uuid.uuid4(),
        source_observation_id=uuid.uuid4(),
        access_snapshot_id=uuid.uuid4(),
        observed_at=timezone.now(),
        explanation=RankingExplanation(1, 1, 1.0, "PREPARE", ("policy",)),
    )
    monkeypatch.setattr(
        mcp_gateway,
        "search_chunks",
        lambda **_kwargs: SearchResponse("governance", "a" * 64, (result,)),
    )

    response = dispatch_tool(
        actor=actor,
        tool_name="anva.search",
        arguments={
            "contract_version": "1",
            "repository_id": str(repository.id),
            "query": "operator bridge authentication shared token workload identity",
            "phase": "PREPARE",
        },
        transport="streamable-http",
    )

    validate_tool_output("anva.search", response)
    returned = response["data"]["results"][0]  # type: ignore[index]
    assert returned["text"] == public_text
    assert returned["content_hash"] == content_hash
    assert MCPToolInvocation.objects.get(request_id=actor.request_id).outcome == "SUCCEEDED"


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
