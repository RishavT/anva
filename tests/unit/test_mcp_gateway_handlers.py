"""Focused branch coverage for the bounded MCP domain and resource facades."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import AnyUrl

from anva.core.models import (
    AcceptanceCriterion,
    MCPProposalSubmission,
    Policy,
    Requirement,
    WorkItem,
)
from anva.core.services import mcp_gateway
from anva.core.services.context import ActorContext
from anva.entrypoints import mcp as mcp_entrypoint
from anva.mcp.contracts import TOOL_CONTRACTS


def _actor() -> ActorContext:
    return ActorContext(
        organization_id=uuid.uuid4(),
        repository_id=uuid.uuid4(),
        credential_id=uuid.uuid4(),
        actor_type="SERVICE",
        actor_id=str(uuid.uuid4()),
        authorization_path="credential:test",
        request_id=uuid.uuid4(),
    )


class _Query:
    def __init__(self, values: list[object]) -> None:
        self.records = values

    def filter(self, **_kwargs: object) -> _Query:
        return self

    def prefetch_related(self, *_args: object) -> _Query:
        return self

    def order_by(self, *_args: object) -> _Query:
        return self

    def values(self, *_args: object) -> _Query:
        return self

    def first(self) -> object | None:
        return self.records[0] if self.records else None

    def all(self) -> list[object]:
        return self.records

    def __getitem__(self, key: slice) -> list[object]:
        return self.records[key]


@pytest.mark.unit
def test_read_handlers_share_bounded_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    actor = _actor()
    monkeypatch.setattr(
        mcp_gateway,
        "_cursor_expires_at",
        lambda *, actor, issued_at: issued_at + mcp_gateway.CURSOR_TTL_SECONDS,
    )
    monkeypatch.setattr(
        mcp_gateway,
        "_authorization_watermark",
        lambda **_kwargs: "a" * 64,
    )
    repository_id = cast(uuid.UUID, actor.repository_id)
    repository = SimpleNamespace(
        id=repository_id,
        organization_id=actor.organization_id,
        external_id="github:anva/repository",
        name="Anva",
        is_active=True,
    )
    monkeypatch.setattr(mcp_gateway, "_repository", lambda **_kwargs: repository)
    monkeypatch.setattr(mcp_gateway, "visible_scope_ids", lambda **_kwargs: (uuid.uuid4(),))
    assert (
        mcp_gateway._resolve_repository(
            actor,
            {"repository_id": str(repository_id)},
        )["active"]
        is True
    )

    work_item = SimpleNamespace(
        id=uuid.uuid4(),
        repository_id=repository_id,
        access_scope_id=uuid.uuid4(),
        external_key="ANVA-9",
        title="MCP",
        work_type="FEATURE",
        status="READY",
        revision=2,
    )
    revision = SimpleNamespace(revision=2, content_hash="a" * 64)
    monkeypatch.setattr(
        WorkItem.objects,
        "filter",
        lambda **_kwargs: _Query([work_item]),
    )
    monkeypatch.setattr(
        mcp_gateway,
        "_work_item",
        lambda **_kwargs: (work_item, revision),
    )
    resolved = mcp_gateway._resolve_work_item(
        actor,
        {
            "repository_id": str(repository_id),
            "work_item_id": str(work_item.id),
        },
    )
    assert resolved["external_key"] == "ANVA-9"

    packet_id = uuid.uuid4()
    monkeypatch.setattr(
        mcp_gateway,
        "get_context_packet",
        lambda **_kwargs: {"packet": "exact"},
    )
    exact = mcp_gateway._context_packet(
        actor,
        {"repository_id": str(repository_id), "packet_id": str(packet_id)},
    )
    assert exact == {
        "packet_id": str(packet_id),
        "created": False,
        "packet": {"packet": "exact"},
    }
    record = SimpleNamespace(id=uuid.uuid4(), artifact=SimpleNamespace(payload={"items": []}))
    monkeypatch.setattr(
        mcp_gateway,
        "build_context_packet",
        lambda **_kwargs: (record, True),
    )
    built = mcp_gateway._context_packet(
        actor,
        {
            "repository_id": str(repository_id),
            "task": "Implement MCP",
            "phase": "BUILD",
            "budget": {"max_items": 5},
        },
    )
    assert built["created"] is True

    results = [
        SimpleNamespace(as_dict=lambda position=position: {"position": position})
        for position in (1, 2)
    ]
    monkeypatch.setattr(
        mcp_gateway,
        "search_chunks",
        lambda **_kwargs: SimpleNamespace(results=results),
    )
    searched, cursor = mcp_gateway._search(
        actor,
        {
            "contract_version": "1",
            "repository_id": str(repository_id),
            "query": "gateway",
            "limit": 1,
        },
    )
    assert searched["results"] == [{"position": 1}]
    assert cursor is not None

    entity = SimpleNamespace(
        id=uuid.uuid4(),
        entity_type="SERVICE",
        canonical_key="service:anva",
        display_name="Anva",
        attributes={"tier": 1},
        revision=3,
    )
    monkeypatch.setattr(mcp_gateway, "get_authorized_entity", lambda **_kwargs: entity)
    assert (
        mcp_gateway._entity(
            actor,
            {"repository_id": str(repository_id), "entity_id": str(entity.id)},
        )["revision"]
        == 3
    )
    edge = SimpleNamespace(as_dict=lambda: {"relationship": "DEPENDS_ON"})
    monkeypatch.setattr(
        mcp_gateway,
        "traverse_graph",
        lambda **_kwargs: SimpleNamespace(edges=[edge]),
    )
    relationships, next_cursor = mcp_gateway._relationships(
        actor,
        {
            "contract_version": "1",
            "repository_id": str(repository_id),
            "entity_id": str(entity.id),
            "limit": 20,
        },
    )
    assert relationships["relationships"] == [{"relationship": "DEPENDS_ON"}]
    assert next_cursor is None
    assert (
        mcp_gateway._repository_profile(
            actor,
            {"repository_id": str(repository_id)},
        )["profile_version"]
        == 1
    )


@pytest.mark.unit
def test_policy_requirements_and_explanation_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor = _actor()
    repository_id = cast(uuid.UUID, actor.repository_id)
    monkeypatch.setattr(mcp_gateway, "_repository", lambda **_kwargs: object())
    monkeypatch.setattr(mcp_gateway, "visible_scope_ids", lambda **_kwargs: (uuid.uuid4(),))
    monkeypatch.setattr(mcp_gateway, "authorize_action", lambda **_kwargs: object())

    requirement_values = [
        {
            "code": "SEC_1",
            "description": "Review",
            "enforcement": "REQUIRED",
            "check_type": "MANUAL",
            "required_evidence": [],
            "required_approval": True,
        }
    ]
    version = SimpleNamespace(
        id=uuid.uuid4(),
        version=2,
        schema_version="1",
        content_hash="b" * 64,
        effective_at=datetime.now(UTC),
        expires_at=None,
        policybinding=None,
        policyrequirement_set=_Query(cast(list[object], requirement_values)),
    )
    policy = SimpleNamespace(
        id=uuid.uuid4(),
        access_scope_id=uuid.uuid4(),
        revision=2,
        name="Security",
        owner="security",
        policyversion_set=_Query([version]),
    )
    monkeypatch.setattr(
        Policy.objects,
        "filter",
        lambda **_kwargs: _Query([policy]),
    )
    bundle, bundle_cursor = mcp_gateway._policy_bundle(
        actor,
        {
            "contract_version": "1",
            "repository_id": str(repository_id),
            "limit": 20,
        },
    )
    assert cast(list[dict[str, object]], bundle["policies"])[0]["name"] == "Security"
    assert bundle_cursor is None

    work_item = SimpleNamespace(id=uuid.uuid4())
    work_revision = SimpleNamespace(id=uuid.uuid4(), revision=4)
    monkeypatch.setattr(
        mcp_gateway,
        "_work_item",
        lambda **_kwargs: (work_item, work_revision),
    )
    requirement = SimpleNamespace(
        id=uuid.uuid4(),
        code="REQ_1",
        normalized_text="The gateway is authenticated.",
        origin="WORK_ITEM",
        owner="platform",
        status="CONFIRMED",
        requires_approval=False,
        source_references=[],
        related_entity_ids=[],
    )
    criterion = {
        "id": uuid.uuid4(),
        "code": "AC_1",
        "normalized_text": "A revoked token fails.",
        "required_evidence_types": [],
        "manual_approval_allowed": False,
    }
    monkeypatch.setattr(
        Requirement.objects,
        "filter",
        lambda **_kwargs: _Query([requirement]),
    )
    monkeypatch.setattr(
        AcceptanceCriterion.objects,
        "filter",
        lambda **_kwargs: _Query([criterion]),
    )
    requirements, requirements_cursor = mcp_gateway._requirements(
        actor,
        {
            "contract_version": "1",
            "repository_id": str(repository_id),
            "work_item_id": str(work_item.id),
            "limit": 20,
        },
    )
    assert cast(list[dict[str, object]], requirements["requirements"])[0]["code"] == "REQ_1"
    assert requirements_cursor is None

    assertion = SimpleNamespace(
        id=uuid.uuid4(),
        subject_key="gateway",
        predicate="requires",
        value={"authentication": True},
        staleness_state="CURRENT",
        is_inferred=False,
        review_state="CONFIRMED",
    )
    monkeypatch.setattr(mcp_gateway, "get_authorized_assertion", lambda **_kwargs: assertion)
    monkeypatch.setattr(
        mcp_gateway,
        "authorized_assertion_citations",
        lambda **_kwargs: ({"source": "normalized"},),
    )
    explanation = mcp_gateway._assertion_explanation(
        actor,
        {
            "repository_id": str(repository_id),
            "assertion_id": str(assertion.id),
        },
    )
    assert explanation["sources"] == [{"source": "normalized"}]


@pytest.mark.unit
def test_all_proposal_change_shapes_remain_review_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor = _actor()
    repository_id = cast(uuid.UUID, actor.repository_id)
    scope_id = uuid.uuid4()
    assertion = SimpleNamespace(id=uuid.uuid4(), access_scope_id=scope_id)
    monkeypatch.setattr(mcp_gateway, "get_authorized_assertion", lambda **_kwargs: assertion)
    correction_kind, correction = mcp_gateway._proposal_change(
        actor=actor,
        tool_name="anva.propose_correction",
        repository_id=repository_id,
        access_scope_id=scope_id,
        arguments={
            "assertion_id": str(assertion.id),
            "correction": {"value": "corrected"},
        },
    )
    assert correction_kind == MCPProposalSubmission.Kind.CORRECTION
    assert correction["operation"] == "CORRECT"

    work_item = SimpleNamespace(id=uuid.uuid4(), access_scope_id=scope_id)
    monkeypatch.setattr(
        mcp_gateway,
        "_work_item",
        lambda **_kwargs: (work_item, SimpleNamespace()),
    )
    common = {"work_item_id": str(work_item.id)}
    decision_kind, decision = mcp_gateway._proposal_change(
        actor=actor,
        tool_name="anva.propose_decision",
        repository_id=repository_id,
        access_scope_id=scope_id,
        arguments={
            **common,
            "title": "Use official SDK",
            "outcome": "Accepted for review",
            "rationale": "Avoid protocol drift",
        },
    )
    assert decision_kind == MCPProposalSubmission.Kind.DECISION
    assert decision["is_inferred"] is False
    summary_kind, summary = mcp_gateway._proposal_change(
        actor=actor,
        tool_name="anva.submit_work_summary",
        repository_id=repository_id,
        access_scope_id=scope_id,
        arguments={**common, "summary_data": {"status": "complete"}},
    )
    assert summary_kind == MCPProposalSubmission.Kind.WORK_SUMMARY
    assert summary["predicate"] == "work.summary"
    preflight_kind, preflight = mcp_gateway._proposal_change(
        actor=actor,
        tool_name="anva.submit_preflight_summary",
        repository_id=repository_id,
        access_scope_id=scope_id,
        arguments={
            **common,
            "commit_sha": "a" * 40,
            "checks": [{"name": "tests", "passed": True}],
            "limitations": ["review required"],
        },
    )
    assert preflight_kind == MCPProposalSubmission.Kind.PREFLIGHT_SUMMARY
    assert cast(dict[str, object], preflight["value"])["advisory"] is True


@pytest.mark.unit
def test_resource_mapping_tool_metadata_and_safe_errors() -> None:
    actor = _actor()
    repository_id = cast(uuid.UUID, actor.repository_id)
    mappings = {
        "anva://repositories/00000000-0000-4000-8000-000000000009/profile": (
            "anva.get_repository_profile",
            "00000000-0000-4000-8000-000000000009",
        ),
        "anva://work-items/00000000-0000-4000-8000-000000000010/requirements": (
            "anva.get_requirements",
            str(repository_id),
        ),
        "anva://entities/00000000-0000-4000-8000-000000000011": (
            "anva.get_entity",
            str(repository_id),
        ),
        "anva://context-packets/00000000-0000-4000-8000-000000000012": (
            "anva.get_context_packet",
            str(repository_id),
        ),
    }
    for uri, (expected_tool, expected_repository) in mappings.items():
        mapped_tool, arguments = mcp_entrypoint._resource_arguments(AnyUrl(uri), actor)
        assert mapped_tool == expected_tool
        assert arguments["repository_id"] == expected_repository
    assert mcp_entrypoint._resource_arguments(AnyUrl("anva://diagnostics"), actor) == ("", {})
    with pytest.raises(ValueError, match="Unsupported"):
        mcp_entrypoint._resource_arguments(AnyUrl("anva://unknown/value"), actor)

    sdk_tool = mcp_entrypoint._tool_definition(TOOL_CONTRACTS[0])
    assert sdk_tool.annotations is not None
    assert sdk_tool.annotations.readOnlyHint is True
    domain_error = mcp_entrypoint._safe_tool_error(
        mcp_gateway.MCPGatewayError("bounded", "Bounded failure"),
        actor.request_id,
    )
    assert domain_error.isError is True
    assert "bounded" in cast(Any, domain_error.content[0]).text
    unknown_error = mcp_entrypoint._safe_tool_error(RuntimeError("secret"), actor.request_id)
    assert "invalid_request" in cast(Any, unknown_error.content[0]).text
    with pytest.raises(TypeError, match="schema"):
        mcp_entrypoint.cast_schema("not-an-object")
