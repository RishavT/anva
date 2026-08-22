"""Focused branch coverage for the bounded MCP domain and resource facades."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from mcp.server.auth.provider import AccessToken
from mcp.shared.exceptions import McpError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent
from pydantic import AnyUrl

from anva.core.exceptions import RateLimitExceededError
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
from anva.mcp.contracts import TOOL_CONTRACTS, validate_tool_output

_NO_CURSOR = object()


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


def _validate_handler_output(
    tool_name: str,
    data: dict[str, object],
    *,
    next_cursor: str | None | object = _NO_CURSOR,
) -> None:
    payload: dict[str, object] = {
        "contract_version": "1",
        "tool": tool_name,
        "data": data,
    }
    if next_cursor is not _NO_CURSOR:
        payload["next_cursor"] = next_cursor
    validate_tool_output(tool_name, payload)


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
    resolved_repository = mcp_gateway._resolve_repository(
        actor,
        {"repository_id": str(repository_id)},
    )
    assert resolved_repository["active"] is True
    _validate_handler_output("anva.resolve_repository", resolved_repository)

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
    _validate_handler_output("anva.resolve_work_item", resolved)

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
        SimpleNamespace(
            as_dict=lambda position=position: {
                "chunk_id": str(uuid.uuid4()),
                "text": f"Result {position}",
                "content_hash": "a" * 64,
                "pointer": f"/result-{position}.md",
                "canonical_url": f"https://example.test/result-{position}.md",
                "access_scope_id": str(uuid.uuid4()),
                "source_location_id": str(uuid.uuid4()),
                "source_observation_id": str(uuid.uuid4()),
                "access_snapshot_id": str(uuid.uuid4()),
                "observed_at": datetime.now(UTC).isoformat(),
                "explanation": {
                    "lexical_rank": position,
                    "semantic_rank": None,
                    "reciprocal_rank_score": 0.5,
                    "phase": None,
                    "phase_terms": [],
                },
            }
        )
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
    assert cast(list[dict[str, object]], searched["results"])[0]["text"] == "Result 1"
    assert cursor is not None
    _validate_handler_output("anva.search", searched, next_cursor=cursor)

    entity = SimpleNamespace(
        id=uuid.uuid4(),
        entity_type="SERVICE",
        canonical_key="service:anva",
        display_name="Anva",
        attributes={"tier": 1},
        revision=3,
    )
    monkeypatch.setattr(mcp_gateway, "get_authorized_entity", lambda **_kwargs: entity)
    entity_data = mcp_gateway._entity(
        actor,
        {"repository_id": str(repository_id), "entity_id": str(entity.id)},
    )
    assert entity_data["revision"] == 3
    _validate_handler_output("anva.get_entity", entity_data)
    relationship_id = uuid.uuid4()
    edge = SimpleNamespace(
        as_dict=lambda: {
            "relationship_id": str(relationship_id),
            "relationship_type": "DEPENDS_ON",
            "source": {
                "id": str(entity.id),
                "type": "SERVICE",
                "key": "service:anva",
                "name": "Anva",
            },
            "target": {
                "id": str(uuid.uuid4()),
                "type": "SERVICE",
                "key": "service:database",
                "name": "Database",
            },
            "assertion_id": str(uuid.uuid4()),
            "source_location_id": str(uuid.uuid4()),
            "source_observation_id": str(uuid.uuid4()),
            "access_snapshot_id": str(uuid.uuid4()),
            "observed_at": datetime.now(UTC).isoformat(),
            "confidence": 0.9,
            "depth": 1,
        }
    )
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
    assert cast(list[dict[str, object]], relationships["relationships"])[0][
        "relationship_id"
    ] == str(relationship_id)
    assert next_cursor is None
    _validate_handler_output("anva.get_relationships", relationships, next_cursor=next_cursor)
    profile = mcp_gateway._repository_profile(
        actor,
        {"repository_id": str(repository_id)},
    )
    assert profile["profile_version"] == 1
    _validate_handler_output("anva.get_repository_profile", profile)


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
            "enforcement": "BLOCKING",
            "check_type": "MANUAL_APPROVAL",
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
    _validate_handler_output("anva.get_policy_bundle", bundle, next_cursor=bundle_cursor)

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
    _validate_handler_output("anva.get_requirements", requirements, next_cursor=requirements_cursor)

    assertion = SimpleNamespace(
        id=uuid.uuid4(),
        subject_key="gateway",
        predicate="requires",
        value={"authentication": True},
        staleness_state="FRESH",
        is_inferred=False,
        review_state="HUMAN_CONFIRMED",
    )
    monkeypatch.setattr(mcp_gateway, "get_authorized_assertion", lambda **_kwargs: assertion)
    monkeypatch.setattr(
        mcp_gateway,
        "authorized_assertion_citations",
        lambda **_kwargs: (
            {
                "source_location_id": str(uuid.uuid4()),
                "source_observation_id": str(uuid.uuid4()),
                "access_snapshot_id": str(uuid.uuid4()),
                "canonical_url": "https://example.test/assertion.md",
                "locator": "/assertion.md#L1-L2",
                "source_content_hash": "a" * 64,
                "observed_at": datetime.now(UTC).isoformat(),
            },
        ),
    )
    explanation = mcp_gateway._assertion_explanation(
        actor,
        {
            "repository_id": str(repository_id),
            "assertion_id": str(assertion.id),
        },
    )
    assert len(cast(list[dict[str, object]], explanation["sources"])) == 1
    _validate_handler_output("anva.explain_assertion", explanation)


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


@pytest.mark.unit
def test_official_sdk_unknown_tool_warning_is_sanitized_without_hiding_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    actor = _actor()
    canary = "anva.CANARY_SUBMITTED_TOOL_NAME_MUST_NOT_ECHO"
    sdk_logger_name = "mcp.server.lowlevel.server"
    caplog.set_level(logging.WARNING, logger=sdk_logger_name)
    monkeypatch.setattr(mcp_entrypoint, "_actor", lambda: actor)

    def rejected_dispatch(**_kwargs: object) -> dict[str, object]:
        raise mcp_gateway.MCPGatewayError(
            "capability_unavailable",
            "Requested capability is unavailable; refresh MCP capability discovery",
            http_status=404,
            reason="unknown_capability",
        )

    monkeypatch.setattr(mcp_entrypoint, "dispatch_tool", rejected_dispatch)

    async def call_unknown_tool() -> None:
        async with create_connected_server_and_client_session(
            mcp_entrypoint._create_server()
        ) as session:
            result = await session.call_tool(canary, arguments={"opaque": "argument-canary"})
            assert result.isError
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "capability_unavailable" in content.text
            assert canary not in content.text

    asyncio.run(call_unknown_tool())
    logging.getLogger(sdk_logger_name).warning("unrelated MCP SDK warning remains visible")

    assert canary not in caplog.text
    assert "Unlisted tool requested; SDK schema validation skipped" in caplog.text
    assert "unrelated MCP SDK warning remains visible" in caplog.text


@pytest.mark.unit
def test_official_sdk_runs_authenticated_actor_outside_async_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor = _actor()
    calls: list[str] = []

    def sync_only_actor() -> ActorContext:
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        calls.append("actor")
        return actor

    monkeypatch.setattr(mcp_entrypoint, "_actor", sync_only_actor)

    def rejected_dispatch(**_kwargs: object) -> dict[str, object]:
        raise mcp_gateway.MCPGatewayError(
            "capability_unavailable",
            "Requested capability is unavailable; refresh MCP capability discovery",
            http_status=404,
            reason="unknown_capability",
        )

    monkeypatch.setattr(mcp_entrypoint, "dispatch_tool", rejected_dispatch)

    async def use_authenticated_handlers() -> None:
        async with create_connected_server_and_client_session(
            mcp_entrypoint._create_server()
        ) as session:
            assert (await session.list_tools()).tools
            assert (await session.list_resources()).resources
            assert (await session.list_resource_templates()).resourceTemplates
            result = await session.read_resource(AnyUrl("anva://diagnostics"))
            assert len(result.contents) == 1
            content = result.contents[0]
            assert hasattr(content, "text")
            assert '"status": "available"' in content.text
            tool_result = await session.call_tool("anva.unknown", arguments={})
            assert tool_result.isError

    asyncio.run(use_authenticated_handlers())
    assert calls == ["actor"] * 6


@pytest.mark.unit
def test_official_sdk_returns_safe_tool_error_when_actor_rate_limit_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exhausted_actor() -> ActorContext:
        raise RateLimitExceededError(17)

    monkeypatch.setattr(mcp_entrypoint, "_actor", exhausted_actor)

    async def call_rate_limited_tool() -> None:
        async with create_connected_server_and_client_session(
            mcp_entrypoint._create_server()
        ) as session:
            result = await session.call_tool("anva.unknown", arguments={})
            assert result.isError
            content = result.content[0]
            assert isinstance(content, TextContent)
            payload = json.loads(content.text)
            assert payload["code"] == "rate_limited"
            assert payload["message"] == "Request rate limit exceeded"
            assert "correlation_id" in payload

    asyncio.run(call_rate_limited_tool())


@pytest.mark.unit
def test_official_sdk_rate_limits_authenticated_discovery_with_safe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exhausted_actor() -> ActorContext:
        raise RateLimitExceededError(17)

    monkeypatch.setattr(mcp_entrypoint, "_actor", exhausted_actor)

    async def list_rate_limited_tools() -> None:
        async with create_connected_server_and_client_session(
            mcp_entrypoint._create_server()
        ) as session:
            with pytest.raises(McpError, match="rate_limited"):
                await session.list_tools()

    asyncio.run(list_rate_limited_tools())


@pytest.mark.unit
def test_mcp_request_tier_rate_limits_valid_initialize_and_ping_once_each(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token_canary = "MCP_VALID_TOKEN_MUST_NOT_BE_STORED_OR_LOGGED"  # noqa: S105
    preauth_keys: list[str] = []
    actor_rate_calls: list[str] = []

    async def valid_token(
        _verifier: object,
        token: str,
    ) -> AccessToken | None:
        assert token == token_canary
        return AccessToken(
            token="opaque-credential-id",
            client_id="rate-limit-client",
            scopes=[],
            subject="rate-limit-client",
        )

    def request_rate_limit(*, client_key: str) -> None:
        preauth_keys.append(client_key)
        if len(preauth_keys) > 1:
            raise RateLimitExceededError(9)

    monkeypatch.setattr(mcp_entrypoint.RepositoryTokenVerifier, "verify_token", valid_token)
    monkeypatch.setattr(
        mcp_entrypoint,
        "enforce_pre_auth_rate_limit",
        request_rate_limit,
    )
    monkeypatch.setattr(
        mcp_entrypoint,
        "enforce_rate_limit",
        lambda **_kwargs: actor_rate_calls.append("actor"),
    )
    headers = {
        "Authorization": f"Bearer {token_canary}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "rate-limit-test", "version": "1"},
        },
    }

    async def invoke() -> tuple[httpx.Response, httpx.Response]:
        application = mcp_entrypoint.create_application()
        transport = httpx.ASGITransport(app=application)
        async with application.router.lifespan_context(application):
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://mcp:8001",
            ) as client:
                initialized = await client.post("/mcp", headers=headers, json=initialize)
                ping = await client.post(
                    "/mcp",
                    headers=headers,
                    json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                )
        return initialized, ping

    initialized, ping = asyncio.run(invoke())

    assert initialized.status_code == 200
    assert initialized.json()["result"]["serverInfo"]["name"] == "anva"
    assert ping.status_code == 429
    assert ping.headers["Retry-After"] == "9"
    assert ping.headers["Cache-Control"] == "no-store"
    assert ping.json() == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32000,
            "message": "Request rate limit exceeded",
            "data": {"code": "rate_limited"},
        },
    }
    assert len(preauth_keys) == 2
    assert preauth_keys[0] == preauth_keys[1]
    assert token_canary not in preauth_keys[0]
    assert actor_rate_calls == []
    assert token_canary not in initialized.text
    assert token_canary not in ping.text
    assert token_canary not in caplog.text


@pytest.mark.unit
def test_mcp_tool_request_charges_request_and_actor_tiers_once_each(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor = _actor()
    preauth_calls: list[str] = []
    actor_rate_calls: list[str] = []

    async def valid_token(
        _verifier: object,
        _token: str,
    ) -> AccessToken | None:
        return AccessToken(
            token=str(actor.credential_id),
            client_id=actor.actor_id,
            scopes=[],
            subject=actor.actor_id,
            claims={
                "organization_id": str(actor.organization_id),
                "repository_id": str(actor.repository_id),
                "credential_id": str(actor.credential_id),
                "actor_type": actor.actor_type,
                "request_id": str(actor.request_id),
            },
        )

    monkeypatch.setattr(mcp_entrypoint.RepositoryTokenVerifier, "verify_token", valid_token)
    monkeypatch.setattr(
        mcp_entrypoint,
        "enforce_pre_auth_rate_limit",
        lambda *, client_key: preauth_calls.append(client_key),
    )
    monkeypatch.setattr(
        mcp_entrypoint,
        "enforce_rate_limit",
        lambda **_kwargs: actor_rate_calls.append("actor"),
    )
    headers = {
        "Authorization": "Bearer valid-token",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    async def invoke() -> tuple[httpx.Response, httpx.Response]:
        application = mcp_entrypoint.create_application()
        transport = httpx.ASGITransport(app=application)
        async with application.router.lifespan_context(application):
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://mcp:8001",
            ) as client:
                initialized = await client.post(
                    "/mcp",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "tier-test", "version": "1"},
                        },
                    },
                )
                called = await client.post(
                    "/mcp",
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "anva.unknown", "arguments": {}},
                    },
                )
        return initialized, called

    initialized, called = asyncio.run(invoke())

    assert initialized.status_code == 200
    assert called.status_code == 200
    assert len(preauth_calls) == 2
    assert actor_rate_calls == ["actor"]


@pytest.mark.unit
def test_actor_tier_reuses_discovery_once_but_preserves_later_handler_charges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actor = _actor()
    access_token = AccessToken(
        token=str(actor.credential_id),
        client_id=actor.actor_id,
        scopes=[],
        subject=actor.actor_id,
        claims={
            "organization_id": str(actor.organization_id),
            "repository_id": str(actor.repository_id),
            "credential_id": str(actor.credential_id),
            "actor_type": actor.actor_type,
            "request_id": str(actor.request_id),
        },
    )
    actor_rate_calls: list[str] = []
    monkeypatch.setattr(mcp_entrypoint, "get_access_token", lambda: access_token)
    monkeypatch.setattr(
        mcp_entrypoint,
        "enforce_rate_limit",
        lambda **_kwargs: actor_rate_calls.append("actor"),
    )
    state_token = mcp_entrypoint._actor_rate_state.set(
        mcp_entrypoint._ActorRateRequestState(set(), {}, set())
    )
    discovery_token = mcp_entrypoint._actor_rate_kind.set("discovery")
    try:
        assert mcp_entrypoint._actor().credential_id == actor.credential_id
        handler_token = mcp_entrypoint._actor_rate_kind.set("handler")
        try:
            assert mcp_entrypoint._actor().credential_id == actor.credential_id
            assert mcp_entrypoint._actor().credential_id == actor.credential_id
        finally:
            mcp_entrypoint._actor_rate_kind.reset(handler_token)
    finally:
        mcp_entrypoint._actor_rate_kind.reset(discovery_token)
        mcp_entrypoint._actor_rate_state.reset(state_token)

    assert actor_rate_calls == ["actor", "actor"]


@pytest.mark.unit
def test_mcp_request_client_key_trusts_forwarding_only_from_exact_proxy(
    settings: object,
) -> None:
    scope = cast(
        Any,
        {
            "client": ("192.0.2.10", 1234),
            "headers": [(b"x-forwarded-for", b"198.51.100.7, 192.0.2.10")],
        },
    )
    settings.ANVA_TRUSTED_PROXY_IPS = []  # type: ignore[attr-defined]
    assert mcp_entrypoint._request_client_rate_key(scope) == "192.0.2.10"

    settings.ANVA_TRUSTED_PROXY_IPS = ["192.0.2.10"]  # type: ignore[attr-defined]
    assert mcp_entrypoint._request_client_rate_key(scope) == "198.51.100.7"

    scope["headers"] = [(b"x-forwarded-for", b"not-an-address")]
    assert mcp_entrypoint._request_client_rate_key(scope) == "unresolved-client"
