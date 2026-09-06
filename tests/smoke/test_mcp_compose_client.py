"""Real official Python MCP client acceptance test against Compose services."""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent
from pydantic import AnyUrl

from anva.mcp.contracts import (
    MCP_PROTOCOL_VERSIONS,
    PROPOSAL_TOOL_NAMES,
    RESOURCE_CONTRACTS,
    TOOL_BY_NAME,
)

COMPOSE_ENVIRONMENT = (
    "ANVA_API_TEST_URL",
    "ANVA_MCP_TEST_URL",
    "ANVA_MCP_READ_ONLY_TEST_URL",
)


def _exception_messages(error: BaseException) -> str:
    """Render nested AnyIO exception groups without losing the actionable cause."""
    if isinstance(error, BaseExceptionGroup):
        return " ".join(_exception_messages(nested) for nested in error.exceptions)
    return str(error)


async def _session(url: str, token: str) -> tuple[set[str], dict[str, object]]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    ) as http_client:
        async with streamable_http_client(url, http_client=http_client) as (
            read_stream,
            write_stream,
            _,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                return {tool.name for tool in tools.tools}, {
                    "protocol_version": initialized.protocolVersion,
                    "server_name": initialized.serverInfo.name,
                }


@pytest.mark.smoke
@pytest.mark.skipif(
    not all(os.getenv(name) for name in COMPOSE_ENVIRONMENT),
    reason="requires the mcp-test Compose profile",
)
def test_real_mcp_client_contract_auth_read_only_revocation_and_http_parity() -> None:
    api_url = os.environ["ANVA_API_TEST_URL"]
    mcp_url = os.environ["ANVA_MCP_TEST_URL"]
    read_only_url = os.environ["ANVA_MCP_READ_ONLY_TEST_URL"]
    run_id = uuid.uuid4().hex[:12]
    bootstrap = httpx.post(
        f"{api_url}/api/v1/bootstrap",
        headers={"X-Anva-Bootstrap-Secret": os.environ["ANVA_BOOTSTRAP_SECRET"]},
        json={
            "organization_slug": f"mcp-compose-{run_id}",
            "organization_name": "MCP Compose",
            "admin_email": f"mcp-compose-{run_id}@anva.test",
            "admin_display_name": "MCP Compose",
            "repository_external_id": f"github:mcp/compose-{run_id}",
            "repository_name": "MCP Compose",
        },
        timeout=10,
    )
    assert bootstrap.status_code == 201, bootstrap.text
    credential = bootstrap.json()
    token = credential["token"]
    repository_id = credential["repository_id"]

    async def acceptance() -> None:
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        ) as http_client:
            async with streamable_http_client(mcp_url, http_client=http_client) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    assert initialized.protocolVersion in MCP_PROTOCOL_VERSIONS
                    tools = await session.list_tools()
                    assert {tool.name for tool in tools.tools} == set(TOOL_BY_NAME)
                    for sdk_tool in tools.tools:
                        contract = TOOL_BY_NAME[sdk_tool.name]
                        assert sdk_tool.inputSchema == contract["input_schema"]
                        assert sdk_tool.outputSchema == contract["output_schema"]
                    resources = await session.list_resources()
                    assert {str(resource.uri) for resource in resources.resources} == {
                        "anva://diagnostics"
                    }
                    templates = await session.list_resource_templates()
                    assert {template.name for template in templates.resourceTemplates} == {
                        contract["name"] for contract in RESOURCE_CONTRACTS
                    }
                    diagnostic_resource = await session.read_resource(AnyUrl("anva://diagnostics"))
                    diagnostic_text = diagnostic_resource.contents[0]
                    assert hasattr(diagnostic_text, "text")
                    assert json.loads(diagnostic_text.text)["status"] == "available"
                    arguments = {
                        "contract_version": "1",
                        "repository_id": repository_id,
                    }
                    mcp_result = await session.call_tool(
                        "anva.resolve_repository",
                        arguments=arguments,
                    )
                    assert not mcp_result.isError
                    assert mcp_result.structuredContent is not None
                    parity = await http_client.post(
                        f"{api_url}/api/v1/mcp/tools/anva.resolve_repository",
                        headers={"X-Correlation-ID": str(uuid.uuid4())},
                        json=arguments,
                    )
                    assert parity.status_code == 200, parity.text
                    assert parity.json() == mcp_result.structuredContent

                    source = await http_client.post(
                        f"{api_url}/api/v1/source-connections/filesystem",
                        headers={"X-Correlation-ID": str(uuid.uuid4())},
                        json={
                            "repository_id": repository_id,
                            "access_scope_id": credential["access_scope_id"],
                            "external_key": f"mcp-compose-{run_id}:anchor",
                            "display_name": "MCP required anchor corpus",
                            "root": "/fixtures/acceptance-public/payload",
                        },
                    )
                    assert source.status_code == 201, source.text
                    source_id = source.json()["id"]
                    sync = await http_client.post(
                        f"{api_url}/api/v1/source-connections/{source_id}/sync",
                        headers={"X-Correlation-ID": str(uuid.uuid4())},
                        json={"scan_mode": "FULL"},
                    )
                    assert sync.status_code == 202, sync.text
                    sync_id = sync.json()["id"]
                    sync_state = "REQUESTED"
                    for _ in range(120):
                        runs = await http_client.get(
                            f"{api_url}/api/v1/source-connections/{source_id}/sync-runs",
                            headers={"X-Correlation-ID": str(uuid.uuid4())},
                        )
                        assert runs.status_code == 200, runs.text
                        matching = [run for run in runs.json()["sync_runs"] if run["id"] == sync_id]
                        assert matching
                        sync_state = matching[0]["state"]
                        if sync_state in {"COMPLETED", "PARTIALLY_COMPLETED", "FAILED"}:
                            break
                        await asyncio.sleep(0.25)
                    assert sync_state == "COMPLETED"

                    search = await session.call_tool(
                        "anva.search",
                        arguments={
                            "contract_version": "1",
                            "repository_id": repository_id,
                            "query": "Payments Platform owns checkout",
                            "phase": "ASSURANCE",
                            "limit": 10,
                        },
                    )
                    assert not search.isError
                    assert search.structuredContent is not None
                    search_results = search.structuredContent["data"]["results"]
                    assert len(search_results) == 1
                    hit = search_results[0]
                    anchor = {
                        key: hit[key]
                        for key in (
                            "chunk_id",
                            "content_hash",
                            "access_scope_id",
                            "source_location_id",
                            "source_observation_id",
                            "access_snapshot_id",
                        )
                    }
                    context_arguments = {
                        "contract_version": "1",
                        "repository_id": repository_id,
                        "task": "Preserve the exact checkout ownership search result",
                        "phase": "ASSURANCE",
                        "budget": {
                            "max_items": 1,
                            "max_tokens": 8_000,
                            "max_bytes": 100_000,
                            "max_citations": 1,
                        },
                        "required_search_anchors": [anchor],
                    }
                    anchored = await session.call_tool(
                        "anva.get_context_packet",
                        arguments=context_arguments,
                    )
                    assert not anchored.isError
                    assert anchored.structuredContent is not None
                    anchored_data = anchored.structuredContent["data"]
                    assert anchored_data["created"] is True
                    anchored_packet = anchored_data["packet"]
                    assert anchored_packet["items"][0]["item_key"] == f"chunk:{hit['chunk_id']}"
                    assert (
                        anchored_packet["items"][0]["payload"]["content_hash"]
                        == hit["content_hash"]
                    )
                    assert anchored_packet["items"][0]["payload"]["required_search_anchor"] is True
                    assert (
                        anchored_packet["items"][0]["anva_sources"][0]["access_snapshot_id"]
                        == hit["access_snapshot_id"]
                    )
                    rest_context = await http_client.post(
                        f"{api_url}/api/v1/context-packets",
                        headers={"X-Correlation-ID": str(uuid.uuid4())},
                        json={
                            key: ([anchor, anchor] if key == "required_search_anchors" else value)
                            for key, value in context_arguments.items()
                            if key != "contract_version"
                        },
                    )
                    assert rest_context.status_code == 200, rest_context.text
                    rest_context_data = rest_context.json()
                    assert rest_context_data["created"] is False
                    assert rest_context_data["packet_id"] == anchored_data["packet_id"]
                    assert (
                        rest_context_data["packet"]["content_hash"]
                        == anchored_packet["content_hash"]
                    )
                    assert rest_context_data["packet"] == anchored_packet

                    unavailable_anchor = {
                        "chunk_id": str(uuid.uuid4()),
                        "content_hash": "a" * 64,
                        "access_scope_id": str(uuid.uuid4()),
                        "source_location_id": str(uuid.uuid4()),
                        "source_observation_id": str(uuid.uuid4()),
                        "access_snapshot_id": str(uuid.uuid4()),
                    }
                    anchor_arguments = {
                        "contract_version": "1",
                        "repository_id": repository_id,
                        "task": "Require one exact prior search result",
                        "phase": "ASSURANCE",
                        "required_search_anchors": [unavailable_anchor],
                    }
                    anchor_rejected = await session.call_tool(
                        "anva.get_context_packet",
                        arguments=anchor_arguments,
                    )
                    assert anchor_rejected.isError
                    anchor_content = anchor_rejected.content[0]
                    assert isinstance(anchor_content, TextContent)
                    mcp_anchor_error = json.loads(anchor_content.text)
                    assert mcp_anchor_error["code"] == "required_search_anchor_unavailable"
                    rest_anchor = await http_client.post(
                        f"{api_url}/api/v1/context-packets",
                        headers={"X-Correlation-ID": str(uuid.uuid4())},
                        json={
                            key: value
                            for key, value in anchor_arguments.items()
                            if key != "contract_version"
                        },
                    )
                    assert rest_anchor.status_code == 409
                    rest_anchor_error = rest_anchor.json()
                    assert rest_anchor_error["code"] == mcp_anchor_error["code"]
                    assert rest_anchor_error["message"] == mcp_anchor_error["message"]

                    secret = f"ghp_{'A' * 36}"
                    secret_rejected = await session.call_tool(
                        "anva.search",
                        arguments={
                            "contract_version": "1",
                            "repository_id": repository_id,
                            "query": "bounded",
                            "phase": secret,
                        },
                    )
                    assert secret_rejected.isError
                    secret_content = secret_rejected.content[0]
                    assert isinstance(secret_content, TextContent)
                    assert "secret_material_rejected" in secret_content.text
                    assert secret not in secret_content.text

                    canary = "CANARY_INVALID_ENUM_MUST_NOT_ECHO"
                    invalid = await session.call_tool(
                        "anva.search",
                        arguments={
                            "contract_version": "1",
                            "repository_id": repository_id,
                            "query": "bounded",
                            "phase": canary,
                        },
                    )
                    assert invalid.isError
                    invalid_content = invalid.content[0]
                    assert isinstance(invalid_content, TextContent)
                    invalid_payload = json.loads(invalid_content.text)
                    assert invalid_payload["code"] == "invalid_tool_input"
                    assert invalid_payload["path"] == "$.phase"
                    assert invalid_payload["reason"] == "allowed_value"
                    assert canary not in invalid_content.text
                    invalid_http = await http_client.post(
                        f"{api_url}/api/v1/mcp/tools/anva.search",
                        headers={"X-Correlation-ID": str(uuid.uuid4())},
                        json={
                            "contract_version": "1",
                            "repository_id": repository_id,
                            "query": "bounded",
                            "phase": canary,
                        },
                    )
                    assert invalid_http.status_code == 400
                    assert invalid_http.json()["path"] == "$.phase"
                    assert invalid_http.json()["reason"] == "allowed_value"
                    assert canary not in invalid_http.text

                    unknown_tool = "anva.CANARY_SUBMITTED_TOOL_NAME_MUST_NOT_ECHO"
                    unknown = await session.call_tool(
                        unknown_tool,
                        arguments={"opaque": "unknown-tool-argument-canary"},
                    )
                    assert unknown.isError
                    unknown_content = unknown.content[0]
                    assert isinstance(unknown_content, TextContent)
                    assert "capability_unavailable" in unknown_content.text
                    assert unknown_tool not in unknown_content.text

                    hidden = await session.call_tool(
                        "anva.resolve_repository",
                        arguments={
                            "contract_version": "1",
                            "repository_id": str(uuid.uuid4()),
                        },
                    )
                    assert hidden.isError
                    hidden_content = hidden.content[0]
                    assert isinstance(hidden_content, TextContent)
                    assert "resource_not_found" in hidden_content.text

        read_only_tools, diagnostic = await _session(read_only_url, token)
        assert not (read_only_tools & PROPOSAL_TOOL_NAMES)
        assert diagnostic["server_name"] == "anva"
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        ) as read_only_client:
            async with streamable_http_client(
                read_only_url,
                http_client=read_only_client,
            ) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    rejected = await session.call_tool(
                        "anva.propose_correction",
                        arguments={
                            "contract_version": "1",
                            "repository_id": repository_id,
                            "access_scope_id": str(uuid.uuid4()),
                            "summary": "Must remain a proposal",
                            "source_references": [{"kind": "ASSERTION", "id": str(uuid.uuid4())}],
                            "idempotency_key": "read-only-proposal",
                            "assertion_id": str(uuid.uuid4()),
                            "correction": {"value": "ignored"},
                        },
                    )
                    assert rejected.isError
                    rejected_content = rejected.content[0]
                    assert isinstance(rejected_content, TextContent)
                    assert "read_only_mode" in rejected_content.text

        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        ) as unsupported_client:
            unsupported = await unsupported_client.post(
                mcp_url,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": "2099-01-01",
                },
                json={"jsonrpc": "2.0", "id": 44, "method": "ping"},
            )
        assert unsupported.status_code == 400
        assert "Unsupported protocol version" in unsupported.text

    asyncio.run(acceptance())

    revoked = httpx.delete(
        f"{api_url}/api/v1/tokens/{credential['token_id']}",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Correlation-ID": str(uuid.uuid4()),
        },
        timeout=10,
    )
    assert revoked.status_code == 200, revoked.text
    with pytest.raises(Exception) as revoked_error:
        asyncio.run(_session(mcp_url, token))
    revoked_message = _exception_messages(revoked_error.value)
    assert "401" in revoked_message or "Unauthorized" in revoked_message


@pytest.mark.smoke
def test_unavailable_mcp_has_actionable_client_failure() -> None:
    async def unavailable() -> None:
        with pytest.raises(Exception) as error:
            await _session("http://127.0.0.1:9/mcp", "synthetic-unavailable-token")
        rendered = _exception_messages(error.value).lower()
        assert "connect" in rendered or "unavailable" in rendered

    asyncio.run(unavailable())
