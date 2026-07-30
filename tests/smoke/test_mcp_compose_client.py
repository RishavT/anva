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
