"""Supported HTTP API and Streamable HTTP MCP clients for product acceptance."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

MAX_RESPONSE_BYTES = 2_000_000


class AcceptanceBoundaryError(RuntimeError):
    """A public product boundary failed without retaining response or credential bytes."""

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _validated_url(value: str, *, expected_suffix: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Acceptance endpoint must be an HTTP(S) URL without credentials")
    normalized = value.rstrip("/")
    if not normalized.endswith(expected_suffix):
        raise ValueError(f"Acceptance endpoint must end with {expected_suffix}")
    return normalized


def _decoded_object(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AcceptanceBoundaryError("response_too_large", "Anva response exceeded its bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceBoundaryError(
            "invalid_response", "Anva returned an invalid response"
        ) from error
    if not isinstance(value, dict):
        raise AcceptanceBoundaryError("invalid_response", "Anva returned an invalid response")
    return cast(dict[str, object], value)


@dataclass(frozen=True, slots=True)
class APIResponse:
    status: int
    payload: dict[str, object]


class PublicAPI:
    """Small JSON/octet-stream client for the documented `/api/v1` contract."""

    def __init__(self, base_url: str, token: str | None = None, *, timeout: float = 30) -> None:
        self.base_url = _validated_url(base_url, expected_suffix="/api/v1")
        self._token = token
        self.timeout = timeout

    def with_token(self, token: str) -> PublicAPI:
        if not token:
            raise ValueError("Acceptance token is required")
        return PublicAPI(self.base_url, token, timeout=self.timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, object] | None = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        expected: frozenset[int] = frozenset({200}),
    ) -> APIResponse:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("Acceptance API path is invalid")
        if payload is not None and content is not None:
            raise ValueError("Acceptance request cannot mix JSON and bytes")
        request_headers = {
            "Accept": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        }
        body: bytes | None = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            request_headers["Content-Type"] = "application/json"
        elif content is not None:
            body = content
            request_headers["Content-Type"] = "application/octet-stream"
        if self._token is not None:
            request_headers["Authorization"] = f"Bearer {self._token}"
        if headers:
            request_headers.update(headers)
        request = Request(  # noqa: S310 - operator-selected, validated Anva endpoint
            f"{self.base_url}{path}",
            data=body,
            method=method,
            headers=request_headers,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                status = response.status
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            status = error.code
            raw = error.read(MAX_RESPONSE_BYTES + 1)
        except (URLError, TimeoutError) as error:
            raise AcceptanceBoundaryError("api_unavailable", "Anva API is unavailable") from error
        response_payload = _decoded_object(raw)
        if status not in expected:
            raw_code = response_payload.get("code")
            code = raw_code if isinstance(raw_code, str) else "api_rejected"
            raise AcceptanceBoundaryError(code, "Anva API rejected the operation", status=status)
        return APIResponse(status=status, payload=response_payload)


class MCPBoundary(Protocol):
    """The only runner-facing MCP operation, injectable for contract tests."""

    def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]: ...


class StreamableHTTPMCP:
    """Real official-client MCP boundary; no HTTP parity shortcut is used."""

    def __init__(self, url: str, token: str, *, timeout: float = 30) -> None:
        self.url = _validated_url(url, expected_suffix="/mcp")
        if not token:
            raise ValueError("MCP token is required")
        self.token = token
        self.timeout = timeout

    async def _call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
        try:
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=self.timeout,
            ) as http_client:
                async with streamable_http_client(self.url, http_client=http_client) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()
                        result = await session.call_tool(tool_name, arguments=dict(arguments))
        except Exception as error:
            raise AcceptanceBoundaryError("mcp_unavailable", "Anva MCP operation failed") from error
        if result.isError or not isinstance(result.structuredContent, dict):
            raise AcceptanceBoundaryError("mcp_rejected", "Anva MCP rejected the operation")
        return cast(dict[str, object], result.structuredContent)

    def call(self, tool_name: str, arguments: Mapping[str, object]) -> dict[str, object]:
        return asyncio.run(self._call(tool_name, arguments))
