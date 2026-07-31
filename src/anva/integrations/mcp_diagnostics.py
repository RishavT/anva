"""Bounded, allowlisted live MCP diagnostics integration for the product UI."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings

from anva.mcp.contracts import CONTRACT_VERSION, MCP_PROTOCOL_VERSIONS
from anva.skills.diagnostics import validate_diagnostics_payload

MAX_RESPONSE_BYTES = 64 * 1024
DIAGNOSTIC_TIMEOUT_SECONDS = 2.0


class _DnsUnavailableError(OSError):
    """The configured, allowlisted service name did not resolve."""


class _InvalidResponseError(ValueError):
    """The service responded outside the bounded diagnostics contract."""


def _diagnostics_url(mcp_url: str) -> str:
    parsed = urlsplit(mcp_url)
    path = parsed.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[: -len("/mcp")]
    return urlunsplit((parsed.scheme, parsed.netloc, f"{path}/diagnostics", "", ""))


def _base_payload(*, status: str, code: str) -> dict[str, object]:
    return {
        "status": status,
        "status_code": code,
        "service": "anva-mcp",
        "transport": "streamable-http",
        "endpoint": _diagnostics_url(settings.ANVA_MCP_URL),
        "contract_version": "unverified",
        "supported_protocol_versions": [],
        "read_only": False,
        "authentication": {
            "type": "unverified",
            "scope": "unverified",
            "rotation": False,
            "revocation": False,
        },
        "limits": {"page_size": "unverified"},
        "compatible": False,
    }


def _read_configured_diagnostics() -> dict[str, object]:
    parsed = urlsplit(settings.ANVA_MCP_URL)
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or hostname not in settings.ANVA_MCP_ALLOWED_HOSTS
    ):
        raise _InvalidResponseError("Configured MCP URL is outside the allowlist")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise _InvalidResponseError("Configured MCP port is invalid") from error
    try:
        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise _DnsUnavailableError from error
    if not addresses:
        raise _DnsUnavailableError

    family, socket_type, protocol, _canonical_name, socket_address = addresses[0]
    connection_socket = socket.socket(family, socket_type, protocol)
    connection_socket.settimeout(DIAGNOSTIC_TIMEOUT_SECONDS)
    connection: http.client.HTTPConnection | None = None
    try:
        connection_socket.connect(socket_address)
        if parsed.scheme == "https":
            connection_socket = ssl.create_default_context().wrap_socket(
                connection_socket,
                server_hostname=hostname,
            )
        connection = http.client.HTTPConnection(
            hostname,
            port,
            timeout=DIAGNOSTIC_TIMEOUT_SECONDS,
        )
        connection.sock = connection_socket
        default_port = 443 if parsed.scheme == "https" else 80
        host_header = hostname if port == default_port else f"{hostname}:{port}"
        diagnostics_path = urlsplit(_diagnostics_url(settings.ANVA_MCP_URL)).path
        connection.request(
            "GET",
            diagnostics_path,
            headers={"Accept": "application/json", "Host": host_header},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise _InvalidResponseError("Diagnostics status is unsupported")
        content_type = response.getheader("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise _InvalidResponseError("Diagnostics content type is unsupported")
        declared_length = response.getheader("Content-Length")
        if declared_length is not None:
            try:
                parsed_length = int(declared_length)
            except ValueError:
                raise _InvalidResponseError("Diagnostics content length is invalid") from None
            if parsed_length < 0 or parsed_length > MAX_RESPONSE_BYTES:
                raise _InvalidResponseError("Diagnostics response is too large")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise _InvalidResponseError("Diagnostics response is too large")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _InvalidResponseError("Diagnostics JSON is invalid") from None
        try:
            return validate_diagnostics_payload(payload)
        except ValueError:
            raise _InvalidResponseError("Diagnostics contract is invalid") from None
    finally:
        if connection is not None:
            connection.close()
        else:
            connection_socket.close()


def probe_mcp_diagnostics() -> dict[str, object]:
    """Probe only the configured allowlisted MCP service and return sanitized state."""
    try:
        payload = _read_configured_diagnostics()
    except _DnsUnavailableError:
        return _base_payload(status="DNS unavailable", code="dns_unavailable")
    except TimeoutError:
        return _base_payload(status="Timed out", code="timeout")
    except _InvalidResponseError:
        return _base_payload(status="Invalid response", code="invalid_response")
    except OSError:
        return _base_payload(status="Service unavailable", code="service_unavailable")

    contract = payload["contract_version"]
    contracts = payload["supported_contract_versions"]
    protocols = payload["supported_protocol_versions"]
    authentication = payload["authentication"]
    read_only = payload["read_only"]
    assert isinstance(contract, str)
    assert isinstance(contracts, list)
    assert isinstance(protocols, list)
    assert isinstance(authentication, dict)
    assert isinstance(read_only, bool)
    result = {
        **payload,
        "endpoint": settings.ANVA_MCP_URL,
        "compatible": False,
    }
    if (
        contract != CONTRACT_VERSION
        or CONTRACT_VERSION not in contracts
        or not set(protocols).intersection(MCP_PROTOCOL_VERSIONS)
    ):
        return {**result, "status": "Version mismatch", "status_code": "version_mismatch"}
    if authentication["revocation"] is not True:
        return {
            **result,
            "status": "Revocation unsupported",
            "status_code": "revocation_unsupported",
        }
    if read_only:
        return {**result, "status": "Read-only", "status_code": "read_only"}
    return {**result, "status": "Compatible", "status_code": "compatible", "compatible": True}
