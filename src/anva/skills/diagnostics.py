"""Secret-safe client compatibility diagnostics for Anva skills."""

from __future__ import annotations

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from anva.skills.contracts import default_package_root, load_distribution

_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_DEPTH = 8
_MAX_NODES = 512
_MAX_COLLECTION_ITEMS = 128
_MAX_STRING_LENGTH = 4096
_TOP_LEVEL_FIELDS = {
    "status",
    "service",
    "transport",
    "endpoint",
    "contract_version",
    "supported_contract_versions",
    "supported_protocol_versions",
    "read_only",
    "authentication",
    "limits",
}
_AUTH_FIELDS = {"type", "scope", "rotation", "revocation"}
_LIMIT_FIELDS = {
    "page_size",
    "input_bytes",
    "output_bytes",
    "source_excerpt_characters",
}


class _UnsupportedDiagnosticsError(ValueError):
    """A response was received but does not satisfy the public diagnostics contract."""


def _diagnostics_url(mcp_url: str) -> str:
    parsed = urlsplit(mcp_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("MCP URL must be an absolute HTTP(S) URL")
    path = parsed.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[: -len("/mcp")]
    return urlunsplit((parsed.scheme, parsed.netloc, f"{path}/diagnostics", "", ""))


def _bounded_structure(value: object, *, depth: int = 0, nodes: list[int]) -> None:
    if depth > _MAX_DEPTH:
        raise _UnsupportedDiagnosticsError("Diagnostics nesting is too deep")
    nodes[0] += 1
    if nodes[0] > _MAX_NODES:
        raise _UnsupportedDiagnosticsError("Diagnostics response has too many values")
    if isinstance(value, str):
        if len(value) > _MAX_STRING_LENGTH:
            raise _UnsupportedDiagnosticsError("Diagnostics string is too long")
    elif isinstance(value, list):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise _UnsupportedDiagnosticsError("Diagnostics array has too many items")
        for item in value:
            _bounded_structure(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, dict):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise _UnsupportedDiagnosticsError("Diagnostics object has too many fields")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise _UnsupportedDiagnosticsError("Diagnostics field name is invalid")
            _bounded_structure(item, depth=depth + 1, nodes=nodes)
    elif value is not None and not isinstance(value, bool | int | float):
        raise _UnsupportedDiagnosticsError("Diagnostics contains an unsupported value")


def _bounded_strings(value: object, *, name: str, pattern: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in value)
    ):
        raise _UnsupportedDiagnosticsError(f"{name} is invalid")
    if len(value) != len(set(value)):
        raise _UnsupportedDiagnosticsError(f"{name} contains duplicates")
    if any(re.fullmatch(pattern, item) is None for item in value):
        raise _UnsupportedDiagnosticsError(f"{name} contains an unsupported value")
    return value


def _positive_int(value: object, *, name: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > maximum:
        raise _UnsupportedDiagnosticsError(f"{name} is invalid")
    return value


def _validate_payload(payload: object) -> dict[str, object]:
    _bounded_structure(payload, nodes=[0])
    if not isinstance(payload, dict) or set(payload) != _TOP_LEVEL_FIELDS:
        raise _UnsupportedDiagnosticsError("Diagnostics fields do not match the stable contract")
    if payload["status"] != "available":
        raise _UnsupportedDiagnosticsError("Diagnostics service is not available")
    if payload["service"] != "anva-mcp":
        raise _UnsupportedDiagnosticsError("Diagnostics service identifier is unsupported")
    if payload["transport"] != "streamable-http":
        raise _UnsupportedDiagnosticsError("Diagnostics transport is unsupported")
    endpoint = payload["endpoint"]
    if not isinstance(endpoint, str) or len(endpoint) > 2048:
        raise _UnsupportedDiagnosticsError("Diagnostics endpoint is invalid")
    parsed_endpoint = urlsplit(endpoint)
    if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.netloc:
        raise _UnsupportedDiagnosticsError("Diagnostics endpoint is invalid")
    contract = payload["contract_version"]
    if not isinstance(contract, str) or not contract or len(contract) > 64:
        raise _UnsupportedDiagnosticsError("Diagnostics contract version is invalid")
    _bounded_strings(
        payload["supported_contract_versions"],
        name="supported contract versions",
        pattern=r"[0-9]{1,8}",
    )
    _bounded_strings(
        payload["supported_protocol_versions"],
        name="supported protocol versions",
        pattern=r"[0-9]{4}-[0-9]{2}-[0-9]{2}",
    )
    if not isinstance(payload["read_only"], bool):
        raise _UnsupportedDiagnosticsError("Diagnostics read-only flag is invalid")
    authentication = payload["authentication"]
    if not isinstance(authentication, dict) or set(authentication) != _AUTH_FIELDS:
        raise _UnsupportedDiagnosticsError("Diagnostics authentication summary is invalid")
    if authentication["type"] != "bearer":
        raise _UnsupportedDiagnosticsError("Diagnostics authentication type is unsupported")
    scope = authentication["scope"]
    if scope != "organization-and-exact-repository":
        raise _UnsupportedDiagnosticsError("Diagnostics authentication scope is invalid")
    if not isinstance(authentication["rotation"], bool) or not isinstance(
        authentication["revocation"], bool
    ):
        raise _UnsupportedDiagnosticsError("Diagnostics authentication flags are invalid")
    if authentication["rotation"] is not True or authentication["revocation"] is not True:
        raise _UnsupportedDiagnosticsError("Diagnostics authentication flags are unsupported")
    limits = payload["limits"]
    if not isinstance(limits, dict) or set(limits) != _LIMIT_FIELDS:
        raise _UnsupportedDiagnosticsError("Diagnostics limits are invalid")
    _positive_int(limits["page_size"], name="page size", maximum=10_000)
    _positive_int(limits["input_bytes"], name="input bytes", maximum=16 * 1024 * 1024)
    _positive_int(limits["output_bytes"], name="output bytes", maximum=16 * 1024 * 1024)
    _positive_int(
        limits["source_excerpt_characters"],
        name="source excerpt characters",
        maximum=1_000_000,
    )
    return payload


def _unsupported(base: dict[str, object], limitation: str) -> dict[str, object]:
    return {**base, "status": "unsupported", "limitations": [limitation]}


def diagnose_skills(
    *,
    mcp_url: str,
    host: str,
    host_version: str,
    token_env: str,
    expected_read_only: bool | None = None,
) -> dict[str, object]:
    """Check the real unauthenticated diagnostics route and local compatibility."""
    distribution = load_distribution(default_package_root())
    token_present = bool(os.getenv(token_env))
    base: dict[str, object] = {
        "skill_version": distribution.skill_version,
        "host": host,
        "host_version": host_version,
        "tested_host_version": distribution.tested_hosts.get(host),
        "token": {"environment": token_env, "present": token_present},
        "limitations": [],
    }
    request = Request(  # noqa: S310 - user-selected Anva endpoint
        _diagnostics_url(mcp_url),
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310
            content_type = str(response.headers.get("Content-Type", ""))
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                raise _UnsupportedDiagnosticsError("Diagnostics content type is unsupported")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except (TypeError, ValueError):
                    raise _UnsupportedDiagnosticsError(
                        "Diagnostics content length is invalid"
                    ) from None
                if declared_length < 0 or declared_length > _MAX_RESPONSE_BYTES:
                    raise _UnsupportedDiagnosticsError("Diagnostics response is too large")
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise _UnsupportedDiagnosticsError("Diagnostics response is too large")
            try:
                decoded = body.decode("utf-8")
                payload = _validate_payload(json.loads(decoded))
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise _UnsupportedDiagnosticsError("Diagnostics JSON is invalid") from None
    except _UnsupportedDiagnosticsError as error:
        return _unsupported(base, str(error))
    except (HTTPError, URLError, TimeoutError, OSError):
        return {
            **base,
            "status": "unavailable",
            "limitations": [
                "Anva diagnostics are unavailable; no organizational alignment is verified."
            ],
        }

    supported = payload["supported_contract_versions"]
    contract = payload["contract_version"]
    protocol = payload["supported_protocol_versions"]
    read_only = payload["read_only"]
    assert isinstance(supported, list)
    assert isinstance(contract, str)
    assert isinstance(protocol, list)
    assert isinstance(read_only, bool)
    limitations: list[str] = []
    compatible = (
        any(version in distribution.mcp_contract_versions for version in supported)
        and contract in distribution.mcp_contract_versions
    )
    if not compatible:
        limitations.append(
            "The server MCP contract or protocol is unsupported; no fallback was attempted."
        )
    tested = distribution.tested_hosts.get(host)
    if tested is None or host_version != tested:
        limitations.append("Host version is UNVERIFIED against this skill release.")
    if expected_read_only is not None and read_only is not expected_read_only:
        compatible = False
        limitations.append("Server read-only mode does not match the expected deployment mode.")
    authentication = payload["authentication"]
    assert isinstance(authentication, dict)
    return {
        **base,
        "status": "compatible" if compatible else "unsupported",
        "mcp_contract_version": contract,
        "supported_mcp_contract_versions": supported,
        "supported_protocol_versions": protocol,
        "read_only": read_only,
        "authentication": {
            "type": authentication["type"],
            "scope": authentication["scope"],
            "rotation": authentication["rotation"],
            "revocation": authentication["revocation"],
        },
        "limitations": limitations,
    }
