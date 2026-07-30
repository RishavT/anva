"""Secret-safe client compatibility diagnostics for Anva skills."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from anva.skills.contracts import default_package_root, load_distribution


def _diagnostics_url(mcp_url: str) -> str:
    parsed = urlsplit(mcp_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("MCP URL must be an absolute HTTP(S) URL")
    path = parsed.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[: -len("/mcp")]
    return urlunsplit((parsed.scheme, parsed.netloc, f"{path}/diagnostics", "", ""))


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
            payload = json.loads(response.read())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
        return {
            **base,
            "status": "unavailable",
            "limitations": [
                "Anva diagnostics are unavailable; no organizational alignment is verified."
            ],
        }
    if not isinstance(payload, dict):
        return {
            **base,
            "status": "unsupported",
            "limitations": ["Anva diagnostics did not return a structured object."],
        }
    supported = payload.get("supported_contract_versions")
    contract = payload.get("contract_version")
    protocol = payload.get("supported_protocol_versions")
    read_only = payload.get("read_only")
    limitations: list[str] = []
    compatible = (
        isinstance(supported, list)
        and any(version in distribution.mcp_contract_versions for version in supported)
        and isinstance(contract, str)
        and contract in distribution.mcp_contract_versions
        and isinstance(protocol, list)
        and bool(protocol)
        and isinstance(read_only, bool)
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
    return {
        **base,
        "status": "compatible" if compatible else "unsupported",
        "mcp_contract_version": contract,
        "supported_mcp_contract_versions": supported,
        "supported_protocol_versions": protocol,
        "read_only": read_only,
        "authentication": payload.get("authentication"),
        "limitations": limitations,
    }
