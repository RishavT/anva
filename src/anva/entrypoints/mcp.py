"""Dedicated MCP process boundary.

The protocol surface deliberately remains unavailable in this foundation issue.
Only health endpoints are exposed, so later MCP work cannot be mistaken for a
production-ready tool contract.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from anva.entrypoints.bootstrap import configure_django

configure_django()

StartResponse = Any


def json_response(
    start_response: StartResponse,
    status: str,
    payload: dict[str, object],
) -> list[bytes]:
    """Build a small standards-compliant WSGI JSON response."""
    body = json.dumps(payload, sort_keys=True).encode()
    start_response(
        status,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def application(environ: dict[str, object], start_response: StartResponse) -> Iterable[bytes]:
    """Serve liveness/readiness and an explicit not-implemented MCP response."""
    from anva import __version__
    from anva.foundation.services import readiness_status

    method = str(environ.get("REQUEST_METHOD", "GET"))
    path = str(environ.get("PATH_INFO", "/"))
    if method != "GET":
        return json_response(
            start_response, "405 Method Not Allowed", {"error": "method_not_allowed"}
        )
    if path == "/health/live":
        return json_response(
            start_response,
            "200 OK",
            {"status": "alive", "service": "mcp", "version": __version__},
        )
    if path == "/health/ready":
        status = readiness_status()
        return json_response(
            start_response,
            "200 OK" if status.healthy else "503 Service Unavailable",
            status.as_dict(),
        )
    if path == "/mcp":
        return json_response(
            start_response,
            "501 Not Implemented",
            {
                "error": "mcp_not_implemented",
                "detail": "The MCP protocol is outside foundation issue #1.",
            },
        )
    return json_response(start_response, "404 Not Found", {"error": "not_found"})


def main() -> int:
    """Reject direct execution in favor of the production WSGI server."""
    print("Start this entrypoint with gunicorn anva.entrypoints.mcp:application")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
