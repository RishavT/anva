"""Administrative CLI for local operators."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from collections.abc import Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from anva import __version__
from anva.entrypoints.bootstrap import configure_django


def build_parser() -> argparse.ArgumentParser:
    """Build the stable CLI contract."""
    parser = argparse.ArgumentParser(prog="anva", description="Operate an Anva installation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Check required service dependencies")
    subparsers.add_parser("version", help="Print the installed Anva version")
    source = subparsers.add_parser("source", help="Operate source connections through the API")
    source.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    source_commands = source.add_subparsers(dest="source_command", required=True)
    connect = source_commands.add_parser("connect", help="Connect a read-only filesystem source")
    connect.add_argument("--repository-id", required=True, type=uuid.UUID)
    connect.add_argument("--access-scope-id", required=True, type=uuid.UUID)
    connect.add_argument("--external-key", required=True)
    connect.add_argument("--display-name", required=True)
    connect.add_argument("--root", required=True)
    for command in ("sync", "resync", "inspect"):
        action = source_commands.add_parser(command)
        action.add_argument("source_connection_id", type=uuid.UUID)
    revoke = source_commands.add_parser("revoke")
    revoke.add_argument("source_connection_id", type=uuid.UUID)
    revoke.add_argument("--expected-revision", required=True, type=int)
    return parser


def _source_request(arguments: argparse.Namespace) -> int:
    token = os.getenv("ANVA_TOKEN", "")
    if not token:
        print(json.dumps({"code": "missing_token", "message": "ANVA_TOKEN is required"}))
        return 2
    command = str(arguments.source_command)
    method = "POST"
    payload: dict[str, object] = {}
    if command == "connect":
        path = "/source-connections/filesystem"
        payload = {
            "repository_id": str(arguments.repository_id),
            "access_scope_id": str(arguments.access_scope_id),
            "external_key": arguments.external_key,
            "display_name": arguments.display_name,
            "root": arguments.root,
        }
    else:
        source_id = str(arguments.source_connection_id)
        path = f"/source-connections/{source_id}"
        if command == "inspect":
            method = "GET"
        elif command in {"sync", "resync"}:
            path = f"{path}/{command}"
        elif command == "revoke":
            path = f"{path}/revoke"
            payload = {"expected_revision": arguments.expected_revision}
        else:
            raise ValueError("Unknown source command")
    body = None if method == "GET" else json.dumps(payload).encode()
    request = Request(  # noqa: S310 - operator-selected Anva API endpoint
        f"{str(arguments.api_url).rstrip('/')}{path}",
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Correlation-ID": str(uuid.uuid4()),
        },
    )
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            result = json.loads(response.read())
    except HTTPError as error:
        result = json.loads(error.read() or b"{}")
        print(json.dumps(result, sort_keys=True))
        return 1
    except (URLError, TimeoutError):
        print(json.dumps({"code": "api_unavailable", "message": "Anva API is unavailable"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one CLI command and return a process exit code."""
    arguments = build_parser().parse_args(argv)
    if arguments.command == "version":
        print(__version__)
        return 0
    if arguments.command == "source":
        return _source_request(arguments)

    configure_django()
    from anva.foundation.services import readiness_status

    status = readiness_status()
    print(json.dumps(status.as_dict(), sort_keys=True))
    return 0 if status.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
