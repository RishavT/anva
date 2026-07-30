"""Administrative CLI for local operators."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from collections.abc import Sequence
from pathlib import Path
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
    search = subparsers.add_parser("search", help="Run permission-safe hybrid search")
    search.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    search.add_argument("--repository-id", required=True, type=uuid.UUID)
    search.add_argument("--query", required=True)
    search.add_argument(
        "--phase",
        choices=("PREPARE", "BUILD", "PREFLIGHT", "ASSURANCE"),
    )
    search.add_argument("--limit", type=int, default=20)
    context = subparsers.add_parser("context", help="Build an immutable context packet")
    context.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    context.add_argument("--repository-id", required=True, type=uuid.UUID)
    context.add_argument("--task", required=True)
    context.add_argument(
        "--phase",
        required=True,
        choices=("PREPARE", "BUILD", "PREFLIGHT", "ASSURANCE"),
    )
    packet = subparsers.add_parser("packet", help="Retrieve an exact context packet")
    packet.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    packet.add_argument("--repository-id", required=True, type=uuid.UUID)
    packet.add_argument("packet_id", type=uuid.UUID)
    work = subparsers.add_parser("work", help="Create or import versioned work intent")
    work.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    work_commands = work.add_subparsers(dest="work_command", required=True)
    for command in ("create", "import"):
        work_action = work_commands.add_parser(command)
        work_action.add_argument("--repository-id", required=True, type=uuid.UUID)
        work_action.add_argument("--file", required=True, type=Path)
    policy = subparsers.add_parser("policy", help="Import or simulate deterministic policy")
    policy.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_import = policy_commands.add_parser("import")
    policy_import.add_argument("--repository-id", required=True, type=uuid.UUID)
    policy_import.add_argument("--file", required=True, type=Path)
    policy_simulate = policy_commands.add_parser("simulate")
    policy_simulate.add_argument("--repository-id", required=True, type=uuid.UUID)
    policy_simulate.add_argument("--inputs", required=True, type=Path)
    evidence = subparsers.add_parser("evidence", help="Submit a nonexecuting evidence manifest")
    evidence.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_submit = evidence_commands.add_parser("submit")
    evidence_submit.add_argument("--repository-id", required=True, type=uuid.UUID)
    evidence_submit.add_argument("--pull-request-number", required=True, type=int)
    evidence_submit.add_argument("--manifest", required=True, type=Path)
    assurance = subparsers.add_parser(
        "assurance",
        help="Ingest and inspect independent manual-diff assurance",
    )
    assurance.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    assurance_commands = assurance.add_subparsers(dest="assurance_command", required=True)
    assurance_ingest = assurance_commands.add_parser("ingest")
    assurance_ingest.add_argument("--repository-id", required=True, type=uuid.UUID)
    assurance_ingest.add_argument("--pull-request-number", required=True, type=int)
    assurance_ingest.add_argument("--metadata", required=True, type=Path)
    assurance_ingest.add_argument("--diff", required=True, type=Path)
    assurance_start = assurance_commands.add_parser("start")
    assurance_start.add_argument("--pull-request-revision-id", required=True, type=uuid.UUID)
    assurance_start.add_argument("--inputs", required=True, type=Path)
    for command in ("status", "report"):
        assurance_read = assurance_commands.add_parser(command)
        assurance_read.add_argument("assurance_run_id", type=uuid.UUID)
    evaluator = subparsers.add_parser(
        "evaluator",
        help="Claim or submit a context-limited manual evaluator task",
    )
    evaluator.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    evaluator_commands = evaluator.add_subparsers(dest="evaluator_command", required=True)
    evaluator_claim = evaluator_commands.add_parser("claim")
    evaluator_claim.add_argument("--repository-id", required=True, type=uuid.UUID)
    evaluator_claim.add_argument("--claimant", required=True)
    evaluator_claim.add_argument("--lease-seconds", type=int, default=900)
    evaluator_submit = evaluator_commands.add_parser("submit")
    evaluator_submit.add_argument("task_id", type=uuid.UUID)
    evaluator_submit.add_argument("--claimant", required=True)
    evaluator_submit.add_argument("--result", required=True, type=Path)
    github = subparsers.add_parser("github", help="Configure or diagnose a GitHub App binding")
    github.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    github_commands = github.add_subparsers(dest="github_command", required=True)
    github_configure = github_commands.add_parser("configure")
    github_configure.add_argument("--repository-id", required=True, type=uuid.UUID)
    github_configure.add_argument("--config", required=True, type=Path)
    github_status = github_commands.add_parser("status")
    github_status.add_argument("--repository-id", required=True, type=uuid.UUID)
    github_revoke = github_commands.add_parser("revoke")
    github_revoke.add_argument("--repository-id", required=True, type=uuid.UUID)
    mcp = subparsers.add_parser("mcp", help="Diagnose the remote MCP gateway")
    mcp.add_argument(
        "--mcp-url",
        default=os.getenv("ANVA_MCP_URL", "http://localhost:8001"),
    )
    mcp_commands = mcp.add_subparsers(dest="mcp_command", required=True)
    mcp_commands.add_parser("diagnose")
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


def _retrieval_request(arguments: argparse.Namespace) -> int:
    token = os.getenv("ANVA_TOKEN", "")
    if not token:
        print(json.dumps({"code": "missing_token", "message": "ANVA_TOKEN is required"}))
        return 2
    method = "POST"
    if arguments.command == "search":
        path = "/search"
        payload: dict[str, object] = {
            "repository_id": str(arguments.repository_id),
            "query": arguments.query,
            "limit": arguments.limit,
        }
        if arguments.phase:
            payload["phase"] = arguments.phase
    elif arguments.command == "context":
        path = "/context-packets"
        payload = {
            "repository_id": str(arguments.repository_id),
            "task": arguments.task,
            "phase": arguments.phase,
        }
    elif arguments.command == "packet":
        method = "GET"
        path = f"/context-packets/{arguments.packet_id}?repository_id={arguments.repository_id}"
        payload = {}
    else:
        raise ValueError("Unknown retrieval command")
    request = Request(  # noqa: S310 - operator-selected Anva API endpoint
        f"{str(arguments.api_url).rstrip('/')}{path}",
        data=None if method == "GET" else json.dumps(payload).encode(),
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


def _bounded_json_file(path: Path) -> dict[str, object]:
    """Read only a small regular non-symlink JSON file supplied by the operator."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("Input must be a regular non-symlink file")
    raw = path.read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("Input file exceeds the 64 KiB limit")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Input JSON must be an object")
    return payload


def _bounded_diff_file(path: Path) -> str:
    """Read a bounded regular UTF-8 diff without following an operator symlink."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("Diff must be a regular non-symlink file")
    raw = path.read_bytes()
    if not raw or len(raw) > 1_000_000:
        raise ValueError("Diff file must contain between 1 byte and 1,000,000 bytes")
    return raw.decode("utf-8")


def _api_request(
    *,
    api_url: str,
    path: str,
    method: str,
    payload: dict[str, object] | None,
) -> int:
    token = os.getenv("ANVA_TOKEN", "")
    if not token:
        print(json.dumps({"code": "missing_token", "message": "ANVA_TOKEN is required"}))
        return 2
    request = Request(  # noqa: S310 - operator-selected Anva API endpoint
        f"{api_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
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


def _assurance_request(arguments: argparse.Namespace) -> int:
    command = str(arguments.assurance_command)
    if command == "ingest":
        payload = _bounded_json_file(arguments.metadata)
        payload["unified_diff"] = _bounded_diff_file(arguments.diff)
        path = (
            f"/repositories/{arguments.repository_id}/pull-requests/"
            f"{arguments.pull_request_number}/manual-diff"
        )
        method = "POST"
    elif command == "start":
        payload = _bounded_json_file(arguments.inputs)
        path = f"/pull-request-revisions/{arguments.pull_request_revision_id}/assurance-runs"
        method = "POST"
    elif command == "status":
        payload = None
        path = f"/assurance-runs/{arguments.assurance_run_id}"
        method = "GET"
    elif command == "report":
        payload = None
        path = f"/assurance-runs/{arguments.assurance_run_id}/report"
        method = "GET"
    else:
        raise ValueError("Unknown assurance command")
    return _api_request(
        api_url=str(arguments.api_url),
        path=path,
        method=method,
        payload=payload,
    )


def _evaluator_request(arguments: argparse.Namespace) -> int:
    command = str(arguments.evaluator_command)
    if command == "claim":
        path = f"/repositories/{arguments.repository_id}/evaluator-tasks/claim"
        payload: dict[str, object] = {
            "claimant": arguments.claimant,
            "lease_seconds": arguments.lease_seconds,
        }
    elif command == "submit":
        claim_token = os.getenv("ANVA_EVALUATOR_CLAIM_TOKEN", "")
        if not claim_token:
            print(
                json.dumps(
                    {
                        "code": "missing_claim_token",
                        "message": "ANVA_EVALUATOR_CLAIM_TOKEN is required",
                    }
                )
            )
            return 2
        path = f"/evaluator-tasks/{arguments.task_id}/submit"
        payload = {
            "claimant": arguments.claimant,
            "claim_token": claim_token,
            "result": _bounded_json_file(arguments.result),
        }
    else:
        raise ValueError("Unknown evaluator command")
    return _api_request(
        api_url=str(arguments.api_url),
        path=path,
        method="POST",
        payload=payload,
    )


def _governance_request(arguments: argparse.Namespace) -> int:
    token = os.getenv("ANVA_TOKEN", "")
    if not token:
        print(json.dumps({"code": "missing_token", "message": "ANVA_TOKEN is required"}))
        return 2
    repository_id = str(arguments.repository_id)
    if arguments.command == "work":
        payload = _bounded_json_file(arguments.file)
        path = "/work-items" if arguments.work_command == "create" else "/work-items/import"
    elif arguments.command == "policy":
        payload = _bounded_json_file(
            arguments.file if arguments.policy_command == "import" else arguments.inputs
        )
        if arguments.policy_command == "import":
            path = "/policies/import"
        else:
            path = "/policies/simulate"
            payload["repository_id"] = repository_id
    elif arguments.command == "evidence":
        payload = _bounded_json_file(arguments.manifest)
        path = (
            f"/repositories/{repository_id}/pull-requests/{arguments.pull_request_number}/evidence"
        )
    else:
        raise ValueError("Unknown governance command")
    payload_repository = payload.get("repository_id")
    if payload_repository is not None and payload_repository != repository_id:
        raise ValueError("Input repository_id does not match --repository-id")
    request = Request(  # noqa: S310 - operator-selected Anva API endpoint
        f"{str(arguments.api_url).rstrip('/')}{path}",
        data=json.dumps(payload).encode(),
        method="POST",
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


def _github_request(arguments: argparse.Namespace) -> int:
    command = str(arguments.github_command)
    base_path = f"/repositories/{arguments.repository_id}/github-binding"
    if command == "configure":
        method = "POST"
        path = base_path
        payload: dict[str, object] | None = _bounded_json_file(arguments.config)
    elif command == "status":
        method = "GET"
        path = base_path
        payload = None
    elif command == "revoke":
        method = "POST"
        path = f"{base_path}/revoke"
        payload = {}
    else:
        raise ValueError("Unknown GitHub command")
    return _api_request(
        api_url=str(arguments.api_url),
        path=path,
        method=method,
        payload=payload,
    )


def _mcp_diagnose(arguments: argparse.Namespace) -> int:
    request = Request(  # noqa: S310 - operator-selected Anva MCP endpoint
        f"{str(arguments.mcp_url).rstrip('/')}/diagnostics",
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310
            result = json.loads(response.read())
    except HTTPError as error:
        result = json.loads(error.read() or b"{}")
        print(json.dumps(result, sort_keys=True))
        return 1
    except (URLError, TimeoutError):
        print(
            json.dumps(
                {
                    "code": "mcp_unavailable",
                    "message": (
                        "Anva MCP is unavailable; verify the URL, network, and "
                        "docker compose mcp service"
                    ),
                }
            )
        )
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
    if arguments.command in {"search", "context", "packet"}:
        return _retrieval_request(arguments)
    if arguments.command in {"work", "policy", "evidence"}:
        try:
            return _governance_request(arguments)
        except (json.JSONDecodeError, OSError, ValueError):
            print(json.dumps({"code": "invalid_input", "message": "Input file is invalid"}))
            return 2
    if arguments.command in {"assurance", "evaluator"}:
        try:
            if arguments.command == "assurance":
                return _assurance_request(arguments)
            return _evaluator_request(arguments)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
            print(json.dumps({"code": "invalid_input", "message": "Input file is invalid"}))
            return 2
    if arguments.command == "github":
        try:
            return _github_request(arguments)
        except (json.JSONDecodeError, OSError, ValueError):
            print(json.dumps({"code": "invalid_input", "message": "Input file is invalid"}))
            return 2
    if arguments.command == "mcp":
        return _mcp_diagnose(arguments)

    configure_django()
    from anva.foundation.services import readiness_status

    status = readiness_status()
    print(json.dumps(status.as_dict(), sort_keys=True))
    return 0 if status.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
