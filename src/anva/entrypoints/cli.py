"""Administrative CLI for local operators."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from anva import __version__
from anva.entrypoints.bootstrap import configure_django

BACKUP_GENERATION_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9]+$")


def _maintenance_batch_limit(raw: str) -> int:
    try:
        limit = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("maintenance batch limit must be an integer") from error
    if not 1 <= limit <= 1_000:
        raise argparse.ArgumentTypeError("maintenance batch limit must be between 1 and 1000")
    return limit


def build_parser() -> argparse.ArgumentParser:
    """Build the stable CLI contract."""
    parser = argparse.ArgumentParser(prog="anva", description="Operate an Anva installation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Check required service dependencies")
    subparsers.add_parser("version", help="Print the installed Anva version")
    demo = subparsers.add_parser("demo", help="Idempotently create a safe local demo tenant")
    demo.add_argument("--organization-slug", default="anva-demo")
    demo.add_argument("--organization-name", default="Anva Demo")
    demo.add_argument("--admin-email", default="admin@anva.local")
    demo.add_argument("--admin-display-name", default="Anva Administrator")
    demo.add_argument("--repository-external-id", default="anva-demo-repository")
    demo.add_argument("--repository-name", default="Anva Demo Repository")
    backup = subparsers.add_parser("backup", help="Create or verify a backup manifest")
    backup.add_argument("--directory", required=True, type=Path)
    backup.add_argument("--generation")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    backup_commands.add_parser("manifest")
    backup_commands.add_parser("verify")
    backup_commands.add_parser("activate")
    backup_commands.add_parser("current")
    operations = subparsers.add_parser("operations", help="Run tenant lifecycle operations")
    operations.add_argument(
        "--api-url",
        default=os.getenv("ANVA_API_URL", "http://localhost:8000/api/v1"),
    )
    operations.add_argument("--organization-id", required=True, type=uuid.UUID)
    operations_commands = operations.add_subparsers(
        dest="operations_command",
        required=True,
    )
    retention = operations_commands.add_parser("retention")
    retention.add_argument("--dry-run", action="store_true")
    maintenance = subparsers.add_parser(
        "maintenance",
        help="Run installation-scoped system maintenance",
    )
    maintenance_commands = maintenance.add_subparsers(
        dest="maintenance_command",
        required=True,
    )
    purge_preauth = maintenance_commands.add_parser(
        "purge-preauth-rate-buckets",
        help="Delete one bounded batch of expired anonymous request counters",
    )
    purge_preauth.add_argument("--limit", type=_maintenance_batch_limit, default=1_000)
    acceptance = subparsers.add_parser(
        "acceptance",
        help="Canonicalize or verify an oracle-isolated public acceptance corpus",
    )
    acceptance_commands = acceptance.add_subparsers(
        dest="acceptance_command",
        required=True,
    )
    acceptance_canonicalize = acceptance_commands.add_parser("canonicalize")
    acceptance_canonicalize.add_argument("--raw-root", required=True, type=Path)
    acceptance_canonicalize.add_argument("--canonical-root", required=True, type=Path)
    acceptance_canonicalize.add_argument("--manifest-sha256", required=True)
    acceptance_canonicalize.add_argument("--max-files", type=int, default=10_000)
    acceptance_canonicalize.add_argument("--max-total-bytes", type=int, default=1_073_741_824)
    acceptance_canonicalize.add_argument("--max-file-bytes", type=int, default=268_435_456)
    acceptance_canonicalize.add_argument("--max-depth", type=int, default=32)
    acceptance_verify = acceptance_commands.add_parser("verify")
    acceptance_verify.add_argument("--canonical-root", required=True, type=Path)
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
    skills = subparsers.add_parser(
        "skills",
        help="Render, package, install, and diagnose portable Anva skills",
    )
    skills.add_argument("--package-root", type=Path)
    skill_commands = skills.add_subparsers(dest="skills_command", required=True)
    skill_commands.add_parser("render")
    skill_commands.add_parser("check")
    package = skill_commands.add_parser("package")
    package.add_argument("--output", type=Path, required=True)
    verify = skill_commands.add_parser("verify")
    verify.add_argument("--output", type=Path, required=True)
    install = skill_commands.add_parser("install")
    install.add_argument("--host", choices=("codex", "claude"), required=True)
    install.add_argument("--scope", choices=("project", "user"), default="project")
    install.add_argument("--destination", type=Path, required=True)
    mcp_config = skill_commands.add_parser("mcp-config")
    mcp_config.add_argument("--host", choices=("codex", "claude"), required=True)
    mcp_config.add_argument("--destination", type=Path, required=True)
    mcp_config.add_argument("--token-env", default="ANVA_TOKEN")
    mcp_config.add_argument("--mcp-url")
    mcp_config.add_argument("--mcp-url-env", default="ANVA_MCP_URL")
    diagnose = skill_commands.add_parser("diagnose")
    diagnose.add_argument("--mcp-url", required=True)
    diagnose.add_argument("--host", choices=("codex", "claude"), required=True)
    diagnose.add_argument("--host-version", required=True)
    diagnose.add_argument("--token-env", default="ANVA_TOKEN")
    mode = diagnose.add_mutually_exclusive_group()
    mode.add_argument("--expect-read-only", action="store_true")
    mode.add_argument("--expect-write-capable", action="store_true")
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


def _operations_request(arguments: argparse.Namespace) -> int:
    organization_id = str(arguments.organization_id)
    if arguments.operations_command == "retention":
        path = f"/organizations/{organization_id}/retention-runs"
        payload: dict[str, object] = {"dry_run": bool(arguments.dry_run)}
    else:
        raise ValueError("Unknown operations command")
    return _api_request(
        api_url=str(arguments.api_url),
        path=path,
        method="POST",
        payload=payload,
    )


def _maintenance_request(arguments: argparse.Namespace) -> int:
    """Run local system maintenance without exposing tenant deletion counts."""
    if arguments.maintenance_command != "purge-preauth-rate-buckets":
        raise ValueError("Unknown maintenance command")
    from anva.core.services.operations import purge_expired_pre_auth_rate_buckets

    purge_expired_pre_auth_rate_buckets(limit=int(arguments.limit))
    print(
        json.dumps(
            {
                "operation": "purge_pre_auth_rate_buckets",
                "status": "completed",
            },
            sort_keys=True,
        )
    )
    return 0


def _bootstrap_demo(arguments: argparse.Namespace) -> int:
    """Create the local demo once and reveal its repository token only on creation."""
    from django.conf import settings

    from anva.core.models import Organization
    from anva.core.services.product_ui import SetupInput, bootstrap_product

    existing = Organization.objects.filter(slug=str(arguments.organization_slug)).first()
    if existing is not None:
        print(
            json.dumps(
                {
                    "status": "already_exists",
                    "organization_id": str(existing.id),
                    "organization_slug": existing.slug,
                },
                sort_keys=True,
            )
        )
        return 0
    if Organization.objects.exists():
        print(
            json.dumps(
                {
                    "code": "installation_already_bootstrapped",
                    "message": "A different organization already exists",
                },
                sort_keys=True,
            )
        )
        return 2
    result = bootstrap_product(
        supplied_secret=str(settings.BOOTSTRAP_SECRET),
        data=SetupInput(
            organization_slug=str(arguments.organization_slug),
            organization_name=str(arguments.organization_name),
            admin_email=str(arguments.admin_email),
            admin_display_name=str(arguments.admin_display_name),
            repository_external_id=str(arguments.repository_external_id),
            repository_name=str(arguments.repository_name),
            retention_days=365,
            model_processing="DISABLED",
            skill_distribution="SELF_SERVICE",
            assurance_mode="OBSERVE",
        ),
    )
    print(
        json.dumps(
            {
                "status": "created",
                "organization_id": str(result.organization.id),
                "repository_id": str(result.repository.id),
                "service_identity_id": str(result.service_identity.id),
                "token": result.issued_token.plaintext,
                "token_expires_at": result.issued_token.record.expires_at.isoformat(),
                "limitations": [
                    "Model processing is disabled",
                    "The token is printed once and must be stored securely",
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def _backup_files(directory: Path) -> tuple[Path, ...]:
    """Return a bounded, symlink-free backup inventory."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Backup directory must be a regular directory")
    files: list[Path] = []
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if (
            relative.as_posix() == "manifest.json"
            or relative.as_posix() == "current"
            or relative.parts[0] == "generations"
            or relative.name.endswith(".tmp")
            or relative.name == ".gitkeep"
        ):
            continue
        if path.is_symlink():
            raise ValueError("Backup directory must not contain symlinks")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise ValueError("Backup directory contains an unsupported entry")
        if len(files) > 10_000:
            raise ValueError("Backup exceeds the 10,000-file safety bound")
    return tuple(files)


def _file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _validate_backup_root(directory: Path) -> Path:
    if directory.is_symlink():
        raise ValueError("Backup directory must be a regular directory")
    root = directory.resolve()
    if not root.is_dir():
        raise ValueError("Backup directory must be a regular directory")
    return root


def _generation_directory(root: Path, generation: str) -> Path:
    if BACKUP_GENERATION_PATTERN.fullmatch(generation) is None:
        raise ValueError("Backup generation is invalid")
    generations = root / "generations"
    if generations.is_symlink():
        raise ValueError("Backup generations directory must not be a symlink")
    directory = generations / generation
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Backup generation is missing")
    return directory


def _current_backup_directory(root: Path) -> Path:
    current = root / "current"
    if not current.exists():
        return root
    generation = _read_current_backup_generation(root)
    return _generation_directory(root, generation)


def _read_current_backup_generation(root: Path) -> str:
    current = root / "current"
    if not current.exists():
        raise ValueError("Backup current pointer is missing")
    if current.is_symlink() or not current.is_file() or current.stat().st_size > 128:
        raise ValueError("Backup current pointer is invalid")
    try:
        generation = current.read_text(encoding="ascii").strip()
    except UnicodeError as error:
        raise ValueError("Backup current pointer is invalid") from error
    _generation_directory(root, generation)
    return generation


def _write_backup_manifest(directory: Path, files: tuple[Path, ...]) -> None:
    relative_names = {path.relative_to(directory).as_posix() for path in files}
    if "database.dump" not in relative_names:
        raise ValueError("Backup is missing database.dump")
    if "objects/.anva-installation-sentinel" not in relative_names:
        raise ValueError("Backup is missing the object-storage sentinel")
    payload: dict[str, object] = {
        "schema_version": 1,
        "anva_version": __version__,
        "created_at": datetime.now(UTC).isoformat(),
        "files": [
            {
                "path": path.relative_to(directory).as_posix(),
                "size": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
            for path in files
        ],
    }
    temporary_path = directory / f"manifest.{uuid.uuid4()}.tmp"
    with temporary_path.open("xb") as stream:
        stream.write((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())
    temporary_path.replace(directory / "manifest.json")


def _verify_backup_manifest(directory: Path, files: tuple[Path, ...]) -> None:
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Backup manifest is missing")
    if manifest_path.stat().st_size > 1_000_000:
        raise ValueError("Backup manifest exceeds the 1 MB safety bound")
    payload = json.loads(manifest_path.read_bytes())
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("Backup manifest is invalid")
    records = payload.get("files")
    if not isinstance(records, list) or len(records) != len(files):
        raise ValueError("Backup manifest inventory does not match")
    expected = {
        path.relative_to(directory).as_posix(): (path.stat().st_size, _file_sha256(path))
        for path in files
    }
    observed: dict[str, tuple[int, str]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Backup manifest is invalid")
        path_value = record.get("path")
        size = record.get("size")
        digest = record.get("sha256")
        if (
            not isinstance(path_value, str)
            or path_value.startswith("/")
            or ".." in Path(path_value).parts
            or not isinstance(size, int)
            or not isinstance(digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", digest) is None
            or path_value in observed
        ):
            raise ValueError("Backup manifest is invalid")
        observed[path_value] = (size, digest)
    if observed != expected:
        raise ValueError("Backup checksum verification failed")


def _backup_request(arguments: argparse.Namespace) -> int:
    """Write or verify a content-addressed backup manifest without reading secrets."""
    root = _validate_backup_root(arguments.directory)
    generation = arguments.generation
    if generation is not None and not isinstance(generation, str):
        raise ValueError("Backup generation is invalid")
    if arguments.backup_command == "current":
        if generation is not None:
            raise ValueError("Backup current lookup does not accept --generation")
        print(_read_current_backup_generation(root))
        return 0
    if arguments.backup_command == "activate":
        if generation is None:
            raise ValueError("Backup activation requires --generation")
        directory = _generation_directory(root, generation)
        files = _backup_files(directory)
        _verify_backup_manifest(directory, files)
        temporary_path = root / f"current.{uuid.uuid4()}.tmp"
        with temporary_path.open("x", encoding="ascii") as stream:
            stream.write(f"{generation}\n")
        temporary_path.replace(root / "current")
        print(json.dumps({"generation": generation, "status": "activated"}, sort_keys=True))
        return 0
    directory = (
        _generation_directory(root, generation)
        if generation is not None
        else _current_backup_directory(root)
    )
    files = _backup_files(directory)
    if arguments.backup_command == "manifest":
        _write_backup_manifest(directory, files)
        print(json.dumps({"status": "created", "files": len(files)}, sort_keys=True))
        return 0
    if arguments.backup_command != "verify":
        raise ValueError("Unknown backup command")
    _verify_backup_manifest(directory, files)
    print(json.dumps({"status": "verified", "files": len(files)}, sort_keys=True))
    return 0


def _skills_request(arguments: argparse.Namespace) -> int:
    from anva.skills.contracts import default_package_root
    from anva.skills.diagnostics import diagnose_skills
    from anva.skills.installer import configure_mcp, install_skills
    from anva.skills.packages import (
        build_distributions,
        check_distributions,
        verify_distributions,
    )
    from anva.skills.render import check_rendered, render_distribution

    package_root = arguments.package_root or default_package_root()
    command = str(arguments.skills_command)
    if command == "render":
        render_distribution(package_root)
        result: dict[str, object] = {
            "status": "rendered",
            "drift": check_rendered(package_root),
        }
    elif command == "check":
        drift = [
            *check_rendered(package_root),
            *check_distributions(package_root, package_root / "dist"),
        ]
        result = {"status": "verified" if not drift else "drifted", "drift": drift}
    elif command == "package":
        checksums = build_distributions(package_root, arguments.output)
        result = {"status": "packaged", "checksums": checksums}
    elif command == "verify":
        result = verify_distributions(arguments.output)
    elif command == "install":
        result = install_skills(
            package_root=package_root,
            destination=arguments.destination,
            host=str(arguments.host),
            scope=str(arguments.scope),
        )
    elif command == "mcp-config":
        result = configure_mcp(
            host=str(arguments.host),
            destination=arguments.destination,
            token_env=str(arguments.token_env),
            mcp_url=arguments.mcp_url,
            mcp_url_env=str(arguments.mcp_url_env),
        )
    elif command == "diagnose":
        expected_read_only = (
            True
            if arguments.expect_read_only
            else False
            if arguments.expect_write_capable
            else None
        )
        result = diagnose_skills(
            mcp_url=str(arguments.mcp_url),
            host=str(arguments.host),
            host_version=str(arguments.host_version),
            token_env=str(arguments.token_env),
            expected_read_only=expected_read_only,
        )
    else:
        raise ValueError("Unknown skills command")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] not in {"unavailable", "unsupported", "drifted"} else 1


def _acceptance_request(arguments: argparse.Namespace) -> int:
    from anva.acceptance.corpus import (
        AcceptanceCorpusError,
        AdapterLimits,
        canonicalize_corpus,
        verify_canonical_corpus,
    )

    try:
        if arguments.acceptance_command == "canonicalize":
            result = canonicalize_corpus(
                raw_root=arguments.raw_root,
                canonical_root=arguments.canonical_root,
                manifest_sha256=str(arguments.manifest_sha256),
                operator_limits=AdapterLimits(
                    max_files=int(arguments.max_files),
                    max_total_bytes=int(arguments.max_total_bytes),
                    max_file_bytes=int(arguments.max_file_bytes),
                    max_depth=int(arguments.max_depth),
                ),
            )
            payload = result.as_dict()
            payload["status"] = "canonicalized"
        elif arguments.acceptance_command == "verify":
            payload = verify_canonical_corpus(arguments.canonical_root).as_dict()
        else:
            raise ValueError("Unknown acceptance command")
    except AcceptanceCorpusError as error:
        print(json.dumps({"code": error.code, "message": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(payload, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Execute one CLI command and return a process exit code."""
    arguments = build_parser().parse_args(argv)
    if arguments.command == "version":
        print(__version__)
        return 0
    if arguments.command == "acceptance":
        return _acceptance_request(arguments)
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
    if arguments.command == "operations":
        return _operations_request(arguments)
    if arguments.command == "maintenance":
        configure_django()
        return _maintenance_request(arguments)
    if arguments.command == "backup":
        try:
            return _backup_request(arguments)
        except (json.JSONDecodeError, OSError, ValueError) as error:
            print(
                json.dumps(
                    {"code": "backup_invalid", "message": str(error)},
                    sort_keys=True,
                )
            )
            return 2
    if arguments.command == "skills":
        try:
            return _skills_request(arguments)
        except (json.JSONDecodeError, OSError, ValueError) as error:
            print(
                json.dumps(
                    {
                        "code": "skill_operation_rejected",
                        "message": str(error),
                    },
                    sort_keys=True,
                )
            )
            return 2

    configure_django()
    if arguments.command == "demo":
        return _bootstrap_demo(arguments)
    from anva.foundation.services import readiness_status

    status = readiness_status()
    print(json.dumps(status.as_dict(), sort_keys=True))
    return 0 if status.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
