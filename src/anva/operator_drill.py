"""Fail-closed helpers for the disposable #44 operator acceptance drill."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PRODUCT_SOURCE_COMMIT = "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac"
SIGNER_WORKFLOW = "RishavT/anva/.github/workflows/operator-drill-signoff.yml"
PREDICATE_TYPE = "https://github.com/RishavT/anva/attestations/operator-drill-signoff/v1"
EXPECTED_APPROVER = "RishavT"
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+$")
SHA256 = re.compile(r"^(?:sha256:)?[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
FORBIDDEN_VALUE = re.compile(
    r"(?:ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{8,}|"
    r"(?:bearer|basic|authorization|cookie|api.?key|secret|password|token|credential)"
    r"\s*[:= ]\s*\S+|"
    r"[A-Za-z][\w.-]*/[\w.-]+|[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+|"
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\+?[0-9][0-9 ()-]{7,}[0-9])",
    re.IGNORECASE,
)
AUTOMATED_CODES = frozenset(
    {"METRICS_AUTH", "PROXY_SPOOF", "RESTORE_FAULT", "STORAGE_INTERRUPT", "DECOMMISSION_RETRY"}
)
DECISION_CODES = frozenset(
    {
        "ROTATE_CREDENTIAL",
        "REVOKE_CREDENTIAL",
        "ESCALATE_PERMISSION_LEAK",
        "ABORT_FAILED_RESTORE",
        "RESUME_STORAGE",
        "ESCALATE_METRICS_PROXY",
    }
)
AUTOMATED_SEQUENCE = (
    "METRICS_AUTH",
    "PROXY_SPOOF",
    "RESTORE_FAULT",
    "STORAGE_INTERRUPT",
    "DECOMMISSION_RETRY",
)
DECISION_SEQUENCE = (
    "ROTATE_CREDENTIAL",
    "REVOKE_CREDENTIAL",
    "ESCALATE_PERMISSION_LEAK",
    "ABORT_FAILED_RESTORE",
    "RESUME_STORAGE",
    "ESCALATE_METRICS_PROXY",
)
DECISION_ROLES = {
    "ROTATE_CREDENTIAL": "SECURITY_OPERATOR",
    "REVOKE_CREDENTIAL": "SECURITY_OPERATOR",
    "ESCALATE_PERMISSION_LEAK": "RELEASE_OWNER",
    "ABORT_FAILED_RESTORE": "RESTORE_OPERATOR",
    "RESUME_STORAGE": "STORAGE_OPERATOR",
    "ESCALATE_METRICS_PROXY": "PLATFORM_OPERATOR",
}
EXPECTED_PARTICIPANT = "RISHAVT"
CLEANUP_CODES = frozenset({"TASK_RESOURCES_ABSENT"})


def _is_exact_int(value: object, expected: int | None = None) -> bool:
    return type(value) is int and (expected is None or value == expected)


def _validate_automated_payload(payload: Mapping[str, object]) -> None:
    common = {"check_code", "outcome", "correlation_id"}
    code = payload.get("check_code")
    if (
        code not in AUTOMATED_CODES
        or payload.get("outcome") != "PASS"
        or not UUID.fullmatch(str(payload.get("correlation_id")))
    ):
        raise EvidenceRejectedError("automated result identity or outcome is invalid")
    if code == "METRICS_AUTH":
        sample_count = payload.get("metric_sample_count")
        expected: dict[str, object] = {
            "missing_token_code": 404,
            "wrong_token_code": 404,
            "correct_token_code": 200,
        }
        if (
            set(payload) != common | set(expected) | {"metric_sample_count"}
            or any(
                not _is_exact_int(payload.get(field), value)
                for field, value in expected.items()
                if type(value) is int
            )
            or not isinstance(sample_count, int)
            or isinstance(sample_count, bool)
            or sample_count <= 0
        ):
            raise EvidenceRejectedError(
                "metrics authentication must prove exact 404/404/200 behavior"
            )
    elif code == "PROXY_SPOOF":
        if set(payload) != common | {"redirect_code"} or not _is_exact_int(
            payload.get("redirect_code"), 301
        ):
            raise EvidenceRejectedError("proxy spoof check must observe exact redirect 301")
    elif code == "RESTORE_FAULT":
        expected = {
            "exit_code": 44,
            "marker_code": "DRILL_OBJECT_RESTORE_FAULT",
            "writers_running": 0,
        }
        if (
            set(payload) != common | set(expected)
            or not _is_exact_int(payload.get("exit_code"), 44)
            or payload.get("marker_code") != "DRILL_OBJECT_RESTORE_FAULT"
            or not _is_exact_int(payload.get("writers_running"), 0)
        ):
            raise EvidenceRejectedError(
                "restore fault must prove exact exit 44, marker, and no writers"
            )
    elif code == "STORAGE_INTERRUPT":
        expected = {
            "interrupted_state": "UNAVAILABLE",
            "failure_code": "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED",
            "resumed_state": "AVAILABLE",
        }
        if set(payload) != common | set(expected) or any(
            payload.get(field) != value for field, value in expected.items()
        ):
            raise EvidenceRejectedError(
                "storage interruption must prove failure and exact recovery states"
            )
    else:
        expected = {
            "initial_state": "FAILED",
            "initial_error_code": "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED",
            "final_state": "COMPLETED",
            "final_error_code": "NONE",
            "attempt_delta": 1,
        }
        if (
            set(payload) != common | set(expected)
            or any(
                payload.get(field) != value
                for field, value in expected.items()
                if field != "attempt_delta"
            )
            or not _is_exact_int(payload.get("attempt_delta"), 1)
        ):
            raise EvidenceRejectedError(
                "decommission retry must prove the exact one-attempt transition"
            )


class EvidenceRejectedError(ValueError):
    """Evidence violates the closed append-only ledger contract."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def preflight_network(
    *,
    subnet: str,
    proxy_ip: str,
    networks: Sequence[Mapping[str, object]],
    owned_network: str | None = None,
) -> dict[str, str]:
    candidate = ipaddress.ip_network(subnet, strict=True)
    if candidate.version != 4 or "/" in proxy_ip:
        raise ValueError("drill proxy configuration must use one exact IPv4 address")
    address = ipaddress.ip_address(proxy_ip)
    if address not in candidate or address in {
        candidate.network_address,
        candidate.broadcast_address,
    }:
        raise ValueError("drill proxy address must be a usable host in the configured subnet")
    for network in networks:
        if owned_network and network.get("Name") == owned_network:
            continue
        ipam = network.get("IPAM")
        configs = ipam.get("Config", []) if isinstance(ipam, dict) else []
        for config in configs if isinstance(configs, list) else []:
            if not isinstance(config, dict) or not config.get("Subnet"):
                continue
            try:
                existing = ipaddress.ip_network(str(config["Subnet"]), strict=False)
            except ValueError:
                continue
            if candidate.overlaps(existing):
                raise ValueError(
                    f"drill subnet collides with Docker network {network.get('Name', '')}"
                )
    return {"proxy_ip": str(address), "status": "available", "subnet": str(candidate)}


def record_release_boundary(
    *,
    product_version: str,
    product_source_commit: str,
    operator_source_commit: str,
    operator_cli_in_product: bool,
) -> dict[str, object]:
    eligible = (
        operator_cli_in_product
        and product_source_commit == operator_source_commit
        and product_version != "0.1.0"
    )
    return {
        "operator_cli_binding": "PRODUCT_IMAGE" if eligible else "SOURCE_BOUND_DEVELOPMENT_HELPER",
        "operator_cli_in_product": operator_cli_in_product,
        "operator_source_commit": operator_source_commit,
        "product_source_commit": product_source_commit,
        "product_version": product_version,
        "status": "ELIGIBLE_FOR_HUMAN_ACCEPTANCE" if eligible else "NOT_ACCEPTED",
    }


def build_evidence(*, drill_id: str, source_revision: str, image_digest: str) -> dict[str, Any]:
    if (
        not UUID.fullmatch(drill_id)
        or not COMMIT.fullmatch(source_revision)
        or not SHA256.fullmatch(image_digest)
    ):
        raise EvidenceRejectedError("header identities must be an exact UUID and SHA-256 values")
    return {
        "event_id": "00000000000000000000",
        "event_type": "header",
        "payload": {
            "drill_id": drill_id,
            "release_boundary": record_release_boundary(
                product_version="0.1.0",
                product_source_commit=PRODUCT_SOURCE_COMMIT,
                operator_source_commit=source_revision,
                operator_cli_in_product=False,
            ),
            "runtime": {"image_digest": image_digest, "source_revision": source_revision},
            "schema_version": 3,
        },
        "previous_hash": None,
        "recorded_at": _now(),
    }


def _reject_unsafe_strings(value: object) -> None:
    if isinstance(value, Mapping):
        for child in value.values():
            _reject_unsafe_strings(child)
    elif isinstance(value, list):
        for child in value:
            _reject_unsafe_strings(child)
    elif isinstance(value, str):
        if (
            UUID.fullmatch(value)
            or SHA256.fullmatch(value)
            or COMMIT.fullmatch(value)
            or re.fullmatch(r"[A-Z][A-Z0-9_]*", value)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
        ):
            return
        if FORBIDDEN_VALUE.search(value):
            raise EvidenceRejectedError(
                "evidence contains free text, PII, credential, token, or object-key material"
            )


def _validate_payload(event_type: str, payload: Mapping[str, object]) -> None:
    _reject_unsafe_strings(payload)
    if event_type == "automated_result":
        _validate_automated_payload(payload)
    elif event_type == "decision_proposal":
        if (
            set(payload)
            != {"decision_code", "correlation_id", "outcome", "participant_code", "role_code"}
            or payload.get("decision_code") not in DECISION_CODES
            or payload.get("outcome") != "PROPOSED"
            or payload.get("participant_code") != EXPECTED_PARTICIPANT
            or payload.get("role_code") != DECISION_ROLES.get(str(payload.get("decision_code")))
            or not UUID.fullmatch(str(payload.get("correlation_id")))
        ):
            raise EvidenceRejectedError("decision proposal does not match the closed schema")
    elif event_type == "cleanup":
        if (
            set(payload) != {"cleanup_code", "outcome", "resource_count"}
            or payload.get("cleanup_code") not in CLEANUP_CODES
            or payload.get("outcome") != "COMPLETE"
            or not _is_exact_int(payload.get("resource_count"), 0)
        ):
            raise EvidenceRejectedError("cleanup does not match the closed schema")
    elif event_type == "github_anchor":
        run_id = payload.get("run_id")
        required = {
            "decision_code_hash",
            "drill_id",
            "ledger_sha256",
            "operator_source_commit",
            "product_source_commit",
            "run_id",
            "tail_hash",
        }
        digest_fields = {"decision_code_hash", "ledger_sha256", "tail_hash"}
        if (
            set(payload) != required
            or not _is_exact_int(run_id)
            or not isinstance(run_id, int)
            or run_id <= 0
            or not UUID.fullmatch(str(payload["drill_id"]))
            or any(not SHA256.fullmatch(str(payload[name])) for name in digest_fields)
            or any(
                not COMMIT.fullmatch(str(payload[name]))
                for name in ("operator_source_commit", "product_source_commit")
            )
        ):
            raise EvidenceRejectedError("GitHub anchor does not match the closed schema")
    else:
        raise EvidenceRejectedError("local event type is forbidden")


def _seal(event: dict[str, Any]) -> dict[str, Any]:
    event["event_hash"] = hashlib.sha256(_canonical(event)).hexdigest()
    return event


def validate_evidence(
    events: list[dict[str, Any]] | dict[str, Any], *, require_anchor: bool = False
) -> None:
    ledger = [events] if isinstance(events, dict) else events
    if not ledger or ledger[0].get("event_type") != "header":
        raise EvidenceRejectedError("evidence ledger header is missing")
    previous: str | None = None
    for index, event in enumerate(ledger):
        if set(event) != {
            "event_hash",
            "event_id",
            "event_type",
            "payload",
            "previous_hash",
            "recorded_at",
        } or not TIMESTAMP.fullmatch(str(event.get("recorded_at"))):
            raise EvidenceRejectedError("event envelope is not closed or timestamped")
        supplied_hash = event.get("event_hash")
        unsigned = {key: value for key, value in event.items() if key != "event_hash"}
        if (
            event.get("previous_hash") != previous
            or supplied_hash != hashlib.sha256(_canonical(unsigned)).hexdigest()
            or event.get("event_id") != f"{index:020d}"
        ):
            raise EvidenceRejectedError("evidence hash chain or monotonic ID is invalid")
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise EvidenceRejectedError("event payload is invalid")
        if index == 0:
            if payload.get("schema_version") != 3 or set(payload) != {
                "drill_id",
                "release_boundary",
                "runtime",
                "schema_version",
            }:
                raise EvidenceRejectedError("evidence schema is incomplete or unknown")
            runtime = payload.get("runtime")
            boundary = payload.get("release_boundary")
            if (
                not UUID.fullmatch(str(payload.get("drill_id")))
                or not isinstance(runtime, dict)
                or set(runtime) != {"image_digest", "source_revision"}
                or not SHA256.fullmatch(str(runtime.get("image_digest")))
                or not COMMIT.fullmatch(str(runtime.get("source_revision")))
                or not isinstance(boundary, dict)
                or set(boundary)
                != {
                    "operator_cli_binding",
                    "operator_cli_in_product",
                    "operator_source_commit",
                    "product_source_commit",
                    "product_version",
                    "status",
                }
                or not COMMIT.fullmatch(str(boundary.get("operator_source_commit")))
                or not COMMIT.fullmatch(str(boundary.get("product_source_commit")))
                or boundary.get("operator_source_commit") != runtime.get("source_revision")
                or not isinstance(boundary.get("operator_cli_in_product"), bool)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(boundary.get("product_version")))
            ):
                raise EvidenceRejectedError("header identities do not match the closed schema")
            expected_boundary = record_release_boundary(
                product_version=str(boundary["product_version"]),
                product_source_commit=str(boundary["product_source_commit"]),
                operator_source_commit=str(boundary["operator_source_commit"]),
                operator_cli_in_product=bool(boundary["operator_cli_in_product"]),
            )
            if boundary != expected_boundary:
                raise EvidenceRejectedError("release boundary is internally inconsistent")
            _reject_unsafe_strings(payload)
        else:
            _validate_payload(str(event.get("event_type")), payload)
            if event.get("event_type") == "github_anchor" and index != len(ledger) - 1:
                raise EvidenceRejectedError("GitHub anchor must close the ledger")
        previous = str(supplied_hash)
    if require_anchor and ledger[-1].get("event_type") != "github_anchor":
        raise EvidenceRejectedError(
            "evidence remains NOT_ACCEPTED without a verified GitHub anchor"
        )


def _read_ledger(handle: Any) -> list[dict[str, Any]]:
    handle.seek(0)
    ledger = [json.loads(line) for line in handle if line.strip()]
    validate_evidence(ledger)
    return ledger


def append_event(path: Path, event_type: str, payload: Mapping[str, object]) -> dict[str, Any]:
    if event_type not in {"automated_result", "decision_proposal", "cleanup"}:
        raise EvidenceRejectedError("human approval and signoff cannot be appended locally")
    _validate_payload(event_type, payload)
    with path.open("r+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        ledger = _read_ledger(handle)
        if ledger[-1]["event_type"] == "github_anchor":
            raise EvidenceRejectedError("anchored evidence is closed")
        event = _seal(
            {
                "event_id": f"{len(ledger):020d}",
                "event_type": event_type,
                "payload": dict(payload),
                "previous_hash": ledger[-1]["event_hash"],
                "recorded_at": _now(),
            }
        )
        validate_evidence([*ledger, event])
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        return event


def _decision_hash(ledger: Sequence[Mapping[str, Any]]) -> str:
    codes = [
        event["payload"]["decision_code"]
        for event in ledger
        if event.get("event_type") == "decision_proposal"
    ]
    return hashlib.sha256(_canonical(codes)).hexdigest()


def validate_completion(ledger: Sequence[Mapping[str, Any]]) -> None:
    """Require the one closed, successful drill transcript before external signoff."""
    local = [event for event in ledger[1:] if event.get("event_type") != "github_anchor"]
    expected_types = (
        *("automated_result" for _ in AUTOMATED_SEQUENCE),
        *("decision_proposal" for _ in DECISION_SEQUENCE),
        "cleanup",
    )
    if tuple(event.get("event_type") for event in local) != expected_types:
        raise EvidenceRejectedError(
            "drill completion sequence is missing, duplicate, or out of order"
        )
    checks = [event["payload"] for event in local[: len(AUTOMATED_SEQUENCE)]]
    if tuple(item.get("check_code") for item in checks) != AUTOMATED_SEQUENCE:
        raise EvidenceRejectedError("every exact automated check must pass with nonempty evidence")
    decisions = [
        event["payload"]
        for event in local[
            len(AUTOMATED_SEQUENCE) : len(AUTOMATED_SEQUENCE) + len(DECISION_SEQUENCE)
        ]
    ]
    if tuple(item.get("decision_code") for item in decisions) != DECISION_SEQUENCE or any(
        item.get("outcome") != "PROPOSED"
        or item.get("participant_code") != EXPECTED_PARTICIPANT
        or item.get("role_code") != DECISION_ROLES[item["decision_code"]]
        for item in decisions
    ):
        raise EvidenceRejectedError("every exact participant decision and role is required")
    cleanup = local[-1]["payload"]
    if cleanup != {
        "cleanup_code": "TASK_RESOURCES_ABSENT",
        "outcome": "COMPLETE",
        "resource_count": 0,
    }:
        raise EvidenceRejectedError("exact successful cleanup evidence is required")


def _verify_external_anchor(
    anchor: Mapping[str, object],
    anchor_path: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    runner(
        [
            "gh",
            "attestation",
            "verify",
            str(anchor_path),
            "--repo",
            "RishavT/anva",
            "--signer-workflow",
            SIGNER_WORKFLOW,
            "--predicate-type",
            PREDICATE_TYPE,
            "--deny-self-hosted-runners",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    api_header = ["-H", "X-GitHub-Api-Version: 2026-03-10"]
    run = json.loads(
        runner(
            ["gh", "api", *api_header, f"repos/RishavT/anva/actions/runs/{anchor['run_id']}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    approvals = json.loads(
        runner(
            [
                "gh",
                "api",
                *api_header,
                f"repos/RishavT/anva/actions/runs/{anchor['run_id']}/approvals",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("path")
        not in {
            ".github/workflows/operator-drill-signoff.yml",
            ".github/workflows/operator-drill-signoff.yml@refs/heads/main",
        }
        or run.get("head_branch") != "main"
        or run.get("conclusion") != "success"
    ):
        raise EvidenceRejectedError("GitHub run identity is invalid")
    if not any(
        item.get("state") == "approved"
        and item.get("user", {}).get("login") == EXPECTED_APPROVER
        and any(
            environment.get("name") == "release" for environment in item.get("environments", [])
        )
        for item in approvals
    ):
        raise EvidenceRejectedError("release deployment lacks exact RishavT approval evidence")


def finalize_with_github_anchor(
    path: Path,
    anchor_path: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    _validate_payload("github_anchor", anchor)
    with path.open("r+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        ledger = _read_ledger(handle)
        header = ledger[0]["payload"]
        if header["release_boundary"]["status"] != "ELIGIBLE_FOR_HUMAN_ACCEPTANCE":
            raise EvidenceRejectedError("release boundary remains NOT_ACCEPTED")
        validate_completion(ledger)
        expected = {
            "drill_id": header["drill_id"],
            "ledger_sha256": _sha256_file(path),
            "tail_hash": ledger[-1]["event_hash"],
            "product_source_commit": header["release_boundary"]["product_source_commit"],
            "operator_source_commit": header["release_boundary"]["operator_source_commit"],
            "decision_code_hash": _decision_hash(ledger),
        }
        if any(anchor.get(key) != value for key, value in expected.items()):
            raise EvidenceRejectedError("GitHub anchor does not bind the exact current ledger")
        _verify_external_anchor(anchor, anchor_path, runner=runner)
        event = _seal(
            {
                "event_id": f"{len(ledger):020d}",
                "event_type": "github_anchor",
                "payload": anchor,
                "previous_hash": ledger[-1]["event_hash"],
                "recorded_at": _now(),
            }
        )
        validate_evidence([*ledger, event], require_anchor=True)
        handle.seek(0, os.SEEK_END)
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def validate_final_evidence(
    path: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Reverify ledger integrity, completion, and external GitHub proof every time."""
    with path.open(encoding="utf-8") as handle:
        ledger = _read_ledger(handle)
    validate_evidence(ledger, require_anchor=True)
    validate_completion(ledger)
    anchor = ledger[-1]["payload"]
    header = ledger[0]["payload"]
    if header["release_boundary"]["status"] != "ELIGIBLE_FOR_HUMAN_ACCEPTANCE":
        raise EvidenceRejectedError("release boundary remains NOT_ACCEPTED")
    prefix = b"".join((json.dumps(event, sort_keys=True) + "\n").encode() for event in ledger[:-1])
    expected = {
        "drill_id": header["drill_id"],
        "ledger_sha256": hashlib.sha256(prefix).hexdigest(),
        "tail_hash": ledger[-2]["event_hash"],
        "product_source_commit": header["release_boundary"]["product_source_commit"],
        "operator_source_commit": header["release_boundary"]["operator_source_commit"],
        "decision_code_hash": _decision_hash(ledger[:-1]),
    }
    if any(anchor.get(key) != value for key, value in expected.items()):
        raise EvidenceRejectedError("GitHub anchor does not bind the exact finalized ledger prefix")
    with tempfile.TemporaryDirectory() as directory:
        anchor_path = Path(directory) / "anchor.json"
        anchor_path.write_bytes(_canonical(anchor) + b"\n")
        _verify_external_anchor(anchor, anchor_path, runner=runner)


def _write_evidence(arguments: argparse.Namespace) -> int:
    header = _seal(
        build_evidence(
            drill_id=arguments.drill_id,
            source_revision=arguments.source_revision,
            image_digest=arguments.image_digest,
        )
    )
    validate_evidence([header])
    output_dir = Path(arguments.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"issue-044-{arguments.drill_id}-{uuid.uuid4().hex}.jsonl"
    raw = (json.dumps(header, sort_keys=True) + "\n").encode()
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    print(
        json.dumps(
            {
                "artifact_sha256": hashlib.sha256(raw).hexdigest(),
                "path": output.name,
                "status": "created",
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("network-preflight")
    preflight.add_argument("--subnet", required=True)
    preflight.add_argument("--proxy-ip", required=True)
    preflight.add_argument("--networks-json", type=Path, required=True)
    preflight.add_argument("--owned-network")
    create = commands.add_parser("create-evidence")
    create.add_argument("--drill-id", required=True)
    create.add_argument("--source-revision", required=True)
    create.add_argument("--image-digest", required=True)
    create.add_argument("--output-dir", required=True)
    validate = commands.add_parser("validate-provisional")
    validate.add_argument("path", type=Path)
    final_validate = commands.add_parser("validate-final")
    final_validate.add_argument("path", type=Path)
    for command, event_type in (
        ("record-check", "automated_result"),
        ("record-decision-proposal", "decision_proposal"),
        ("record-cleanup", "cleanup"),
    ):
        item = commands.add_parser(command)
        item.add_argument("path", type=Path)
        item.add_argument("--event-json", type=Path, required=True)
        item.set_defaults(event_type=event_type)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("path", type=Path)
    finalize.add_argument("--anchor-json", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "network-preflight":
            print(
                json.dumps(
                    preflight_network(
                        subnet=arguments.subnet,
                        proxy_ip=arguments.proxy_ip,
                        networks=json.loads(arguments.networks_json.read_text()),
                        owned_network=arguments.owned_network,
                    ),
                    sort_keys=True,
                )
            )
            return 0
        if arguments.command == "create-evidence":
            return _write_evidence(arguments)
        if arguments.command == "validate-provisional":
            with arguments.path.open(encoding="utf-8") as handle:
                ledger = _read_ledger(handle)
            validate_evidence(ledger)
        elif arguments.command == "validate-final":
            validate_final_evidence(arguments.path)
        elif arguments.command == "finalize":
            finalize_with_github_anchor(arguments.path, arguments.anchor_json)
        else:
            append_event(
                arguments.path, arguments.event_type, json.loads(arguments.event_json.read_text())
            )
    except (
        EvidenceRejectedError,
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
        TypeError,
        ValueError,
    ) as error:
        print(
            json.dumps({"code": "drill_evidence_rejected", "message": str(error)}, sort_keys=True)
        )
        return 2
    print(json.dumps({"status": "verified"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
