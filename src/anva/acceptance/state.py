"""Fail-closed, content-minimized resume records for sealed acceptance."""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

STATE_SCHEMA_VERSION = 1
STATE_STATUSES = frozenset(
    {
        "BOOTSTRAP_PREPARED",
        "PREPARING",
        "AWAITING_EXTERNAL_REVIEW",
        "REVIEW_CLAIMING",
        "REVIEW_CLAIMED",
        "REVIEW_SUBMITTING",
        "EXTERNAL_REVIEW_SUBMITTED",
        "COMPLETE",
    }
)
HASH_PATTERN = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")
ID_KEYS = frozenset(
    {
        "organization_id",
        "repository_id",
        "access_scope_id",
        "source_connection_id",
        "sync_run_id",
        "work_item_id",
        "work_item_revision_id",
        "policy_id",
        "policy_version_id",
        "evidence_blob_id",
        "evidence_manifest_id",
        "pull_request_revision_id",
        "assurance_run_id",
        "evaluator_task_id",
        "report_id",
        "stale_probe_run_id",
        "canvas_view_id",
    }
)
HASH_KEYS = frozenset(
    {
        "manifest_sha256",
        "source_fingerprint",
        "canonical_manifest_sha256",
        "canonical_input_sha256",
        "case_sha256",
        "product_commit",
        "corpus_commit",
        "base_commit",
        "head_commit",
        "new_head_commit",
        "reference_time_sha256",
        "bootstrap_idempotency_sha256",
        "bootstrap_request_sha256",
        "diff_hash",
        "input_hash",
        "review_claim_idempotency_sha256",
        "review_handoff_sha256",
        "review_result_sha256",
        "sealed_manifest_sha256",
        "product_image_sha256",
        "build_input_sha256",
        "product_package_sha256",
        "launch_manifest_sha256",
    }
)


class AcceptanceStateError(ValueError):
    """A resume record was absent, unsafe, or tampered with."""


@dataclass(slots=True)
class ResumeState:
    corpus_id: str
    run_id: str
    reference_time: str
    product_version: str
    status: str = "PREPARING"
    identities: dict[str, str] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "status": self.status,
            "corpus_id": self.corpus_id,
            "run_id": self.run_id,
            "reference_time": self.reference_time,
            "product_version": self.product_version,
            "identities": dict(sorted(self.identities.items())),
            "hashes": dict(sorted(self.hashes.items())),
        }


def _validate_state(payload: dict[str, object]) -> ResumeState:
    if (
        set(payload)
        != {
            "schema_version",
            "status",
            "corpus_id",
            "run_id",
            "reference_time",
            "product_version",
            "identities",
            "hashes",
        }
        or payload.get("schema_version") != STATE_SCHEMA_VERSION
    ):
        raise AcceptanceStateError("Acceptance resume record is invalid")
    scalar_names = ("status", "corpus_id", "run_id", "reference_time", "product_version")
    if not all(isinstance(payload.get(name), str) for name in scalar_names):
        raise AcceptanceStateError("Acceptance resume record is invalid")
    status = cast(str, payload["status"])
    if status not in STATE_STATUSES:
        raise AcceptanceStateError("Acceptance resume state is invalid")
    identities = payload["identities"]
    hashes = payload["hashes"]
    if not isinstance(identities, dict) or not isinstance(hashes, dict):
        raise AcceptanceStateError("Acceptance resume record is invalid")
    if set(identities) - ID_KEYS or set(hashes) - HASH_KEYS:
        raise AcceptanceStateError("Acceptance resume record contains an unsupported field")
    if not all(isinstance(value, str) for value in identities.values()):
        raise AcceptanceStateError("Acceptance resume identity is invalid")
    if not all(isinstance(value, str) for value in hashes.values()):
        raise AcceptanceStateError("Acceptance resume hash is invalid")
    try:
        for value in identities.values():
            uuid.UUID(cast(str, value))
    except ValueError as error:
        raise AcceptanceStateError("Acceptance resume identity is invalid") from error
    if any(HASH_PATTERN.fullmatch(cast(str, value)) is None for value in hashes.values()):
        raise AcceptanceStateError("Acceptance resume hash is invalid")
    rendered = json.dumps(payload, sort_keys=True).casefold()
    if any(marker in rendered for marker in ("token", "secret", "password", "authorization")):
        raise AcceptanceStateError("Acceptance resume record contains credential material")
    return ResumeState(
        corpus_id=cast(str, payload["corpus_id"]),
        run_id=cast(str, payload["run_id"]),
        reference_time=cast(str, payload["reference_time"]),
        product_version=cast(str, payload["product_version"]),
        status=status,
        identities=cast(dict[str, str], identities),
        hashes=cast(dict[str, str], hashes),
    )


def load_state(path: Path) -> ResumeState:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.is_symlink()
        or not path.is_file()
    ):
        raise AcceptanceStateError("Acceptance resume record is unavailable")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise AcceptanceStateError("Acceptance resume record permissions are too broad")
    raw = path.read_bytes()
    if len(raw) > 64 * 1024:
        raise AcceptanceStateError("Acceptance resume record exceeds its bound")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceStateError("Acceptance resume record is invalid") from error
    if not isinstance(payload, dict):
        raise AcceptanceStateError("Acceptance resume record is invalid")
    return _validate_state(cast(dict[str, object], payload))


def save_state(path: Path, state: ResumeState) -> None:
    payload = _validate_state(state.as_dict()).as_dict()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AcceptanceStateError("Acceptance state directory is unsafe")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
