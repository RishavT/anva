"""Deployment-local operator surface for decommission cleanup recovery."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from anva.core.services.authorization import Action
from anva.core.services.context import ActorContext

RETRY_ACTION = "retry_decommission_cleanup"
RETRY_ERROR = "DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED"
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
OPERATOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.@:_-]{0,199}$")


@dataclass(frozen=True, slots=True)
class DecommissionCleanupStatus:
    """Safe exact-run state returned to a local operator."""

    organization_id: uuid.UUID
    run_id: uuid.UUID
    request_hash: str
    state: str
    error_code: str
    cleanup_retry_attempts: int
    claim_expires_at: str | None = None
    claim_expired: bool = False

    @property
    def eligible(self) -> bool:
        return (self.state == "FAILED" and self.error_code == RETRY_ERROR) or (
            self.state == "RUNNING" and self.claim_expired
        )


class OperatorCommandError(Exception):
    """A safe operator-facing rejection with a stable process exit code."""

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def _read_operator_credential(path: Path) -> tuple[str, frozenset[str]]:
    expected_digest = os.getenv("ANVA_DECOMMISSION_OPERATOR_CREDENTIAL_SHA256", "")
    try:
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink() or path_stat.st_size > 4_096:
            raise ValueError
        raw = path.read_bytes()
        if not SHA256_PATTERN.fullmatch(expected_digest) or not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), expected_digest
        ):
            raise ValueError
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != {
            "actions",
            "credential",
            "operator_id",
            "schema_version",
        }:
            raise ValueError
        operator_id = payload["operator_id"]
        actions = payload["actions"]
        credential = payload["credential"]
        if (
            payload["schema_version"] != 1
            or not isinstance(operator_id, str)
            or OPERATOR_ID_PATTERN.fullmatch(operator_id) is None
            or not isinstance(credential, str)
            or SHA256_PATTERN.fullmatch(credential) is None
            or not isinstance(actions, list)
            or not all(isinstance(action, str) for action in actions)
            or RETRY_ACTION not in actions
        ):
            raise ValueError
    except (json.JSONDecodeError, OSError, TypeError, UnicodeDecodeError, ValueError):
        raise OperatorCommandError(
            "operator_authorization_rejected",
            "Deployment-local operator authorization was rejected",
            2,
        ) from None
    return operator_id, frozenset(actions)


def _load_status(*, organization_id: uuid.UUID, run_id: uuid.UUID) -> DecommissionCleanupStatus:
    from django.utils import timezone

    from anva.core.models import RetentionRun
    from anva.core.services.operations import DECOMMISSION_CLEANUP_CLAIM_TTL

    run = RetentionRun.objects.filter(
        id=run_id,
        organization_id=organization_id,
        kind=RetentionRun.Kind.ORGANIZATION_DECOMMISSION,
    ).first()
    if run is None:
        raise OperatorCommandError(
            "decommission_cleanup_run_not_found",
            "The exact tenant and decommission run identity was not found",
            3,
        )
    attempts = run.summary.get("cleanup_retry_attempts", 0)
    claim_expires_at: datetime | None = None
    if run.state == RetentionRun.State.RUNNING:
        claimed_at_raw = run.summary.get("cleanup_retry_claimed_at")
        try:
            claimed_at = datetime.fromisoformat(str(claimed_at_raw))
        except ValueError:
            claimed_at = None
        if claimed_at is not None and claimed_at.tzinfo is not None:
            claim_expires_at = claimed_at + DECOMMISSION_CLEANUP_CLAIM_TTL
    return DecommissionCleanupStatus(
        organization_id=organization_id,
        run_id=run.id,
        request_hash=run.request_hash,
        state=run.state,
        error_code=run.error_code,
        cleanup_retry_attempts=attempts if isinstance(attempts, int) else 0,
        claim_expires_at=claim_expires_at.isoformat() if claim_expires_at is not None else None,
        claim_expired=claim_expires_at is not None and timezone.now() >= claim_expires_at,
    )


def _status_payload(
    status: DecommissionCleanupStatus, *, request_id: uuid.UUID
) -> dict[str, object]:
    return {
        "cleanup_retry_attempts": status.cleanup_retry_attempts,
        "claim_expires_at": status.claim_expires_at,
        "eligible": status.eligible,
        "error_code": status.error_code,
        "operation": RETRY_ACTION,
        "organization_id": str(status.organization_id),
        "request_hash": status.request_hash,
        "request_id": str(request_id),
        "run_id": str(status.run_id),
        "state": status.state,
    }


def execute_decommission_cleanup(arguments: argparse.Namespace) -> int:
    """Authenticate, inspect, or execute one exact local cleanup retry."""
    request_id = arguments.request_id or uuid.uuid4()
    try:
        credential_file = Path(str(arguments.credential_file))
        operator_id, _actions = _read_operator_credential(credential_file)
        organization_id = arguments.organization_id
        run_id = arguments.run_id
        status = _load_status(organization_id=organization_id, run_id=run_id)
        payload = _status_payload(status, request_id=request_id)
        if bool(arguments.status):
            payload["status"] = "inspection_complete"
            print(json.dumps(payload, sort_keys=True))
            return 0

        expected_hash = arguments.expected_request_hash
        expected_attempt = arguments.expected_attempt
        if (
            not isinstance(expected_hash, str)
            or SHA256_PATTERN.fullmatch(expected_hash) is None
            or not hmac.compare_digest(expected_hash, status.request_hash)
        ):
            raise OperatorCommandError(
                "decommission_cleanup_revision_mismatch",
                "The decommission run revision did not match",
                4,
            )
        if not isinstance(expected_attempt, int) or not (
            expected_attempt == status.cleanup_retry_attempts
            or (
                status.state == "COMPLETED"
                and expected_attempt + 1 == status.cleanup_retry_attempts
            )
        ):
            raise OperatorCommandError(
                "decommission_cleanup_revision_mismatch",
                "The decommission cleanup attempt revision did not match",
                4,
            )
        if bool(arguments.dry_run):
            payload["status"] = "dry_run_complete"
            print(json.dumps(payload, sort_keys=True))
            return 0
        if not status.eligible and status.state != "COMPLETED":
            raise OperatorCommandError(
                "decommission_cleanup_not_retryable",
                "The exact decommission run is not retryable",
                4,
            )
        expected_confirmation = (
            f"RETRY DECOMMISSION CLEANUP {organization_id} {run_id} {expected_hash} "
            f"ATTEMPT {expected_attempt}"
        )
        if arguments.confirm != expected_confirmation:
            raise OperatorCommandError(
                "decommission_cleanup_confirmation_rejected",
                "The exact decommission cleanup confirmation did not match",
                2,
            )

        from anva.core.exceptions import ResourceNotFoundError
        from anva.core.services.operations import retry_decommission_cleanup

        actor = ActorContext(
            organization_id=organization_id,
            actor_type="SYSTEM",
            actor_id="anva-retention-worker",
            authorization_path=f"deployment-local:decommission-cleanup:{operator_id}",
            request_id=request_id,
            credential_actions=frozenset({Action.RETENTION_MANAGE.value}),
        )
        try:
            run = retry_decommission_cleanup(
                actor=actor,
                run_id=run_id,
                expected_request_hash=expected_hash,
                expected_retry_attempt=expected_attempt,
            )
        except ResourceNotFoundError:
            raise OperatorCommandError(
                "decommission_cleanup_collision",
                "The decommission cleanup run changed or is already being retried",
                4,
            ) from None
        payload.update(
            {
                "cleanup_retry_attempts": run.summary.get("cleanup_retry_attempts", 0),
                "error_code": run.error_code,
                "state": run.state,
                "status": "completed" if run.state == "COMPLETED" else "retry_required",
            }
        )
        print(json.dumps(payload, sort_keys=True))
        return 0 if run.state == "COMPLETED" else 5
    except OperatorCommandError as error:
        print(
            json.dumps(
                {
                    "code": error.code,
                    "message": str(error),
                    "operation": RETRY_ACTION,
                    "request_id": str(request_id),
                },
                sort_keys=True,
            )
        )
        return error.exit_code
    except Exception as error:
        from django.db import DatabaseError

        if not isinstance(error, DatabaseError):
            raise
        print(
            json.dumps(
                {
                    "code": "operator_dependency_unavailable",
                    "message": "A required operator dependency is unavailable",
                    "operation": RETRY_ACTION,
                    "request_id": str(request_id),
                },
                sort_keys=True,
            )
        )
        return 6
