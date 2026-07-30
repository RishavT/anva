"""Raw-body verification and bounded normalization for GitHub webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from typing import cast

MAX_WEBHOOK_BYTES = 1_000_000
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 20_000
MAX_JSON_STRING = 200_000
SIGNATURE_PATTERN = re.compile(r"sha256=([a-f0-9]{64})")
EVENT_PATTERN = re.compile(r"[a-z_]{1,64}")

ALLOWED_ACTIONS: dict[str, frozenset[str]] = {
    "installation": frozenset(
        {"created", "new_permissions_accepted", "suspend", "unsuspend", "deleted"}
    ),
    "installation_repositories": frozenset({"added", "removed"}),
    "repository": frozenset({"renamed", "archived", "unarchived", "deleted"}),
    "pull_request": frozenset(
        {
            "opened",
            "edited",
            "synchronize",
            "ready_for_review",
            "reopened",
            "closed",
        }
    ),
    "check_run": frozenset({"completed"}),
    "check_suite": frozenset({"completed", "requested", "rerequested"}),
    "workflow_run": frozenset({"completed"}),
}


class DuplicateJsonKeyError(ValueError):
    """JSON object contained duplicate keys and is not canonical enough to accept."""


@dataclass(frozen=True, slots=True)
class VerifiedGitHubEvent:
    """Bounded event envelope after signature and schema validation."""

    delivery_id: uuid.UUID
    event_type: str
    action: str
    installation_id: int
    repository_external_id: int | None
    checksum: str
    normalized_payload: dict[str, object]


def verify_signature(*, raw_body: bytes, signature: str, secrets: tuple[str, ...]) -> None:
    """Verify GitHub's SHA-256 HMAC over the exact raw body."""
    if not raw_body or len(raw_body) > MAX_WEBHOOK_BYTES:
        raise ValueError("Webhook body is outside the allowed size")
    match = SIGNATURE_PATTERN.fullmatch(signature)
    if match is None or not secrets or any(not secret for secret in secrets):
        raise PermissionError("GitHub webhook signature is invalid")
    supplied = match.group(1)
    valid = False
    for secret in secrets:
        expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(expected, supplied) or valid
    if not valid:
        raise PermissionError("GitHub webhook signature is invalid")


def parse_verified_event(
    *,
    raw_body: bytes,
    delivery_header: str,
    event_header: str,
) -> VerifiedGitHubEvent:
    """Parse only after HMAC verification and retain only a bounded safe projection."""
    try:
        delivery_id = uuid.UUID(delivery_header)
    except (ValueError, AttributeError):
        raise ValueError("GitHub delivery identifier is invalid") from None
    if str(delivery_id) != delivery_header:
        raise ValueError("GitHub delivery identifier must be canonical")
    if EVENT_PATTERN.fullmatch(event_header) is None or event_header not in ALLOWED_ACTIONS:
        raise ValueError("GitHub event type is unsupported")
    try:
        payload = json.loads(raw_body, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("GitHub webhook JSON is invalid") from None
    if not isinstance(payload, dict):
        raise ValueError("GitHub webhook payload must be an object")
    _validate_json_bounds(payload)
    payload = cast(dict[str, object], payload)
    action = _string(payload, "action", maximum=64)
    if action not in ALLOWED_ACTIONS[event_header]:
        raise ValueError("GitHub event action is unsupported")
    installation = _object(payload, "installation")
    installation_id = _positive_int(installation, "id")
    repository = payload.get("repository")
    repository_id = (
        _positive_int(cast(dict[str, object], repository), "id")
        if isinstance(repository, dict)
        else None
    )
    normalized = _normalize(
        event_type=event_header,
        action=action,
        payload=payload,
        installation=installation,
        repository=cast(dict[str, object] | None, repository),
    )
    return VerifiedGitHubEvent(
        delivery_id=delivery_id,
        event_type=event_header,
        action=action,
        installation_id=installation_id,
        repository_external_id=repository_id,
        checksum=hashlib.sha256(raw_body).hexdigest(),
        normalized_payload=normalized,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError("GitHub webhook JSON contains duplicate keys")
        result[key] = value
    return result


def _validate_json_bounds(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("GitHub webhook JSON exceeds structural limits")
        if isinstance(current, str) and len(current) > MAX_JSON_STRING:
            raise ValueError("GitHub webhook JSON string exceeds the limit")
        if isinstance(current, dict):
            if len(current) > 1_000:
                raise ValueError("GitHub webhook JSON object exceeds the limit")
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            if len(current) > 1_000:
                raise ValueError("GitHub webhook JSON array exceeds the limit")
            stack.extend((child, depth + 1) for child in current)


def _normalize(
    *,
    event_type: str,
    action: str,
    payload: dict[str, object],
    installation: dict[str, object],
    repository: dict[str, object] | None,
) -> dict[str, object]:
    normalized: dict[str, object] = {
        "action": action,
        "installation_id": _positive_int(installation, "id"),
    }
    if repository is not None:
        normalized["repository"] = _repository(repository)
    if event_type == "installation":
        account = _object(installation, "account")
        permissions = installation.get("permissions", {})
        if not isinstance(permissions, dict) or len(permissions) > 50:
            raise ValueError("GitHub installation permissions are invalid")
        normalized["installation"] = {
            "account_id": _positive_int(account, "id"),
            "account_login": _string(account, "login", maximum=300),
            "account_type": _string(account, "type", maximum=32),
            "repository_selection": _string(
                installation,
                "repository_selection",
                maximum=16,
            ),
            "permissions": _string_map(cast(dict[str, object], permissions), maximum=50),
        }
    elif event_type == "installation_repositories":
        key = "repositories_added" if action == "added" else "repositories_removed"
        rows = payload.get(key)
        if not isinstance(rows, list) or len(rows) > 1_000:
            raise ValueError("GitHub installation repository list is invalid")
        normalized[key] = [
            _repository(cast(dict[str, object], row)) for row in rows if isinstance(row, dict)
        ]
        if len(cast(list[object], normalized[key])) != len(rows):
            raise ValueError("GitHub installation repository list is invalid")
    elif event_type == "pull_request":
        pull_request = _object(payload, "pull_request")
        base = _object(pull_request, "base")
        head = _object(pull_request, "head")
        base_repo = _object(base, "repo")
        head_repo = _object(head, "repo")
        normalized["pull_request"] = {
            "external_id": _positive_int(pull_request, "id"),
            "number": _positive_int(pull_request, "number"),
            "base_commit": _commit(base, "sha"),
            "head_commit": _commit(head, "sha"),
            "base_repository_id": _positive_int(base_repo, "id"),
            "head_repository_id": _positive_int(head_repo, "id"),
            "head_ref": _string(head, "ref", maximum=300),
            "is_fork": _positive_int(head_repo, "id") != _positive_int(base_repo, "id"),
        }
    elif event_type in {"check_run", "check_suite", "workflow_run"}:
        key = event_type
        check = _object(payload, key)
        pull_requests = check.get("pull_requests", [])
        if not isinstance(pull_requests, list) or len(pull_requests) > 100:
            raise ValueError("GitHub Check pull request list is invalid")
        pr_numbers = []
        for pull_request in pull_requests:
            if not isinstance(pull_request, dict):
                raise ValueError("GitHub Check pull request list is invalid")
            pr_numbers.append(_positive_int(pull_request, "number"))
        normalized["check"] = {
            "kind": event_type.upper(),
            "external_id": _positive_int(check, "id"),
            "name": _optional_string(check, "name", maximum=300)
            or _optional_string(check, "workflow_name", maximum=300)
            or event_type.replace("_", " ").title(),
            "head_commit": _commit(check, "head_sha"),
            "status": _string(check, "status", maximum=32),
            "conclusion": _optional_string(check, "conclusion", maximum=32),
            "details_url": _optional_string(
                check,
                "details_url" if event_type != "workflow_run" else "html_url",
                maximum=2_000,
            ),
            "pull_request_numbers": sorted(set(pr_numbers)),
        }
    return normalized


def _repository(payload: dict[str, object]) -> dict[str, object]:
    return {
        "external_id": _positive_int(payload, "id"),
        "full_name": _string(payload, "full_name", maximum=600),
        "default_branch": _optional_string(payload, "default_branch", maximum=300) or "main",
        "private": _optional_boolean(payload, "private", default=True),
        "archived": _optional_boolean(payload, "archived", default=False),
    }


def _object(payload: dict[str, object], name: str) -> dict[str, object]:
    value = payload.get(name)
    if not isinstance(value, dict):
        raise ValueError(f"GitHub {name} object is required")
    return cast(dict[str, object], value)


def _positive_int(payload: dict[str, object], name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"GitHub {name} must be a positive integer")
    return value


def _string(payload: dict[str, object], name: str, *, maximum: int) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"GitHub {name} is invalid")
    return value


def _optional_string(payload: dict[str, object], name: str, *, maximum: int) -> str:
    value = payload.get(name)
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"GitHub {name} is invalid")
    return value


def _optional_boolean(payload: dict[str, object], name: str, *, default: bool) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"GitHub {name} is invalid")
    return value


def _commit(payload: dict[str, object], name: str) -> str:
    value = _string(payload, name, maximum=40)
    if re.fullmatch(r"[a-f0-9]{40}", value) is None:
        raise ValueError(f"GitHub {name} is not a full commit SHA")
    return value


def _string_map(payload: dict[str, object], *, maximum: int) -> dict[str, str]:
    if len(payload) > maximum or not all(
        isinstance(key, str) and len(key) <= 100 and isinstance(value, str) and len(value) <= 32
        for key, value in payload.items()
    ):
        raise ValueError("GitHub string map is invalid")
    return {key: cast(str, value) for key, value in sorted(payload.items())}
