"""Closed public shape for least-privilege organization bootstrap scopes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, cast

ROLE_CODES: Final[tuple[str, ...]] = (
    "ORG_ADMIN",
    "KNOWLEDGE_ADMIN",
    "TECHNICAL_OWNER",
    "PRODUCT_OWNER",
    "DEVELOPER",
    "REVIEWER",
    "SECURITY_REVIEWER",
    "VIEWER",
)

ACTION_VALUES: Final[tuple[str, ...]] = (
    "organization.view",
    "membership.manage",
    "repository.view",
    "token.manage",
    "source.view",
    "source.sync",
    "source.revoke",
    "knowledge.view",
    "knowledge.propose",
    "knowledge.review",
    "assurance.view",
    "assurance.execute",
    "assurance.review",
    "audit.view",
    "finding.dismiss",
    "policy.override",
    "work.view",
    "work.manage",
    "work.approve",
    "policy.view",
    "policy.manage",
    "evidence.view",
    "evidence.submit",
    "search.query",
    "canvas.view",
    "canvas.manage",
    "mcp.context",
    "artifact.view",
    "artifact.create",
    "scope.manage",
    "github.manage",
    "retention.manage",
)

ACCEPTANCE_INITIATOR_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "source.view",
        "source.sync",
        "work.manage",
        "policy.view",
        "policy.manage",
        "evidence.view",
        "evidence.submit",
        "assurance.execute",
        "knowledge.view",
        "search.query",
        "canvas.view",
        "mcp.context",
        "artifact.view",
        "artifact.create",
    }
)
ACCEPTANCE_REVIEWER_ACTIONS: Final[frozenset[str]] = frozenset({"assurance.review"})

KEY_PATTERN = "^[a-z][a-z0-9_-]{0,63}$"

BOOTSTRAP_SCOPE_SCHEMA: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "roles": {
            "type": "array",
            "minItems": 1,
            "maxItems": 8,
            "uniqueItems": True,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "key": {"type": "string", "pattern": KEY_PATTERN},
                    "code": {"type": "string", "enum": list(ROLE_CODES)},
                    "name": {"type": "string", "minLength": 1, "maxLength": 100},
                },
                "required": ["key", "code", "name"],
            },
        },
        "memberships": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "uniqueItems": True,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "key": {"type": "string", "pattern": KEY_PATTERN},
                    "email": {"type": "string", "format": "email", "maxLength": 300},
                    "display_name": {"type": "string", "minLength": 1, "maxLength": 300},
                    "role_key": {"type": "string", "pattern": KEY_PATTERN},
                },
                "required": ["key", "email", "display_name", "role_key"],
            },
        },
        "repositories": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "uniqueItems": True,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "key": {"type": "string", "pattern": KEY_PATTERN},
                    "external_id": {"type": "string", "minLength": 1, "maxLength": 300},
                    "name": {"type": "string", "minLength": 1, "maxLength": 300},
                },
                "required": ["key", "external_id", "name"],
            },
        },
        "service_identities": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "uniqueItems": True,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "key": {"type": "string", "pattern": KEY_PATTERN},
                    "name": {"type": "string", "minLength": 1, "maxLength": 200},
                    "grants": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 100,
                        "uniqueItems": True,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "repository_key": {"type": "string", "pattern": KEY_PATTERN},
                                "actions": {
                                    "type": "array",
                                    "minItems": 1,
                                    "maxItems": len(ACTION_VALUES),
                                    "uniqueItems": True,
                                    "items": {"type": "string", "enum": list(ACTION_VALUES)},
                                },
                            },
                            "required": ["repository_key", "actions"],
                        },
                    },
                },
                "required": ["key", "name", "grants"],
            },
        },
        "access_scope": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 200},
                "membership_keys": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": KEY_PATTERN},
                },
                "repository_keys": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": KEY_PATTERN},
                },
                "service_identity_keys": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": KEY_PATTERN},
                },
            },
            "required": [
                "name",
                "membership_keys",
                "repository_keys",
                "service_identity_keys",
            ],
        },
        "primary_membership_key": {"type": "string", "pattern": KEY_PATTERN},
        "primary_repository_key": {"type": "string", "pattern": KEY_PATTERN},
        "initiator_service_identity_key": {"type": "string", "pattern": KEY_PATTERN},
        "reviewer_service_identity_key": {"type": "string", "pattern": KEY_PATTERN},
    },
    "required": [
        "roles",
        "memberships",
        "repositories",
        "service_identities",
        "access_scope",
        "primary_membership_key",
        "primary_repository_key",
        "initiator_service_identity_key",
        "reviewer_service_identity_key",
    ],
}


class BootstrapScopeError(ValueError):
    """A requested bootstrap scope was ambiguous or over-broad."""


@dataclass(frozen=True, slots=True)
class RoleRequest:
    key: str
    code: str
    name: str


@dataclass(frozen=True, slots=True)
class MembershipRequest:
    key: str
    email: str
    display_name: str
    role_key: str


@dataclass(frozen=True, slots=True)
class RepositoryRequest:
    key: str
    external_id: str
    name: str


@dataclass(frozen=True, slots=True)
class GrantRequest:
    repository_key: str
    actions: frozenset[str]


@dataclass(frozen=True, slots=True)
class ServiceIdentityRequest:
    key: str
    name: str
    grants: tuple[GrantRequest, ...]


@dataclass(frozen=True, slots=True)
class AccessScopeRequest:
    name: str
    membership_keys: frozenset[str]
    repository_keys: frozenset[str]
    service_identity_keys: frozenset[str]


@dataclass(frozen=True, slots=True)
class BootstrapScopeRequest:
    roles: tuple[RoleRequest, ...]
    memberships: tuple[MembershipRequest, ...]
    repositories: tuple[RepositoryRequest, ...]
    service_identities: tuple[ServiceIdentityRequest, ...]
    access_scope: AccessScopeRequest
    primary_membership_key: str
    primary_repository_key: str
    initiator_service_identity_key: str
    reviewer_service_identity_key: str


def _closed(value: object, *, keys: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BootstrapScopeError(f"Bootstrap scope {label} fields are invalid")
    return cast(dict[str, object], value)


def _text(payload: dict[str, object], key: str, *, maximum: int) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise BootstrapScopeError("Bootstrap scope text field is invalid")
    return value.strip()


def _key(payload: dict[str, object], key: str) -> str:
    value = _text(payload, key, maximum=64)
    if not value[0].islower() or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in value
    ):
        raise BootstrapScopeError("Bootstrap scope key is invalid")
    return value


def _items(value: object, *, minimum: int, maximum: int, label: str) -> list[object]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise BootstrapScopeError(f"Bootstrap scope {label} count is invalid")
    return cast(list[object], value)


def _unique(values: list[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise BootstrapScopeError(f"Bootstrap scope {label} values must be unique")


def parse_bootstrap_scope(value: object) -> BootstrapScopeRequest:
    """Parse the strict wire object and reject every ambiguous cross-reference."""
    root = _closed(
        value,
        keys=frozenset(cast(list[str], BOOTSTRAP_SCOPE_SCHEMA["required"])),
        label="root",
    )
    roles: list[RoleRequest] = []
    for raw in _items(root["roles"], minimum=1, maximum=8, label="role"):
        item = _closed(raw, keys=frozenset({"key", "code", "name"}), label="role")
        code = _text(item, "code", maximum=32)
        if code not in ROLE_CODES:
            raise BootstrapScopeError("Bootstrap scope role code is unknown")
        roles.append(RoleRequest(_key(item, "key"), code, _text(item, "name", maximum=100)))
    _unique([item.key for item in roles], label="role keys")
    _unique([item.code for item in roles], label="role codes")

    memberships: list[MembershipRequest] = []
    for raw in _items(root["memberships"], minimum=1, maximum=32, label="membership"):
        item = _closed(
            raw,
            keys=frozenset({"key", "email", "display_name", "role_key"}),
            label="membership",
        )
        email = _text(item, "email", maximum=300).lower()
        if email.count("@") != 1 or email.startswith("@") or email.endswith("@"):
            raise BootstrapScopeError("Bootstrap scope membership email is invalid")
        memberships.append(
            MembershipRequest(
                _key(item, "key"),
                email,
                _text(item, "display_name", maximum=300),
                _key(item, "role_key"),
            )
        )
    _unique([item.key for item in memberships], label="membership keys")
    _unique([item.email for item in memberships], label="membership emails")

    repositories: list[RepositoryRequest] = []
    for raw in _items(root["repositories"], minimum=1, maximum=100, label="repository"):
        item = _closed(raw, keys=frozenset({"key", "external_id", "name"}), label="repository")
        repositories.append(
            RepositoryRequest(
                _key(item, "key"),
                _text(item, "external_id", maximum=300),
                _text(item, "name", maximum=300),
            )
        )
    _unique([item.key for item in repositories], label="repository keys")
    _unique([item.external_id for item in repositories], label="repository external IDs")

    identities: list[ServiceIdentityRequest] = []
    for raw in _items(root["service_identities"], minimum=1, maximum=32, label="identity"):
        item = _closed(raw, keys=frozenset({"key", "name", "grants"}), label="identity")
        grants: list[GrantRequest] = []
        for raw_grant in _items(item["grants"], minimum=1, maximum=100, label="grant"):
            grant = _closed(
                raw_grant,
                keys=frozenset({"repository_key", "actions"}),
                label="grant",
            )
            raw_actions = _items(
                grant["actions"], minimum=1, maximum=len(ACTION_VALUES), label="action"
            )
            if not all(
                isinstance(action, str) and action in ACTION_VALUES for action in raw_actions
            ):
                raise BootstrapScopeError("Bootstrap scope action is unknown")
            actions = cast(list[str], raw_actions)
            _unique(actions, label="actions")
            grants.append(GrantRequest(_key(grant, "repository_key"), frozenset(actions)))
        _unique([grant.repository_key for grant in grants], label="grant repositories")
        identities.append(
            ServiceIdentityRequest(
                _key(item, "key"),
                _text(item, "name", maximum=200),
                tuple(grants),
            )
        )
    _unique([item.key for item in identities], label="identity keys")
    _unique([item.name for item in identities], label="identity names")

    raw_scope = _closed(
        root["access_scope"],
        keys=frozenset({"name", "membership_keys", "repository_keys", "service_identity_keys"}),
        label="access scope",
    )

    def key_set(name: str, maximum: int) -> frozenset[str]:
        raw_keys = _items(raw_scope[name], minimum=1, maximum=maximum, label=name)
        if not all(isinstance(item, str) for item in raw_keys):
            raise BootstrapScopeError("Bootstrap scope reference key is invalid")
        values = cast(list[str], raw_keys)
        for item in values:
            _key({"key": item}, "key")
        _unique(values, label=name)
        return frozenset(values)

    access_scope = AccessScopeRequest(
        _text(raw_scope, "name", maximum=200),
        key_set("membership_keys", 32),
        key_set("repository_keys", 100),
        key_set("service_identity_keys", 32),
    )
    role_keys = {item.key for item in roles}
    membership_keys = {item.key for item in memberships}
    repository_keys = {item.key for item in repositories}
    identity_keys = {item.key for item in identities}
    if {item.role_key for item in memberships} != role_keys:
        raise BootstrapScopeError("Bootstrap scope roles must be referenced exactly")
    if any(
        grant.repository_key not in repository_keys
        for identity in identities
        for grant in identity.grants
    ):
        raise BootstrapScopeError("Bootstrap scope grant references an unknown repository")
    granted_repository_keys = {
        grant.repository_key for identity in identities for grant in identity.grants
    }
    if granted_repository_keys != repository_keys:
        raise BootstrapScopeError("Bootstrap scope repositories must be granted exactly")
    if (
        access_scope.membership_keys != membership_keys
        or access_scope.repository_keys != repository_keys
        or access_scope.service_identity_keys != identity_keys
    ):
        raise BootstrapScopeError("Bootstrap access scope must bind requested records exactly")
    primary_membership_key = _key(root, "primary_membership_key")
    primary_repository_key = _key(root, "primary_repository_key")
    initiator_key = _key(root, "initiator_service_identity_key")
    reviewer_key = _key(root, "reviewer_service_identity_key")
    if (
        primary_membership_key not in membership_keys
        or primary_repository_key not in repository_keys
    ):
        raise BootstrapScopeError("Bootstrap primary scope reference is unknown")
    if (
        initiator_key not in identity_keys
        or reviewer_key not in identity_keys
        or initiator_key == reviewer_key
    ):
        raise BootstrapScopeError("Bootstrap credential identity references are invalid")
    selected_grants = {
        identity.key: {grant.repository_key for grant in identity.grants}
        for identity in identities
        if identity.key in {initiator_key, reviewer_key}
    }
    if any(primary_repository_key not in grants for grants in selected_grants.values()):
        raise BootstrapScopeError(
            "Bootstrap credential identities must grant the primary repository"
        )
    return BootstrapScopeRequest(
        tuple(roles),
        tuple(memberships),
        tuple(repositories),
        tuple(identities),
        access_scope,
        primary_membership_key,
        primary_repository_key,
        initiator_key,
        reviewer_key,
    )


def validate_acceptance_bootstrap_scope(scope: BootstrapScopeRequest) -> None:
    """Require the exact minimal principals and grants used by the new runner path."""
    if len(scope.roles) != 1 or len(scope.memberships) != 1 or len(scope.repositories) != 1:
        raise BootstrapScopeError("Acceptance scope must request one role, member, and repository")
    if scope.roles[0].code != "VIEWER":
        raise BootstrapScopeError("Acceptance scope human role must be least-privilege VIEWER")
    identities = {item.key: item for item in scope.service_identities}
    if set(identities) != {
        scope.initiator_service_identity_key,
        scope.reviewer_service_identity_key,
    }:
        raise BootstrapScopeError(
            "Acceptance scope must request only runner and reviewer identities"
        )
    initiator = identities[scope.initiator_service_identity_key]
    reviewer = identities[scope.reviewer_service_identity_key]
    if len(initiator.grants) != 1 or len(reviewer.grants) != 1:
        raise BootstrapScopeError("Acceptance identities must use one repository grant")
    if (
        initiator.grants[0].repository_key != scope.primary_repository_key
        or initiator.grants[0].actions != ACCEPTANCE_INITIATOR_ACTIONS
        or reviewer.grants[0].repository_key != scope.primary_repository_key
        or reviewer.grants[0].actions != ACCEPTANCE_REVIEWER_ACTIONS
    ):
        raise BootstrapScopeError("Acceptance identity grants are not the exact minimal set")


def acceptance_bootstrap_scope_payload(
    *,
    admin_email: str,
    admin_display_name: str,
    repository_external_id: str,
    repository_name: str,
    initiator_name: str,
    reviewer_name: str,
    access_scope_name: str,
) -> dict[str, object]:
    """Build the closed minimal public scope without hiding any requested grant."""
    return {
        "roles": [{"key": "viewer", "code": "VIEWER", "name": "Viewer"}],
        "memberships": [
            {
                "key": "operator",
                "email": admin_email,
                "display_name": admin_display_name,
                "role_key": "viewer",
            }
        ],
        "repositories": [
            {
                "key": "repository",
                "external_id": repository_external_id,
                "name": repository_name,
            }
        ],
        "service_identities": [
            {
                "key": "initiator",
                "name": initiator_name,
                "grants": [
                    {
                        "repository_key": "repository",
                        "actions": sorted(ACCEPTANCE_INITIATOR_ACTIONS),
                    }
                ],
            },
            {
                "key": "reviewer",
                "name": reviewer_name,
                "grants": [
                    {
                        "repository_key": "repository",
                        "actions": sorted(ACCEPTANCE_REVIEWER_ACTIONS),
                    }
                ],
            },
        ],
        "access_scope": {
            "name": access_scope_name,
            "membership_keys": ["operator"],
            "repository_keys": ["repository"],
            "service_identity_keys": ["initiator", "reviewer"],
        },
        "primary_membership_key": "operator",
        "primary_repository_key": "repository",
        "initiator_service_identity_key": "initiator",
        "reviewer_service_identity_key": "reviewer",
    }
