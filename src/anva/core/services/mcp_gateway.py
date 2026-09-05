"""Canonical versioned domain facade shared by MCP and HTTP adapters."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import unicodedata
import uuid
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from typing import cast

from django.conf import settings
from django.db import transaction
from django.db.models import Prefetch, Q
from django.utils import timezone
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.contracts.catalog import SOURCE_REFERENCE
from anva.contracts.validation import validate_knowledge_changes
from anva.core.exceptions import (
    DomainOperationError,
    IdempotencyConflictError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AcceptanceCriterion,
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AccessScopeSource,
    AccessSnapshot,
    ContextPacketRecord,
    KnowledgeProposal,
    KnowledgeRelationship,
    MCPProposalSubmission,
    MCPToolInvocation,
    Policy,
    PolicyVersion,
    Repository,
    RepositoryAccessToken,
    Requirement,
    SourceChunkVisibility,
    SourceConnection,
    WorkItem,
    WorkItemRevision,
    canonical_payload_bytes,
    content_hash,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import (
    PacketBudget,
    authorized_assertion_citations,
    build_context_packet,
    get_context_packet,
)
from anva.core.services.creation import submit_knowledge_proposal
from anva.core.services.graph import traverse_graph
from anva.core.services.hostile_inputs import reject_secrets
from anva.core.services.retrieval import (
    authorized_source_chunks,
    get_authorized_assertion,
    get_authorized_entity,
    get_authorized_source_excerpt,
    visible_scope_ids,
)
from anva.core.services.search import search_chunks
from anva.mcp.contracts import (
    CONTRACT_VERSION,
    MAX_PAGE_SIZE,
    MCP_PROTOCOL_VERSIONS,
    PROPOSAL_TOOL_NAMES,
    PUBLIC_NATIVE_ASSERTION_VALUE,
    TOOL_BY_NAME,
)

MAX_GATEWAY_OUTPUT_BYTES = 250_000
MAX_GATEWAY_INPUT_BYTES = 250_000
MAX_CURSOR_OFFSET = 10_000
CURSOR_TTL_SECONDS = 300
_SOURCE_TYPE = {
    "ASSERTION": "DOCUMENT",
    "SOURCE_CHUNK": "DOCUMENT",
    "ENTITY": "DOCUMENT",
    "WORK_ITEM": "DECISION",
    "POLICY": "POLICY",
    "CONTEXT_PACKET": "EVIDENCE",
}
logger = logging.getLogger(__name__)
_PRIVATE_CONTROL_FIELD = re.compile(
    r"(?i)(?:^|[_-])(?:private|oracle|grader|ground[_-]?truth|answer[_-]?key)(?:$|[_-])"
)
_PUBLIC_NATIVE_ASSERTION_VALUE_VALIDATOR = Draft202012Validator(PUBLIC_NATIVE_ASSERTION_VALUE)


class MCPGatewayError(DomainOperationError):
    """A structured, safe failure at the shared MCP/HTTP contract boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: int = 400,
        path: str = "$",
        reason: str = "boundary_rejected",
    ) -> None:
        self.code = code
        self.http_status = http_status
        self.path = path
        self.reason = reason
        super().__init__(message)


def _uuid(arguments: dict[str, object], key: str) -> uuid.UUID:
    return uuid.UUID(cast(str, arguments[key]))


def _limit(arguments: dict[str, object]) -> int:
    return cast(int, arguments.get("limit", 20))


def _cursor_key() -> bytes:
    return str(settings.TOKEN_PEPPER).encode()


def _keyed_payload_hash(payload: object) -> str:
    """Hash boundary payloads without exposing low-entropy values to offline guessing."""
    return hmac.new(
        _cursor_key(),
        canonical_payload_bytes(payload),
        hashlib.sha256,
    ).hexdigest()


def _cursor_timestamp() -> int:
    return int(timezone.now().timestamp())


def _cursor_expires_at(*, actor: ActorContext, issued_at: int) -> int:
    expires_at = issued_at + CURSOR_TTL_SECONDS
    if actor.credential_id is None:
        return expires_at
    credential_expiry = (
        RepositoryAccessToken.objects.filter(
            id=actor.credential_id,
            organization_id=actor.organization_id,
        )
        .values_list("expires_at", flat=True)
        .first()
    )
    if credential_expiry is not None:
        expires_at = min(expires_at, int(credential_expiry.timestamp()))
    return expires_at


def _watermark_rows(rows: Iterable[tuple[object, ...]]) -> list[list[object]]:
    normalized: list[list[object]] = []
    for row in rows:
        normalized.append(
            [
                value.isoformat()
                if isinstance(value, datetime)
                else value
                if value is None or isinstance(value, bool | int | float | str)
                else str(value)
                for value in row
            ]
        )
    return normalized


def _authorization_watermark(
    *,
    actor: ActorContext,
    tool_name: str,
) -> str:
    """Hash current grants, scopes, credential state, and retrieval visibility."""
    contract = TOOL_BY_NAME.get(tool_name)
    action = Action(contract["required_action"]) if contract is not None else Action.REPOSITORY_VIEW
    repository_id = actor.repository_id
    credential_id = actor.credential_id
    if repository_id is None or credential_id is None:
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    authorize_action(
        actor=actor,
        action=action,
        repository_id=repository_id,
    )
    scope_ids = tuple(
        visible_scope_ids(actor=actor, repository_id=repository_id)
        .order_by("id")
        .values_list("id", flat=True)
    )
    principal_filter = (
        Q(service_identity_id=actor.actor_id)
        if actor.actor_type == "SERVICE"
        else Q(membership_id=actor.actor_id)
    )
    parts: dict[str, object] = {
        "credential": _watermark_rows(
            RepositoryAccessToken.objects.filter(
                organization_id=actor.organization_id,
                repository_id=repository_id,
                id=credential_id,
            ).values_list(
                "id",
                "service_identity_id",
                "allowed_actions",
                "expires_at",
                "revoked_at",
            )
        ),
        "repository": _watermark_rows(
            Repository.objects.filter(
                organization_id=actor.organization_id,
                id=repository_id,
            ).values_list("id", "is_active", "updated_at")
        ),
        "grants": _watermark_rows(
            AccessGrant.objects.filter(
                Q(repository_id=repository_id) | Q(repository__isnull=True),
                organization_id=actor.organization_id,
            )
            .filter(principal_filter)
            .order_by("id")
            .values_list(
                "id",
                "repository_id",
                "source_connection_id",
                "action",
                "expires_at",
                "revoked_at",
                "updated_at",
            )
        ),
        "scopes": _watermark_rows(
            AccessScope.objects.filter(
                organization_id=actor.organization_id,
                id__in=scope_ids,
            )
            .order_by("id")
            .values_list(
                "id",
                "revision",
                "is_active",
                "all_memberships",
                "all_service_identities",
                "all_repositories",
                "updated_at",
            )
        ),
        "scope_memberships": _watermark_rows(
            AccessScopeMembership.objects.filter(
                organization_id=actor.organization_id,
                access_scope_id__in=scope_ids,
            )
            .order_by("id")
            .values_list("id", "access_scope_id", "membership_id", "updated_at")
        ),
        "scope_services": _watermark_rows(
            AccessScopeServiceIdentity.objects.filter(
                organization_id=actor.organization_id,
                access_scope_id__in=scope_ids,
            )
            .order_by("id")
            .values_list("id", "access_scope_id", "service_identity_id", "updated_at")
        ),
        "scope_repositories": _watermark_rows(
            AccessScopeRepository.objects.filter(
                organization_id=actor.organization_id,
                access_scope_id__in=scope_ids,
            )
            .order_by("id")
            .values_list("id", "access_scope_id", "repository_id", "updated_at")
        ),
        "scope_sources": _watermark_rows(
            AccessScopeSource.objects.filter(
                organization_id=actor.organization_id,
                access_scope_id__in=scope_ids,
            )
            .order_by("id")
            .values_list("id", "access_scope_id", "source_connection_id", "updated_at")
        ),
        "sources": _watermark_rows(
            SourceConnection.objects.filter(
                organization_id=actor.organization_id,
            )
            .filter(
                Q(repository_id=repository_id)
                | Q(access_scope_id__in=scope_ids)
                | Q(accessscopesource__access_scope_id__in=scope_ids)
            )
            .distinct()
            .order_by("id")
            .values_list(
                "id",
                "repository_id",
                "access_scope_id",
                "state",
                "revision",
                "updated_at",
            )
        ),
        "snapshots": _watermark_rows(
            AccessSnapshot.objects.filter(
                organization_id=actor.organization_id,
                access_scope_id__in=scope_ids,
            )
            .order_by("id")
            .values_list(
                "id",
                "source_connection_id",
                "access_scope_id",
                "scope_revision",
                "content_hash",
                "captured_at",
                "revoked_at",
            )
        ),
        "visibility": _watermark_rows(
            SourceChunkVisibility.objects.filter(
                organization_id=actor.organization_id,
                access_scope_id__in=scope_ids,
            )
            .order_by("id")
            .values_list(
                "id",
                "source_chunk_id",
                "source_observation_id",
                "access_snapshot_id",
                "access_scope_id",
                "state",
                "observed_at",
                "revoked_at",
            )
        ),
    }
    return _keyed_payload_hash(parts)


def _binding_payload(
    *,
    actor: ActorContext,
    tool_name: str,
    arguments: dict[str, object],
) -> dict[str, object]:
    stable_arguments = {
        key: value for key, value in arguments.items() if key not in {"cursor", "limit"}
    }
    return {
        "contract_version": CONTRACT_VERSION,
        "tool": tool_name,
        "organization_id": str(actor.organization_id),
        "repository_id": str(actor.repository_id),
        "actor_type": actor.actor_type,
        "actor_id": actor.actor_id,
        "credential_id": str(actor.credential_id) if actor.credential_id else None,
        "request_hash": _keyed_payload_hash(stable_arguments),
        "authorization_watermark": _authorization_watermark(
            actor=actor,
            tool_name=tool_name,
        ),
    }


def _encode_cursor(
    *,
    actor: ActorContext,
    tool_name: str,
    arguments: dict[str, object],
    offset: int,
) -> str:
    issued_at = _cursor_timestamp()
    expires_at = _cursor_expires_at(actor=actor, issued_at=issued_at)
    payload = {
        **_binding_payload(actor=actor, tool_name=tool_name, arguments=arguments),
        "offset": offset,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    encoded = base64.urlsafe_b64encode(canonical_payload_bytes(payload)).rstrip(b"=")
    signature = hmac.new(_cursor_key(), encoded, hashlib.sha256).hexdigest().encode()
    return (encoded + b"." + signature).decode()


def _decode_cursor(
    *,
    actor: ActorContext,
    tool_name: str,
    arguments: dict[str, object],
) -> int:
    cursor = arguments.get("cursor")
    if cursor is None:
        return 0
    if not isinstance(cursor, str):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    encoded, separator, signature = cursor.encode().partition(b".")
    expected = hmac.new(_cursor_key(), encoded, hashlib.sha256).hexdigest().encode()
    if separator != b"." or not hmac.compare_digest(signature, expected):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    try:
        padding = b"=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except (ValueError, json.JSONDecodeError):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid") from None
    if not isinstance(payload, dict):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    now = _cursor_timestamp()
    issued_at = payload.get("issued_at")
    expires_at = payload.get("expires_at")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or issued_at > now + 5
        or expires_at <= now
        or expires_at - issued_at > CURSOR_TTL_SECONDS
    ):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    expected_binding = _binding_payload(
        actor=actor,
        tool_name=tool_name,
        arguments=arguments,
    )
    if any(payload.get(key) != value for key, value in expected_binding.items()):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    offset = payload.get("offset")
    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or not 0 <= offset <= MAX_CURSOR_OFFSET
    ):
        raise MCPGatewayError("invalid_cursor", "Pagination cursor is invalid")
    return offset


def _page(
    *,
    actor: ActorContext,
    tool_name: str,
    arguments: dict[str, object],
    values: list[dict[str, object]],
    offset: int,
) -> tuple[list[dict[str, object]], str | None]:
    limit = _limit(arguments)
    selected = values[offset : offset + limit]
    next_offset = offset + len(selected)
    cursor = (
        _encode_cursor(
            actor=actor,
            tool_name=tool_name,
            arguments=arguments,
            offset=next_offset,
        )
        if next_offset < len(values)
        else None
    )
    return selected, cursor


def _repository(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    action: Action,
    for_update: bool = False,
) -> Repository:
    """Authorize the actor/repository binding before a composite tenant lookup."""
    authorize_action(actor=actor, action=action, repository_id=repository_id)
    lookup = get_tenant_record_for_update if for_update else get_tenant_record
    return lookup(
        queryset=Repository.objects.filter(is_active=True),
        record_id=repository_id,
        organization_id=actor.organization_id,
    )


def _work_item(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    work_item_id: uuid.UUID,
) -> tuple[WorkItem, WorkItemRevision]:
    scope_ids = visible_scope_ids(actor=actor, repository_id=repository_id)
    work_item = get_tenant_record(
        queryset=WorkItem.objects.filter(
            repository_id=repository_id,
            access_scope__in=scope_ids,
        ),
        record_id=work_item_id,
        organization_id=actor.organization_id,
    )
    authorize_action(
        actor=actor,
        action=Action.WORK_VIEW,
        repository_id=repository_id,
        access_scope_id=work_item.access_scope_id,
    )
    revision = WorkItemRevision.objects.filter(
        organization_id=actor.organization_id,
        work_item_id=work_item.id,
        revision=work_item.revision,
    ).first()
    if revision is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    return work_item, revision


def _work_item_data(work_item: WorkItem, revision: WorkItemRevision) -> dict[str, object]:
    return {
        "work_item_id": str(work_item.id),
        "repository_id": str(work_item.repository_id),
        "external_key": work_item.external_key,
        "title": work_item.title,
        "work_type": work_item.work_type,
        "status": work_item.status,
        "revision": revision.revision,
        "content_hash": revision.content_hash,
    }


def _resolve_repository(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    repository = _repository(
        actor=actor,
        repository_id=_uuid(arguments, "repository_id"),
        action=Action.REPOSITORY_VIEW,
    )
    return {
        "repository_id": str(repository.id),
        "organization_id": str(repository.organization_id),
        "external_id": repository.external_id,
        "name": repository.name,
        "active": repository.is_active,
    }


def _resolve_work_item(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    repository_id = _uuid(arguments, "repository_id")
    _repository(actor=actor, repository_id=repository_id, action=Action.WORK_VIEW)
    queryset = WorkItem.objects.filter(
        organization_id=actor.organization_id,
        repository_id=repository_id,
        access_scope__in=visible_scope_ids(actor=actor, repository_id=repository_id),
    )
    if "work_item_id" in arguments:
        queryset = queryset.filter(id=_uuid(arguments, "work_item_id"))
    else:
        queryset = queryset.filter(external_key=cast(str, arguments["external_key"]))
    work_item = queryset.first()
    if work_item is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    work_item, revision = _work_item(
        actor=actor,
        repository_id=repository_id,
        work_item_id=work_item.id,
    )
    return _work_item_data(work_item, revision)


def _context_packet(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    repository_id = _uuid(arguments, "repository_id")
    _repository(actor=actor, repository_id=repository_id, action=Action.MCP_CONTEXT)
    if "packet_id" in arguments:
        packet_id = _uuid(arguments, "packet_id")
        packet = get_context_packet(
            actor=actor,
            repository_id=repository_id,
            packet_id=packet_id,
        )
        return {"packet_id": str(packet_id), "created": False, "packet": packet}
    raw_budget = cast(dict[str, object], arguments.get("budget", {}))
    budget = PacketBudget(
        max_items=cast(int, raw_budget.get("max_items", 50)),
        max_tokens=cast(int, raw_budget.get("max_tokens", 8_000)),
        max_bytes=cast(int, raw_budget.get("max_bytes", 100_000)),
        max_citations=cast(int, raw_budget.get("max_citations", 100)),
    )
    record, created = build_context_packet(
        actor=actor,
        repository_id=repository_id,
        task=cast(str, arguments["task"]),
        phase=cast(str, arguments["phase"]),
        budget=budget,
    )
    return {
        "packet_id": str(record.id),
        "created": created,
        "packet": cast(dict[str, object], record.artifact.payload),
    }


def _search(
    actor: ActorContext, arguments: dict[str, object]
) -> tuple[dict[str, object], str | None]:
    repository_id = _uuid(arguments, "repository_id")
    offset = _decode_cursor(actor=actor, tool_name="anva.search", arguments=arguments)
    limit = _limit(arguments)
    if offset + limit > 100:
        raise MCPGatewayError(
            "pagination_limit_exceeded",
            "Search pagination is bounded to the first 100 authorized results",
        )
    response = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query=cast(str, arguments["query"]),
        phase=cast(str | None, arguments.get("phase")),
        limit=min(100, offset + limit + 1),
    )
    values = [result.as_dict() for result in response.results]
    selected, cursor = _page(
        actor=actor,
        tool_name="anva.search",
        arguments=arguments,
        values=values,
        offset=offset,
    )
    return {"results": selected}, cursor


def _entity(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    entity = get_authorized_entity(
        actor=actor,
        repository_id=_uuid(arguments, "repository_id"),
        entity_id=_uuid(arguments, "entity_id"),
    )
    return {
        "entity_id": str(entity.id),
        "entity_type": entity.entity_type,
        "canonical_key": entity.canonical_key,
        "display_name": entity.display_name,
        "attributes": cast(dict[str, object], entity.attributes),
        "revision": entity.revision,
    }


def _relationships(
    actor: ActorContext,
    arguments: dict[str, object],
) -> tuple[dict[str, object], str | None]:
    repository_id = _uuid(arguments, "repository_id")
    entity_id = _uuid(arguments, "entity_id")
    get_authorized_entity(
        actor=actor,
        repository_id=repository_id,
        entity_id=entity_id,
    )
    offset = _decode_cursor(
        actor=actor,
        tool_name="anva.get_relationships",
        arguments=arguments,
    )
    graph = traverse_graph(
        actor=actor,
        repository_id=repository_id,
        start_entity_id=entity_id,
        depth=1,
        edge_limit=500,
    )
    values = [edge.as_dict() for edge in graph.edges]
    selected, cursor = _page(
        actor=actor,
        tool_name="anva.get_relationships",
        arguments=arguments,
        values=values,
        offset=offset,
    )
    return {"entity_id": str(entity_id), "relationships": selected}, cursor


def _repository_profile(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    data = _resolve_repository(actor, arguments)
    return {
        **data,
        "profile_version": 1,
        "limitations": [
            "MVP repository profiles contain identity and activation state only; "
            "onboarding-derived commands and ownership fields are not yet modeled."
        ],
    }


def _policy_bundle(
    actor: ActorContext,
    arguments: dict[str, object],
) -> tuple[dict[str, object], str | None]:
    repository_id = _uuid(arguments, "repository_id")
    _repository(actor=actor, repository_id=repository_id, action=Action.POLICY_VIEW)
    scope_ids = visible_scope_ids(actor=actor, repository_id=repository_id)
    policies = list(
        Policy.objects.filter(
            organization_id=actor.organization_id,
            access_scope__in=scope_ids,
            status=Policy.Status.ACTIVE,
        )
        .prefetch_related(
            Prefetch(
                "policyversion_set",
                queryset=PolicyVersion.objects.order_by("version"),
            )
        )
        .order_by("id")[:501]
    )
    values: list[dict[str, object]] = []
    repository_text = str(repository_id)
    for policy in policies:
        authorize_action(
            actor=actor,
            action=Action.POLICY_VIEW,
            repository_id=repository_id,
            access_scope_id=policy.access_scope_id,
        )
        versions = list(policy.policyversion_set.all())
        version = next((item for item in versions if item.version == policy.revision), None)
        if version is None:
            continue
        binding = getattr(version, "policybinding", None)
        if (
            binding is not None
            and binding.repository_ids
            and repository_text not in binding.repository_ids
        ):
            continue
        requirements = list(
            version.policyrequirement_set.order_by("code").values(
                "code",
                "description",
                "enforcement",
                "check_type",
                "required_evidence",
                "required_approval",
            )[:100]
        )
        values.append(
            {
                "policy_id": str(policy.id),
                "policy_version_id": str(version.id),
                "name": policy.name,
                "owner": policy.owner,
                "version": version.version,
                "schema_version": version.schema_version,
                "content_hash": version.content_hash,
                "effective_at": version.effective_at.isoformat(),
                "expires_at": version.expires_at.isoformat() if version.expires_at else None,
                "binding": (
                    {
                        "scope_level": binding.scope_level,
                        "mandatory": binding.mandatory,
                        "repository_ids": binding.repository_ids[:100],
                        "path_patterns": binding.path_patterns[:100],
                        "target_branches": binding.target_branches[:100],
                    }
                    if binding is not None
                    else None
                ),
                "requirements": requirements,
            }
        )
    offset = _decode_cursor(
        actor=actor,
        tool_name="anva.get_policy_bundle",
        arguments=arguments,
    )
    selected, cursor = _page(
        actor=actor,
        tool_name="anva.get_policy_bundle",
        arguments=arguments,
        values=values,
        offset=offset,
    )
    return {"policies": selected}, cursor


def _requirements(
    actor: ActorContext,
    arguments: dict[str, object],
) -> tuple[dict[str, object], str | None]:
    repository_id = _uuid(arguments, "repository_id")
    work_item, revision = _work_item(
        actor=actor,
        repository_id=repository_id,
        work_item_id=_uuid(arguments, "work_item_id"),
    )
    requirements = list(
        Requirement.objects.filter(
            organization_id=actor.organization_id,
            work_item_revision=revision,
        ).order_by("position", "id")[:501]
    )
    values: list[dict[str, object]] = []
    for requirement in requirements:
        criteria = list(
            AcceptanceCriterion.objects.filter(
                organization_id=actor.organization_id,
                work_item_revision=revision,
                requirement=requirement,
            )
            .order_by("position", "id")
            .values(
                "id",
                "code",
                "normalized_text",
                "required_evidence_types",
                "manual_approval_allowed",
            )[:50]
        )
        values.append(
            {
                "requirement_id": str(requirement.id),
                "code": requirement.code,
                "text": requirement.normalized_text,
                "origin": requirement.origin,
                "owner": requirement.owner,
                "status": requirement.status,
                "requires_approval": requirement.requires_approval,
                "source_references": requirement.source_references[:50],
                "related_entity_ids": requirement.related_entity_ids[:100],
                "acceptance_criteria": [
                    {
                        **criterion,
                        "id": str(criterion["id"]),
                    }
                    for criterion in criteria
                ],
            }
        )
    offset = _decode_cursor(
        actor=actor,
        tool_name="anva.get_requirements",
        arguments=arguments,
    )
    selected, cursor = _page(
        actor=actor,
        tool_name="anva.get_requirements",
        arguments=arguments,
        values=values,
        offset=offset,
    )
    return {
        "work_item_id": str(work_item.id),
        "revision": revision.revision,
        "requirements": selected,
    }, cursor


def _assertion_explanation(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    repository_id = _uuid(arguments, "repository_id")
    assertion = get_authorized_assertion(
        actor=actor,
        repository_id=repository_id,
        assertion_id=_uuid(arguments, "assertion_id"),
        action=Action.KNOWLEDGE_VIEW,
    )
    sources = authorized_assertion_citations(
        actor=actor,
        repository_id=repository_id,
        assertion_id=assertion.id,
    )
    return {
        "assertion_id": str(assertion.id),
        "summary": (
            f"{assertion.subject_key} {assertion.predicate} "
            f"{json.dumps(assertion.value, ensure_ascii=False, sort_keys=True)}"
        ),
        "freshness": assertion.staleness_state,
        "is_inferred": assertion.is_inferred,
        "review_state": assertion.review_state,
        "sources": list(sources),
    }


def _source_excerpt(actor: ActorContext, arguments: dict[str, object]) -> dict[str, object]:
    excerpt = get_authorized_source_excerpt(
        actor=actor,
        repository_id=_uuid(arguments, "repository_id"),
        chunk_id=_uuid(arguments, "chunk_id"),
    )
    offset = cast(int, arguments.get("offset", 0))
    maximum = cast(int, arguments.get("max_characters", 2_000))
    text = excerpt.text[offset : offset + maximum]
    return {
        "chunk_id": str(excerpt.chunk_id),
        "text": text,
        "content_hash": excerpt.content_hash,
        "offset": offset,
        "truncated": offset + len(text) < len(excerpt.text),
        "provenance": {
            "pointer": excerpt.pointer,
            "canonical_url": excerpt.canonical_url,
            "source_location_id": str(excerpt.source_location_id),
            "source_observation_id": str(excerpt.source_observation_id),
            "access_snapshot_id": str(excerpt.access_snapshot_id),
            "observed_at": excerpt.observed_at.isoformat(),
        },
        "trust": "UNTRUSTED_INERT_SOURCE_TEXT",
    }


def _require_scope(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
) -> str:
    decision = authorize_action(
        actor=actor,
        action=Action.KNOWLEDGE_PROPOSE,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
    )
    return decision.authorization_path


def _source_reference(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    reference: dict[str, str],
) -> dict[str, object]:
    kind = reference["kind"]
    source_id = uuid.UUID(reference["id"])
    revision_id: str | None = None
    canonical_url: str | None = None
    source_hash: str | None = None
    observed_at = timezone.now()
    locator = f"anva:{kind.casefold()}:{source_id}"
    if kind == "ASSERTION":
        assertion = get_authorized_assertion(
            actor=actor,
            repository_id=repository_id,
            assertion_id=source_id,
            action=Action.KNOWLEDGE_VIEW,
        )
        if assertion.access_scope_id != access_scope_id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        source_hash = content_hash(
            {
                "subject_key": assertion.subject_key,
                "predicate": assertion.predicate,
                "value": assertion.value,
                "revision": assertion.revision,
            }
        )
        observed_at = assertion.observed_at
    elif kind == "SOURCE_CHUNK":
        excerpt = get_authorized_source_excerpt(
            actor=actor,
            repository_id=repository_id,
            chunk_id=source_id,
        )
        if (
            not authorized_source_chunks(
                actor=actor,
                repository_id=repository_id,
            )
            .filter(id=source_id, sourcechunkvisibility__access_scope_id=access_scope_id)
            .exists()
        ):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        revision_id = str(excerpt.source_observation_id)
        canonical_url = excerpt.canonical_url
        source_hash = excerpt.content_hash
        observed_at = excerpt.observed_at
        locator = excerpt.pointer
    elif kind == "ENTITY":
        entity = get_authorized_entity(
            actor=actor,
            repository_id=repository_id,
            entity_id=source_id,
        )
        if entity.access_scope_id != access_scope_id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        source_hash = content_hash(
            {
                "canonical_key": entity.canonical_key,
                "attributes": entity.attributes,
                "revision": entity.revision,
            }
        )
        observed_at = entity.updated_at
    elif kind == "WORK_ITEM":
        work_item, revision = _work_item(
            actor=actor,
            repository_id=repository_id,
            work_item_id=source_id,
        )
        if work_item.access_scope_id != access_scope_id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        revision_id = str(revision.id)
        source_hash = revision.content_hash
        observed_at = revision.created_at
    elif kind == "POLICY":
        policy = get_tenant_record(
            queryset=Policy.objects.filter(access_scope_id=access_scope_id),
            record_id=source_id,
            organization_id=actor.organization_id,
        )
        authorize_action(
            actor=actor,
            action=Action.POLICY_VIEW,
            repository_id=repository_id,
            access_scope_id=policy.access_scope_id,
        )
        version = PolicyVersion.objects.filter(
            organization_id=actor.organization_id,
            policy=policy,
            version=policy.revision,
        ).first()
        if version is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        revision_id = str(version.id)
        source_hash = version.content_hash
        observed_at = version.created_at
    elif kind == "CONTEXT_PACKET":
        packet = (
            ContextPacketRecord.objects.filter(
                id=source_id,
                organization_id=actor.organization_id,
                repository_id=repository_id,
                access_scope_id=access_scope_id,
            )
            .select_related("artifact")
            .first()
        )
        if packet is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        get_context_packet(
            actor=actor,
            repository_id=repository_id,
            packet_id=packet.id,
        )
        revision_id = str(packet.artifact_id)
        source_hash = packet.artifact.content_hash
        observed_at = packet.generated_at
    else:  # pragma: no cover - JSON Schema rejects unknown kinds.
        raise ValueError("Unknown proposal source reference kind")
    normalized: dict[str, object] = {
        "source_id": str(source_id),
        "source_type": _SOURCE_TYPE[kind],
        "revision_id": revision_id,
        "canonical_url": canonical_url,
        "content_hash": source_hash,
        "observed_at": observed_at.isoformat(),
        "locator": locator,
    }
    Draft202012Validator(SOURCE_REFERENCE, format_checker=FormatChecker()).validate(normalized)
    return normalized


def _proposal_change(
    *,
    actor: ActorContext,
    tool_name: str,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    arguments: dict[str, object],
) -> tuple[MCPProposalSubmission.Kind, dict[str, object]]:
    if tool_name == "anva.propose_correction":
        assertion = get_authorized_assertion(
            actor=actor,
            repository_id=repository_id,
            assertion_id=_uuid(arguments, "assertion_id"),
            action=Action.KNOWLEDGE_VIEW,
        )
        if assertion.access_scope_id != access_scope_id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        return MCPProposalSubmission.Kind.CORRECTION, {
            "operation": "CORRECT",
            "target_id": str(assertion.id),
            "predicate": "knowledge.correction",
            "value": arguments["correction"],
            "is_inferred": False,
        }
    if tool_name == "anva.propose_relationship":
        source = get_authorized_entity(
            actor=actor,
            repository_id=repository_id,
            entity_id=_uuid(arguments, "source_entity_id"),
        )
        target = get_authorized_entity(
            actor=actor,
            repository_id=repository_id,
            entity_id=_uuid(arguments, "target_entity_id"),
        )
        if (
            source.id == target.id
            or source.access_scope_id != access_scope_id
            or target.access_scope_id != access_scope_id
            or arguments["relationship_type"] not in KnowledgeRelationship.RelationshipType.values
        ):
            raise ValueError("Relationship proposal is invalid")
        return MCPProposalSubmission.Kind.RELATIONSHIP, {
            "operation": "ADD",
            "target_id": None,
            "predicate": "knowledge.relationship",
            "value": {
                "source_entity_id": str(source.id),
                "target_entity_id": str(target.id),
                "relationship_type": arguments["relationship_type"],
                "rationale": arguments["rationale"],
            },
            "is_inferred": False,
        }
    work_item, _revision = _work_item(
        actor=actor,
        repository_id=repository_id,
        work_item_id=_uuid(arguments, "work_item_id"),
    )
    if work_item.access_scope_id != access_scope_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if tool_name == "anva.propose_decision":
        return MCPProposalSubmission.Kind.DECISION, {
            "operation": "ADD",
            "target_id": str(work_item.id),
            "predicate": "work.decision",
            "value": {
                "title": arguments["title"],
                "outcome": arguments["outcome"],
                "rationale": arguments["rationale"],
            },
            "is_inferred": False,
        }
    if tool_name == "anva.submit_work_summary":
        return MCPProposalSubmission.Kind.WORK_SUMMARY, {
            "operation": "ADD",
            "target_id": str(work_item.id),
            "predicate": "work.summary",
            "value": arguments["summary_data"],
            "is_inferred": False,
        }
    return MCPProposalSubmission.Kind.PREFLIGHT_SUMMARY, {
        "operation": "ADD",
        "target_id": str(work_item.id),
        "predicate": "work.preflight_summary",
        "value": {
            "commit_sha": arguments["commit_sha"],
            "checks": arguments["checks"],
            "limitations": arguments["limitations"],
            "advisory": True,
        },
        "is_inferred": False,
    }


def _proposal(
    actor: ActorContext, tool_name: str, arguments: dict[str, object]
) -> dict[str, object]:
    repository_id = _uuid(arguments, "repository_id")
    access_scope_id = _uuid(arguments, "access_scope_id")
    authorization_path = _require_scope(
        actor=actor,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
    )
    actor = replace(actor, authorization_path=authorization_path)
    payload_for_hash = {
        "tool": tool_name,
        **{key: value for key, value in arguments.items() if key != "idempotency_key"},
    }
    payload_hash = _keyed_payload_hash(payload_for_hash)
    idempotency_hash = _keyed_payload_hash(arguments["idempotency_key"])
    _repository(
        actor=actor,
        repository_id=repository_id,
        action=Action.KNOWLEDGE_PROPOSE,
        for_update=True,
    )
    existing = (
        MCPProposalSubmission.objects.select_related("knowledge_proposal")
        .filter(
            organization_id=actor.organization_id,
            repository_id=repository_id,
            idempotency_hash=idempotency_hash,
        )
        .first()
    )
    if existing is not None:
        if (
            existing.payload_hash != payload_hash
            or existing.actor_type != actor.actor_type
            or existing.actor_id != actor.actor_id
            or existing.access_scope_id != access_scope_id
        ):
            raise IdempotencyConflictError(
                "The proposal idempotency key was already used for different content"
            )
        proposal = existing.knowledge_proposal
        if proposal.state != KnowledgeProposal.State.PROPOSED:
            raise IdempotencyConflictError(
                "The replayed proposal is no longer in the original review state"
            )
        return {
            "proposal_id": str(proposal.id),
            "submission_id": str(existing.id),
            "proposal_kind": existing.proposal_kind,
            "review_state": KnowledgeProposal.State.PROPOSED,
            "approved": False,
            "review_required": True,
            "created": False,
        }
    references = [
        _source_reference(
            actor=actor,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
            reference=cast(dict[str, str], reference),
        )
        for reference in cast(list[dict[str, object]], arguments["source_references"])
    ]
    kind, change = _proposal_change(
        actor=actor,
        tool_name=tool_name,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
        arguments=arguments,
    )
    validate_knowledge_changes([change])
    proposal = submit_knowledge_proposal(
        actor=actor,
        summary=cast(str, arguments["summary"]),
        proposed_changes=[change],
        anva_sources=references,
    )
    if proposal.state != KnowledgeProposal.State.PROPOSED:
        raise ValueError("New agent proposals must remain in PROPOSED state")
    submission = MCPProposalSubmission.objects.create(
        organization_id=actor.organization_id,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
        knowledge_proposal=proposal,
        credential_id=actor.credential_id,
        proposal_kind=kind,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        payload_hash=payload_hash,
        idempotency_hash=idempotency_hash,
    )
    return {
        "proposal_id": str(proposal.id),
        "submission_id": str(submission.id),
        "proposal_kind": kind,
        "review_state": KnowledgeProposal.State.PROPOSED,
        "approved": False,
        "review_required": True,
        "created": True,
    }


HandlerResult = dict[str, object] | tuple[dict[str, object], str | None]
Handler = Callable[[ActorContext, dict[str, object]], HandlerResult]
_READ_HANDLERS: dict[str, Handler] = {
    "anva.resolve_repository": _resolve_repository,
    "anva.resolve_work_item": _resolve_work_item,
    "anva.get_context_packet": _context_packet,
    "anva.search": _search,
    "anva.get_entity": _entity,
    "anva.get_relationships": _relationships,
    "anva.get_repository_profile": _repository_profile,
    "anva.get_policy_bundle": _policy_bundle,
    "anva.get_requirements": _requirements,
    "anva.explain_assertion": _assertion_explanation,
    "anva.get_source_excerpt": _source_excerpt,
}


def _record_invocation(
    *,
    actor: ActorContext,
    transport: str,
    tool_name: str,
    required_action: str,
    arguments: dict[str, object],
    outcome: MCPToolInvocation.Outcome,
    error_code: str = "",
    target_id: uuid.UUID | None = None,
) -> None:
    if actor.repository_id is None:
        return
    MCPToolInvocation.objects.create(
        organization_id=actor.organization_id,
        repository_id=actor.repository_id,
        credential_id=actor.credential_id,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        transport=transport,
        tool_name=tool_name,
        required_action=required_action,
        arguments_hash=_keyed_payload_hash(arguments),
        request_id=actor.request_id,
        outcome=outcome,
        error_code=error_code,
        target_id=target_id,
    )


def _validate(schema: dict[str, object], payload: object, *, code: str, label: str) -> None:
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    except ValidationError as error:
        path = "$"
        for part in error.absolute_path:
            if isinstance(part, int):
                path += f"[{part}]"
            elif isinstance(part, str) and part.replace("_", "").replace("-", "").isalnum():
                path += f".{part}"
            else:
                path += ".*"
        validators = {error.validator}
        pending = list(error.context)
        while pending:
            nested = pending.pop()
            validators.add(nested.validator)
            pending.extend(nested.context)
        reason = {
            "additionalProperties": "closed_object",
            "anyOf": "value_shape",
            "const": "allowed_value",
            "enum": "allowed_value",
            "format": "value_format",
            "maxItems": "collection_limit",
            "maxLength": "value_limit",
            "maxProperties": "collection_limit",
            "minItems": "collection_limit",
            "minLength": "value_limit",
            "minProperties": "collection_limit",
            "not": "value_shape",
            "oneOf": "value_shape",
            "pattern": "value_format",
            "required": "required_field",
            "type": "value_type",
        }.get(
            "enum"
            if "enum" in validators
            else "const"
            if "const" in validators
            else error.validator,
            "schema_rule",
        )
        raise MCPGatewayError(
            code,
            f"{label} failed (path={path}, reason={reason})",
            path=path,
            reason=reason,
        ) from error


def _reject_private_output_material(
    value: object,
    *,
    path: str = "$",
    depth: int = 0,
) -> None:
    """Reject control-plane fields and credential strings before an MCP result leaves Anva."""
    if depth > 20:
        raise MCPGatewayError(
            "invalid_tool_output",
            "MCP output contains unsupported nesting",
            path=path,
            reason="nesting_limit",
        )
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            try:
                reject_secrets(key_text)
            except ValueError:
                raise MCPGatewayError(
                    "invalid_tool_output",
                    "MCP output contains prohibited credential material",
                    path=f"{path}.*",
                    reason="secret_material",
                ) from None
            child_path = (
                f"{path}.{key_text}" if key_text.replace("_", "").isalnum() else f"{path}.*"
            )
            normalized_key = re.sub(r"[^a-z0-9]", "", key_text.casefold())
            if _PRIVATE_CONTROL_FIELD.search(key_text) or normalized_key.startswith(
                ("private", "oracle", "grader", "groundtruth", "answerkey")
            ):
                raise MCPGatewayError(
                    "invalid_tool_output",
                    "MCP output contains prohibited private control material",
                    path=child_path,
                    reason="private_control_material",
                )
            _reject_private_output_material(child, path=child_path, depth=depth + 1)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_private_output_material(child, path=f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, str):
        try:
            reject_secrets(_mask_public_credential_terminology(value))
        except ValueError:
            raise MCPGatewayError(
                "invalid_tool_output",
                "MCP output contains prohibited credential material",
                path=path,
                reason="secret_material",
            ) from None


_PUBLIC_BEARER_TERMINOLOGY = re.compile(
    r"(?i)\b(?:(?:long|short)[ -]lived\s+)?(?:shared\s+)?"
    r"bearer\s+(?:token|tokens|authentication|credential|credentials|scheme)\b"
)
_AUTHORIZATION_VALUE_PREFIX = re.compile(r"(?i)authorization\s*[:=]\s*$")
_ZERO_WIDTH = re.compile("[\u00ad\u200b\u200c\u200d\u2060\ufeff]")
_DISCLOSURE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:is|was|equals?)\s+"
    r"(?!(?:approved|documented|prohibited|deprecated|forbidden|not|never|required|unsupported|obsolete)\b)\S+"
)
_PUBLIC_PROSE_FOLLOWERS = frozenset(
    {
        "and",
        "are",
        "authentication",
        "became",
        "by",
        "during",
        "for",
        "from",
        "in",
        "is",
        "must",
        "only",
        "or",
        "requires",
        "remain",
        "remains",
        "should",
        "to",
        "was",
        "were",
        "with",
        "without",
    }
)
_VALUE_CONNECTORS = frozenset({"and", "during", "for", "from", "in", "or", "to", "with"})
_SAFE_CONNECTOR_CLAUSE_WORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "approved",
        "authentication",
        "authorization",
        "audience",
        "control",
        "controls",
        "documented",
        "demonstration",
        "examples",
        "hour",
        "identity",
        "is",
        "migration",
        "must",
        "never",
        "obsolete",
        "one",
        "operator",
        "policy",
        "production",
        "prohibited",
        "public",
        "ready",
        "remain",
        "remained",
        "remains",
        "required",
        "rotation",
        "sample",
        "script",
        "separate",
        "service",
        "services",
        "shell",
        "standard",
        "standards",
        "unsupported",
        "was",
        "validation",
        "workload",
        "are",
        "as",
        "be",
    }
)


def _mask_public_credential_terminology(value: str) -> str:
    """Mask bearer terminology, but never credential syntax, before output scanning."""

    classified = unicodedata.normalize("NFKC", _ZERO_WIDTH.sub("", value))

    def replacement(match: re.Match[str]) -> str:
        # An Authorization field is credential syntax even when its value is a weak word.
        if _AUTHORIZATION_VALUE_PREFIX.search(classified[: match.start()]):
            return match.group(0)
        tail = classified[match.end() :]
        sentence_tail = re.split(r"[.!?\n]", tail, maxsplit=1)[0]
        if re.match(r"\s*[,;:=]\s*(?!(?:which|and|or|but)\b)\S+", sentence_tail, re.I):
            return match.group(0)
        if _DISCLOSURE_ASSIGNMENT.search(sentence_tail):
            return match.group(0)
        following = re.match(r"\s+([^\s,.;:]+)", sentence_tail)
        if following is not None and following.group(1).casefold() not in _PUBLIC_PROSE_FOLLOWERS:
            return match.group(0)
        if following is not None and following.group(1).casefold() in _VALUE_CONNECTORS:
            clause = sentence_tail[following.end() :].strip()
            if re.fullmatch(r"[A-Za-z0-9\s()'-]+", clause) is None:
                return match.group(0)
            clause_words = re.findall(r"[a-z0-9]+", clause.casefold())
            if any(word not in _SAFE_CONNECTOR_CLAUSE_WORDS for word in clause_words):
                return match.group(0)
        return "public authentication terminology"

    return _PUBLIC_BEARER_TERMINOLOGY.sub(replacement, classified)


def _normalize_public_output(
    tool_name: str,
    result: dict[str, object],
) -> dict[str, object]:
    """Return a closed public representation for arbitrary persisted assertion JSON."""
    if tool_name != "anva.get_context_packet":
        return result
    normalized = deepcopy(result)
    data = normalized.get("data")
    if not isinstance(data, dict):
        return normalized
    packet = data.get("packet")
    if not isinstance(packet, dict):
        return normalized
    items = packet.get("items")
    if not isinstance(items, list):
        return normalized
    for item in items:
        if not isinstance(item, dict):
            continue
        payload = item.get("payload")
        if not isinstance(payload, dict):
            continue
        value_containers = [payload]
        if item.get("kind") == "CONFLICT":
            value_containers.extend(
                side for name in ("left", "right") if isinstance((side := payload.get(name)), dict)
            )
        for value_container in value_containers:
            if "value" not in value_container:
                continue
            value = value_container["value"]
            if _PUBLIC_NATIVE_ASSERTION_VALUE_VALIDATOR.is_valid(value):
                continue
            value_container["value"] = {
                "format": "CANONICAL_JSON",
                "json": canonical_payload_bytes(value).decode("utf-8"),
            }
    return normalized


def _target_id(data: dict[str, object]) -> uuid.UUID | None:
    for key in (
        "proposal_id",
        "packet_id",
        "work_item_id",
        "entity_id",
        "repository_id",
    ):
        value = data.get(key)
        if isinstance(value, str):
            try:
                return uuid.UUID(value)
            except ValueError:
                continue
    return None


def dispatch_tool(
    *,
    actor: ActorContext,
    tool_name: str,
    arguments: dict[str, object],
    transport: str,
) -> dict[str, object]:
    """Validate, authorize, execute, bound, validate, and audit one tool call."""
    contract = TOOL_BY_NAME.get(tool_name)
    audit_tool_name = tool_name if contract is not None else "unrecognized"
    audit_action = contract["required_action"] if contract is not None else "unrecognized"
    try:
        try:
            reject_secrets({"tool": tool_name, "arguments": arguments})
        except ValueError:
            raise MCPGatewayError(
                "secret_material_rejected",
                "Tool input contains prohibited credential material",
                path="$",
                reason="secret_material",
            ) from None
        if contract is None:
            raise MCPGatewayError(
                "capability_unavailable",
                "Requested capability is unavailable; refresh MCP capability discovery",
                http_status=404,
                reason="unknown_capability",
            )
        if len(canonical_payload_bytes(arguments)) > MAX_GATEWAY_INPUT_BYTES:
            raise MCPGatewayError(
                "input_limit_exceeded",
                "Tool input exceeds the gateway byte limit; narrow the request",
            )
        if arguments.get("contract_version") != CONTRACT_VERSION:
            raise MCPGatewayError(
                "unsupported_contract_version",
                "Unsupported contract_version; supported versions: 1",
            )
        _validate(
            contract["input_schema"],
            arguments,
            code="invalid_tool_input",
            label=f"{tool_name} input",
        )
        repository_id = _uuid(arguments, "repository_id")
        action = Action(contract["required_action"])
        _repository(actor=actor, repository_id=repository_id, action=action)
        with transaction.atomic():
            if tool_name in PROPOSAL_TOOL_NAMES:
                if settings.ANVA_MCP_READ_ONLY:
                    raise MCPGatewayError(
                        "read_only_mode",
                        "This Anva MCP deployment is read-only; proposal tools are unavailable",
                        http_status=409,
                    )
                handled: HandlerResult = _proposal(actor, tool_name, arguments)
            else:
                handled = _READ_HANDLERS[tool_name](actor, arguments)
            if isinstance(handled, tuple):
                data, next_cursor = handled
                result: dict[str, object] = {
                    "contract_version": CONTRACT_VERSION,
                    "tool": tool_name,
                    "data": data,
                    "next_cursor": next_cursor,
                }
            else:
                data = handled
                result = {
                    "contract_version": CONTRACT_VERSION,
                    "tool": tool_name,
                    "data": data,
                }
            _reject_private_output_material(result)
            result = _normalize_public_output(tool_name, result)
            if len(canonical_payload_bytes(result)) > MAX_GATEWAY_OUTPUT_BYTES:
                raise MCPGatewayError(
                    "output_limit_exceeded",
                    "Authorized output exceeds the gateway byte limit; narrow the request",
                )
            _validate(
                contract["output_schema"],
                result,
                code="invalid_tool_output",
                label=f"{tool_name} output",
            )
            _record_invocation(
                actor=actor,
                transport=transport,
                tool_name=audit_tool_name,
                required_action=audit_action,
                arguments=arguments,
                outcome=MCPToolInvocation.Outcome.SUCCEEDED,
                target_id=_target_id(data),
            )
            return result
    except Exception as error:
        code = error.code if isinstance(error, DomainOperationError) else "invalid_request"
        try:
            with transaction.atomic():
                _record_invocation(
                    actor=actor,
                    transport=transport,
                    tool_name=audit_tool_name,
                    required_action=audit_action,
                    arguments=arguments,
                    outcome=MCPToolInvocation.Outcome.FAILED,
                    error_code=code,
                )
        except Exception:
            logger.exception(
                "Unable to persist MCP failure audit",
                extra={"tool_name": audit_tool_name},
            )
        raise


def diagnostics_payload() -> dict[str, object]:
    """Return non-secret capability and compatibility diagnostics."""
    return {
        "status": "available",
        "service": "anva-mcp",
        "transport": "streamable-http",
        "endpoint": f"{settings.ANVA_MCP_PUBLIC_BASE_URL.rstrip('/')}/mcp",
        "contract_version": CONTRACT_VERSION,
        "supported_contract_versions": [CONTRACT_VERSION],
        "supported_protocol_versions": list(MCP_PROTOCOL_VERSIONS),
        "read_only": settings.ANVA_MCP_READ_ONLY,
        "authentication": {
            "type": "bearer",
            "scope": "organization-and-exact-repository",
            "rotation": True,
            "revocation": True,
        },
        "limits": {
            "page_size": MAX_PAGE_SIZE,
            "input_bytes": MAX_GATEWAY_INPUT_BYTES,
            "output_bytes": MAX_GATEWAY_OUTPUT_BYTES,
            "source_excerpt_characters": 4_000,
        },
    }
