"""Thin versioned REST adapters for tenancy and authorization behavior."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from functools import wraps
from typing import IO, Any, cast

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_http_methods

from anva.contracts.validation import validate_payload
from anva.core.exceptions import (
    AuthenticationError,
    DomainOperationError,
    RateLimitExceededError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AssuranceReport,
    AssuranceRun,
    EvaluatorTask,
    EvidenceManifest,
    Finding,
    GitHubEventProcessing,
    GitHubWebhookDelivery,
    GitHubWriteIntent,
    Organization,
    Policy,
    WorkItem,
    WorkItemRevision,
)
from anva.core.services.assurance import (
    claim_evaluator_task,
    decide_finding,
    ingest_manual_diff,
    propose_post_merge_knowledge,
    start_assurance,
    submit_evaluator_result,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
)
from anva.core.services.bootstrap import bootstrap_local_organization
from anva.core.services.canvas import (
    CANVAS_PAYLOAD_LIMIT_BYTES,
    CanvasQuery,
    canvas_entity_detail,
    canvas_path,
    canvas_projection,
    create_canvas_share,
    create_canvas_view,
    list_canvas_views,
    propose_canvas_relationship,
    revoke_canvas_share,
    save_canvas_revision,
)
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import (
    PacketBudget,
    build_context_packet,
    get_context_packet,
)
from anva.core.services.evidence import (
    map_criterion_evidence,
    submit_evidence_manifest,
)
from anva.core.services.github_bindings import authorized_active_github_bindings
from anva.core.services.graph import traverse_graph
from anva.core.services.ingestion import (
    connect_filesystem_source,
    inspect_source,
    request_ingestion_sync,
    source_sync_runs,
)
from anva.core.services.intent import (
    approve_work_item_revision,
    import_work_item,
    revoke_work_item_approval,
)
from anva.core.services.mcp_gateway import (
    MCPGatewayError,
    diagnostics_payload,
    dispatch_tool,
)
from anva.core.services.operations import (
    decommission_organization,
    enforce_rate_limit,
    run_retention,
)
from anva.core.services.policies import (
    create_policy_override,
    evaluate_policy,
    import_policy,
    revoke_policy_override,
)
from anva.core.services.retrieval import (
    get_authorized_artifact,
    get_authorized_assertion,
)
from anva.core.services.scopes import revoke_source_connection
from anva.core.services.search import search_chunks
from anva.core.services.secured_operations import (
    authorize_sensitive_placeholder,
    execute_assurance_transition,
    review_assertion,
)
from anva.core.services.tenancy import (
    add_membership,
    deactivate_membership,
    list_memberships,
    update_membership,
)
from anva.core.services.tokens import (
    authenticate_bearer,
    issue_repository_token,
    revoke_repository_token,
    rotate_repository_token,
)
from anva.core.services.web_auth import (
    require_recent_web_authentication,
    resolve_web_principal,
)
from anva.integrations.github.service import (
    accept_verified_event,
    configure_repository_binding,
    revoke_repository_binding,
)
from anva.integrations.github.webhooks import (
    MAX_WEBHOOK_BYTES,
    parse_verified_event,
    verify_signature,
)

MAX_JSON_BODY_BYTES = 64 * 1024
MAX_DIFF_JSON_BODY_BYTES = 1_200_000


def _correlation_id(request: HttpRequest) -> uuid.UUID:
    resolved = getattr(request, "anva_correlation_id", "")
    if isinstance(resolved, str):
        try:
            return uuid.UUID(resolved)
        except ValueError:
            pass
    raw = request.headers.get("X-Correlation-ID", "")
    try:
        return uuid.UUID(raw) if raw else uuid.uuid4()
    except ValueError:
        return uuid.uuid4()


def _error(
    code: str,
    message: str,
    correlation_id: uuid.UUID,
    status: int,
    *,
    path: str | None = None,
    reason: str | None = None,
) -> JsonResponse:
    payload = {
        "code": code,
        "message": message,
        "correlation_id": str(correlation_id),
    }
    if path is not None and reason is not None:
        payload["path"] = path
        payload["reason"] = reason
    return JsonResponse(payload, status=status)


def _canvas_json_response(payload: dict[str, object], *, status: int = 200) -> JsonResponse:
    """Enforce the documented Canvas response budget on exact UTF-8 wire bytes."""
    response = JsonResponse(
        payload,
        status=status,
        json_dumps_params={
            "ensure_ascii": False,
            "separators": (",", ":"),
            "sort_keys": True,
        },
    )
    if len(response.content) > CANVAS_PAYLOAD_LIMIT_BYTES:
        raise ValueError("Canvas response exceeds the 750 KiB byte budget")
    return response


def api_errors[**Parameters](
    view: Callable[Parameters, JsonResponse],
) -> Callable[Parameters, JsonResponse]:
    """Map known domain failures to stable, non-leaking REST errors."""

    @wraps(view)
    def wrapped(*args: Parameters.args, **kwargs: Parameters.kwargs) -> JsonResponse:
        request = cast(HttpRequest, args[0])
        correlation_id = _correlation_id(request)
        try:
            return view(*args, **kwargs)
        except AuthenticationError as error:
            return _error(error.code, str(error), correlation_id, 401)
        except ResourceNotFoundError as error:
            return _error(error.code, str(error), correlation_id, 404)
        except MCPGatewayError as error:
            return _error(
                error.code,
                str(error),
                correlation_id,
                error.http_status,
                path=error.path,
                reason=error.reason,
            )
        except RateLimitExceededError as error:
            response = _error(error.code, str(error), correlation_id, 429)
            response.headers["Retry-After"] = str(error.retry_after_seconds)
            return response
        except DomainOperationError as error:
            return _error(error.code, str(error), correlation_id, 409)
        except (json.JSONDecodeError, TypeError, ValueError):
            return _error("invalid_request", "Request is invalid", correlation_id, 400)

    return wrapped


def _json_body(request: HttpRequest) -> dict[str, object]:
    if len(request.body) > MAX_JSON_BODY_BYTES:
        raise ValueError("Request body is too large")
    payload = json.loads(request.body or b"{}")
    if not isinstance(payload, dict):
        raise ValueError("Request body must be an object")
    return payload


def _stream_content_length(request: HttpRequest) -> int | None:
    """Parse Content-Length without reading or buffering the upload body."""
    raw = request.headers.get("Content-Length")
    if raw is None or raw == "":
        return None
    if not raw.isascii() or not raw.isdecimal():
        raise ValueError("Content-Length is invalid")
    value = int(raw)
    if value < 0:
        raise ValueError("Content-Length is invalid")
    return value


def _diff_json_body(request: HttpRequest) -> dict[str, object]:
    if len(request.body) > MAX_DIFF_JSON_BODY_BYTES:
        raise ValueError("Request body is too large")
    payload = json.loads(request.body or b"{}")
    if not isinstance(payload, dict):
        raise ValueError("Request body must be an object")
    return payload


def _closed_payload(
    payload: dict[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
) -> dict[str, object]:
    if set(payload) - allowed or required - set(payload):
        raise ValueError("Request body fields are invalid")
    return payload


def _string(payload: dict[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    return value


def _integer(payload: dict[str, object], name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _boolean(payload: dict[str, object], name: str, default: bool = False) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _optional_string(payload: dict[str, object], name: str) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_integer(
    payload: dict[str, object],
    name: str,
    default: int,
) -> int:
    value = payload.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _date_time(payload: dict[str, object], name: str) -> datetime:
    value = _string(payload, name)
    parsed = parse_datetime(value)
    if parsed is None or parsed.tzinfo is None:
        raise ValueError(f"{name} must be a timezone-aware ISO 8601 timestamp")
    return parsed


def _string_list(payload: dict[str, object], name: str) -> list[str]:
    value = payload.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return value


def _uuid_list(payload: dict[str, object], name: str) -> list[uuid.UUID]:
    return [uuid.UUID(value) for value in _string_list(payload, name)]


def _object_list(payload: dict[str, object], name: str) -> list[dict[str, str]]:
    value = payload.get(name)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{name} must be a list of objects")
    if not all(
        set(item) == {"id", "type"}
        and isinstance(item["id"], str)
        and isinstance(item["type"], str)
        for item in value
    ):
        raise ValueError(f"{name} entries require string id and type")
    return cast(list[dict[str, str]], value)


def _actor(request: HttpRequest) -> ActorContext:
    actor = authenticate_bearer(request.headers.get("Authorization", ""))
    actor = replace(actor, request_id=_correlation_id(request))
    decision = enforce_rate_limit(actor=actor, channel="api")
    request.anva_rate_limit = decision  # type: ignore[attr-defined]
    return actor


def _canvas_query_payload(payload: dict[str, object]) -> CanvasQuery:
    """Parse the closed, bounded Canvas read contract shared by API consumers."""
    allowed = frozenset(
        {
            "view_id",
            "view_revision",
            "repository_ids",
            "entity_types",
            "owner",
            "status",
            "risk",
            "freshness",
            "as_of",
            "search",
            "layers",
            "anchor_id",
            "depth",
            "node_limit",
            "edge_limit",
        }
    )
    _closed_payload(payload, allowed=allowed, required=frozenset())

    def optional_uuid(name: str) -> uuid.UUID | None:
        if name not in payload:
            return None
        value = payload[name]
        if name == "anchor_id" and value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a UUID")
        return uuid.UUID(value)

    def optional_strings(name: str) -> tuple[str, ...]:
        value = payload.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{name} must be a list of strings")
        return tuple(value)

    def optional_text(name: str) -> str:
        value = payload.get(name, "")
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        return value

    def optional_int(name: str, default: int) -> int:
        value = payload.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")
        return value

    def optional_as_of() -> datetime | None:
        value = payload.get("as_of")
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("as_of must be an ISO 8601 string")
        parsed = parse_datetime(value)
        if parsed is None or parsed.tzinfo is None:
            raise ValueError("as_of must be timezone-aware")
        return parsed

    view_revision = payload.get("view_revision")
    if "view_revision" in payload and (
        not isinstance(view_revision, int) or isinstance(view_revision, bool)
    ):
        raise ValueError("view_revision must be an integer")
    provided_semantic_fields = frozenset(
        "root_entity_id" if name == "anchor_id" else name
        for name in (
            "entity_types",
            "owner",
            "status",
            "risk",
            "freshness",
            "as_of",
            "search",
            "layers",
            "anchor_id",
            "depth",
        )
        if name in payload
    )
    return CanvasQuery(
        view_id=optional_uuid("view_id"),
        view_revision=cast(int | None, view_revision),
        repository_ids=tuple(uuid.UUID(value) for value in optional_strings("repository_ids")),
        entity_types=optional_strings("entity_types"),
        owner=optional_text("owner"),
        status=optional_text("status"),
        risk=optional_text("risk"),
        freshness=optional_text("freshness"),
        as_of=optional_as_of(),
        search=optional_text("search"),
        layers=optional_strings("layers"),
        anchor_id=optional_uuid("anchor_id"),
        depth=optional_int("depth", 2) if "depth" in payload else None,
        provided_semantic_fields=provided_semantic_fields,
        node_limit=optional_int("node_limit", 300),
        edge_limit=optional_int("edge_limit", 600),
    )


def _canvas_json_body(request: HttpRequest) -> dict[str, object]:
    if len(request.body) > CANVAS_PAYLOAD_LIMIT_BYTES:
        raise ValueError("Canvas request exceeds the 750 KiB byte budget")
    payload = json.loads(request.body or b"{}")
    if not isinstance(payload, dict):
        raise ValueError("Canvas request must be an object")
    return payload


def _canvas_presentation(payload: object) -> dict[str, list[dict[str, object]]]:
    if not isinstance(payload, dict):
        raise ValueError("presentation must be an object")
    allowed = {"placements", "filters", "layers", "groups", "annotations"}
    if set(payload) != allowed:
        raise ValueError("presentation fields are invalid")
    for value in payload.values():
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError("presentation entries must be object lists")
    return cast(dict[str, list[dict[str, object]]], payload)


@api_errors
@require_http_methods(["POST"])
def canvas_query(request: HttpRequest) -> JsonResponse:
    """Return only the deterministic union of strict per-repository authorized projections."""
    actor = _actor(request)
    return _canvas_json_response(
        canvas_projection(actor=actor, query=_canvas_query_payload(_canvas_json_body(request)))
    )


@api_errors
@require_http_methods(["POST"])
def canvas_path_query(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _closed_payload(
        _canvas_json_body(request),
        allowed=frozenset({"source_id", "target_id", "repository_ids", "max_depth"}),
        required=frozenset({"source_id", "target_id"}),
    )
    return _canvas_json_response(
        canvas_path(
            actor=actor,
            source_id=uuid.UUID(_string(payload, "source_id")),
            target_id=uuid.UUID(_string(payload, "target_id")),
            repository_ids=tuple(_uuid_list(payload, "repository_ids"))
            if "repository_ids" in payload
            else (),
            max_depth=_optional_integer(payload, "max_depth", 6),
        )
    )


@api_errors
@require_http_methods(["GET"])
def canvas_entity(request: HttpRequest, entity_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    repository_ids = tuple(uuid.UUID(value) for value in request.GET.getlist("repository_id"))
    return _canvas_json_response(
        canvas_entity_detail(
            actor=actor,
            entity_id=entity_id,
            repository_ids=repository_ids,
        )
    )


@api_errors
@require_http_methods(["GET", "POST"])
def canvas_views(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    if request.method == "GET":
        return _canvas_json_response(
            {
                "views": [
                    {
                        "id": str(view.id),
                        "name": view.name,
                        "description": view.description,
                        "view_type": view.view_type,
                        "revision": view.revision,
                        "repository_id": str(view.repository_id) if view.repository_id else None,
                    }
                    for view in list_canvas_views(actor=actor)
                ]
            }
        )
    payload = _closed_payload(
        _canvas_json_body(request),
        allowed=frozenset(
            {
                "name",
                "description",
                "view_type",
                "semantic_query",
                "repository_id",
                "access_scope_id",
                "idempotency_key",
            }
        ),
        required=frozenset({"name", "view_type", "semantic_query", "idempotency_key"}),
    )
    if actor.actor_type != "USER":
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    semantic_query = payload["semantic_query"]
    if not isinstance(semantic_query, dict):
        raise ValueError("semantic_query must be an object")
    description = payload.get("description", "")
    if not isinstance(description, str):
        raise ValueError("description must be a string")
    repository = _optional_string(payload, "repository_id")
    scope = _optional_string(payload, "access_scope_id")
    view, created = create_canvas_view(
        actor=actor,
        name=_string(payload, "name"),
        description=description,
        view_type=_string(payload, "view_type"),
        semantic_query=cast(dict[str, object], semantic_query),
        repository_id=uuid.UUID(repository) if repository else None,
        access_scope_id=uuid.UUID(scope) if scope else None,
        idempotency_key=_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {"id": str(view.id), "revision": view.revision, "created": created},
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def canvas_view_revisions(request: HttpRequest, view_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _closed_payload(
        _canvas_json_body(request),
        allowed=frozenset(
            {"expected_revision", "semantic_query", "presentation", "idempotency_key"}
        ),
        required=frozenset(
            {"expected_revision", "semantic_query", "presentation", "idempotency_key"}
        ),
    )
    semantic_query = payload["semantic_query"]
    if not isinstance(semantic_query, dict):
        raise ValueError("semantic_query must be an object")
    presentation = _canvas_presentation(payload["presentation"])
    revision, created = save_canvas_revision(
        actor=actor,
        view_id=view_id,
        expected_revision=_integer(payload, "expected_revision"),
        semantic_query=cast(dict[str, object], semantic_query),
        placements=presentation["placements"],
        filters=presentation["filters"],
        layers=presentation["layers"],
        groups=presentation["groups"],
        annotations=presentation["annotations"],
        idempotency_key=_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {
            "id": str(revision.id),
            "revision": revision.revision,
            "content_hash": revision.content_hash,
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def canvas_view_shares(request: HttpRequest, view_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _closed_payload(
        _canvas_json_body(request),
        allowed=frozenset({"recipient_membership_id", "expires_at", "idempotency_key"}),
        required=frozenset({"idempotency_key"}),
    )
    recipient = _optional_string(payload, "recipient_membership_id")
    expires = payload.get("expires_at")
    if expires is not None and not isinstance(expires, str):
        raise ValueError("expires_at must be an ISO 8601 string")
    parsed_expires = parse_datetime(expires) if isinstance(expires, str) else None
    if expires is not None and (parsed_expires is None or parsed_expires.tzinfo is None):
        raise ValueError("expires_at must be timezone-aware")
    share, created = create_canvas_share(
        actor=actor,
        view_id=view_id,
        recipient_membership_id=uuid.UUID(recipient) if recipient else None,
        expires_at=parsed_expires,
        idempotency_key=_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {
            "id": str(share.id),
            "view_revision": share.view_revision.revision,
            "deep_link": f"/app/canvas?share={share.id}",
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def canvas_share_revoke(request: HttpRequest, share_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _closed_payload(
        _canvas_json_body(request),
        allowed=frozenset({"expected_view_revision", "idempotency_key"}),
        required=frozenset({"expected_view_revision", "idempotency_key"}),
    )
    share, revoked = revoke_canvas_share(
        actor=actor,
        share_id=share_id,
        expected_view_revision=_integer(payload, "expected_view_revision"),
        idempotency_key=_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {
            "id": str(share.id),
            "state": "REVOKED",
            "view_revision": share.view_revision.revision,
            "revoked": revoked,
            "revoked_at": share.revoked_at.isoformat() if share.revoked_at else None,
        }
    )


@api_errors
@require_http_methods(["POST"])
def canvas_relationship_proposals(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _closed_payload(
        _canvas_json_body(request),
        allowed=frozenset(
            {
                "source_id",
                "target_id",
                "relationship_type",
                "repository_id",
                "expected_source_revision",
                "expected_target_revision",
                "rationale",
                "idempotency_key",
            }
        ),
        required=frozenset(
            {
                "source_id",
                "target_id",
                "relationship_type",
                "repository_id",
                "expected_source_revision",
                "expected_target_revision",
                "rationale",
                "idempotency_key",
            }
        ),
    )
    proposal, created = propose_canvas_relationship(
        actor=actor,
        source_id=uuid.UUID(_string(payload, "source_id")),
        target_id=uuid.UUID(_string(payload, "target_id")),
        relationship_type=_string(payload, "relationship_type"),
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        expected_source_revision=_integer(payload, "expected_source_revision"),
        expected_target_revision=_integer(payload, "expected_target_revision"),
        rationale=_string(payload, "rationale"),
        idempotency_key=_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {"id": str(proposal.id), "state": proposal.state, "created": created},
        status=201 if created else 200,
    )


@require_http_methods(["POST"])
def github_webhook(request: HttpRequest) -> JsonResponse:
    """Verify the exact raw request before parsing or resolving tenant state."""
    correlation_id = _correlation_id(request)
    if not settings.ANVA_GITHUB_WEBHOOK_CONFIGURED:
        return _error(
            "github_webhook_unconfigured",
            "GitHub webhook handling is not configured",
            correlation_id,
            503,
        )
    content_length = request.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_WEBHOOK_BYTES:
                return _error(
                    "payload_too_large",
                    "Webhook payload exceeds the limit",
                    correlation_id,
                    413,
                )
        except ValueError:
            return _error("invalid_request", "Request is invalid", correlation_id, 400)
    try:
        raw_body = request.body
        verify_signature(
            raw_body=raw_body,
            signature=request.headers.get("X-Hub-Signature-256", ""),
            secrets=settings.ANVA_GITHUB_WEBHOOK_SECRETS,
        )
        event = parse_verified_event(
            raw_body=raw_body,
            delivery_header=request.headers.get("X-GitHub-Delivery", ""),
            event_header=request.headers.get("X-GitHub-Event", ""),
        )
        accepted = accept_verified_event(event)
    except PermissionError:
        return _error(
            "invalid_github_signature",
            "GitHub webhook signature is invalid",
            correlation_id,
            401,
        )
    except RequestDataTooBig:
        return _error(
            "payload_too_large",
            "Webhook payload exceeds the limit",
            correlation_id,
            413,
        )
    except DomainOperationError as error:
        return _error(error.code, str(error), correlation_id, 409)
    except (json.JSONDecodeError, TypeError, ValueError):
        return _error("invalid_request", "Request is invalid", correlation_id, 400)
    return JsonResponse(
        {
            "status": accepted.status,
            "delivery_id": str(accepted.delivery_id),
            "deduplicated": not accepted.created and accepted.status == "duplicate",
            "correlation_id": str(correlation_id),
        },
        status=202,
    )


@api_errors
@require_http_methods(["GET", "POST"])
def github_repository_binding(
    request: HttpRequest,
    repository_id: uuid.UUID,
) -> JsonResponse:
    """Configure or diagnose a tenant-scoped GitHub repository binding."""
    actor = _actor(request)
    if request.method == "GET":
        authorize_action(
            actor=actor,
            action=Action.GITHUB_MANAGE,
            repository_id=repository_id,
        )
        binding = (
            authorized_active_github_bindings(
                actor=actor,
                repository_ids=[repository_id],
            )
            .select_related("installation")
            .first()
        )
        if binding is None:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        deliveries = GitHubWebhookDelivery.objects.filter(
            organization_id=actor.organization_id,
            repository_binding=binding,
        ).order_by("-received_at")
        last_delivery = deliveries.first()
        last_processing = (
            GitHubEventProcessing.objects.filter(
                organization_id=actor.organization_id,
                delivery=last_delivery,
            ).first()
            if last_delivery is not None
            else None
        )
        last_write = (
            GitHubWriteIntent.objects.filter(
                organization_id=actor.organization_id,
                publication__repository_binding=binding,
            )
            .order_by("-created_at")
            .first()
        )
        return JsonResponse(
            {
                "id": str(binding.id),
                "installation_id": binding.installation.external_id,
                "external_repository_id": binding.external_repository_id,
                "full_name": binding.full_name,
                "state": (
                    "ACTIVE"
                    if binding.is_active
                    and binding.installation.state == binding.installation.State.ACTIVE
                    else "INACTIVE"
                ),
                "permissions": binding.installation.permissions,
                "auto_assurance": binding.auto_assurance,
                "policy_version_ids": binding.policy_version_ids,
                "last_delivery": (
                    {
                        "event": last_delivery.event_type,
                        "action": last_delivery.action,
                        "received_at": last_delivery.received_at.isoformat(),
                        "processing_state": (
                            last_processing.state if last_processing is not None else "MISSING"
                        ),
                    }
                    if last_delivery is not None
                    else None
                ),
                "last_write": (
                    {
                        "state": last_write.state,
                        "attempt_count": last_write.attempt_count,
                        "last_error_code": last_write.last_error_code,
                    }
                    if last_write is not None
                    else None
                ),
            }
        )
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset(
            {
                "access_scope_id",
                "installation_id",
                "account_id",
                "account_login",
                "account_type",
                "repository_selection",
                "permissions",
                "external_repository_id",
                "full_name",
                "default_branch",
                "private",
                "archived",
                "auto_assurance",
                "policy_version_ids",
                "work_item_revision_id",
            }
        ),
        required=frozenset(
            {
                "access_scope_id",
                "installation_id",
                "account_id",
                "account_login",
                "account_type",
                "repository_selection",
                "permissions",
                "external_repository_id",
                "full_name",
                "default_branch",
                "private",
                "archived",
                "auto_assurance",
                "policy_version_ids",
            }
        ),
    )
    raw_permissions = payload["permissions"]
    if not isinstance(raw_permissions, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw_permissions.items()
    ):
        raise ValueError("permissions must be a string map")
    result = configure_repository_binding(
        actor=actor,
        repository_id=repository_id,
        access_scope_id=uuid.UUID(_string(payload, "access_scope_id")),
        installation_external_id=_integer(payload, "installation_id"),
        account_id=_integer(payload, "account_id"),
        account_login=_string(payload, "account_login"),
        account_type=_string(payload, "account_type"),
        repository_selection=_string(payload, "repository_selection"),
        permissions=cast(dict[str, str], raw_permissions),
        external_repository_id=_integer(payload, "external_repository_id"),
        full_name=_string(payload, "full_name"),
        default_branch=_string(payload, "default_branch"),
        is_private=cast(bool, payload["private"]),
        is_archived=cast(bool, payload["archived"]),
        auto_assurance=cast(bool, payload["auto_assurance"]),
        policy_version_ids=[
            uuid.UUID(value) for value in _string_list(payload, "policy_version_ids")
        ],
        work_item_revision_id=(
            uuid.UUID(value)
            if (value := _optional_string(payload, "work_item_revision_id")) is not None
            else None
        ),
    )
    return JsonResponse(
        {
            "id": str(result.binding.id),
            "installation_id": result.installation.external_id,
            "external_repository_id": result.binding.external_repository_id,
            "state": "ACTIVE",
            "created": result.created,
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def github_repository_binding_revoke(
    request: HttpRequest,
    repository_id: uuid.UUID,
) -> JsonResponse:
    """Revoke a bound repository through an explicit admin operation."""
    actor = _actor(request)
    _closed_payload(
        _json_body(request),
        allowed=frozenset(),
        required=frozenset(),
    )
    authorize_action(
        actor=actor,
        action=Action.GITHUB_MANAGE,
        repository_id=repository_id,
    )
    binding = (
        authorized_active_github_bindings(
            actor=actor,
            repository_ids=[repository_id],
        )
        .select_related("installation")
        .first()
    )
    if binding is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    revoke_repository_binding(binding=binding, request_id=actor.request_id)
    return JsonResponse({"id": str(binding.id), "state": "REVOKED"})


@api_errors
@require_http_methods(["POST"])
def bootstrap(request: HttpRequest) -> JsonResponse:
    payload = _json_body(request)
    result = bootstrap_local_organization(
        supplied_secret=request.headers.get("X-Anva-Bootstrap-Secret", ""),
        organization_slug=_string(payload, "organization_slug"),
        organization_name=_string(payload, "organization_name"),
        admin_email=_string(payload, "admin_email"),
        admin_display_name=_string(payload, "admin_display_name"),
        repository_external_id=_string(payload, "repository_external_id"),
        repository_name=_string(payload, "repository_name"),
    )
    return JsonResponse(
        {
            "organization_id": str(result.organization.id),
            "user_id": str(result.user.id),
            "membership_id": str(result.membership.id),
            "repository_id": str(result.repository.id),
            "service_identity_id": str(result.service_identity.id),
            "token_id": str(result.issued_token.record.id),
            "token": result.issued_token.plaintext,
            "expires_at": result.issued_token.record.expires_at.isoformat(),
        },
        status=201,
    )


@api_errors
@require_http_methods(["GET"])
def organization_detail(request: HttpRequest, organization_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    if actor.organization_id != organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    decision = authorize_action(
        actor=actor,
        action=Action.ORG_VIEW,
        repository_id=actor.repository_id,
    )
    organization = Organization.objects.get(id=organization_id)
    return JsonResponse(
        {
            "id": str(organization.id),
            "slug": organization.slug,
            "name": organization.name,
            "authorization_path": decision.authorization_path,
        }
    )


@api_errors
@require_http_methods(["POST"])
def organization_retention_run(
    request: HttpRequest,
    organization_id: uuid.UUID,
) -> JsonResponse:
    """Execute one bounded retention pass for the caller's organization."""
    actor = _actor(request)
    if actor.organization_id != organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset({"dry_run"}),
        required=frozenset(),
    )
    run = run_retention(
        actor=actor,
        dry_run=_boolean(payload, "dry_run"),
    )
    return JsonResponse(
        {
            "id": str(run.id),
            "kind": run.kind,
            "state": run.state,
            "dry_run": run.dry_run,
            "cutoff_at": run.cutoff_at.isoformat(),
            "summary": run.summary,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        status=201,
    )


@api_errors
@require_http_methods(["POST"])
def organization_decommission(
    request: HttpRequest,
    organization_id: uuid.UUID,
) -> JsonResponse:
    """Revoke a tenant after recent human-session and two exact confirmations."""
    principal = resolve_web_principal(request)
    require_recent_web_authentication(request)
    actor = principal.actor
    if actor.organization_id != organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset({"confirmation", "acknowledgement"}),
        required=frozenset({"confirmation", "acknowledgement"}),
    )
    confirmation = _string(payload, "confirmation")
    acknowledgement = _string(payload, "acknowledgement")
    if acknowledgement != f"DECOMMISSION {confirmation}":
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    run = decommission_organization(
        actor=actor,
        confirmation=confirmation,
        acknowledgement=acknowledgement,
    )
    return JsonResponse(
        {
            "id": str(run.id),
            "kind": run.kind,
            "state": run.state,
            "summary": run.summary,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "limitations": [
                "Governed audit, provenance, and immutable evidence metadata are retained."
            ],
        },
        status=202,
    )


@api_errors
@require_http_methods(["GET", "POST"])
def memberships(request: HttpRequest, organization_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    if request.method == "GET":
        records = list_memberships(actor=actor, organization_id=organization_id)
        return JsonResponse(
            {
                "memberships": [
                    {
                        "id": str(record.id),
                        "user_id": str(record.user_id),
                        "display_name": record.user.display_name,
                        "role": record.role.code,
                        "active": record.is_active,
                        "revision": record.revision,
                    }
                    for record in records
                ]
            }
        )
    payload = _json_body(request)
    record = add_membership(
        actor=actor,
        organization_id=organization_id,
        email=_string(payload, "email"),
        display_name=_string(payload, "display_name"),
        role_code=_string(payload, "role"),
    )
    return JsonResponse(
        {"id": str(record.id), "role": record.role.code, "revision": record.revision},
        status=201,
    )


@api_errors
@require_http_methods(["PATCH", "DELETE"])
def membership_detail(
    request: HttpRequest,
    organization_id: uuid.UUID,
    membership_id: uuid.UUID,
) -> JsonResponse:
    actor = _actor(request)
    if organization_id != actor.organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    payload = _json_body(request)
    if request.method == "PATCH":
        record = update_membership(
            actor=actor,
            membership_id=membership_id,
            role_code=_string(payload, "role"),
            expected_revision=_integer(payload, "expected_revision"),
        )
    else:
        record = deactivate_membership(
            actor=actor,
            membership_id=membership_id,
            expected_revision=_integer(payload, "expected_revision"),
        )
    return JsonResponse(
        {
            "id": str(record.id),
            "role": record.role.code,
            "active": record.is_active,
            "revision": record.revision,
        }
    )


def _actions(payload: dict[str, object]) -> frozenset[Action]:
    values = payload.get("actions")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("actions must be a list of strings")
    return frozenset(Action(value) for value in values)


@api_errors
@require_http_methods(["POST"])
def repository_tokens(request: HttpRequest, repository_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    issued = issue_repository_token(
        actor=actor,
        repository_id=repository_id,
        service_identity_id=uuid.UUID(_string(payload, "service_identity_id")),
        actions=_actions(payload),
        expires_at=timezone.now() + timedelta(seconds=_integer(payload, "expires_in_seconds")),
    )
    return JsonResponse(
        {
            "id": str(issued.record.id),
            "token": issued.plaintext,
            "expires_at": issued.record.expires_at.isoformat(),
        },
        status=201,
    )


@api_errors
@require_http_methods(["POST"])
def rotate_token(request: HttpRequest, token_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    issued = rotate_repository_token(
        actor=actor,
        token_id=token_id,
        expires_at=timezone.now() + timedelta(seconds=_integer(payload, "expires_in_seconds")),
    )
    return JsonResponse(
        {
            "id": str(issued.record.id),
            "token": issued.plaintext,
            "expires_at": issued.record.expires_at.isoformat(),
        },
        status=201,
    )


@api_errors
@require_http_methods(["DELETE"])
def revoke_token(request: HttpRequest, token_id: uuid.UUID) -> JsonResponse:
    record = revoke_repository_token(actor=_actor(request), token_id=token_id)
    return JsonResponse({"id": str(record.id), "status": "REVOKED"})


@api_errors
@require_http_methods(["POST"])
def search(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    repository_id = uuid.UUID(_string(payload, "repository_id"))
    response = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query=_string(payload, "query"),
        phase=_optional_string(payload, "phase"),
        limit=_optional_integer(payload, "limit", 20),
    )
    return JsonResponse(
        {
            "results": [result.as_dict() for result in response.results],
        }
    )


@api_errors
@require_http_methods(["POST"])
def context_packets(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    budget_payload = payload.get("budget", {})
    if not isinstance(budget_payload, dict):
        raise ValueError("budget must be an object")
    budget = PacketBudget(
        max_items=_optional_integer(budget_payload, "max_items", 50),
        max_tokens=_optional_integer(budget_payload, "max_tokens", 8_000),
        max_bytes=_optional_integer(budget_payload, "max_bytes", 100_000),
        max_citations=_optional_integer(budget_payload, "max_citations", 100),
    )
    packet, created = build_context_packet(
        actor=actor,
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        task=_string(payload, "task"),
        phase=_string(payload, "phase"),
        budget=budget,
    )
    return JsonResponse(
        {
            "packet_id": str(packet.id),
            "artifact_id": str(packet.artifact_id),
            "content_hash": packet.artifact.content_hash,
            "created": created,
            "packet": packet.artifact.payload,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["GET"])
def context_packet_detail(
    request: HttpRequest,
    packet_id: uuid.UUID,
) -> JsonResponse:
    actor = _actor(request)
    repository_id = uuid.UUID(request.GET.get("repository_id", ""))
    return JsonResponse(
        {
            "packet": get_context_packet(
                actor=actor,
                repository_id=repository_id,
                packet_id=packet_id,
            )
        }
    )


@api_errors
@require_http_methods(["POST"])
def query(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    repository_id = uuid.UUID(_string(payload, "repository_id"))
    response = search_chunks(
        actor=actor,
        repository_id=repository_id,
        query=_string(payload, "query"),
        phase=_optional_string(payload, "phase"),
        limit=_optional_integer(payload, "limit", 20),
    )
    result: dict[str, object] = {
        "results": [search_result.as_dict() for search_result in response.results],
    }
    start_entity = _optional_string(payload, "start_entity_id")
    if start_entity is not None:
        result["graph"] = traverse_graph(
            actor=actor,
            repository_id=repository_id,
            start_entity_id=uuid.UUID(start_entity),
            depth=_optional_integer(payload, "depth", 2),
            degree=_optional_integer(payload, "degree", 100),
            edge_limit=_optional_integer(payload, "edge_limit", 500),
        ).as_dict()
    return JsonResponse(result)


def _entity_graph(
    request: HttpRequest,
    entity_id: uuid.UUID,
    *,
    depth: int,
) -> dict[str, object]:
    actor = _actor(request)
    repository_id = uuid.UUID(request.GET.get("repository_id", ""))
    return traverse_graph(
        actor=actor,
        repository_id=repository_id,
        start_entity_id=entity_id,
        depth=depth,
    ).as_dict()


@api_errors
@require_http_methods(["GET"])
def entity_relationships(request: HttpRequest, entity_id: uuid.UUID) -> JsonResponse:
    return JsonResponse(_entity_graph(request, entity_id, depth=1))


@api_errors
@require_http_methods(["GET"])
def entity_history(request: HttpRequest, entity_id: uuid.UUID) -> JsonResponse:
    graph = _entity_graph(request, entity_id, depth=4)
    edges = cast(list[dict[str, object]], graph["edges"])
    return JsonResponse(
        {
            "entity_id": str(entity_id),
            "history": sorted(
                edges,
                key=lambda edge: (
                    str(edge["observed_at"]),
                    str(edge["relationship_id"]),
                ),
            ),
            "truncated": graph["truncated"],
        }
    )


@api_errors
@require_http_methods(["GET"])
def entity_sources(request: HttpRequest, entity_id: uuid.UUID) -> JsonResponse:
    graph = _entity_graph(request, entity_id, depth=4)
    edges = cast(list[dict[str, object]], graph["edges"])
    sources = {
        (
            str(edge["source_location_id"]),
            str(edge["source_observation_id"]),
            str(edge["access_snapshot_id"]),
        )
        for edge in edges
    }
    return JsonResponse(
        {
            "entity_id": str(entity_id),
            "sources": [
                {
                    "source_location_id": source[0],
                    "source_observation_id": source[1],
                    "access_snapshot_id": source[2],
                }
                for source in sorted(sources)
            ],
        }
    )


@api_errors
@require_http_methods(["GET"])
def assertion_explanation(
    request: HttpRequest,
    assertion_id: uuid.UUID,
) -> JsonResponse:
    actor = _actor(request)
    repository_id = uuid.UUID(request.GET.get("repository_id", ""))
    assertion = get_authorized_assertion(
        actor=actor,
        repository_id=repository_id,
        assertion_id=assertion_id,
        action=Action.KNOWLEDGE_VIEW,
    )
    return JsonResponse(
        {
            "assertion_id": str(assertion.id),
            "summary": (
                f"{assertion.subject_key} {assertion.predicate} "
                f"{json.dumps(assertion.value, sort_keys=True)}"
            ),
            "freshness": assertion.staleness_state,
            "is_inferred": assertion.is_inferred,
            "selection_reason": "Direct governed assertion lookup",
            "anva_sources": assertion.provenance,
        }
    )


def _assertion_response(record: Any) -> JsonResponse:
    return JsonResponse(
        {
            "id": str(record.id),
            "subject_key": record.subject_key,
            "predicate": record.predicate,
            "value": record.value,
            "review_state": record.review_state,
            "revision": record.revision,
        }
    )


@api_errors
@require_http_methods(["GET"])
def canvas_assertion(
    request: HttpRequest,
    assertion_id: uuid.UUID,
) -> JsonResponse:
    actor = _actor(request)
    repository_id = uuid.UUID(request.GET.get("repository_id", ""))
    record = get_authorized_assertion(
        actor=actor,
        repository_id=repository_id,
        assertion_id=assertion_id,
        action=Action.CANVAS_VIEW,
    )
    return _assertion_response(record)


@api_errors
@require_http_methods(["POST"])
def mcp_context(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    repository_id = uuid.UUID(_string(payload, "repository_id"))
    authorize_action(
        actor=actor,
        repository_id=repository_id,
        action=Action.MCP_CONTEXT,
    )
    return JsonResponse(
        {
            **diagnostics_payload(),
            "repository_id": str(repository_id),
            "message": "Use /api/v1/mcp/tools/{tool_name} for HTTP parity calls.",
        }
    )


@api_errors
@require_http_methods(["POST"])
def mcp_tool(request: HttpRequest, tool_name: str) -> JsonResponse:
    """Expose the exact canonical domain facade used by Streamable HTTP MCP."""
    return JsonResponse(
        dispatch_tool(
            actor=_actor(request),
            tool_name=tool_name,
            arguments=_json_body(request),
            transport="HTTP",
        )
    )


@require_http_methods(["GET"])
def mcp_diagnostics(_request: HttpRequest) -> JsonResponse:
    """Return non-secret compatibility and availability diagnostics."""
    return JsonResponse(diagnostics_payload())


@api_errors
@require_http_methods(["GET"])
def artifact_detail(request: HttpRequest, artifact_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    repository_id = uuid.UUID(request.GET.get("repository_id", ""))
    artifact = get_authorized_artifact(
        actor=actor,
        repository_id=repository_id,
        artifact_id=artifact_id,
    )
    return JsonResponse(
        {
            "id": str(artifact.id),
            "kind": artifact.kind,
            "schema_name": artifact.schema_name,
            "schema_version": artifact.schema_version,
            "content_hash": artifact.content_hash,
            "payload": artifact.payload,
        }
    )


@api_errors
@require_http_methods(["POST"])
def work_items_import(request: HttpRequest) -> JsonResponse:
    payload = _json_body(request)
    result = import_work_item(actor=_actor(request), payload=payload)
    return JsonResponse(
        {
            "work_item_id": str(result.work_item.id),
            "work_item_revision_id": str(result.work_item_revision.id),
            "revision": result.work_item_revision.revision,
            "content_hash": result.work_item_revision.content_hash,
            "created": result.created,
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["GET"])
def work_item_detail(request: HttpRequest, work_item_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    work_item = get_tenant_record(
        queryset=WorkItem.objects.all(),
        record_id=work_item_id,
        organization_id=actor.organization_id,
    )
    authorize_action(
        actor=actor,
        action=Action.WORK_VIEW,
        repository_id=work_item.repository_id,
        access_scope_id=work_item.access_scope_id,
    )
    revision = WorkItemRevision.objects.get(
        organization_id=actor.organization_id,
        work_item=work_item,
        revision=work_item.revision,
    )
    return JsonResponse(
        {
            "id": str(work_item.id),
            "repository_id": str(work_item.repository_id),
            "revision": work_item.revision,
            "status": work_item.status,
            "content_hash": revision.content_hash,
            "intent": revision.normalized_payload,
        }
    )


@api_errors
@require_http_methods(["POST"])
def work_revision_approval(
    request: HttpRequest,
    work_item_revision_id: uuid.UUID,
) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset(
            {
                "repository_id",
                "status",
                "target_kind",
                "target_key",
                "reason",
                "expires_at",
            }
        ),
        required=frozenset({"repository_id", "status", "target_kind", "target_key", "reason"}),
    )
    expires = _optional_string(payload, "expires_at")
    approval, created = approve_work_item_revision(
        actor=_actor(request),
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        work_item_revision_id=work_item_revision_id,
        status=_string(payload, "status"),
        target_kind=_string(payload, "target_kind"),
        target_key=_string(payload, "target_key"),
        reason=_string(payload, "reason"),
        expires_at=_date_time(payload, "expires_at") if expires else None,
    )
    return JsonResponse(
        {
            "approval_id": str(approval.id),
            "work_item_revision_id": str(approval.work_item_revision_id),
            "status": approval.status,
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def work_approval_revocation(
    request: HttpRequest,
    approval_id: uuid.UUID,
) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset({"repository_id", "reason"}),
        required=frozenset({"repository_id", "reason"}),
    )
    revocation, created = revoke_work_item_approval(
        actor=_actor(request),
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        approval_id=approval_id,
        reason=_string(payload, "reason"),
    )
    return JsonResponse(
        {
            "approval_revocation_id": str(revocation.id),
            "approval_id": str(revocation.approval_id),
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def policies_import(request: HttpRequest) -> JsonResponse:
    result = import_policy(actor=_actor(request), payload=_json_body(request))
    return JsonResponse(
        {
            "policy_id": str(result.policy.id),
            "policy_version_id": str(result.policy_version.id),
            "version": result.policy_version.version,
            "content_hash": result.policy_version.content_hash,
            "created": result.created,
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["GET"])
def policy_detail(request: HttpRequest, policy_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    repository_id = uuid.UUID(request.GET.get("repository_id", ""))
    policy = get_tenant_record(
        queryset=Policy.objects.all(),
        record_id=policy_id,
        organization_id=actor.organization_id,
    )
    authorize_action(
        actor=actor,
        action=Action.POLICY_VIEW,
        repository_id=repository_id,
        access_scope_id=policy.access_scope_id,
    )
    version = policy.policyversion_set.get(version=policy.revision)
    return JsonResponse(
        {
            "id": str(policy.id),
            "version_id": str(version.id),
            "version": version.version,
            "status": policy.status,
            "content_hash": version.content_hash,
            "definition": version.definition,
        }
    )


@api_errors
@require_http_methods(["POST"])
def policy_simulation(request: HttpRequest) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset(
            {
                "repository_id",
                "pull_request_number",
                "commit_sha",
                "policy_version_ids",
                "reference_time",
                "affected_paths",
                "affected_entities",
                "target_branch",
                "work_item_revision_id",
            }
        ),
        required=frozenset(
            {
                "repository_id",
                "pull_request_number",
                "commit_sha",
                "policy_version_ids",
                "reference_time",
                "affected_paths",
                "affected_entities",
                "target_branch",
            }
        ),
    )
    raw_work_revision_id = _optional_string(payload, "work_item_revision_id")
    evaluation, created = evaluate_policy(
        actor=_actor(request),
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        pull_request_number=_integer(payload, "pull_request_number"),
        commit_sha=_string(payload, "commit_sha"),
        policy_version_ids=_uuid_list(payload, "policy_version_ids"),
        reference_time=_date_time(payload, "reference_time"),
        affected_paths=_string_list(payload, "affected_paths"),
        affected_entities=_object_list(payload, "affected_entities"),
        target_branch=_string(payload, "target_branch"),
        work_item_revision_id=(uuid.UUID(raw_work_revision_id) if raw_work_revision_id else None),
        is_simulation=True,
    )
    return JsonResponse(
        {
            "policy_evaluation_id": str(evaluation.id),
            "input_hash": evaluation.input_hash,
            "output_hash": evaluation.output_hash,
            "output": evaluation.output_payload,
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def review_knowledge(request: HttpRequest, assertion_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    record = review_assertion(
        actor=actor,
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        assertion_id=assertion_id,
        target_state=_string(payload, "target_state"),
        expected_revision=_integer(payload, "expected_revision"),
    )
    return _assertion_response(record)


@api_errors
@require_http_methods(["POST"])
def manual_diff_ingestion(
    request: HttpRequest,
    repository_id: uuid.UUID,
    pull_request_number: int,
) -> JsonResponse:
    payload = _closed_payload(
        _diff_json_body(request),
        allowed=frozenset(
            {
                "access_scope_id",
                "base_commit",
                "head_commit",
                "title",
                "description",
                "target_branch",
                "is_draft",
                "state",
                "unified_diff",
            }
        ),
        required=frozenset(
            {
                "access_scope_id",
                "base_commit",
                "head_commit",
                "title",
                "description",
                "target_branch",
                "is_draft",
                "state",
                "unified_diff",
            }
        ),
    )
    is_draft = payload["is_draft"]
    if not isinstance(is_draft, bool):
        raise ValueError("is_draft must be boolean")
    result = ingest_manual_diff(
        actor=_actor(request),
        repository_id=repository_id,
        access_scope_id=uuid.UUID(_string(payload, "access_scope_id")),
        pull_request_number=pull_request_number,
        base_commit=_string(payload, "base_commit"),
        head_commit=_string(payload, "head_commit"),
        title=_string(payload, "title"),
        description=cast(str, payload["description"]),
        target_branch=_string(payload, "target_branch"),
        is_draft=is_draft,
        state=_string(payload, "state"),
        unified_diff=_string(payload, "unified_diff"),
    )
    return JsonResponse(
        {
            "pull_request_id": str(result.pull_request.id),
            "pull_request_revision_id": str(result.revision.id),
            "revision": result.revision.revision,
            "head_commit": result.revision.head_commit,
            "diff_artifact_id": str(result.revision.diff_artifact_id),
            "diff_hash": result.revision.diff_hash,
            "changed_paths": result.revision.changed_paths,
            "classification_summary": result.revision.classification_summary,
            "limitations": result.revision.limitations,
            "created": result.created,
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def assurance_start(
    request: HttpRequest,
    pull_request_revision_id: uuid.UUID,
) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset(
            {
                "policy_version_ids",
                "reference_time",
                "deterministic_checks",
                "work_item_revision_id",
                "evaluator_version",
                "prompt_version",
                "trigger_key",
            }
        ),
        required=frozenset(
            {
                "policy_version_ids",
                "reference_time",
                "deterministic_checks",
            }
        ),
    )
    checks = payload["deterministic_checks"]
    if not isinstance(checks, list) or not all(isinstance(item, dict) for item in checks):
        raise ValueError("deterministic_checks must be a list of objects")
    work_revision = _optional_string(payload, "work_item_revision_id")
    result = start_assurance(
        actor=_actor(request),
        pull_request_revision_id=pull_request_revision_id,
        policy_version_ids=_uuid_list(payload, "policy_version_ids"),
        reference_time=_date_time(payload, "reference_time"),
        deterministic_checks=cast(list[dict[str, object]], checks),
        work_item_revision_id=uuid.UUID(work_revision) if work_revision else None,
        evaluator_version=cast(
            str,
            payload.get("evaluator_version", "manual-evaluator-v1"),
        ),
        prompt_version=cast(str, payload.get("prompt_version", "assurance-prompt-v1")),
        trigger_key=cast(str, payload.get("trigger_key", "")),
    )
    return JsonResponse(
        {
            "assurance_run_id": str(result.run.id),
            "evaluator_task_id": str(result.evaluator_task.id),
            "state": result.run.state,
            "head_commit": result.run.head_commit,
            "input_hash": result.run.input_hash,
            "created": result.created,
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def evaluator_task_claim(request: HttpRequest, repository_id: uuid.UUID) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset({"claimant", "lease_seconds"}),
        required=frozenset({"claimant"}),
    )
    claim = claim_evaluator_task(
        actor=_actor(request),
        repository_id=repository_id,
        claimant=_string(payload, "claimant"),
        lease_seconds=_optional_integer(payload, "lease_seconds", 900),
    )
    if claim is None:
        return JsonResponse({"status": "EMPTY"}, status=200)
    return JsonResponse(
        {
            "task_id": str(claim.task.id),
            "claimant": claim.task.claimant,
            "attempt": claim.task.attempt_count,
            "lease_expires_at": claim.task.lease_expires_at.isoformat()
            if claim.task.lease_expires_at
            else None,
            "claim_token": claim.claim_token,
            "request": claim.request,
        }
    )


@api_errors
@require_http_methods(["POST"])
def evaluator_task_submit(request: HttpRequest, task_id: uuid.UUID) -> JsonResponse:
    payload = _closed_payload(
        _diff_json_body(request),
        allowed=frozenset({"claimant", "claim_token", "result"}),
        required=frozenset({"claimant", "claim_token", "result"}),
    )
    result_payload = payload["result"]
    if not isinstance(result_payload, dict):
        raise ValueError("result must be an object")
    completion = submit_evaluator_result(
        actor=_actor(request),
        task_id=task_id,
        claimant=_string(payload, "claimant"),
        claim_token=_string(payload, "claim_token"),
        result=cast(dict[str, object], result_payload),
    )
    return JsonResponse(
        {
            "assurance_run_id": str(completion.run.id),
            "state": completion.run.state,
            "readiness": completion.readiness.status,
            "reason_codes": completion.readiness.reason_codes,
            "report_id": str(completion.report.id),
            "finding_ids": [str(finding.id) for finding in completion.findings],
            "created": completion.created,
        },
        status=201 if completion.created else 200,
    )


def _authorized_assurance_run(request: HttpRequest, run_id: uuid.UUID) -> AssuranceRun:
    actor = _actor(request)
    run = get_tenant_record(
        queryset=AssuranceRun.objects.select_related("repository", "context_packet"),
        record_id=run_id,
        organization_id=actor.organization_id,
    )
    if run.repository_id is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    task = (
        EvaluatorTask.objects.select_related("request_artifact")
        .filter(
            organization_id=actor.organization_id,
            assurance_run=run,
        )
        .first()
    )
    packet = run.context_packet
    if task is None or packet is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=run.repository_id,
        access_scope_id=task.request_artifact.access_scope_id,
    )
    authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=run.repository_id,
        access_scope_id=packet.access_scope_id,
    )
    return run


@api_errors
@require_http_methods(["GET"])
def assurance_detail(request: HttpRequest, run_id: uuid.UUID) -> JsonResponse:
    run = _authorized_assurance_run(request, run_id)
    return JsonResponse(
        {
            "id": str(run.id),
            "state": run.state,
            "readiness": run.readiness or None,
            "revision": run.revision,
            "pull_request_number": run.pull_request_number,
            "pull_request_revision_id": str(run.pull_request_revision_id),
            "head_commit": run.head_commit,
            "input_hash": run.input_hash,
            "requirements_hash": run.requirements_hash,
            "policy_bundle_hash": run.policy_bundle_hash,
            "evidence_bundle_hash": run.evidence_bundle_hash,
            "evaluator_version": run.evaluator_version,
            "prompt_version": run.prompt_version,
            "limitations": run.limitations,
        }
    )


@api_errors
@require_http_methods(["GET"])
def assurance_findings(request: HttpRequest, run_id: uuid.UUID) -> JsonResponse:
    run = _authorized_assurance_run(request, run_id)
    findings = Finding.objects.filter(
        organization_id=run.organization_id,
        findingoccurrence__assurance_run=run,
    ).order_by("severity", "fingerprint")
    return JsonResponse(
        {
            "assurance_run_id": str(run.id),
            "findings": [
                {
                    "id": str(finding.id),
                    "fingerprint": finding.fingerprint,
                    "code": finding.code,
                    "kind": finding.kind,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "title": finding.title,
                    "explanation": finding.explanation,
                    "path": finding.path,
                    "line": finding.line,
                    "citations": finding.citations,
                    "evidence_ids": finding.evidence_ids,
                    "criterion_codes": finding.criterion_codes,
                    "uncertainty": finding.uncertainty,
                    "suggested_resolution": finding.suggested_resolution,
                    "state": finding.state,
                    "revision": finding.revision,
                }
                for finding in findings
            ],
        }
    )


@api_errors
@require_http_methods(["GET"])
def assurance_report(request: HttpRequest, run_id: uuid.UUID) -> JsonResponse:
    run = _authorized_assurance_run(request, run_id)
    report = AssuranceReport.objects.filter(
        organization_id=run.organization_id,
        assurance_run=run,
    ).first()
    if report is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    return JsonResponse(
        {
            "id": str(report.id),
            "assurance_run_id": str(run.id),
            "readiness": run.readiness,
            "head_commit": run.head_commit,
            "renderer_version": report.renderer_version,
            "content_hash": report.content_hash,
            "markdown": report.markdown,
            "html": report.html,
            "limitations": run.limitations,
        }
    )


@api_errors
@require_http_methods(["POST"])
def assurance_post_merge_proposals(
    request: HttpRequest,
    run_id: uuid.UUID,
) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset({"proposals"}),
        required=frozenset({"proposals"}),
    )
    proposals = payload["proposals"]
    if not isinstance(proposals, list) or not all(isinstance(item, dict) for item in proposals):
        raise ValueError("proposals must be a list of objects")
    links = propose_post_merge_knowledge(
        actor=_actor(request),
        run_id=run_id,
        proposals=cast(list[dict[str, object]], proposals),
    )
    return JsonResponse(
        {
            "assurance_run_id": str(run_id),
            "proposals": [
                {
                    "link_id": str(link.id),
                    "knowledge_proposal_id": str(link.knowledge_proposal_id),
                    "state": link.knowledge_proposal.state,
                    "classification": link.classification,
                    "confidence": link.confidence,
                }
                for link in links
            ],
            "automatic_acceptance": False,
        },
        status=201,
    )


@api_errors
@require_http_methods(["POST"])
def transition_assurance(request: HttpRequest, run_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    artifact_id = _optional_string(payload, "context_artifact_id")
    run = execute_assurance_transition(
        actor=actor,
        run_id=run_id,
        target_state=_string(payload, "target_state"),
        expected_revision=_integer(payload, "expected_revision"),
        evaluated_commit=_optional_string(payload, "evaluated_commit"),
        report_commit=_optional_string(payload, "report_commit"),
        context_artifact_id=uuid.UUID(artifact_id) if artifact_id else None,
    )
    return JsonResponse(
        {
            "id": str(run.id),
            "state": run.state,
            "revision": run.revision,
            "head_commit": run.head_commit,
        }
    )


@api_errors
@require_http_methods(["POST"])
def dismiss_finding(request: HttpRequest, finding_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    raw_payload = _json_body(request)
    repository_id = uuid.UUID(_string(raw_payload, "repository_id"))
    authorize_sensitive_placeholder(
        actor=actor,
        repository_id=repository_id,
        action=Action.FINDING_DISMISS,
    )
    payload = _closed_payload(
        raw_payload,
        allowed=frozenset(
            {
                "repository_id",
                "target_state",
                "expected_revision",
                "reason",
            }
        ),
        required=frozenset({"repository_id"}),
    )
    target_state = _optional_string(payload, "target_state") or Finding.State.DISMISSED
    reason = _optional_string(payload, "reason") or "Authorized finding dismissal."
    finding = decide_finding(
        actor=actor,
        repository_id=repository_id,
        finding_id=finding_id,
        target_state=target_state,
        expected_revision=_optional_integer(payload, "expected_revision", 1),
        reason=reason,
    )
    return JsonResponse(
        {
            "id": str(finding.id),
            "state": finding.state,
            "revision": finding.revision,
        }
    )


@api_errors
@require_http_methods(["POST"])
def override_policy(request: HttpRequest, policy_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    raw_payload = _json_body(request)
    repository_id = uuid.UUID(_string(raw_payload, "repository_id"))
    authorize_action(
        actor=actor,
        action=Action.POLICY_OVERRIDE,
        repository_id=repository_id,
    )
    payload = _closed_payload(
        raw_payload,
        allowed=frozenset(
            {
                "repository_id",
                "policy_evaluation_id",
                "policy_version_id",
                "requirement_code",
                "pull_request_number",
                "commit_sha",
                "reason",
                "expires_at",
            }
        ),
        required=frozenset(
            {
                "repository_id",
                "policy_evaluation_id",
                "policy_version_id",
                "requirement_code",
                "pull_request_number",
                "commit_sha",
                "reason",
            }
        ),
    )
    expires = _optional_string(payload, "expires_at")
    override, created = create_policy_override(
        actor=actor,
        repository_id=repository_id,
        policy_id=policy_id,
        policy_evaluation_id=uuid.UUID(_string(payload, "policy_evaluation_id")),
        policy_version_id=uuid.UUID(_string(payload, "policy_version_id")),
        requirement_code=_string(payload, "requirement_code"),
        pull_request_number=_integer(payload, "pull_request_number"),
        commit_sha=_string(payload, "commit_sha"),
        reason=_string(payload, "reason"),
        expires_at=_date_time(payload, "expires_at") if expires else None,
    )
    return JsonResponse(
        {
            "policy_override_id": str(override.id),
            "policy_version_id": str(override.policy_version_id),
            "commit_sha": override.commit_sha,
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def policy_override_revocation(
    request: HttpRequest,
    policy_override_id: uuid.UUID,
) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset({"repository_id", "reason"}),
        required=frozenset({"repository_id", "reason"}),
    )
    revocation, created = revoke_policy_override(
        actor=_actor(request),
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        policy_override_id=policy_override_id,
        reason=_string(payload, "reason"),
    )
    return JsonResponse(
        {
            "policy_override_revocation_id": str(revocation.id),
            "policy_override_id": str(revocation.policy_override_id),
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def evidence_submission(
    request: HttpRequest,
    repository_id: uuid.UUID,
    pull_request_number: int,
) -> JsonResponse:
    result = submit_evidence_manifest(
        actor=_actor(request),
        repository_id=repository_id,
        pull_request_number=pull_request_number,
        payload=_json_body(request),
    )
    return JsonResponse(
        {
            "manifest_id": str(result.manifest.id),
            "payload_hash": result.manifest.payload_hash,
            "evidence_ids": [str(record.id) for record in result.evidence],
            "created": result.created,
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def evidence_upload_authorization(
    request: HttpRequest,
    repository_id: uuid.UUID,
    pull_request_number: int,
) -> JsonResponse:
    """Issue a scoped upload secret without persisting or logging its raw value."""
    from anva.core.services.evidence_uploads import (
        EvidenceUploadError,
        issue_upload_authorization,
    )

    actor = _actor(request)
    payload = _json_body(request)
    validate_payload("evidence-upload-authorization", payload)
    try:
        grant = issue_upload_authorization(
            actor=actor,
            repository_id=repository_id,
            access_scope_id=uuid.UUID(_string(payload, "access_scope_id")),
            pull_request_number=pull_request_number,
            commit_sha=_string(payload, "commit_sha"),
            filename=_string(payload, "filename"),
            declared_sha256=_string(payload, "declared_sha256"),
            declared_size=_integer(payload, "declared_size"),
            idempotency_key=_string(payload, "idempotency_key"),
        )
    except EvidenceUploadError as error:
        return _error(
            error.code,
            error.safe_message,
            _correlation_id(request),
            error.http_status,
        )
    authorization = grant.authorization
    return JsonResponse(
        {
            "authorization_id": str(authorization.id),
            "repository_id": str(repository_id),
            "access_scope_id": str(authorization.access_scope_id),
            "pull_request_number": pull_request_number,
            "commit_sha": authorization.commit_sha,
            "declared_sha256": authorization.declared_sha256,
            "declared_size": authorization.declared_size,
            "state": authorization.state,
            "expires_at": authorization.expires_at.isoformat(),
            "upload_path": (f"/api/v1/evidence-upload-authorizations/{authorization.id}/content"),
            "upload_token": grant.raw_token,
            "replayed": grant.replayed,
        },
        status=200 if grant.replayed else 201,
    )


@api_errors
@require_http_methods(["PUT"])
def evidence_upload_content(
    request: HttpRequest,
    authorization_id: uuid.UUID,
) -> JsonResponse:
    """Stream untrusted evidence bytes to the bounded accepted-only pipeline."""
    from anva.core.services.evidence_uploads import (
        EvidenceUploadError,
        accept_evidence_upload,
    )

    actor = _actor(request)
    try:
        blob = accept_evidence_upload(
            authorization_id=authorization_id,
            raw_token=request.headers.get("X-Anva-Evidence-Upload-Token", ""),
            actor=actor,
            stream=cast(IO[bytes], request),
            content_length=_stream_content_length(request),
            expected_sha256=request.headers.get("X-Anva-Content-SHA256", ""),
        )
    except EvidenceUploadError as error:
        return _error(
            error.code,
            error.safe_message,
            _correlation_id(request),
            error.http_status,
        )
    return JsonResponse(
        {
            "evidence_blob_id": str(blob.id),
            "authorization_id": str(authorization_id),
            "sha256": blob.content_hash,
            "verified_size": blob.verified_size,
            "detected_type": blob.detected_media_type,
            "archive_summary": blob.archive_summary,
            "storage_state": blob.storage_state,
        },
        status=201,
    )


@api_errors
@require_http_methods(["GET"])
def evidence_manifest_detail(
    request: HttpRequest,
    manifest_id: uuid.UUID,
) -> JsonResponse:
    actor = _actor(request)
    manifest = get_tenant_record(
        queryset=EvidenceManifest.objects.all(),
        record_id=manifest_id,
        organization_id=actor.organization_id,
    )
    authorize_action(
        actor=actor,
        action=Action.EVIDENCE_VIEW,
        repository_id=manifest.repository_id,
        access_scope_id=manifest.access_scope_id,
    )
    return JsonResponse(
        {
            "id": str(manifest.id),
            "repository_id": str(manifest.repository_id),
            "pull_request_number": manifest.pull_request_number,
            "commit_sha": manifest.commit_sha,
            "payload_hash": manifest.payload_hash,
            "manifest": manifest.artifact.payload,
        }
    )


@api_errors
@require_http_methods(["POST"])
def criterion_evidence_mapping(
    request: HttpRequest,
    work_item_revision_id: uuid.UUID,
) -> JsonResponse:
    payload = _closed_payload(
        _json_body(request),
        allowed=frozenset(
            {
                "repository_id",
                "pull_request_number",
                "commit_sha",
                "reference_time",
            }
        ),
        required=frozenset(
            {
                "repository_id",
                "pull_request_number",
                "commit_sha",
                "reference_time",
            }
        ),
    )
    result = map_criterion_evidence(
        actor=_actor(request),
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        pull_request_number=_integer(payload, "pull_request_number"),
        work_item_revision_id=work_item_revision_id,
        commit_sha=_string(payload, "commit_sha"),
        reference_time=_date_time(payload, "reference_time"),
    )
    return JsonResponse(
        {
            "mappings": [
                {
                    "id": str(mapping.id),
                    "criterion_id": str(mapping.criterion_id),
                    "evidence_id": (str(mapping.evidence_id) if mapping.evidence_id else None),
                    "required_evidence_type": mapping.required_evidence_type,
                    "pull_request_number": mapping.pull_request_number,
                    "reference_time": mapping.reference_time.isoformat(),
                    "engine_version": mapping.engine_version,
                    "input_hash": mapping.input_hash,
                    "assessment": mapping.assessment,
                    "classification": mapping.classification,
                    "gap_code": mapping.gap_code,
                    "gap_description": mapping.gap_description,
                }
                for mapping in result.mappings
            ]
        },
        status=201 if result.created else 200,
    )


@api_errors
@require_http_methods(["POST"])
def revoke_source(request: HttpRequest, source_connection_id: uuid.UUID) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    source = revoke_source_connection(
        actor=actor,
        source_connection_id=source_connection_id,
        expected_revision=_integer(payload, "expected_revision"),
    )
    return JsonResponse({"id": str(source.id), "state": source.state, "revision": source.revision})


@api_errors
@require_http_methods(["POST"])
def connect_filesystem(request: HttpRequest) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    source, created = connect_filesystem_source(
        actor=actor,
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        access_scope_id=uuid.UUID(_string(payload, "access_scope_id")),
        external_key=_string(payload, "external_key"),
        display_name=_string(payload, "display_name"),
        root=_string(payload, "root"),
    )
    return JsonResponse(
        {
            "id": str(source.id),
            "state": source.state,
            "revision": source.revision,
            "created": created,
        },
        status=201 if created else 200,
    )


@api_errors
@require_http_methods(["GET"])
def source_detail(request: HttpRequest, source_connection_id: uuid.UUID) -> JsonResponse:
    return JsonResponse(
        inspect_source(
            actor=_actor(request),
            source_connection_id=source_connection_id,
        )
    )


def _request_source_sync(
    request: HttpRequest,
    source_connection_id: uuid.UUID,
    *,
    force_full: bool,
) -> JsonResponse:
    actor = _actor(request)
    payload = _json_body(request)
    requested_mode = _optional_string(payload, "scan_mode")
    scan_mode = "FULL" if force_full else requested_mode or "FULL"
    run, created = request_ingestion_sync(
        actor=actor,
        source_connection_id=source_connection_id,
        scan_mode=scan_mode,
    )
    return JsonResponse(
        {
            "id": str(run.id),
            "source_connection_id": str(run.source_connection_id),
            "access_snapshot_id": str(run.access_snapshot_id),
            "scan_mode": run.scan_mode,
            "state": run.state,
            "created": created,
        },
        status=202,
    )


@api_errors
@require_http_methods(["POST"])
def sync_source(request: HttpRequest, source_connection_id: uuid.UUID) -> JsonResponse:
    return _request_source_sync(request, source_connection_id, force_full=False)


@api_errors
@require_http_methods(["POST"])
def resync_source(request: HttpRequest, source_connection_id: uuid.UUID) -> JsonResponse:
    return _request_source_sync(request, source_connection_id, force_full=True)


@api_errors
@require_http_methods(["GET"])
def source_runs(request: HttpRequest, source_connection_id: uuid.UUID) -> JsonResponse:
    return JsonResponse(
        {
            "sync_runs": source_sync_runs(
                actor=_actor(request),
                source_connection_id=source_connection_id,
            )
        }
    )
