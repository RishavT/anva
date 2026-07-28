"""Thin versioned REST adapters for tenancy and authorization behavior."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from functools import wraps
from typing import Any, cast

from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from anva.core.exceptions import (
    AuthenticationError,
    DomainOperationError,
    ResourceNotFoundError,
)
from anva.core.models import Organization
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
)
from anva.core.services.bootstrap import bootstrap_local_organization
from anva.core.services.context import ActorContext
from anva.core.services.retrieval import (
    get_authorized_artifact,
    get_authorized_assertion,
    search_assertions,
)
from anva.core.services.scopes import revoke_source_connection
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

MAX_JSON_BODY_BYTES = 64 * 1024


def _correlation_id(request: HttpRequest) -> uuid.UUID:
    raw = request.headers.get("X-Correlation-ID", "")
    try:
        return uuid.UUID(raw) if raw else uuid.uuid4()
    except ValueError:
        return uuid.uuid4()


def _error(code: str, message: str, correlation_id: uuid.UUID, status: int) -> JsonResponse:
    return JsonResponse(
        {
            "code": code,
            "message": message,
            "correlation_id": str(correlation_id),
        },
        status=status,
    )


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


def _optional_string(payload: dict[str, object], name: str) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _actor(request: HttpRequest) -> ActorContext:
    actor = authenticate_bearer(request.headers.get("Authorization", ""))
    return replace(actor, request_id=_correlation_id(request))


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
    records = search_assertions(
        actor=actor,
        repository_id=repository_id,
        query=_string(payload, "query"),
    )
    return JsonResponse(
        {
            "results": [
                {
                    "id": str(record.id),
                    "subject_key": record.subject_key,
                    "predicate": record.predicate,
                    "value": record.value,
                }
                for record in records
            ]
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
    assertion_id = uuid.UUID(_string(payload, "assertion_id"))
    record = get_authorized_assertion(
        actor=actor,
        repository_id=repository_id,
        assertion_id=assertion_id,
        action=Action.MCP_CONTEXT,
    )
    return _assertion_response(record)


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
    del finding_id
    actor = _actor(request)
    payload = _json_body(request)
    authorize_sensitive_placeholder(
        actor=actor,
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        action=Action.FINDING_DISMISS,
    )
    return JsonResponse({"status": "AUTHORIZED_NOT_IMPLEMENTED"}, status=202)


@api_errors
@require_http_methods(["POST"])
def override_policy(request: HttpRequest, policy_id: uuid.UUID) -> JsonResponse:
    del policy_id
    actor = _actor(request)
    payload = _json_body(request)
    authorize_sensitive_placeholder(
        actor=actor,
        repository_id=uuid.UUID(_string(payload, "repository_id")),
        action=Action.POLICY_OVERRIDE,
    )
    return JsonResponse({"status": "AUTHORIZED_NOT_IMPLEMENTED"}, status=202)


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
