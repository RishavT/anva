"""Thin server-rendered adapters over the permission-safe product facade."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import replace
from functools import wraps
from typing import Any, cast

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from anva import __version__
from anva.core.exceptions import (
    AuthenticationError,
    DomainOperationError,
    RateLimitExceededError,
    ResourceNotFoundError,
)
from anva.core.models import KnowledgeProposal, SyncRun
from anva.core.services.canvas import CANVAS_PAYLOAD_LIMIT_BYTES, CanvasQuery
from anva.core.services.product_ui import (
    ProductUIFacade,
    SetupInput,
    bootstrap_product,
    setup_available,
)
from anva.core.services.web_auth import (
    clear_web_session,
    establish_web_session,
    resolve_web_principal,
)


def _safe_next(request: HttpRequest) -> str:
    value = request.GET.get("next", "")
    return value if value.startswith("/app") and not value.startswith("//") else "/app"


def _correlation(request: HttpRequest) -> str:
    resolved = getattr(request, "anva_correlation_id", "")
    if isinstance(resolved, str):
        try:
            return str(uuid.UUID(resolved))
        except ValueError:
            pass
    raw = request.headers.get("X-Correlation-ID", "")
    try:
        return str(uuid.UUID(raw)) if raw else str(uuid.uuid4())
    except ValueError:
        return str(uuid.uuid4())


def _product(request: HttpRequest) -> tuple[ProductUIFacade, dict[str, object]]:
    principal = resolve_web_principal(request)
    facade = ProductUIFacade(principal.actor)
    shell = facade.shell()
    return facade, shell


def _render(
    request: HttpRequest,
    template: str,
    *,
    shell: dict[str, object],
    section: str,
    status: int = 200,
    **context: object,
) -> HttpResponse:
    return render(
        request,
        template,
        {
            "version": __version__,
            "shell": shell,
            "current_section": section,
            "notice": request.GET.get("notice", "")[:200],
            **context,
        },
        status=status,
    )


def web_errors[**Parameters](
    view: Callable[Parameters, HttpResponse],
) -> Callable[Parameters, HttpResponse]:
    """Use stable browser errors without leaking governed object existence."""

    @wraps(view)
    def wrapped(*args: Parameters.args, **kwargs: Parameters.kwargs) -> HttpResponse:
        request = cast(HttpRequest, args[0])
        try:
            return view(*args, **kwargs)
        except AuthenticationError:
            clear_web_session(request)
            next_path = request.path if request.path.startswith("/app") else "/app"
            return redirect(f"{reverse('product-access')}?next={next_path}")
        except ResourceNotFoundError:
            return render(
                request,
                "product/error.html",
                {
                    "version": __version__,
                    "status_code": 404,
                    "error_title": "This record is not available",
                    "error_message": (
                        "It may not exist, may be outside your current access, or may have "
                        "been revoked."
                    ),
                    "correlation_id": _correlation(request),
                },
                status=404,
            )
        except RateLimitExceededError as error:
            response = render(
                request,
                "product/error.html",
                {
                    "version": __version__,
                    "status_code": 429,
                    "error_title": "Too many requests",
                    "error_message": "Wait briefly, then try again.",
                    "correlation_id": _correlation(request),
                },
                status=429,
            )
            response.headers["Retry-After"] = str(error.retry_after_seconds)
            return response
        except DomainOperationError:
            return render(
                request,
                "product/error.html",
                {
                    "version": __version__,
                    "status_code": 409,
                    "error_title": "The record changed",
                    "error_message": (
                        "The operation was not applied. Review the current state before trying "
                        "again."
                    ),
                    "correlation_id": _correlation(request),
                },
                status=409,
            )
        except (TypeError, ValueError):
            return render(
                request,
                "product/error.html",
                {
                    "version": __version__,
                    "status_code": 400,
                    "error_title": "Check the submitted information",
                    "error_message": "No change was applied. Correct the highlighted request.",
                    "correlation_id": _correlation(request),
                },
                status=400,
            )

    return wrapped


def web_json_errors[**Parameters](
    view: Callable[Parameters, JsonResponse],
) -> Callable[Parameters, JsonResponse]:
    """Return stable fetch errors without leaking inaccessible Canvas records."""

    @wraps(view)
    def wrapped(*args: Parameters.args, **kwargs: Parameters.kwargs) -> JsonResponse:
        request = cast(HttpRequest, args[0])
        correlation_id = _correlation(request)
        try:
            return view(*args, **kwargs)
        except AuthenticationError:
            clear_web_session(request)
            return _canvas_json_response(
                {"code": "invalid_credential", "correlation_id": correlation_id},
                status=401,
            )
        except ResourceNotFoundError:
            return _canvas_json_response(
                {"code": "resource_not_found", "correlation_id": correlation_id},
                status=404,
            )
        except DomainOperationError as error:
            return _canvas_json_response(
                {"code": error.code, "correlation_id": correlation_id},
                status=409,
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return _canvas_json_response(
                {"code": "invalid_request", "correlation_id": correlation_id},
                status=400,
            )

    return wrapped


def _canvas_json_response(payload: dict[str, object], *, status: int = 200) -> JsonResponse:
    """Serialize exactly like the service budget: compact, sorted, UTF-8 JSON."""
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
        raise ValueError("Canvas response exceeds its byte budget")
    return response


@require_GET
def root(request: HttpRequest) -> HttpResponse:
    """Route an active human session to attention and everyone else to truthful access."""
    try:
        resolve_web_principal(request)
    except AuthenticationError:
        return redirect("product-setup" if setup_available() else "product-access")
    return redirect("product-home")


@require_http_methods(["GET", "POST"])
def setup(request: HttpRequest) -> HttpResponse:
    """One-time setup; accepted choices are persisted atomically."""
    if not setup_available():
        return redirect("product-access")
    errors: list[str] = []
    if request.method == "POST":
        try:
            result = bootstrap_product(
                supplied_secret=request.POST.get("bootstrap_secret", ""),
                data=SetupInput(
                    organization_slug=request.POST.get("organization_slug", "").strip(),
                    organization_name=request.POST.get("organization_name", "").strip(),
                    admin_email=request.POST.get("admin_email", "").strip(),
                    admin_display_name=request.POST.get("admin_name", "").strip(),
                    repository_external_id=request.POST.get("repository_external_id", "").strip(),
                    repository_name=request.POST.get("repository_name", "").strip(),
                    retention_days=int(request.POST.get("retention_days", "365")),
                    model_processing=request.POST.get("model_processing", "REDACTED_ONLY"),
                    skill_distribution=request.POST.get("skill_distribution", "SELF_SERVICE"),
                    assurance_mode=request.POST.get("assurance_mode", "OBSERVE"),
                ),
            )
            establish_web_session(
                request,
                user_id=result.user.id,
                organization_id=result.organization.id,
            )
            return redirect("product-onboarding")
        except (AuthenticationError, DomainOperationError, TypeError, ValueError):
            errors.append(
                "Setup could not be completed. Check every field and the local bootstrap secret."
            )
    return render(
        request,
        "product/setup.html",
        {
            "version": __version__,
            "errors": errors,
            "safe_values": {
                key: request.POST.get(key, "")
                for key in (
                    "organization_name",
                    "organization_slug",
                    "admin_name",
                    "admin_email",
                    "repository_name",
                    "repository_external_id",
                    "retention_days",
                    "model_processing",
                    "skill_distribution",
                    "assurance_mode",
                )
            },
        },
        status=400 if errors else 200,
    )


@require_GET
def access(request: HttpRequest) -> HttpResponse:
    """Truthful re-entry state until an approved user authenticator is configured."""
    try:
        resolve_web_principal(request)
    except AuthenticationError:
        pass
    else:
        return redirect(_safe_next(request))
    return render(
        request,
        "product/access.html",
        {
            "version": __version__,
            "next": _safe_next(request),
            "bootstrap_available": setup_available(),
        },
        status=200,
    )


@web_errors
@require_POST
def logout(request: HttpRequest) -> HttpResponse:
    resolve_web_principal(request)
    clear_web_session(request)
    return redirect("product-access")


@web_errors
@require_GET
def home(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/home.html",
        shell=shell,
        section="home",
        page=facade.home(),
    )


@web_errors
@require_GET
def onboarding(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/onboarding.html",
        shell=shell,
        section="onboarding",
        page=facade.onboarding(),
    )


def _optional_uuid(value: str | None) -> uuid.UUID | None:
    return uuid.UUID(value) if value else None


@web_errors
@require_GET
def explorer(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    page = facade.explorer(
        repository_id=_optional_uuid(request.GET.get("repository")),
        start_entity_id=_optional_uuid(request.GET.get("start_entity")),
        query=request.GET.get("q", "").strip()[:500],
        entity_type=request.GET.get("type", ""),
        freshness=request.GET.get("freshness", ""),
    )
    return _render(
        request,
        "product/explorer.html",
        shell=shell,
        section="explorer",
        page=page,
    )


@web_errors
@require_GET
def entity_detail(request: HttpRequest, entity_id: uuid.UUID) -> HttpResponse:
    facade, shell = _product(request)
    repository_id = _optional_uuid(request.GET.get("repository"))
    if repository_id is None:
        repositories = cast(list[object], shell["repositories"])
        if not repositories:
            raise ResourceNotFoundError("Governed record was not found")
        repository_id = cast(Any, repositories[0]).id
    return _render(
        request,
        "product/entity.html",
        shell=shell,
        section="explorer",
        page=facade.entity(repository_id=repository_id, entity_id=entity_id),
    )


def _uuid_tuple(values: list[object]) -> tuple[uuid.UUID, ...]:
    return tuple(uuid.UUID(str(value)) for value in values if value)


def _string_tuple(values: list[object]) -> tuple[str, ...]:
    return tuple(str(value) for value in values if value)


def _json_string(payload: dict[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Canvas {name} must be a non-empty string")
    return value


def _json_integer(payload: dict[str, object], name: str, *, default: int | None = None) -> int:
    value = payload.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Canvas {name} must be an integer")
    return value


def _json_uuid(payload: dict[str, object], name: str) -> uuid.UUID:
    return uuid.UUID(_json_string(payload, name))


def _canvas_query(
    payload: dict[str, object],
    *,
    query_string_values: bool = False,
) -> CanvasQuery:
    allowed = {
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
    if set(payload) - allowed:
        raise ValueError("Canvas query contains additional properties")
    repositories = payload.get("repository_ids", [])
    entity_types = payload.get("entity_types", [])
    layers = payload.get("layers", [])
    if not all(
        isinstance(value, list) and all(isinstance(item, str) for item in value)
        for value in (repositories, entity_types, layers)
    ):
        raise ValueError("Canvas query list fields are invalid")
    as_of_value = payload.get("as_of")
    if as_of_value is not None and not isinstance(as_of_value, str):
        raise ValueError("Canvas as-of time is invalid")
    parsed_as_of = parse_datetime(as_of_value) if as_of_value else None
    if parsed_as_of is not None and parsed_as_of.tzinfo is None:
        parsed_as_of = timezone.make_aware(parsed_as_of)
    if as_of_value and parsed_as_of is None:
        raise ValueError("Canvas as-of time is invalid")

    def optional_uuid(name: str) -> uuid.UUID | None:
        if name not in payload:
            return None
        value = payload[name]
        if query_string_values and value == "":
            return None
        if name == "anchor_id" and value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"Canvas {name} must be a UUID string")
        return uuid.UUID(value)

    def text(name: str) -> str:
        value = payload.get(name, "")
        if not isinstance(value, str):
            raise ValueError(f"Canvas {name} must be a string")
        return value

    def integer(name: str, default: int, *, optional: bool = False) -> int | None:
        if name not in payload:
            return None if optional else default
        value = payload[name]
        if query_string_values and optional and value == "":
            return None
        if query_string_values:
            if not isinstance(value, str):
                raise ValueError(f"Canvas {name} must be an integer string")
            return int(value)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"Canvas {name} must be an integer")
        return value

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
        view_revision=integer("view_revision", 0, optional=True),
        repository_ids=tuple(
            uuid.UUID(value)
            for value in cast(list[str], repositories)
            if value or not query_string_values
        ),
        entity_types=_string_tuple(cast(list[object], entity_types)),
        owner=text("owner"),
        status=text("status"),
        risk=text("risk"),
        freshness=text("freshness"),
        as_of=parsed_as_of,
        search=text("search"),
        layers=_string_tuple(cast(list[object], layers)),
        anchor_id=optional_uuid("anchor_id"),
        depth=integer("depth", 2, optional=True),
        provided_semantic_fields=provided_semantic_fields,
        node_limit=cast(int, integer("node_limit", 300)),
        edge_limit=cast(int, integer("edge_limit", 600)),
    )


def _request_json(request: HttpRequest) -> dict[str, object]:
    if len(request.body) > CANVAS_PAYLOAD_LIMIT_BYTES:
        raise ValueError("Canvas request exceeds its byte budget")
    payload = json.loads(request.body or b"{}")
    if not isinstance(payload, dict):
        raise ValueError("Canvas request must be an object")
    return cast(dict[str, object], payload)


def _canvas_presentation(payload: object) -> dict[str, list[dict[str, object]]]:
    if not isinstance(payload, dict):
        raise ValueError("Canvas presentation must be an object")
    fields = {"placements", "filters", "layers", "groups", "annotations"}
    if set(payload) != fields:
        raise ValueError("Canvas presentation fields are invalid")
    if not all(
        isinstance(value, list) and all(isinstance(item, dict) for item in value)
        for value in payload.values()
    ):
        raise ValueError("Canvas presentation entries must be object lists")
    return cast(dict[str, list[dict[str, object]]], payload)


def _canvas_get_query(request: HttpRequest) -> CanvasQuery:
    payload: dict[str, object] = {}
    controls_submitted = request.GET.get("semantic_controls") == "1"
    scalar_fields = {
        "view": "view_id",
        "revision": "view_revision",
        "owner": "owner",
        "status": "status",
        "risk": "risk",
        "freshness": "freshness",
        "as_of": "as_of",
        "q": "search",
        "focus": "anchor_id",
        "depth": "depth",
        "node_limit": "node_limit",
        "edge_limit": "edge_limit",
    }
    semantic_controls = {"owner", "status", "risk", "freshness", "as_of", "q", "focus"}
    for query_name, payload_name in scalar_fields.items():
        if query_name in request.GET or (controls_submitted and query_name in semantic_controls):
            payload[payload_name] = request.GET.get(query_name, "")
    payload["repository_ids"] = request.GET.getlist("repository")
    if "type" in request.GET or controls_submitted:
        payload["entity_types"] = request.GET.getlist("type")
    if "layer" in request.GET or controls_submitted:
        payload["layers"] = request.GET.getlist("layer")
    return _canvas_query(payload, query_string_values=True)


@web_errors
@require_GET
def canvas(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    path_source = _optional_uuid(request.GET.get("path_from"))
    path_target = _optional_uuid(request.GET.get("path_to"))
    share_id = _optional_uuid(request.GET.get("share"))
    if share_id:
        shared_query = facade.canvas_share_query(share_id)
        requested_query = _canvas_get_query(request)
        query = replace(
            shared_query,
            anchor_id=requested_query.anchor_id,
            depth=requested_query.depth,
            provided_semantic_fields=requested_query.provided_semantic_fields,
        )
    else:
        query = _canvas_get_query(request)
    page = facade.canvas(
        query=query,
        path_source_id=path_source,
        path_target_id=path_target,
    )
    page["active_share_id"] = str(share_id) if share_id else ""
    return _render(
        request,
        "product/canvas.html",
        shell=shell,
        section="canvas",
        page=page,
    )


@web_json_errors
@require_POST
def canvas_query(request: HttpRequest) -> JsonResponse:
    facade, _shell = _product(request)
    page = facade.canvas(query=_canvas_query(_request_json(request)))
    return _canvas_json_response(cast(dict[str, object], page["graph"]))


@web_json_errors
@require_POST
def canvas_path_query(request: HttpRequest) -> JsonResponse:
    facade, _shell = _product(request)
    payload = _request_json(request)
    if set(payload) - {"source_id", "target_id", "repository_ids", "max_depth"}:
        raise ValueError("Canvas path contains additional properties")
    repositories = payload.get("repository_ids", [])
    if not isinstance(repositories, list) or not all(
        isinstance(item, str) for item in repositories
    ):
        raise ValueError("Canvas path repositories are invalid")
    from anva.core.services.canvas import canvas_path

    return _canvas_json_response(
        canvas_path(
            actor=facade.actor,
            source_id=_json_uuid(payload, "source_id"),
            target_id=_json_uuid(payload, "target_id"),
            repository_ids=tuple(uuid.UUID(value) for value in cast(list[str], repositories)),
            max_depth=_json_integer(payload, "max_depth", default=6),
        )
    )


@web_json_errors
@require_GET
def canvas_entity_detail(request: HttpRequest, entity_id: uuid.UUID) -> JsonResponse:
    facade, _shell = _product(request)
    return _canvas_json_response(
        facade.canvas_detail(
            entity_id=entity_id,
            repository_ids=_uuid_tuple(cast(list[object], request.GET.getlist("repository"))),
        )
    )


@web_json_errors
@require_POST
def canvas_question(request: HttpRequest) -> JsonResponse:
    facade, _shell = _product(request)
    payload = _request_json(request)
    if set(payload) != {"entity_id", "repository_id", "question"}:
        raise ValueError("Canvas question request is invalid")
    if not all(isinstance(payload[key], str) for key in payload):
        raise ValueError("Canvas question fields must be strings")
    return _canvas_json_response(
        facade.canvas_question(
            entity_id=uuid.UUID(cast(str, payload["entity_id"])),
            repository_id=uuid.UUID(cast(str, payload["repository_id"])),
            question=cast(str, payload["question"]),
        )
    )


@web_errors
@require_POST
def canvas_view_create(request: HttpRequest) -> HttpResponse:
    facade, _shell = _product(request)
    entity_types = request.POST.getlist("entity_type")
    repository_id = _optional_uuid(request.POST.get("repository_id"))
    view, _created = facade.create_canvas(
        name=request.POST.get("name", ""),
        description=request.POST.get("description", ""),
        view_type=request.POST.get("view_type", ""),
        semantic_query={"entity_types": entity_types} if entity_types else {},
        repository_id=repository_id,
        idempotency_key=request.POST.get("idempotency_key", ""),
    )
    return redirect(f"{reverse('product-canvas')}?view={view.id}&notice=View+saved")


@web_json_errors
@require_POST
def canvas_view_revision(request: HttpRequest, view_id: uuid.UUID) -> JsonResponse:
    facade, _shell = _product(request)
    payload = _request_json(request)
    if set(payload) - {
        "expected_revision",
        "semantic_query",
        "presentation",
        "idempotency_key",
    }:
        raise ValueError("Canvas save contains additional properties")
    semantic = payload.get("semantic_query", {})
    if not isinstance(semantic, dict):
        raise ValueError("Canvas save objects are invalid")
    presentation = _canvas_presentation(payload.get("presentation"))
    revision, created = facade.save_canvas(
        view_id=view_id,
        expected_revision=_json_integer(payload, "expected_revision"),
        semantic_query=cast(dict[str, object], semantic),
        presentation=presentation,
        idempotency_key=_json_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {
            "view_id": str(view_id),
            "revision": revision.revision,
            "content_hash": revision.content_hash,
            "created": created,
        },
        status=201 if created else 200,
    )


@web_json_errors
@require_POST
def canvas_view_share(request: HttpRequest, view_id: uuid.UUID) -> JsonResponse:
    facade, _shell = _product(request)
    payload = _request_json(request)
    if set(payload) != {"idempotency_key"}:
        raise ValueError("Canvas share request is invalid")
    share, created = facade.share_canvas(
        view_id=view_id,
        idempotency_key=_json_string(payload, "idempotency_key"),
    )
    return _canvas_json_response(
        {
            "share_id": str(share.id),
            "deep_link": f"/app/canvas?share={share.id}",
            "created": created,
            "authorization_required": True,
        },
        status=201 if created else 200,
    )


@web_errors
@require_POST
def canvas_share_revoke(request: HttpRequest, share_id: uuid.UUID) -> HttpResponse:
    facade, _shell = _product(request)
    facade.revoke_canvas_share(
        share_id=share_id,
        expected_view_revision=int(request.POST.get("expected_view_revision", "0")),
        idempotency_key=request.POST.get("idempotency_key", ""),
    )
    return redirect(f"{reverse('product-canvas')}?notice=Share+revoked")


@web_errors
@require_POST
def canvas_relationship_proposal(request: HttpRequest) -> HttpResponse:
    facade, _shell = _product(request)
    proposal, _created = facade.propose_canvas_relationship(
        source_id=uuid.UUID(request.POST.get("source_id", "")),
        target_id=uuid.UUID(request.POST.get("target_id", "")),
        relationship_type=request.POST.get("relationship_type", ""),
        repository_id=uuid.UUID(request.POST.get("repository_id", "")),
        expected_source_revision=int(request.POST.get("expected_source_revision", "0")),
        expected_target_revision=int(request.POST.get("expected_target_revision", "0")),
        rationale=request.POST.get("rationale", ""),
        idempotency_key=request.POST.get("idempotency_key", ""),
    )
    return redirect(
        f"{reverse('product-canvas')}?notice=Relationship+proposal+{proposal.id}+created"
    )


@web_errors
@require_GET
def sources(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/sources.html",
        shell=shell,
        section="sources",
        page=facade.sources(),
    )


@web_errors
@require_GET
def source_detail(request: HttpRequest, source_id: uuid.UUID) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/source.html",
        shell=shell,
        section="sources",
        page=facade.source(source_id),
    )


@web_errors
@require_POST
def source_sync(request: HttpRequest, source_id: uuid.UUID) -> HttpResponse:
    facade, _shell = _product(request)
    facade.sync_source(
        source_id=source_id,
        scan_mode=request.POST.get("scan_mode", SyncRun.ScanMode.INCREMENTAL),
    )
    return redirect(f"{reverse('product-source', args=[source_id])}?notice=Sync+requested")


@web_errors
@require_POST
def source_revoke(request: HttpRequest, source_id: uuid.UUID) -> HttpResponse:
    facade, _shell = _product(request)
    if request.POST.get("confirmation") != "REVOKE":
        raise ValueError("Confirmation is required")
    facade.revoke_source(
        source_id=source_id,
        expected_revision=int(request.POST.get("expected_revision", "0")),
    )
    return redirect(f"{reverse('product-source', args=[source_id])}?notice=Source+revoked")


@web_errors
@require_GET
def review(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/review.html",
        shell=shell,
        section="review",
        page=facade.review_queue(
            repository_id=_optional_uuid(request.GET.get("repository")),
            queue=request.GET.get("queue", "unreviewed"),
        ),
    )


@web_errors
@require_POST
def review_decision(request: HttpRequest, assertion_id: uuid.UUID) -> HttpResponse:
    facade, _shell = _product(request)
    result = facade.review_assertion(
        repository_id=uuid.UUID(request.POST.get("repository_id", "")),
        assertion_id=assertion_id,
        decision=request.POST.get("decision", ""),
        expected_revision=int(request.POST.get("expected_revision", "0")),
        correction=request.POST.get("correction", "")[:2000],
    )
    notice = "Correction+proposed" if isinstance(result, KnowledgeProposal) else "Review+recorded"
    return redirect(f"{reverse('product-review')}?notice={notice}")


@web_errors
@require_GET
def repositories(request: HttpRequest, repository_id: uuid.UUID) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/repository.html",
        shell=shell,
        section="repositories",
        page=facade.repository(repository_id),
    )


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()][:100]


@web_errors
@require_POST
def repository_profile(request: HttpRequest, repository_id: uuid.UUID) -> HttpResponse:
    facade, _shell = _product(request)
    facade.save_repository_profile(
        repository_id=repository_id,
        expected_revision=int(request.POST.get("expected_revision", "0")),
        purpose=request.POST.get("purpose", "")[:4000],
        owning_team=request.POST.get("owning_team", "")[:300],
        setup_commands=_lines(request.POST.get("setup_commands", "")),
        required_checks=_lines(request.POST.get("required_checks", "")),
        sensitive_paths=_lines(request.POST.get("sensitive_paths", "")),
    )
    return redirect(
        f"{reverse('product-repository', args=[repository_id])}?notice=Profile+confirmed"
    )


@web_errors
@require_GET
def work(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/work.html",
        shell=shell,
        section="work",
        page=facade.work(),
    )


@web_errors
@require_GET
def work_detail(request: HttpRequest, work_item_id: uuid.UUID) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/work_detail.html",
        shell=shell,
        section="work",
        page=facade.work_detail(work_item_id),
    )


@web_errors
@require_GET
def policies(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/policies.html",
        shell=shell,
        section="policies",
        page=facade.policies(),
    )


@web_errors
@require_GET
def policy_detail(request: HttpRequest, policy_id: uuid.UUID) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/policy.html",
        shell=shell,
        section="policies",
        page=facade.policy(policy_id),
    )


@web_errors
@require_GET
def assurance(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/assurance.html",
        shell=shell,
        section="assurance",
        page=facade.assurance(),
    )


@web_errors
@require_GET
def assurance_detail(request: HttpRequest, run_id: uuid.UUID) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/assurance_detail.html",
        shell=shell,
        section="assurance",
        page=facade.assurance_detail(run_id),
    )


@web_errors
@require_GET
def skills(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    return _render(
        request,
        "product/skills.html",
        shell=shell,
        section="skills",
        page=facade.skills(),
    )


@web_errors
@require_GET
def audit(request: HttpRequest) -> HttpResponse:
    facade, shell = _product(request)
    filters = {
        key: request.GET.get(key, "").strip()
        for key in ("actor", "action", "target", "request_id", "date_from")
    }
    return _render(
        request,
        "product/audit.html",
        shell=shell,
        section="audit",
        page=facade.audit(filters),
    )
