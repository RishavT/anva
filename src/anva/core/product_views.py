"""Thin server-rendered adapters over the permission-safe product facade."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from functools import wraps
from typing import Any, cast

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from anva import __version__
from anva.core.exceptions import (
    AuthenticationError,
    DomainOperationError,
    ResourceNotFoundError,
)
from anva.core.models import KnowledgeProposal, SyncRun
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
