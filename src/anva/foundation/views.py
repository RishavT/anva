"""Thin HTTP adapters for foundation services."""

from __future__ import annotations

import hmac

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from anva import __version__
from anva.foundation.services import readiness_status
from anva.foundation.telemetry import PROCESS_METRICS


@require_GET
def home(request: HttpRequest) -> HttpResponse:
    """Render the server-owned application shell."""
    return render(request, "home.html", {"version": __version__})


@require_GET
def liveness(request: HttpRequest) -> JsonResponse:
    """Report that the API process can serve requests."""
    return JsonResponse({"status": "alive", "version": __version__})


@require_GET
def readiness(request: HttpRequest) -> JsonResponse:
    """Report bounded dependency readiness without leaking configuration."""
    status = readiness_status()
    return JsonResponse(status.as_dict(), status=200 if status.healthy else 503)


@require_GET
def metrics(request: HttpRequest) -> HttpResponse:
    """Expose non-tenant operational metrics to an authenticated scraper."""
    configured_token = str(settings.ANVA_METRICS_TOKEN)
    supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not configured_token or not hmac.compare_digest(configured_token, supplied):
        return HttpResponse(status=404)
    status = readiness_status()
    return HttpResponse(
        PROCESS_METRICS.render(version=__version__, ready=status.healthy),
        content_type="text/plain; version=0.0.4; charset=utf-8",
    )
