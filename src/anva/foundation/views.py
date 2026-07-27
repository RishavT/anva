"""Thin HTTP adapters for foundation services."""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from anva import __version__
from anva.foundation.services import readiness_status


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
