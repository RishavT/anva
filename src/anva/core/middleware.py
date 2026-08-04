"""Browser response hardening for the server-rendered product."""

from __future__ import annotations

import ipaddress
import logging
import time
import uuid
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.middleware.csrf import CsrfViewMiddleware

from anva.core.exceptions import RateLimitExceededError
from anva.core.services.operations import enforce_pre_auth_rate_limit
from anva.foundation.telemetry import (
    PROCESS_METRICS,
    bind_context,
    reset_context,
    trace_context,
)

LOGGER = logging.getLogger("anva.http")


class TrustedProxyHeadersMiddleware:
    """Accept forwarded transport metadata only from explicitly trusted proxy IPs."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        remote = str(request.META.get("REMOTE_ADDR", ""))
        forwarded_proto = request.META.get("HTTP_X_FORWARDED_PROTO")
        if remote not in settings.ANVA_TRUSTED_PROXY_IPS or forwarded_proto not in {
            "http",
            "https",
        }:
            request.META.pop("HTTP_X_FORWARDED_PROTO", None)
        return self.get_response(request)


class BrowserCsrfViewMiddleware(CsrfViewMiddleware):
    """Protect session-backed web routes while leaving bearer APIs cookie-independent."""

    def process_view(  # type: ignore[override]
        self,
        request: HttpRequest,
        callback: Callable[..., HttpResponse],
        callback_args: tuple[object, ...],
        callback_kwargs: dict[str, object],
    ) -> HttpResponse | None:
        route_name = getattr(request.resolver_match, "url_name", None)
        if request.path.startswith("/api/v1/") and route_name != "api-v1-organization-decommission":
            return None
        return super().process_view(request, callback, callback_args, callback_kwargs)


def _client_rate_key(request: HttpRequest) -> str:
    """Resolve a client address without trusting arbitrary forwarding headers."""
    remote = str(request.META.get("REMOTE_ADDR", ""))
    candidate = remote
    if remote in settings.ANVA_TRUSTED_PROXY_IPS:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",", maxsplit=1)[0].strip()
        if forwarded:
            candidate = forwarded
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "unresolved-client"


class OperationalTelemetryMiddleware:
    """Emit correlated JSON request logs, W3C trace context, and safe metrics."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        raw_correlation_id = request.headers.get("X-Correlation-ID", "")
        try:
            correlation_id = str(uuid.UUID(raw_correlation_id))
        except ValueError:
            correlation_id = str(uuid.uuid4())
        if not raw_correlation_id:
            correlation_id = str(uuid.uuid4())
        trace = trace_context(request.headers.get("traceparent", ""))
        request.anva_correlation_id = correlation_id  # type: ignore[attr-defined]
        request.anva_trace_context = trace  # type: ignore[attr-defined]
        tokens = bind_context(correlation_id=correlation_id, trace=trace)
        started = time.monotonic()
        status = 500
        PROCESS_METRICS.begin()
        try:
            try:
                if request.path not in {"/health/live", "/health/ready", "/metrics"}:
                    request.anva_rate_limit = enforce_pre_auth_rate_limit(  # type: ignore[attr-defined]
                        client_key=_client_rate_key(request)
                    )
                response = self.get_response(request)
            except RateLimitExceededError as error:
                response = JsonResponse(
                    {
                        "code": error.code,
                        "message": str(error),
                        "correlation_id": correlation_id,
                    },
                    status=429,
                )
                response.headers["Retry-After"] = str(error.retry_after_seconds)
            status = response.status_code
            response.headers["X-Correlation-ID"] = correlation_id
            response.headers["traceparent"] = trace.traceparent
            decision = getattr(request, "anva_rate_limit", None)
            if decision is not None:
                response.headers["X-RateLimit-Limit"] = str(decision.limit)
                response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
            return response
        finally:
            duration_ms = (time.monotonic() - started) * 1_000
            PROCESS_METRICS.finish(status=status, duration_ms=duration_ms)
            LOGGER.info(
                "request completed",
                extra={
                    "http_method": request.method,
                    "http_path": request.path,
                    "http_status": status,
                    "duration_ms": round(duration_ms, 3),
                },
            )
            reset_context(tokens)


class ProductSecurityHeadersMiddleware:
    """Set a restrictive policy without inline-script exceptions."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'; "
            "script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'",
        )
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        return response
