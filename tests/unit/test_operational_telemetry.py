"""Focused tests for request telemetry, metrics, and operational redaction."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.http import HttpResponse
from django.test import Client, RequestFactory, override_settings

from anva.core.exceptions import RateLimitExceededError
from anva.core.logging import SecretRedactionFilter, StructuredJsonFormatter
from anva.core.middleware import OperationalTelemetryMiddleware, _client_rate_key
from anva.foundation.services import DependencyStatus, ReadinessStatus
from anva.foundation.telemetry import (
    ProcessMetrics,
    TraceContext,
    bind_context,
    correlation_id_context,
    reset_context,
    span_id_context,
    trace_context,
    trace_id_context,
)
from anva.foundation.views import metrics


@pytest.mark.unit
def test_trace_context_continues_only_valid_nonzero_w3c_trace_ids() -> None:
    incoming_trace_id = "1" * 32
    with patch("anva.foundation.telemetry.secrets.token_hex", return_value="2" * 16):
        continued = trace_context(f"00-{incoming_trace_id}-{'3' * 16}-00")

    assert continued == TraceContext(incoming_trace_id, "2" * 16, "00")
    assert continued.traceparent == f"00-{incoming_trace_id}-{'2' * 16}-00"

    with patch(
        "anva.foundation.telemetry.secrets.token_hex",
        side_effect=("4" * 32, "5" * 16),
    ):
        regenerated = trace_context(f"00-{'0' * 32}-{'3' * 16}-ff")

    assert regenerated == TraceContext("4" * 32, "5" * 16, "01")


@pytest.mark.unit
def test_structured_logs_include_bound_context_and_redact_operational_secrets(
    settings: MagicMock,
) -> None:
    settings.ANVA_METRICS_TOKEN = "metrics-scrape-secret"  # noqa: S105
    settings.OBJECT_STORAGE_SECRET_KEY = "storage-signing-secret"  # noqa: S105
    trace = TraceContext("a" * 32, "b" * 16, "01")
    tokens = bind_context(correlation_id="correlation-123", trace=trace)
    try:
        record = logging.LogRecord(
            name="anva.http",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="tokens: %s and %s",
            args=("metrics-scrape-secret", "storage-signing-secret"),
            exc_info=None,
        )
        record.http_method = "GET"
        record.http_path = "/metrics?token=metrics-scrape-secret"
        record.http_status = 200
        assert SecretRedactionFilter().filter(record)
        rendered = StructuredJsonFormatter().format(record)
    finally:
        reset_context(tokens)

    payload = json.loads(rendered)
    assert payload["correlation_id"] == "correlation-123"
    assert payload["trace_id"] == "a" * 32
    assert payload["span_id"] == "b" * 16
    assert payload["http_path"] == "/metrics[REDACTED]"
    assert "metrics-scrape-secret" not in rendered
    assert "storage-signing-secret" not in rendered
    assert correlation_id_context.get() == ""
    assert trace_id_context.get() == ""
    assert span_id_context.get() == ""


@pytest.mark.unit
def test_process_metrics_count_errors_rate_limits_and_cumulative_latency() -> None:
    process_metrics = ProcessMetrics()
    process_metrics.begin()
    process_metrics.finish(status=429, duration_ms=25.0)
    process_metrics.begin()
    process_metrics.finish(status=503, duration_ms=6_000.0)

    rendered = process_metrics.render(version="1.2.3", ready=False)

    assert 'anva_build_info{version="1.2.3"} 1' in rendered
    assert "anva_ready 0" in rendered
    assert "anva_http_requests_total 2" in rendered
    assert "anva_http_errors_total 1" in rendered
    assert "anva_rate_limited_total 1" in rendered
    assert "anva_http_in_flight 0" in rendered
    assert 'bucket{le="10"} 0' in rendered
    assert 'bucket{le="25"} 1' in rendered
    assert 'bucket{le="5000"} 1' in rendered
    assert 'bucket{le="+Inf"} 2' in rendered
    assert "organization" not in rendered
    assert "tenant" not in rendered


@pytest.mark.unit
def test_client_rate_key_trusts_forwarding_only_from_exact_proxy_ips(
    settings: MagicMock,
) -> None:
    settings.ANVA_TRUSTED_PROXY_IPS = ("10.0.0.10",)
    factory = RequestFactory()

    untrusted = factory.get(
        "/api/v1/organizations",
        REMOTE_ADDR="203.0.113.5",
        HTTP_X_FORWARDED_FOR="198.51.100.7",
    )
    trusted = factory.get(
        "/api/v1/organizations",
        REMOTE_ADDR="10.0.0.10",
        HTTP_X_FORWARDED_FOR="198.51.100.7, 10.0.0.10",
    )

    assert _client_rate_key(untrusted) == "203.0.113.5"
    assert _client_rate_key(trusted) == "198.51.100.7"


@pytest.mark.unit
def test_telemetry_middleware_emits_correlation_trace_and_limit_headers() -> None:
    factory = RequestFactory()
    request = factory.get(
        "/api/v1/organizations",
        REMOTE_ADDR="203.0.113.5",
        HTTP_X_CORRELATION_ID="00000000-0000-4000-8000-000000000001",
        HTTP_TRACEPARENT=f"00-{'1' * 32}-{'2' * 16}-01",
    )
    decision = SimpleNamespace(limit=10, remaining=9, retry_after_seconds=42)
    process_metrics = ProcessMetrics()

    with (
        patch(
            "anva.core.middleware.enforce_pre_auth_rate_limit",
            return_value=decision,
        ) as enforce,
        patch("anva.core.middleware.PROCESS_METRICS", process_metrics),
    ):
        response = OperationalTelemetryMiddleware(lambda _request: HttpResponse(status=204))(
            request
        )

    enforce.assert_called_once_with(client_key="203.0.113.5")
    assert response.status_code == 204
    assert response.headers["X-Correlation-ID"] == ("00000000-0000-4000-8000-000000000001")
    assert response.headers["traceparent"].startswith(f"00-{'1' * 32}-")
    assert response.headers["X-RateLimit-Limit"] == "10"
    assert response.headers["X-RateLimit-Remaining"] == "9"
    assert process_metrics.requests == 1
    assert process_metrics.in_flight == 0
    assert correlation_id_context.get() == ""


@pytest.mark.unit
def test_telemetry_middleware_returns_retry_after_and_skips_dependency_rate_limits() -> None:
    factory = RequestFactory()
    limited_request = factory.get("/api/v1/organizations", REMOTE_ADDR="203.0.113.5")
    process_metrics = ProcessMetrics()
    downstream = MagicMock(return_value=HttpResponse(status=200))

    with (
        patch(
            "anva.core.middleware.enforce_pre_auth_rate_limit",
            side_effect=RateLimitExceededError(17),
        ) as enforce,
        patch("anva.core.middleware.PROCESS_METRICS", process_metrics),
    ):
        limited = OperationalTelemetryMiddleware(downstream)(limited_request)

    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "17"
    assert json.loads(limited.content)["code"] == "rate_limited"
    downstream.assert_not_called()
    assert process_metrics.rate_limited == 1

    enforce.reset_mock()
    enforce.side_effect = None
    with patch("anva.core.middleware.enforce_pre_auth_rate_limit", enforce):
        for path in ("/health/live", "/health/ready", "/metrics"):
            response = OperationalTelemetryMiddleware(downstream)(
                factory.get(path, REMOTE_ADDR="203.0.113.5")
            )
            assert response.status_code == 200
    enforce.assert_not_called()


@pytest.mark.unit
def test_metrics_endpoint_is_non_oracular_and_requires_exact_bearer_token(
    settings: MagicMock,
) -> None:
    factory = RequestFactory()
    readiness = ReadinessStatus("ready", (DependencyStatus("database", True, "available"),))

    with patch("anva.foundation.views.readiness_status", return_value=readiness) as ready:
        settings.ANVA_METRICS_TOKEN = ""
        disabled = metrics(factory.get("/metrics"))
        settings.ANVA_METRICS_TOKEN = "scraper-token"  # noqa: S105
        rejected = metrics(factory.get("/metrics", HTTP_AUTHORIZATION="Bearer wrong-token"))
        accepted = metrics(factory.get("/metrics", HTTP_AUTHORIZATION="Bearer scraper-token"))

    assert disabled.status_code == 404
    assert disabled.content == b""
    assert rejected.status_code == 404
    assert rejected.content == b""
    assert accepted.status_code == 200
    assert accepted["Content-Type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert b"anva_build_info" in accepted.content
    ready.assert_called_once_with()


@pytest.mark.unit
@override_settings(
    SECURE_SSL_REDIRECT=True,
    SECURE_REDIRECT_EXEMPT=[r"^health/"],
    ANVA_METRICS_TOKEN="scraper-token",
)
def test_metrics_requires_https_when_transport_redirects_are_enabled() -> None:
    client = Client()
    readiness = ReadinessStatus("ready", (DependencyStatus("database", True, "available"),))

    with patch("anva.foundation.views.readiness_status", return_value=readiness):
        plaintext = client.get(
            "/metrics",
            HTTP_AUTHORIZATION="Bearer scraper-token",
        )
        secure = client.get(
            "/metrics",
            secure=True,
            HTTP_AUTHORIZATION="Bearer scraper-token",
        )

    assert plaintext.status_code == 301
    assert plaintext["Location"] == "https://testserver/metrics"
    assert secure.status_code == 200


@pytest.mark.unit
@override_settings(SECURE_SSL_REDIRECT=True, ANVA_TRUSTED_PROXY_IPS=())
def test_untrusted_peer_cannot_spoof_forwarded_https() -> None:
    client = Client()

    response = client.get(
        "/metrics",
        HTTP_X_FORWARDED_PROTO="https",
        HTTP_AUTHORIZATION="Bearer scraper-token",
        REMOTE_ADDR="203.0.113.10",
    )

    assert response.status_code == 301
    assert response["Location"] == "https://testserver/metrics"


@pytest.mark.unit
def test_csrf_boundary_exempts_only_bearer_api_routes() -> None:
    client = Client(enforce_csrf_checks=True)
    decision = SimpleNamespace(limit=10, remaining=9, retry_after_seconds=42)

    with patch(
        "anva.core.middleware.enforce_pre_auth_rate_limit",
        return_value=decision,
    ):
        api_response = client.post(
            "/api/v1/search",
            data="{}",
            content_type="application/json",
        )
        web_response = client.post(
            "/setup",
            data={"organization_slug": "csrf-must-block"},
        )
        decommission_response = client.post(
            "/api/v1/organizations/00000000-0000-0000-0000-000000000001/decommission",
            data="{}",
            content_type="application/json",
        )

    assert api_response.status_code == 401
    assert api_response.json()["code"] == "invalid_credential"
    assert web_response.status_code == 403
    assert decommission_response.status_code == 403
