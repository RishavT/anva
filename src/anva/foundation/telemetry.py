"""Secret-safe request correlation, trace context, and process metrics."""

from __future__ import annotations

import re
import secrets
import threading
from contextvars import ContextVar, Token
from dataclasses import dataclass

TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
LATENCY_BUCKETS_MS = (10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000)

correlation_id_context: ContextVar[str] = ContextVar("anva_correlation_id", default="")
trace_id_context: ContextVar[str] = ContextVar("anva_trace_id", default="")
span_id_context: ContextVar[str] = ContextVar("anva_span_id", default="")


@dataclass(frozen=True, slots=True)
class TraceContext:
    """Validated W3C trace context for one server request."""

    trace_id: str
    span_id: str
    flags: str

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.flags}"


def trace_context(raw_traceparent: str) -> TraceContext:
    """Continue a valid W3C trace ID or create a new server trace."""
    match = TRACEPARENT.fullmatch(raw_traceparent.strip().lower())
    if match is not None and match.group(1) != "0" * 32 and match.group(2) != "0" * 16:
        return TraceContext(
            trace_id=match.group(1), span_id=secrets.token_hex(8), flags=match.group(3)
        )
    return TraceContext(trace_id=secrets.token_hex(16), span_id=secrets.token_hex(8), flags="01")


def bind_context(*, correlation_id: str, trace: TraceContext) -> tuple[Token[str], ...]:
    """Bind request identifiers until the middleware resets the returned tokens."""
    return (
        correlation_id_context.set(correlation_id),
        trace_id_context.set(trace.trace_id),
        span_id_context.set(trace.span_id),
    )


def reset_context(tokens: tuple[Token[str], ...]) -> None:
    """Restore prior context in reverse binding order."""
    span_id_context.reset(tokens[2])
    trace_id_context.reset(tokens[1])
    correlation_id_context.reset(tokens[0])


class ProcessMetrics:
    """Small thread-safe per-process counters without tenant labels."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests = 0
        self.errors = 0
        self.rate_limited = 0
        self.in_flight = 0
        self.latency_sum = 0.0
        self.latency_buckets = dict.fromkeys(LATENCY_BUCKETS_MS, 0)
        self.latency_infinite = 0

    def begin(self) -> None:
        with self._lock:
            self.requests += 1
            self.in_flight += 1

    def finish(self, *, status: int, duration_ms: float) -> None:
        with self._lock:
            self.in_flight = max(0, self.in_flight - 1)
            if status >= 500:
                self.errors += 1
            if status == 429:
                self.rate_limited += 1
            self.latency_sum += duration_ms
            for boundary in LATENCY_BUCKETS_MS:
                if duration_ms <= boundary:
                    self.latency_buckets[boundary] += 1
            self.latency_infinite += 1

    def render(self, *, version: str, ready: bool) -> str:
        """Render a bounded Prometheus text exposition with no tenant dimensions."""
        with self._lock:
            lines = [
                "# HELP anva_build_info Anva process build information.",
                "# TYPE anva_build_info gauge",
                f'anva_build_info{{version="{version}"}} 1',
                "# HELP anva_ready Whether required dependencies are ready.",
                "# TYPE anva_ready gauge",
                f"anva_ready {1 if ready else 0}",
                "# HELP anva_http_requests_total Requests served by this process.",
                "# TYPE anva_http_requests_total counter",
                f"anva_http_requests_total {self.requests}",
                "# HELP anva_http_errors_total Responses with status 5xx.",
                "# TYPE anva_http_errors_total counter",
                f"anva_http_errors_total {self.errors}",
                "# HELP anva_rate_limited_total Responses rejected with status 429.",
                "# TYPE anva_rate_limited_total counter",
                f"anva_rate_limited_total {self.rate_limited}",
                "# HELP anva_http_in_flight Requests currently executing.",
                "# TYPE anva_http_in_flight gauge",
                f"anva_http_in_flight {self.in_flight}",
                "# HELP anva_http_request_duration_milliseconds Request latency histogram.",
                "# TYPE anva_http_request_duration_milliseconds histogram",
            ]
            lines.extend(
                f'anva_http_request_duration_milliseconds_bucket{{le="{boundary}"}} {count}'
                for boundary, count in self.latency_buckets.items()
            )
            lines.extend(
                (
                    'anva_http_request_duration_milliseconds_bucket{le="+Inf"} '
                    f"{self.latency_infinite}",
                    f"anva_http_request_duration_milliseconds_sum {self.latency_sum:.3f}",
                    f"anva_http_request_duration_milliseconds_count {self.latency_infinite}",
                )
            )
        return "\n".join(lines) + "\n"


PROCESS_METRICS = ProcessMetrics()
