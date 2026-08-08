"""Structured operational logging with mandatory secret redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from django.conf import settings

from anva.foundation.telemetry import (
    correlation_id_context,
    span_id_context,
    trace_id_context,
)

REDACTED = "[REDACTED]"
SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+"),
    re.compile(r"\banva_v1\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]+"),
    re.compile(r"\banva_upload_v1\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]+"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_-]{8,}"),
    re.compile(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{12,})"),
    re.compile(r"\bgh[usro]_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b(?:npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,})"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bhttps?://[^/\s:@]+:[^@\s/]+@"),
    re.compile(
        r"""(?ix)
        (?:[?&]|&amp;)
        (?:
            [a-z0-9_.~-]*(?:credential|signature|security[-_]?token)
            |googleaccessid
            |access[-_]?key(?:[-_]?id)?
            |key[-_]?pair[-_]?id
            |sig
            |token
        )
        \s*=\s*[^&#\s"']+
        """
    ),
    re.compile(
        r"""(?ix)
        ["']?
        (?:authorization|x-anva-bootstrap-secret|api[_-]?key|access[_-]?token|
           refresh[_-]?token|client[_-]?secret|password|passwd|pwd|
           private[_-]?key|set[_-]?cookie|cookie|session[_-]?(?:id|token)?)
        ["']?\s*[:=]\s*["']?[^\s,;}\]]+
        """
    ),
)


def redact_text(value: object) -> str:
    """Remove bearer formats, sensitive headers, and configured secret literals."""
    result = str(value)
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(REDACTED, result)
    configured_secrets = {
        str(settings.SECRET_KEY),
        str(settings.TOKEN_PEPPER),
        str(settings.BOOTSTRAP_SECRET),
        str(settings.ANVA_METRICS_TOKEN),
        str(settings.OBJECT_STORAGE_SECRET_KEY),
        *(str(secret) for secret in settings.ANVA_GITHUB_WEBHOOK_SECRETS),
    }
    for secret in configured_secrets:
        if secret:
            result = result.replace(secret, REDACTED)
    return result


class SecretRedactionFilter(logging.Filter):
    """Redact before any handler receives a formatted message."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Render valid single-line JSON without interpolating unsafe structure."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        context_fields = {
            "correlation_id": correlation_id_context.get(),
            "trace_id": trace_id_context.get(),
            "span_id": span_id_context.get(),
        }
        payload.update({key: value for key, value in context_fields.items() if value})
        for name in (
            "http_method",
            "http_path",
            "http_status",
            "duration_ms",
            "job_id",
            "job_kind",
            "worker_id",
            "signal",
            "error_code",
        ):
            value = getattr(record, name, None)
            if isinstance(value, str | int | float):
                payload[name] = redact_text(value) if isinstance(value, str) else value
        if record.exc_info is not None and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
