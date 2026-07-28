"""Structured operational logging with mandatory secret redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from django.conf import settings

REDACTED = "[REDACTED]"
SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\banva_v1\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]+"),
    re.compile(r"(?i)(authorization|x-anva-bootstrap-secret)\s*[:=]\s*[^\s,;]+"),
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
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)
