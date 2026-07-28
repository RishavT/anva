"""Secret-safe structured logging tests."""

from __future__ import annotations

import json
import logging

import pytest

from anva.core.logging import SecretRedactionFilter, StructuredJsonFormatter, redact_text


@pytest.mark.unit
@pytest.mark.parametrize(
    "message",
    [
        "Authorization: Bearer anva_v1.00000000-0000-4000-8000-000000000000.secret",
        "authorization=opaque-token",
        "X-Anva-Bootstrap-Secret: test-only-bootstrap-secret",
        "configured test-only-token-pepper accidentally emitted",
    ],
)
def test_secret_redaction_covers_headers_tokens_and_configured_secrets(message: str) -> None:
    redacted = redact_text(message)
    assert "[REDACTED]" in redacted
    assert "secret" not in redacted.lower().replace("[redacted]", "")
    assert "opaque-token" not in redacted
    assert "test-only-token-pepper" not in redacted


@pytest.mark.unit
def test_filter_redacts_before_structured_json_formatting() -> None:
    record = logging.LogRecord(
        name="anva.security",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="request %s",
        args=("Bearer anva_v1.00000000-0000-4000-8000-000000000000.raw-secret",),
        exc_info=None,
    )
    assert SecretRedactionFilter().filter(record)
    rendered = StructuredJsonFormatter().format(record)
    payload = json.loads(rendered)

    assert payload["level"] == "WARNING"
    assert payload["logger"] == "anva.security"
    assert payload["message"] == "request [REDACTED]"
    assert "raw-secret" not in rendered
