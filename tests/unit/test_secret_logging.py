"""Secret-safe structured logging tests."""

from __future__ import annotations

import json
import logging
import sys

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
        "api_key=sk_live_51DEADBEEF012345",
        "{'nested': {'password': 'correct-horse-battery-staple'}}",
        "access_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
        "cookie=session_id=highly-sensitive-cookie",
        "private_key=-----BEGIN PRIVATE KEY-----",
    ],
)
def test_secret_redaction_covers_headers_tokens_and_configured_secrets(message: str) -> None:
    redacted = redact_text(message)
    assert "[REDACTED]" in redacted
    assert "secret" not in redacted.lower().replace("[redacted]", "")
    assert "opaque-token" not in redacted
    assert "test-only-token-pepper" not in redacted
    assert "sk_live_" not in redacted
    assert "correct-horse" not in redacted
    assert "ghp_" not in redacted
    assert "highly-sensitive-cookie" not in redacted


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


@pytest.mark.unit
def test_exception_message_and_nested_mapping_are_redacted_before_formatting() -> None:
    try:
        raise ValueError("api_key=sk_live_EXCEPTION012345")
    except ValueError as error:
        record = logging.LogRecord(
            name="anva.security",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg={"nested": {"exception": str(error), "password": "do-not-log-me"}},
            args=(),
            exc_info=sys.exc_info(),
        )

    assert SecretRedactionFilter().filter(record)
    rendered = StructuredJsonFormatter().format(record)
    payload = json.loads(rendered)

    assert payload["exception_type"] == "ValueError"
    assert "[REDACTED]" in payload["message"]
    assert "sk_live_" not in rendered
    assert "do-not-log-me" not in rendered
