"""Secret-safe structured logging tests."""

from __future__ import annotations

import json
import logging
import sys

import pytest

from anva.core.logging import SecretRedactionFilter, StructuredJsonFormatter, redact_text
from anva.core.services.events import _validate_audit_value


@pytest.mark.unit
@pytest.mark.parametrize(
    "message",
    [
        "Authorization: Bearer anva_v1.00000000-0000-4000-8000-000000000000.secret",
        "X-Anva-Evidence-Upload-Token: "
        "anva_upload_v1.00000000-0000-4000-8000-000000000000.upload-secret",
        "authorization=opaque-token",
        "X-Anva-Bootstrap-Secret: test-only-bootstrap-secret",
        "configured test-only-token-pepper accidentally emitted",
        "api_key=sk_live_51DEADBEEF012345",
        "{'nested': {'password': 'correct-horse-battery-staple'}}",
        "access_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
        "cookie=session_id=highly-sensitive-cookie",
        "private_key=-----BEGIN PRIVATE KEY-----",
        "GET https://s3.example.test/result?X-Amz-Signature=aws-signed-value",
        "GET https://s3.example.test/result?x-AMZ-security-TOKEN=session-value",
        "GET https://storage.googleapis.test/result?X-Goog-Credential=gcp-identity",
        "GET https://blob.example.test/result?sv=2026-01-01&sig=azure-signed-value",
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
    assert "signed-value" not in redacted
    assert "session-value" not in redacted
    assert "gcp-identity" not in redacted


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
def test_credential_id_in_authorization_path_is_not_secret_material() -> None:
    authorization_path = (
        "credential:00000000-0000-4000-8000-000000000001"
        ">role:ORG_ADMIN>repository:00000000-0000-4000-8000-000000000002"
    )
    assert redact_text(authorization_path) == authorization_path


@pytest.mark.unit
def test_permission_namespace_containing_session_is_not_credential_material() -> None:
    permission_diff = '+    return actor.has_perm("identity:support-session:assume")'
    assert redact_text(permission_diff) == permission_diff


@pytest.mark.unit
@pytest.mark.parametrize(
    "message",
    [
        "session_id=highly-sensitive-cookie",
        "session-id: highly-sensitive-cookie",
        "session_token=highly-sensitive-token",
        "session-token: highly-sensitive-token",
        '"session_id": "highly-sensitive-cookie"',
        "'session-token'='highly-sensitive-token'",
    ],
)
def test_exact_session_credential_names_remain_redacted(message: str) -> None:
    redacted = redact_text(message)
    assert "[REDACTED]" in redacted
    assert "highly-sensitive" not in redacted


@pytest.mark.unit
def test_reviewer_identity_and_token_ids_are_safe_audit_metadata_but_secrets_are_not() -> None:
    _validate_audit_value(
        {
            "reviewer_service_identity_id": "00000000-0000-4000-8000-000000000008",
            "reviewer_token_id": "00000000-0000-4000-8000-000000000009",
        }
    )
    with pytest.raises(ValueError, match="credential material"):
        _validate_audit_value(
            {"reviewer_token_id": ("anva_v1.00000000-0000-4000-8000-000000000009.raw-secret")}
        )


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
