"""Published contracts for accepted evidence byte uploads."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest
from django.http import HttpRequest
from django.test import Client, RequestFactory
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.generate import openapi_document
from anva.core import views as core_views
from anva.core.exceptions import AuthenticationError


def authorization_payload(*, scope_id: uuid.UUID) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "access_scope_id": str(scope_id),
        "commit_sha": "a" * 40,
        "filename": "evidence.zip",
        "declared_sha256": "b" * 64,
        "declared_size": 631,
        "idempotency_key": "ci-run-17-evidence",
    }


@pytest.mark.contract
def test_upload_authorization_contract_is_closed_and_bounded() -> None:
    schema = SCHEMAS["evidence-upload-authorization"]
    payload = authorization_payload(scope_id=uuid.uuid4())

    Draft202012Validator(schema).validate(payload)
    for _name, value in (
        ("missing", {key: item for key, item in payload.items() if key != "commit_sha"}),
        ("extra", {**payload, "content_type": "application/zip"}),
        ("oversized", {**payload, "declared_size": 4_097}),
        ("bad_digest", {**payload, "declared_sha256": "not-a-digest"}),
        ("unsafe_filename", {**payload, "filename": "secret\r\nheader"}),
    ):
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(value)


@pytest.mark.contract
def test_evidence_manifest_accepts_only_an_optional_blob_uuid_link() -> None:
    schema = SCHEMAS["evidence-manifest"]
    payload = deepcopy(EXAMPLES["evidence-manifest"])
    payload["entries"][0]["artifact_blob_id"] = (  # type: ignore[index]
        "00000000-0000-4000-8000-000000000777"
    )

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    payload["entries"][0]["artifact_blob_id"] = "not-a-uuid"  # type: ignore[index]
    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)


@pytest.mark.contract
def test_upload_openapi_requires_actor_and_separate_upload_secret() -> None:
    document = openapi_document()
    paths = cast(dict[str, Any], document["paths"])
    components = cast(dict[str, Any], document["components"])
    create = paths[
        "/repositories/{repository_id}/pull-requests/{pull_request_number}/"
        "evidence-upload-authorizations"
    ]["post"]
    upload = paths["/evidence-upload-authorizations/{resource_id}/content"]["put"]

    assert create["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/evidence-upload-authorization"
    }
    assert upload["security"] == [
        {"bearerAuth": [], "evidenceUploadToken": []},
    ]
    assert components["securitySchemes"]["evidenceUploadToken"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-Anva-Evidence-Upload-Token",
        "description": (
            "Short-lived single-use opaque evidence-upload secret; required in "
            "addition to the normal actor bearer credential."
        ),
    }
    for status in ("200", "201"):
        response_schema = create["responses"][status]["content"]["application/json"]["schema"]
        assert response_schema["properties"]["state"]["enum"] == [
            "ISSUED",
            "RECEIVING",
            "RECOVERING",
            "ACCEPTED",
            "REJECTED",
            "EXPIRED",
            "REVOKED",
        ]
    assert upload["requestBody"]["content"] == {
        "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
    }
    parameters = cast(list[dict[str, Any]], upload["parameters"])
    digest = next(item for item in parameters if item.get("name") == "X-Anva-Content-SHA256")
    assert digest["required"] is True
    assert digest["schema"]["pattern"] == "^[a-f0-9]{64}$"
    assert {"413", "415", "422", "503"} <= upload["responses"].keys()


@pytest.mark.contract
def test_authorization_http_returns_secret_once_and_preserves_binding(client: Client) -> None:
    repository_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    authorization_id = uuid.uuid4()
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    authorization = SimpleNamespace(
        id=authorization_id,
        access_scope_id=scope_id,
        commit_sha="a" * 40,
        filename="evidence.zip",
        declared_sha256="b" * 64,
        declared_size=631,
        state="ISSUED",
        expires_at=expires_at,
    )
    grants = (
        SimpleNamespace(authorization=authorization, raw_token="opaque-once", replayed=False),
        SimpleNamespace(authorization=authorization, raw_token=None, replayed=True),
    )
    path = f"/api/v1/repositories/{repository_id}/pull-requests/17/evidence-upload-authorizations"

    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.services.evidence_uploads.issue_upload_authorization",
            side_effect=grants,
        ) as issue,
    ):
        first = client.post(
            path,
            data=json.dumps(authorization_payload(scope_id=scope_id)),
            content_type="application/json",
        )
        replay = client.post(
            path,
            data=json.dumps(authorization_payload(scope_id=scope_id)),
            content_type="application/json",
        )

    assert first.status_code == 201
    assert replay.status_code == 200
    assert first.json()["upload_token"] == "opaque-once"  # noqa: S105
    assert replay.json()["upload_token"] is None
    assert first.json()["upload_path"] == (
        f"/api/v1/evidence-upload-authorizations/{authorization_id}/content"
    )
    assert "object_key" not in first.json()
    assert "token_hash" not in first.json()
    assert issue.call_count == 2
    assert issue.call_args.kwargs["declared_size"] == 631
    assert issue.call_args.kwargs["pull_request_number"] == 17


@pytest.mark.contract
def test_upload_authorization_authenticates_before_parsing_untrusted_body(client: Client) -> None:
    repository_id = uuid.uuid4()
    with (
        patch(
            "anva.core.views._actor",
            side_effect=AuthenticationError("Credential is invalid or expired"),
        ),
        patch("anva.core.services.evidence_uploads.issue_upload_authorization") as issue,
    ):
        response = client.post(
            f"/api/v1/repositories/{repository_id}/pull-requests/17/evidence-upload-authorizations",
            data=b'{"malformed":',
            content_type="application/json",
        )

    assert response.status_code == 401
    issue.assert_not_called()


@pytest.mark.contract
def test_content_http_streams_request_and_returns_only_safe_blob_metadata(client: Client) -> None:
    authorization_id = uuid.uuid4()
    blob = SimpleNamespace(
        id=uuid.uuid4(),
        content_hash="c" * 64,
        verified_size=631,
        detected_media_type="application/zip",
        archive_summary={"member_count": 2, "expanded_bytes": 512},
        storage_state="AVAILABLE",
        object_key="must-not-leak",
    )
    body = b"PK\x03\x04bounded fixture"

    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.services.evidence_uploads.accept_evidence_upload",
            return_value=blob,
        ) as accept,
    ):
        response = client.put(
            f"/api/v1/evidence-upload-authorizations/{authorization_id}/content",
            data=body,
            content_type="application/octet-stream",
            HTTP_X_ANVA_EVIDENCE_UPLOAD_TOKEN="opaque-upload-secret",
            HTTP_X_ANVA_CONTENT_SHA256="c" * 64,
        )

    assert response.status_code == 201
    assert response.json() == {
        "evidence_blob_id": str(blob.id),
        "authorization_id": str(authorization_id),
        "sha256": "c" * 64,
        "verified_size": 631,
        "detected_type": "application/zip",
        "archive_summary": {"member_count": 2, "expanded_bytes": 512},
        "storage_state": "AVAILABLE",
    }
    arguments = accept.call_args.kwargs
    assert isinstance(arguments["stream"], HttpRequest)
    assert arguments["content_length"] == len(body)
    assert arguments["expected_sha256"] == "c" * 64
    assert arguments["raw_token"] == "opaque-upload-secret"  # noqa: S105
    assert "object_key" not in response.json()


@pytest.mark.contract
def test_content_http_returns_only_stable_sanitized_upload_error(client: Client) -> None:
    from anva.core.services.evidence_uploads import EvidenceUploadError

    authorization_id = uuid.uuid4()
    secret = "ghp_TST007_must_never_appear_in_response"  # noqa: S105
    with (
        patch("anva.core.views._actor", return_value=object()),
        patch(
            "anva.core.services.evidence_uploads.accept_evidence_upload",
            side_effect=EvidenceUploadError(
                "MANIFEST_MALFORMED",
                "The evidence JSON is not well-formed.",
                422,
            ),
        ),
    ):
        response = client.put(
            f"/api/v1/evidence-upload-authorizations/{authorization_id}/content",
            data=secret.encode(),
            content_type="application/octet-stream",
            HTTP_X_ANVA_EVIDENCE_UPLOAD_TOKEN="opaque-upload-secret",
            HTTP_X_ANVA_CONTENT_SHA256="d" * 64,
        )

    assert response.status_code == 422
    assert response.json()["code"] == "MANIFEST_MALFORMED"
    assert response.json()["message"] == "The evidence JSON is not well-formed."
    assert secret not in response.content.decode()
    assert "opaque-upload-secret" not in response.content.decode()


@pytest.mark.contract
def test_stream_content_length_is_optional_and_strict() -> None:
    factory = RequestFactory()
    absent = factory.put("/", data=b"", content_type="application/octet-stream")
    absent.META.pop("CONTENT_LENGTH", None)
    invalid = factory.put("/", data=b"x", content_type="application/octet-stream")
    invalid.META["CONTENT_LENGTH"] = "1x"

    assert core_views._stream_content_length(absent) is None
    with pytest.raises(ValueError, match="Content-Length"):
        core_views._stream_content_length(invalid)


@pytest.mark.contract
def test_upload_routes_reject_unsupported_methods(client: Client) -> None:
    repository_id = uuid.uuid4()
    authorization_id = uuid.uuid4()
    create_path = (
        f"/api/v1/repositories/{repository_id}/pull-requests/17/evidence-upload-authorizations"
    )
    content_path = f"/api/v1/evidence-upload-authorizations/{authorization_id}/content"

    assert client.get(create_path).status_code == 405
    assert client.post(content_path).status_code == 405
