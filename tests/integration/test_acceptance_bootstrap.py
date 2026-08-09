"""Public bootstrap support required by the boundary-only acceptance runner."""

from __future__ import annotations

import json

import pytest
from django.test import Client, override_settings

from anva.core.models import (
    AccessGrant,
    AccessScopeServiceIdentity,
    AuditEvent,
    Organization,
    RepositoryAccessToken,
    ServiceIdentity,
)
from anva.core.services.authorization import Action
from anva.core.services.tokens import authenticate_bearer


def _payload(*, reviewer: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "organization_slug": "acceptance-bootstrap",
        "organization_name": "Acceptance Bootstrap",
        "admin_email": "acceptance-bootstrap@anva.invalid",
        "admin_display_name": "Acceptance operator",
        "repository_external_id": "acceptance:bootstrap",
        "repository_name": "Acceptance repository",
    }
    if reviewer:
        payload["independent_reviewer_name"] = "Independent acceptance evaluator"
    return payload


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_bootstrap_default_returns_scope_without_creating_reviewer() -> None:
    response = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(_payload(reviewer=False)),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["access_scope_id"]
    assert "reviewer_token" not in result
    assert ServiceIdentity.objects.count() == 1


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_bootstrap_rejects_fields_outside_its_closed_public_contract() -> None:
    payload = _payload(reviewer=False)
    payload["unexpected"] = "must not be accepted"

    response = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )

    assert response.status_code == 400
    assert not Organization.objects.exists()


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_opt_in_reviewer_is_distinct_least_privilege_and_token_is_never_persisted() -> None:
    response = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(_payload(reviewer=True)),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["reviewer_service_identity_id"] != result["service_identity_id"]
    reviewer_token = result["reviewer_token"]
    reviewer = authenticate_bearer(f"Bearer {reviewer_token}")
    assert reviewer.actor_id == result["reviewer_service_identity_id"]
    assert reviewer.credential_actions == frozenset({Action.ASSURANCE_REVIEW.value})
    assert (
        AccessGrant.objects.filter(
            service_identity_id=result["reviewer_service_identity_id"],
            action=Action.ASSURANCE_REVIEW.value,
        ).count()
        == 1
    )
    assert (
        AccessGrant.objects.filter(
            service_identity_id=result["reviewer_service_identity_id"]
        ).count()
        == 1
    )
    assert AccessScopeServiceIdentity.objects.filter(
        access_scope_id=result["access_scope_id"],
        service_identity_id=result["reviewer_service_identity_id"],
    ).exists()
    stored = RepositoryAccessToken.objects.get(id=result["reviewer_token_id"])
    assert stored.token_hash != reviewer_token
    persisted = json.dumps(
        list(AuditEvent.objects.values("metadata", "actor_id", "authorization_path")),
        sort_keys=True,
    )
    assert reviewer_token not in persisted


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_exact_bootstrap_retry_revokes_and_reissues_only_precommitted_credentials() -> None:
    client = Client(HTTP_X_ANVA_BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
    payload = {**_payload(reviewer=True), "idempotency_key": "a" * 64}
    first = client.post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert first.status_code == 201, first.json()
    original = first.json()

    recovered = client.post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert recovered.status_code == 201
    replacement = recovered.json()
    assert replacement["recovered"] is True
    assert replacement["bootstrap_request_sha256"] == original["bootstrap_request_sha256"]
    assert replacement["organization_id"] == original["organization_id"]
    assert replacement["token_id"] != original["token_id"]
    assert replacement["reviewer_token_id"] != original["reviewer_token_id"]
    assert RepositoryAccessToken.objects.get(id=original["token_id"]).revoked_at is not None
    assert (
        RepositoryAccessToken.objects.get(id=original["reviewer_token_id"]).revoked_at is not None
    )
    assert (
        authenticate_bearer(f"Bearer {replacement['token']}").actor_id
        == replacement["service_identity_id"]
    )
    assert (
        authenticate_bearer(f"Bearer {replacement['reviewer_token']}").actor_id
        == (replacement["reviewer_service_identity_id"])
    )

    mismatched = client.post(
        "/api/v1/bootstrap",
        data=json.dumps({**payload, "repository_name": "Mismatched"}),
        content_type="application/json",
    )
    assert mismatched.status_code == 404
    assert authenticate_bearer(f"Bearer {replacement['token']}")
