"""Public bootstrap support required by the boundary-only acceptance runner."""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from django.test import Client, override_settings
from jsonschema import Draft202012Validator, FormatChecker

from anva.contracts.acceptance import validate_acceptance_http_response
from anva.contracts.bootstrap_scope import acceptance_bootstrap_scope_payload
from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AuditEvent,
    Membership,
    Organization,
    Repository,
    RepositoryAccessToken,
    Role,
    ServiceIdentity,
)
from anva.core.services.authorization import Action, authorize_action
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


def _scoped_payload(*, suffix: str = "ember") -> dict[str, object]:
    return {
        "organization_slug": f"scoped-{suffix}",
        "organization_name": f"Scoped {suffix.title()}",
        "scope": acceptance_bootstrap_scope_payload(
            admin_email=f"operator@{suffix}.invalid",
            admin_display_name=f"{suffix.title()} operator",
            repository_external_id=f"github:synthetic/{suffix}",
            repository_name=suffix,
            initiator_name=f"{suffix.title()} acceptance runner",
            reviewer_name=f"{suffix.title()} independent reviewer",
            access_scope_name=f"{suffix.title()} exact acceptance scope",
        ),
    }


def _validate_published_exchange(
    request: dict[str, object],
    response: dict[str, object],
) -> None:
    bundle = json.loads(Path("contracts/acceptance/v1/operations.json").read_text(encoding="utf-8"))
    operation = next(
        item
        for item in bundle["http_operations"]
        if item["operation_id"] == "bootstrapOrganization"
    )
    schema = operation["x-anva-request-response-correlation"]["status_schemas"]["201"]
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(
        {"request": request, "status": 201, "response": response}
    )


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_bootstrap_default_returns_scope_without_creating_reviewer() -> None:
    payload = _payload(reviewer=False)
    response = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["access_scope_id"]
    assert result["bootstrap_mode"] == "LEGACY"
    assert "reviewer_token" not in result
    validate_acceptance_http_response("bootstrapOrganization", 201, result, request_payload=payload)
    _validate_published_exchange(payload, result)
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
@pytest.mark.parametrize("suffix", ["ember", "lantern"])
def test_scoped_bootstrap_creates_only_explicit_records_bindings_and_action_grants(
    suffix: str,
) -> None:
    payload = _scoped_payload(suffix=suffix)
    response = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )

    assert response.status_code == 201, response.json()
    result = response.json()
    assert result["bootstrap_mode"] == "SCOPED"
    validate_acceptance_http_response("bootstrapOrganization", 201, result, request_payload=payload)
    _validate_published_exchange(payload, result)
    scope = AccessScope.objects.get(id=result["access_scope_id"])
    assert (scope.all_memberships, scope.all_repositories, scope.all_service_identities) == (
        False,
        False,
        False,
    )
    assert Role.objects.values_list("code", flat=True).get() == Role.Code.VIEWER
    assert Membership.objects.count() == 1
    assert Repository.objects.values_list("external_id", flat=True).get() == (
        f"github:synthetic/{suffix}"
    )
    assert set(ServiceIdentity.objects.values_list("name", flat=True)) == {
        f"{suffix.title()} acceptance runner",
        f"{suffix.title()} independent reviewer",
    }
    assert AccessScopeMembership.objects.filter(access_scope=scope).count() == 1
    assert AccessScopeRepository.objects.filter(access_scope=scope).count() == 1
    assert AccessScopeServiceIdentity.objects.filter(access_scope=scope).count() == 2

    initiator = authenticate_bearer(f"Bearer {result['token']}")
    reviewer = authenticate_bearer(f"Bearer {result['reviewer_token']}")
    requested = _scoped_payload(suffix=suffix)["scope"]
    assert isinstance(requested, dict)
    identities = requested["service_identities"]
    assert isinstance(identities, list)
    initiator_actions = frozenset(identities[0]["grants"][0]["actions"])
    assert initiator.credential_actions == initiator_actions
    assert reviewer.credential_actions == frozenset({Action.ASSURANCE_REVIEW.value})
    assert (
        set(
            AccessGrant.objects.filter(
                service_identity_id=result["service_identity_id"]
            ).values_list("action", flat=True)
        )
        == initiator_actions
    )
    assert not AccessGrant.objects.filter(action=Action.GITHUB_MANAGE.value).exists()
    authorize_action(
        actor=initiator,
        action=Action.SOURCE_SYNC,
        repository_id=uuid.UUID(result["repository_id"]),
        access_scope_id=uuid.UUID(result["access_scope_id"]),
    )
    knowledge_decision = authorize_action(
        actor=initiator,
        action=Action.KNOWLEDGE_VIEW,
        repository_id=uuid.UUID(result["repository_id"]),
        access_scope_id=uuid.UUID(result["access_scope_id"]),
    )
    assert knowledge_decision.action is Action.KNOWLEDGE_VIEW
    with pytest.raises(ResourceNotFoundError):
        authorize_action(
            actor=initiator,
            action=Action.GITHUB_MANAGE,
            repository_id=uuid.UUID(result["repository_id"]),
            access_scope_id=uuid.UUID(result["access_scope_id"]),
        )
    omitted_scope = AccessScope.objects.create(
        organization_id=result["organization_id"],
        name="omitted",
    )
    with pytest.raises(ResourceNotFoundError):
        authorize_action(
            actor=initiator,
            action=Action.KNOWLEDGE_VIEW,
            repository_id=uuid.UUID(result["repository_id"]),
            access_scope_id=omitted_scope.id,
        )
    omitted_repository = Repository.objects.create(
        organization_id=result["organization_id"],
        external_id="github:synthetic/omitted",
        name="omitted",
    )
    with pytest.raises(ResourceNotFoundError):
        authorize_action(
            actor=initiator,
            action=Action.KNOWLEDGE_VIEW,
            repository_id=omitted_repository.id,
            access_scope_id=uuid.UUID(result["access_scope_id"]),
        )


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
@pytest.mark.parametrize(
    "mutation",
    [
        lambda scope: scope.pop("roles"),
        lambda scope: scope.update({"unknown": True}),
        lambda scope: scope["roles"].append(dict(scope["roles"][0])),
        lambda scope: scope["memberships"][0].update({"role_key": "omitted"}),
        lambda scope: scope["service_identities"][0]["grants"][0]["actions"].append(
            "unknown.action"
        ),
        lambda scope: scope["access_scope"].update({"repository_keys": ["omitted"]}),
        lambda scope: scope.update({"reviewer_service_identity_key": "initiator"}),
    ],
)
def test_scoped_bootstrap_fails_closed_for_ambiguous_or_invalid_scope(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    payload = _scoped_payload(suffix="strict")
    scope = payload["scope"]
    assert isinstance(scope, dict)
    mutation(scope)

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
def test_scoped_bootstrap_recovery_reissues_only_declared_actions() -> None:
    client = Client(HTTP_X_ANVA_BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
    payload = {**_scoped_payload(suffix="recovery"), "idempotency_key": "b" * 64}
    first = client.post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert first.status_code == 201, first.json()
    original = first.json()
    original_actor = authenticate_bearer(f"Bearer {original['token']}")
    declared_actions = original_actor.credential_actions
    original_grants = set(AccessGrant.objects.values_list("action", flat=True))

    recovered = client.post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert recovered.status_code == 201, recovered.json()
    replacement = recovered.json()
    assert replacement["recovered"] is True
    assert replacement["bootstrap_request_sha256"] == original["bootstrap_request_sha256"]
    assert authenticate_bearer(f"Bearer {replacement['token']}").credential_actions == (
        declared_actions
    )
    assert authenticate_bearer(
        f"Bearer {replacement['reviewer_token']}"
    ).credential_actions == frozenset({Action.ASSURANCE_REVIEW.value})
    assert set(AccessGrant.objects.values_list("action", flat=True)) == original_grants
    assert not AccessGrant.objects.filter(action=Action.GITHUB_MANAGE.value).exists()
    assert RepositoryAccessToken.objects.get(id=original["token_id"]).revoked_at is not None
    assert (
        RepositoryAccessToken.objects.get(id=original["reviewer_token_id"]).revoked_at is not None
    )

    changed = _scoped_payload(suffix="recovery")
    scope = changed["scope"]
    assert isinstance(scope, dict)
    repositories = scope["repositories"]
    assert isinstance(repositories, list)
    repositories[0]["name"] = "changed"
    mismatch = client.post(
        "/api/v1/bootstrap",
        data=json.dumps({**changed, "idempotency_key": "b" * 64}),
        content_type="application/json",
    )
    assert mismatch.status_code == 404


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_opt_in_reviewer_is_distinct_least_privilege_and_token_is_never_persisted() -> None:
    payload = _payload(reviewer=True)
    response = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )

    assert response.status_code == 201
    result = response.json()
    assert result["bootstrap_mode"] == "LEGACY"
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
    validate_acceptance_http_response("bootstrapOrganization", 201, result, request_payload=payload)
    _validate_published_exchange(payload, result)
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
