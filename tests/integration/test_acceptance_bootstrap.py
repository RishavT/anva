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
from anva.contracts.bootstrap_credentials import bootstrap_credential_set_id
from anva.contracts.bootstrap_scope import acceptance_bootstrap_scope_payload
from anva.core.exceptions import AuthenticationError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AuditEvent,
    Membership,
    Organization,
    OutboxEvent,
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
    assert set(result["credential_metadata"]) == {
        "schema_version",
        "bootstrap_request_sha256",
        "credential_set_id",
        "credential_set_generation",
        "observed_at",
        "primary",
    }
    primary_metadata = result["credential_metadata"]["primary"]
    assert primary_metadata["token_id"] == result["token_id"]
    assert primary_metadata["service_identity_id"] == result["service_identity_id"]
    assert primary_metadata["repository_id"] == result["repository_id"]
    assert primary_metadata["access_scope_id"] == result["access_scope_id"]
    assert primary_metadata["allowed_actions"] == sorted(action.value for action in Action)
    assert primary_metadata["service_identity_active_at_issuance"] is True
    assert primary_metadata["token_active_at_issuance"] is True
    assert primary_metadata["revoked_at_issuance"] is None
    assert primary_metadata["expires_at"] == result["expires_at"]
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
    metadata = result["credential_metadata"]
    assert set(metadata) == {
        "schema_version",
        "bootstrap_request_sha256",
        "credential_set_id",
        "credential_set_generation",
        "observed_at",
        "primary",
        "reviewer",
    }
    assert metadata["schema_version"] == 1
    assert metadata["bootstrap_request_sha256"] == result["bootstrap_request_sha256"]
    assert metadata["credential_set_generation"] == 0
    assert result["credential_set_generation"] == metadata["credential_set_generation"]
    uuid.UUID(metadata["credential_set_id"])
    primary_metadata = metadata["primary"]
    reviewer_metadata = metadata["reviewer"]
    assert primary_metadata == {
        "token_id": result["token_id"],
        "service_identity_id": result["service_identity_id"],
        "repository_id": result["repository_id"],
        "access_scope_id": result["access_scope_id"],
        "allowed_actions": sorted(initiator_actions),
        "service_identity_active_at_issuance": True,
        "token_active_at_issuance": True,
        "revoked_at_issuance": None,
        "expires_at": result["expires_at"],
        "issued_at": primary_metadata["issued_at"],
    }
    assert len(primary_metadata["allowed_actions"]) == 15
    assert "token.manage" in primary_metadata["allowed_actions"]
    assert reviewer_metadata == {
        "token_id": result["reviewer_token_id"],
        "service_identity_id": result["reviewer_service_identity_id"],
        "repository_id": result["repository_id"],
        "access_scope_id": result["access_scope_id"],
        "allowed_actions": ["assurance.review"],
        "service_identity_active_at_issuance": True,
        "token_active_at_issuance": True,
        "revoked_at_issuance": None,
        "expires_at": result["reviewer_expires_at"],
        "issued_at": reviewer_metadata["issued_at"],
    }
    assert primary_metadata["service_identity_id"] != reviewer_metadata["service_identity_id"]
    assert primary_metadata["token_id"] != reviewer_metadata["token_id"]
    assert result["token_id"] != result["reviewer_token_id"]
    assert RepositoryAccessToken.objects.get(id=result["token_id"]).service_identity_id == (
        uuid.UUID(result["service_identity_id"])
    )
    assert RepositoryAccessToken.objects.get(
        id=result["reviewer_token_id"]
    ).service_identity_id == uuid.UUID(result["reviewer_service_identity_id"])
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
def test_bootstrap_ids_support_public_revocation_of_both_official_credentials() -> None:
    bootstrap = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(_scoped_payload(suffix="revocation")),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )
    assert bootstrap.status_code == 201, bootstrap.json()
    credentials = bootstrap.json()
    assert credentials["token_id"] != credentials["reviewer_token_id"]
    assert credentials["credential_metadata"]["primary"]["token_id"] == credentials["token_id"]
    assert (
        credentials["credential_metadata"]["reviewer"]["token_id"]
        == credentials["reviewer_token_id"]
    )
    administrator = Client(HTTP_AUTHORIZATION=f"Bearer {credentials['token']}")

    reviewer_revoke = administrator.delete(f"/api/v1/tokens/{credentials['reviewer_token_id']}")
    assert reviewer_revoke.status_code == 200, reviewer_revoke.json()
    assert reviewer_revoke.json() == {
        "id": credentials["reviewer_token_id"],
        "status": "REVOKED",
    }
    with pytest.raises(AuthenticationError):
        authenticate_bearer(f"Bearer {credentials['reviewer_token']}")

    administrator_revoke = administrator.delete(f"/api/v1/tokens/{credentials['token_id']}")
    assert administrator_revoke.status_code == 200, administrator_revoke.json()
    assert administrator_revoke.json() == {
        "id": credentials["token_id"],
        "status": "REVOKED",
    }
    with pytest.raises(AuthenticationError):
        authenticate_bearer(f"Bearer {credentials['token']}")
    persisted_audit = json.dumps(
        list(AuditEvent.objects.values("metadata", "actor_id", "authorization_path")),
        sort_keys=True,
    )
    assert credentials["token"] not in persisted_audit
    assert credentials["reviewer_token"] not in persisted_audit


@pytest.mark.integration
@pytest.mark.django_db
@override_settings(BOOTSTRAP_SECRET="acceptance-bootstrap-secret")
def test_acceptance_initiator_cannot_rotate_reviewer_authority_but_can_rotate_own() -> None:
    bootstrap = Client().post(
        "/api/v1/bootstrap",
        data=json.dumps(_scoped_payload(suffix="rotation-boundary")),
        content_type="application/json",
        headers={"X-Anva-Bootstrap-Secret": "acceptance-bootstrap-secret"},
    )
    assert bootstrap.status_code == 201, bootstrap.json()
    credentials = bootstrap.json()
    original_admin_actions = authenticate_bearer(
        f"Bearer {credentials['token']}"
    ).credential_actions
    administrator = Client(HTTP_AUTHORIZATION=f"Bearer {credentials['token']}")
    credential_count = RepositoryAccessToken.objects.count()
    audit_count = AuditEvent.objects.count()
    outbox_count = OutboxEvent.objects.count()

    rejected = administrator.post(
        f"/api/v1/tokens/{credentials['reviewer_token_id']}/rotate",
        data=json.dumps({"expires_in_seconds": 3600}),
        content_type="application/json",
    )

    assert rejected.status_code == 404
    assert rejected.json()["code"] == "resource_not_found"
    assert "token" not in rejected.json()
    rejected_body = rejected.content.decode()
    assert credentials["token"] not in rejected_body
    assert credentials["reviewer_token"] not in rejected_body
    assert RepositoryAccessToken.objects.count() == credential_count
    assert AuditEvent.objects.count() == audit_count
    assert OutboxEvent.objects.count() == outbox_count
    reviewer = RepositoryAccessToken.objects.get(id=credentials["reviewer_token_id"])
    assert reviewer.revoked_at is None
    assert authenticate_bearer(f"Bearer {credentials['reviewer_token']}").credential_id == (
        reviewer.id
    )

    rotated = administrator.post(
        f"/api/v1/tokens/{credentials['token_id']}/rotate",
        data=json.dumps({"expires_in_seconds": 3600}),
        content_type="application/json",
    )

    assert rotated.status_code == 201, rotated.json()
    replacement = rotated.json()
    assert replacement["id"] != credentials["token_id"]
    assert replacement["token"] != credentials["token"]
    assert RepositoryAccessToken.objects.count() == credential_count + 1
    assert AuditEvent.objects.count() == audit_count + 1
    assert OutboxEvent.objects.count() == outbox_count + 1
    assert RepositoryAccessToken.objects.get(id=credentials["token_id"]).revoked_at is not None
    replacement_actor = authenticate_bearer(f"Bearer {replacement['token']}")
    assert replacement_actor.credential_actions == original_admin_actions
    assert authenticate_bearer(
        f"Bearer {credentials['reviewer_token']}"
    ).credential_actions == frozenset({Action.ASSURANCE_REVIEW.value})


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
    original_snapshot = original["credential_metadata"]
    replacement_snapshot = replacement["credential_metadata"]
    assert original_snapshot["credential_set_generation"] == 0
    assert replacement_snapshot["credential_set_generation"] == 1
    assert original["credential_set_generation"] == original_snapshot["credential_set_generation"]
    assert (
        replacement["credential_set_generation"]
        == replacement_snapshot["credential_set_generation"]
    )
    assert original_snapshot["credential_set_id"] != replacement_snapshot["credential_set_id"]
    assert (
        original_snapshot["bootstrap_request_sha256"]
        == replacement_snapshot["bootstrap_request_sha256"]
    )
    assert original_snapshot["primary"]["token_active_at_issuance"] is True
    assert original_snapshot["primary"]["revoked_at_issuance"] is None
    for response, snapshot in ((original, original_snapshot), (replacement, replacement_snapshot)):
        primary_record = RepositoryAccessToken.objects.get(id=response["token_id"])
        reviewer_record = RepositoryAccessToken.objects.get(id=response["reviewer_token_id"])
        assert (
            snapshot["observed_at"]
            == max(primary_record.issued_at, reviewer_record.issued_at).isoformat()
        )
        assert snapshot["credential_set_id"] == str(
            bootstrap_credential_set_id(
                request_sha256=response["bootstrap_request_sha256"],
                generation=response["credential_set_generation"],
                primary_token_id=response["token_id"],
                primary_issued_at=primary_record.issued_at,
                reviewer_token_id=response["reviewer_token_id"],
                reviewer_issued_at=reviewer_record.issued_at,
            )
        )
    assert RepositoryAccessToken.objects.get(id=original["token_id"]).revoked_at is not None
    assert (
        RepositoryAccessToken.objects.get(id=original["reviewer_token_id"]).revoked_at is not None
    )
    with pytest.raises(AuthenticationError):
        authenticate_bearer(f"Bearer {original['token']}")
    with pytest.raises(AuthenticationError):
        authenticate_bearer(f"Bearer {original['reviewer_token']}")
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
