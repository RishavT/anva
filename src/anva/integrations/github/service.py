"""Tenant mapping, webhook persistence, event processing, and revocation."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import cast

from django.db import IntegrityError, connection, transaction
from django.db.models import F
from django.utils import timezone

from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeRepository,
    AccessScopeServiceIdentity,
    AssuranceRun,
    BackgroundJob,
    EvaluatorTask,
    GitHubCheckObservation,
    GitHubEventProcessing,
    GitHubInstallation,
    GitHubPublication,
    GitHubPullRequestObservation,
    GitHubRepositoryBinding,
    GitHubWebhookDelivery,
    GitHubWriteIntent,
    OutboxEvent,
    PolicyVersion,
    PullRequest,
    Repository,
    RepositoryAccessToken,
    ServiceIdentity,
    SourceConnection,
    WorkItemRevision,
    content_hash,
)
from anva.core.services.assurance import ingest_manual_diff, start_assurance
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.jobs import enqueue_job
from anva.core.services.transitions import transition_assurance_run
from anva.integrations.github.client import (
    GitHubClient,
    GitHubClientError,
    PullRequestSnapshot,
    RepositoryReference,
)
from anva.integrations.github.webhooks import VerifiedGitHubEvent

GITHUB_EVENT_JOB_KIND = "github.event.process"
GITHUB_SERVICE_ACTIONS = frozenset(
    {
        Action.ARTIFACT_CREATE,
        Action.ARTIFACT_VIEW,
        Action.ASSURANCE_EXECUTE,
        Action.EVIDENCE_VIEW,
        Action.KNOWLEDGE_VIEW,
        Action.POLICY_VIEW,
        Action.REPOSITORY_VIEW,
        Action.SEARCH,
        Action.WORK_VIEW,
    }
)
ALLOWED_PERMISSIONS = {
    "actions": {"read"},
    "checks": {"write"},
    "contents": {"read"},
    "issues": {"write"},
    "metadata": {"read"},
    "pull_requests": {"read", "write"},
}
GITHUB_INSTALLATION_SUSPENDED = "GITHUB_INSTALLATION_SUSPENDED"
GITHUB_ACCESS_REVOKED = "GITHUB_ACCESS_REVOKED"
MAX_PROVIDER_REFRESH_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class WebhookAcceptance:
    """Non-oracular acknowledgement of a verified delivery."""

    status: str
    delivery_id: uuid.UUID
    created: bool
    delivery: GitHubWebhookDelivery | None


@dataclass(frozen=True, slots=True)
class BindingResult:
    installation: GitHubInstallation
    binding: GitHubRepositoryBinding
    created: bool


def _delivery_may_run(
    *,
    installation: GitHubInstallation,
    event_type: str,
    action: str,
) -> bool:
    if installation.state == GitHubInstallation.State.ACTIVE:
        return True
    return (
        installation.state == GitHubInstallation.State.SUSPENDED
        and event_type == "installation"
        and action in {"suspend", "unsuspend", "deleted"}
    )


def _binding_has_active_authority(binding_id: uuid.UUID) -> bool:
    binding = (
        GitHubRepositoryBinding.objects.select_related(
            "installation__service_identity",
            "repository",
        )
        .filter(id=binding_id)
        .first()
    )
    if binding is None or not _binding_is_active(binding):
        return False
    active_actions = set(
        AccessGrant.objects.filter(
            organization=binding.organization,
            service_identity=binding.installation.service_identity,
            repository=binding.repository,
            source_connection=None,
            action__in=[action.value for action in GITHUB_SERVICE_ACTIONS],
            revoked_at__isnull=True,
            expires_at__isnull=True,
        ).values_list("action", flat=True)
    )
    return active_actions == {action.value for action in GITHUB_SERVICE_ACTIONS}


def _binding_is_active(binding: GitHubRepositoryBinding) -> bool:
    return bool(
        binding.is_active
        and binding.revoked_at is None
        and not binding.is_archived
        and binding.repository.is_active
        and binding.installation.state == GitHubInstallation.State.ACTIVE
        and binding.installation.service_identity.is_active
    )


def _lock_active_binding(binding_id: uuid.UUID) -> GitHubRepositoryBinding | None:
    installation_id = (
        GitHubRepositoryBinding.objects.filter(id=binding_id)
        .values_list("installation_id", flat=True)
        .first()
    )
    if installation_id is None:
        return None
    GitHubInstallation.objects.select_for_update().get(id=installation_id)
    binding = (
        GitHubRepositoryBinding.objects.select_for_update()
        .select_related("installation__service_identity", "repository")
        .get(id=binding_id)
    )
    return binding if _binding_has_active_authority(binding.id) else None


def _lock_pull_request_refresh(*, binding_id: uuid.UUID, pull_request_number: int) -> None:
    """Serialize provider refreshes for one binding/PR until the transaction commits."""
    digest = hashlib.sha256(
        b"anva:github-pr-refresh:v1"
        + binding_id.bytes
        + pull_request_number.to_bytes(8, byteorder="big", signed=False)
    ).digest()
    lock_key = int.from_bytes(digest[:8], byteorder="big", signed=True)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [lock_key])


def _validated_pull_request_snapshot(
    snapshot: PullRequestSnapshot,
    *,
    expected_number: int,
) -> PullRequestSnapshot:
    if (
        snapshot.number != expected_number
        or snapshot.head_repository_id < 1
        or snapshot.external_id < 1
    ):
        raise ValueError("GitHub pull-request identity changed during synchronization")
    return snapshot


def _refresh_provider_truth(
    *,
    client: GitHubClient,
    repository: RepositoryReference,
    pull_request_number: int,
) -> tuple[PullRequestSnapshot, str]:
    """Return a diff bracketed by identical provider snapshots under the PR lock."""
    candidate = _validated_pull_request_snapshot(
        client.get_pull_request(
            repository=repository,
            pull_request_number=pull_request_number,
        ),
        expected_number=pull_request_number,
    )
    for _attempt in range(MAX_PROVIDER_REFRESH_ATTEMPTS):
        candidate_diff = client.get_pull_request_diff(
            repository=repository,
            pull_request_number=pull_request_number,
        )
        current = _validated_pull_request_snapshot(
            client.get_pull_request(
                repository=repository,
                pull_request_number=pull_request_number,
            ),
            expected_number=pull_request_number,
        )
        if current == candidate:
            return current, candidate_diff
        candidate = current
    raise GitHubClientError(
        "github_pull_request_changed_during_sync",
        transient=True,
        retry_after_seconds=1,
    )


def _validate_permissions(permissions: dict[str, str]) -> dict[str, str]:
    if not permissions or len(permissions) > len(ALLOWED_PERMISSIONS):
        raise ValueError("GitHub App permissions are invalid")
    normalized: dict[str, str] = {}
    for name, level in permissions.items():
        if name not in ALLOWED_PERMISSIONS or level not in ALLOWED_PERMISSIONS[name]:
            raise ValueError("GitHub App requests permissions outside the reviewed set")
        normalized[name] = level
    required = {
        "checks": "write",
        "contents": "read",
        "issues": "write",
        "pull_requests": "read",
    }
    if any(normalized.get(name) != level for name, level in required.items()):
        raise ValueError("GitHub App permissions do not satisfy the reviewed minimum")
    return dict(sorted(normalized.items()))


@transaction.atomic
def configure_repository_binding(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    installation_external_id: int,
    account_id: int,
    account_login: str,
    account_type: str,
    repository_selection: str,
    permissions: dict[str, str],
    external_repository_id: int,
    full_name: str,
    default_branch: str,
    is_private: bool,
    is_archived: bool,
    auto_assurance: bool,
    policy_version_ids: list[uuid.UUID],
    work_item_revision_id: uuid.UUID | None,
) -> BindingResult:
    """Bind one stored repository to a pre-authorized least-privilege installation."""
    if min(installation_external_id, account_id, external_repository_id) < 1:
        raise ValueError("GitHub identifiers must be positive")
    if (
        not account_login
        or len(account_login) > 300
        or account_type not in {"Organization", "User"}
        or repository_selection not in {"all", "selected"}
        or not full_name
        or len(full_name) > 600
        or "/" not in full_name
        or not default_branch
        or len(default_branch) > 300
    ):
        raise ValueError("GitHub binding metadata is invalid")
    if not isinstance(is_private, bool) or not isinstance(is_archived, bool):
        raise ValueError("GitHub repository flags must be boolean")
    if not isinstance(auto_assurance, bool):
        raise ValueError("auto_assurance must be boolean")
    if len(policy_version_ids) > 100 or len(policy_version_ids) != len(set(policy_version_ids)):
        raise ValueError("GitHub policy version configuration is invalid")
    normalized_permissions = _validate_permissions(permissions)
    decision = authorize_action(
        actor=actor,
        action=Action.GITHUB_MANAGE,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    repository = get_tenant_record_for_update(
        queryset=Repository.objects.select_related("organization").filter(is_active=True),
        record_id=repository_id,
        organization_id=actor.organization_id,
    )
    scope = get_tenant_record(
        queryset=AccessScope.objects.filter(is_active=True),
        record_id=access_scope_id,
        organization_id=actor.organization_id,
    )
    work_revision = None
    if work_item_revision_id is not None:
        work_revision = get_tenant_record(
            queryset=WorkItemRevision.objects.select_related("work_item"),
            record_id=work_item_revision_id,
            organization_id=actor.organization_id,
        )
        if (
            work_revision.work_item.repository_id != repository.id
            or work_revision.work_item.access_scope_id != scope.id
        ):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    versions = list(
        PolicyVersion.objects.select_related("policy")
        .filter(
            organization_id=actor.organization_id,
            id__in=policy_version_ids,
            policy__access_scope=scope,
        )
        .order_by("id")
    )
    if len(versions) != len(policy_version_ids):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    existing_installation = (
        GitHubInstallation.objects.select_for_update()
        .filter(external_id=installation_external_id)
        .first()
    )
    if existing_installation is not None:
        if existing_installation.organization_id != actor.organization_id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        installation = existing_installation
        if installation.state == GitHubInstallation.State.REVOKED:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        previous_installation_state = installation.state
        installation.account_id = account_id
        installation.account_login = account_login
        installation.account_type = account_type
        installation.repository_selection = repository_selection
        installation.permissions = normalized_permissions
        installation.state = GitHubInstallation.State.ACTIVE
        installation.suspended_at = None
        installation.revision += 1
        installation.save(
            update_fields=[
                "account_id",
                "account_login",
                "account_type",
                "repository_selection",
                "permissions",
                "state",
                "suspended_at",
                "revision",
                "updated_at",
            ]
        )
        service_identity = installation.service_identity
        service_identity.is_active = True
        service_identity.revision += 1
        service_identity.save(update_fields=["is_active", "revision", "updated_at"])
        if previous_installation_state != GitHubInstallation.State.ACTIVE:
            record_transition(
                organization=repository.organization,
                actor=actor,
                target_type="githubinstallation",
                target_id=installation.id,
                from_state=previous_installation_state,
                to_state=GitHubInstallation.State.ACTIVE,
                revision=installation.revision,
                metadata={"installation_id": installation_external_id},
            )
    else:
        service_identity = ServiceIdentity.objects.create(
            organization=repository.organization,
            name=f"github-installation-{installation_external_id}",
            issuer="github-app",
            audience="anva-github-adapter",
        )
        installation = GitHubInstallation.objects.create(
            organization=repository.organization,
            external_id=installation_external_id,
            account_id=account_id,
            account_login=account_login,
            account_type=account_type,
            repository_selection=repository_selection,
            permissions=normalized_permissions,
            service_identity=service_identity,
        )
        record_transition(
            organization=repository.organization,
            actor=actor,
            target_type="githubinstallation",
            target_id=installation.id,
            from_state="",
            to_state=installation.state,
            revision=installation.revision,
            metadata={"installation_id": installation_external_id},
        )
    binding = (
        GitHubRepositoryBinding.objects.select_for_update()
        .filter(organization=repository.organization, repository=repository)
        .first()
    )
    binding_created = binding is None
    if binding is not None:
        if (
            binding.installation_id != installation.id
            or binding.external_repository_id != external_repository_id
        ):
            raise IdempotencyConflictError(
                "Repository is already bound to a different GitHub identity"
            )
        was_active = binding.is_active
        binding.access_scope = scope
        binding.full_name = full_name
        binding.default_branch = default_branch
        binding.is_private = is_private
        binding.is_archived = is_archived
        binding.is_active = True
        binding.auto_assurance = auto_assurance
        binding.policy_version_ids = [str(identifier) for identifier in policy_version_ids]
        binding.work_item_revision = work_revision
        binding.revoked_at = None
        binding.revision += 1
        binding.save(
            update_fields=[
                "access_scope",
                "full_name",
                "default_branch",
                "is_private",
                "is_archived",
                "is_active",
                "auto_assurance",
                "policy_version_ids",
                "work_item_revision",
                "revoked_at",
                "revision",
                "updated_at",
            ]
        )
        if not was_active:
            repository.is_active = True
            repository.save(update_fields=["is_active", "updated_at"])
            record_transition(
                organization=repository.organization,
                actor=actor,
                target_type="githubrepositorybinding",
                target_id=binding.id,
                from_state="REVOKED",
                to_state="ACTIVE",
                revision=binding.revision,
                metadata={
                    "binding_id": str(binding.id),
                    "external_repository_id": external_repository_id,
                    "repository_id": str(repository.id),
                },
            )
    else:
        binding = GitHubRepositoryBinding.objects.create(
            organization=repository.organization,
            installation=installation,
            repository=repository,
            access_scope=scope,
            external_repository_id=external_repository_id,
            full_name=full_name,
            default_branch=default_branch,
            is_private=is_private,
            is_archived=is_archived,
            auto_assurance=auto_assurance,
            policy_version_ids=[str(identifier) for identifier in policy_version_ids],
            work_item_revision=work_revision,
        )
        record_transition(
            organization=repository.organization,
            actor=actor,
            target_type="githubrepositorybinding",
            target_id=binding.id,
            from_state="",
            to_state="ACTIVE",
            revision=binding.revision,
            metadata={
                "binding_id": str(binding.id),
                "external_repository_id": external_repository_id,
                "repository_id": str(repository.id),
            },
        )
    AccessScopeRepository.objects.get_or_create(
        organization=repository.organization,
        access_scope=scope,
        repository=repository,
    )
    AccessScopeServiceIdentity.objects.get_or_create(
        organization=repository.organization,
        access_scope=scope,
        service_identity=service_identity,
    )
    for action in GITHUB_SERVICE_ACTIONS:
        AccessGrant.objects.update_or_create(
            organization=repository.organization,
            service_identity=service_identity,
            repository=repository,
            source_connection=None,
            action=action.value,
            defaults={"revoked_at": None, "expires_at": None},
        )
    return BindingResult(installation, binding, binding_created)


def accept_verified_event(event: VerifiedGitHubEvent) -> WebhookAcceptance:
    """Persist exactly one verified delivery and its process job atomically."""
    installation = (
        GitHubInstallation.objects.select_related("organization", "service_identity")
        .filter(external_id=event.installation_id)
        .first()
    )
    if installation is None:
        return WebhookAcceptance("unmapped", event.delivery_id, False, None)
    try:
        with transaction.atomic():
            installation = (
                GitHubInstallation.objects.select_for_update()
                .select_related("organization", "service_identity")
                .get(id=installation.id)
            )
            binding = None
            if event.repository_external_id is not None:
                binding = GitHubRepositoryBinding.objects.filter(
                    organization=installation.organization,
                    installation=installation,
                    external_repository_id=event.repository_external_id,
                ).first()
            existing = (
                GitHubWebhookDelivery.objects.select_for_update()
                .filter(delivery_id=event.delivery_id)
                .first()
            )
            if existing is not None:
                return _duplicate_acceptance(existing=existing, event=event)
            delivery = GitHubWebhookDelivery.objects.create(
                organization=installation.organization,
                installation=installation,
                repository_binding=binding,
                delivery_id=event.delivery_id,
                event_type=event.event_type,
                action=event.action,
                payload_checksum=event.checksum,
                normalized_payload=event.normalized_payload,
            )
            may_run = _delivery_may_run(
                installation=installation,
                event_type=event.event_type,
                action=event.action,
            )
            if may_run:
                GitHubEventProcessing.objects.create(
                    organization=installation.organization,
                    delivery=delivery,
                )
            else:
                GitHubEventProcessing.objects.create(
                    organization=installation.organization,
                    delivery=delivery,
                    state=GitHubEventProcessing.State.IGNORED,
                    result_identifiers={
                        "status": "ignored",
                        "reason": "inactive_installation",
                    },
                    last_error_code=(
                        "github_installation_suspended"
                        if installation.state == GitHubInstallation.State.SUSPENDED
                        else "github_access_revoked"
                    ),
                    processed_at=timezone.now(),
                )
            actor = _installation_actor(installation, request_id=event.delivery_id)
            if may_run:
                enqueue_job(
                    actor=actor,
                    kind=GITHUB_EVENT_JOB_KIND,
                    payload={"delivery_id": str(delivery.id)},
                    idempotency_key=f"github-delivery:{event.delivery_id}",
                    max_attempts=8,
                )
            record_transition(
                organization=installation.organization,
                actor=actor,
                target_type="githubwebhookdelivery",
                target_id=delivery.id,
                from_state="",
                to_state="VERIFIED",
                revision=1,
                metadata={
                    "delivery_id": str(delivery.delivery_id),
                    "event_type": delivery.event_type,
                },
            )
            return WebhookAcceptance("accepted", event.delivery_id, True, delivery)
    except IntegrityError:
        existing = GitHubWebhookDelivery.objects.get(delivery_id=event.delivery_id)
        return _duplicate_acceptance(existing=existing, event=event)


def _duplicate_acceptance(
    *,
    existing: GitHubWebhookDelivery,
    event: VerifiedGitHubEvent,
) -> WebhookAcceptance:
    if (
        existing.payload_checksum != event.checksum
        or existing.event_type != event.event_type
        or existing.installation.external_id != event.installation_id
    ):
        raise IdempotencyConflictError(
            "GitHub delivery identifier was reused with different content"
        )
    return WebhookAcceptance("duplicate", event.delivery_id, False, existing)


def process_delivery(
    *,
    delivery_id: uuid.UUID,
    client: GitHubClient | None,
) -> GitHubEventProcessing:
    """Process one verified bounded event; current provider state wins over delivery order."""
    with transaction.atomic():
        delivery_seed = GitHubWebhookDelivery.objects.only(
            "id",
            "installation_id",
            "event_type",
            "action",
        ).get(id=delivery_id)
        installation = GitHubInstallation.objects.select_for_update().get(
            id=delivery_seed.installation_id
        )
        processing = (
            GitHubEventProcessing.objects.select_for_update(of=("self",))
            .select_related(
                "delivery__installation__service_identity",
                "delivery__repository_binding__repository",
                "delivery__repository_binding__access_scope",
            )
            .get(delivery_id=delivery_id)
        )
        if processing.state in {
            GitHubEventProcessing.State.PROCESSED,
            GitHubEventProcessing.State.IGNORED,
        }:
            return processing
        if not _delivery_may_run(
            installation=installation,
            event_type=delivery_seed.event_type,
            action=delivery_seed.action,
        ):
            return _ignore_processing_locked(
                processing,
                reason="inactive_installation",
                error_code=(
                    "github_installation_suspended"
                    if installation.state == GitHubInstallation.State.SUSPENDED
                    else "github_access_revoked"
                ),
            )
        processing.state = GitHubEventProcessing.State.PROCESSING
        processing.attempt_count += 1
        processing.last_error_code = ""
        processing.revision += 1
        processing.save(
            update_fields=[
                "state",
                "attempt_count",
                "last_error_code",
                "revision",
                "updated_at",
            ]
        )
    delivery = processing.delivery
    try:
        result = _dispatch_delivery(delivery=delivery, client=client)
    except Exception as error:
        with transaction.atomic():
            installation = GitHubInstallation.objects.select_for_update().get(
                id=delivery.installation_id
            )
            processing = GitHubEventProcessing.objects.select_for_update().get(id=processing.id)
            if not _delivery_may_run(
                installation=installation,
                event_type=delivery.event_type,
                action=delivery.action,
            ):
                return _ignore_processing_locked(
                    processing,
                    reason="inactive_installation",
                    error_code=(
                        "github_installation_suspended"
                        if installation.state == GitHubInstallation.State.SUSPENDED
                        else "github_access_revoked"
                    ),
                )
            processing.state = GitHubEventProcessing.State.FAILED
            processing.last_error_code = getattr(error, "code", "github_event_processing_failed")[
                :100
            ]
            processing.revision += 1
            processing.save(
                update_fields=[
                    "state",
                    "last_error_code",
                    "revision",
                    "updated_at",
                ]
            )
        raise
    with transaction.atomic():
        installation = GitHubInstallation.objects.select_for_update().get(
            id=delivery.installation_id
        )
        processing = GitHubEventProcessing.objects.select_for_update().get(id=processing.id)
        if not _delivery_may_run(
            installation=installation,
            event_type=delivery.event_type,
            action=delivery.action,
        ):
            return _ignore_processing_locked(
                processing,
                reason="inactive_installation",
                error_code=(
                    "github_installation_suspended"
                    if installation.state == GitHubInstallation.State.SUSPENDED
                    else "github_access_revoked"
                ),
            )
        processing.state = (
            GitHubEventProcessing.State.PROCESSED
            if result.get("status") != "ignored"
            else GitHubEventProcessing.State.IGNORED
        )
        processing.result_identifiers = result
        processing.processed_at = timezone.now()
        processing.revision += 1
        processing.save(
            update_fields=[
                "state",
                "result_identifiers",
                "processed_at",
                "revision",
                "updated_at",
            ]
        )
        return processing


def _ignore_processing_locked(
    processing: GitHubEventProcessing,
    *,
    reason: str,
    error_code: str,
) -> GitHubEventProcessing:
    processing.state = GitHubEventProcessing.State.IGNORED
    processing.result_identifiers = {"status": "ignored", "reason": reason}
    processing.last_error_code = error_code
    processing.processed_at = timezone.now()
    processing.revision += 1
    processing.save(
        update_fields=[
            "state",
            "result_identifiers",
            "last_error_code",
            "processed_at",
            "revision",
            "updated_at",
        ]
    )
    return processing


def _dispatch_delivery(
    *,
    delivery: GitHubWebhookDelivery,
    client: GitHubClient | None,
) -> dict[str, object]:
    event_type = delivery.event_type
    if event_type == "installation":
        return _process_installation_event(delivery)
    if event_type in {"installation_repositories", "repository"}:
        return _process_repository_event(delivery)
    binding = delivery.repository_binding
    if binding is None or not _binding_has_active_authority(binding.id):
        return {"status": "ignored", "reason": "inactive_or_unmapped_repository"}
    if event_type == "pull_request":
        if client is None:
            raise ValueError("A GitHub client is required for pull-request ingestion")
        return _process_pull_request_event(delivery=delivery, binding=binding, client=client)
    if event_type in {"check_run", "check_suite", "workflow_run"}:
        return _process_check_event(delivery=delivery, binding=binding)
    return {"status": "ignored", "reason": "unsupported_event"}


@transaction.atomic
def _process_installation_event(delivery: GitHubWebhookDelivery) -> dict[str, object]:
    installation = GitHubInstallation.objects.select_for_update().get(id=delivery.installation_id)
    details = cast(dict[str, object], delivery.normalized_payload.get("installation", {}))
    if delivery.action == "deleted":
        revoke_installation(installation=installation, request_id=delivery.delivery_id)
        return {"status": "revoked", "installation_id": str(installation.id)}
    if delivery.action == "suspend":
        suspend_installation(
            installation=installation,
            request_id=delivery.delivery_id,
            current_delivery_id=delivery.id,
        )
        return {"status": "suspended", "installation_id": str(installation.id)}
    if details:
        installation.account_id = cast(int, details["account_id"])
        installation.account_login = cast(str, details["account_login"])
        installation.account_type = cast(str, details["account_type"])
        installation.repository_selection = cast(str, details["repository_selection"])
        installation.permissions = _validate_permissions(
            cast(dict[str, str], details["permissions"])
        )
    if delivery.action == "unsuspend":
        installation.save(
            update_fields=[
                "account_id",
                "account_login",
                "account_type",
                "repository_selection",
                "permissions",
                "updated_at",
            ]
        )
        reactivate_installation(
            installation=installation,
            request_id=delivery.delivery_id,
        )
        return {"status": "reactivated", "installation_id": str(installation.id)}
    installation.state = GitHubInstallation.State.ACTIVE
    installation.revision += 1
    installation.save()
    return {"status": "processed", "installation_id": str(installation.id)}


@transaction.atomic
def _process_repository_event(delivery: GitHubWebhookDelivery) -> dict[str, object]:
    installation = GitHubInstallation.objects.select_for_update().get(id=delivery.installation_id)
    if installation.state != GitHubInstallation.State.ACTIVE:
        return {"status": "ignored", "reason": "inactive_installation"}
    binding = delivery.repository_binding
    if delivery.event_type == "installation_repositories":
        key = "repositories_removed" if delivery.action == "removed" else "repositories_added"
        rows = cast(list[dict[str, object]], delivery.normalized_payload.get(key, []))
        changed = 0
        for row in rows:
            candidate = (
                GitHubRepositoryBinding.objects.select_for_update()
                .filter(
                    installation=delivery.installation,
                    external_repository_id=cast(int, row["external_id"]),
                )
                .first()
            )
            if candidate is None:
                continue
            if not _binding_has_active_authority(candidate.id):
                continue
            if delivery.action == "removed":
                revoke_repository_binding(
                    binding=candidate,
                    request_id=delivery.delivery_id,
                )
            else:
                candidate.full_name = cast(str, row["full_name"])
                candidate.default_branch = cast(str, row["default_branch"])
                candidate.is_private = cast(bool, row["private"])
                candidate.is_archived = cast(bool, row["archived"])
                candidate.revision += 1
                candidate.save()
            changed += 1
        return {"status": "processed", "changed_binding_count": changed}
    if binding is None:
        return {"status": "ignored", "reason": "unmapped_repository"}
    binding = GitHubRepositoryBinding.objects.select_for_update().get(id=binding.id)
    if not _binding_has_active_authority(binding.id):
        return {"status": "ignored", "reason": "inactive_repository"}
    if delivery.action == "deleted":
        revoke_repository_binding(binding=binding, request_id=delivery.delivery_id)
        return {"status": "revoked", "binding_id": str(binding.id)}
    repository = cast(dict[str, object], delivery.normalized_payload["repository"])
    binding.full_name = cast(str, repository["full_name"])
    binding.default_branch = cast(str, repository["default_branch"])
    binding.is_private = cast(bool, repository["private"])
    binding.is_archived = cast(bool, repository["archived"])
    binding.revision += 1
    binding.save()
    return {"status": "processed", "binding_id": str(binding.id)}


def _process_pull_request_event(
    *,
    delivery: GitHubWebhookDelivery,
    binding: GitHubRepositoryBinding,
    client: GitHubClient,
) -> dict[str, object]:
    event = cast(dict[str, object], delivery.normalized_payload["pull_request"])
    pull_request_number = cast(int, event["number"])
    with transaction.atomic():
        _lock_pull_request_refresh(
            binding_id=binding.id,
            pull_request_number=pull_request_number,
        )
        active_binding = _lock_active_binding(binding.id)
        if active_binding is None:
            return {"status": "ignored", "reason": "inactive_repository"}
        # Every credential-bearing provider read occurs while locked authority is
        # active. Suspension either wins before this point or waits for this
        # read/persistence transaction to drain completely.
        repository = RepositoryReference(
            active_binding.external_repository_id,
            active_binding.full_name,
        )
        snapshot, unified_diff = _refresh_provider_truth(
            client=client,
            repository=repository,
            pull_request_number=pull_request_number,
        )
        actor = _installation_actor(
            active_binding.installation,
            request_id=delivery.delivery_id,
        )
        state = (
            PullRequest.State.MERGED
            if snapshot.merged
            else PullRequest.State.CLOSED
            if snapshot.state == "CLOSED"
            else PullRequest.State.OPEN
        )
        result = ingest_manual_diff(
            actor=actor,
            repository_id=active_binding.repository_id,
            access_scope_id=active_binding.access_scope_id,
            pull_request_number=snapshot.number,
            base_commit=snapshot.base_commit,
            head_commit=snapshot.head_commit,
            title=snapshot.title,
            description=snapshot.description,
            target_branch=snapshot.target_branch,
            is_draft=snapshot.is_draft,
            state=state,
            unified_diff=unified_diff,
        )
        observation_payload = {
            "external_pull_request_id": snapshot.external_id,
            "head_repository_id": snapshot.head_repository_id,
            "head_ref": snapshot.head_ref,
            "is_fork": snapshot.is_fork,
            "head_commit": snapshot.head_commit,
        }
        GitHubPullRequestObservation.objects.get_or_create(
            organization=active_binding.organization,
            pull_request_revision=result.revision,
            defaults={
                "repository_binding": active_binding,
                "delivery": delivery,
                "external_pull_request_id": snapshot.external_id,
                "head_repository_id": snapshot.head_repository_id,
                "head_ref": snapshot.head_ref,
                "is_fork": snapshot.is_fork,
                "payload_hash": content_hash(observation_payload),
            },
        )
        run_id: str | None = None
        if (
            active_binding.auto_assurance
            and active_binding.policy_version_ids
            and state == PullRequest.State.OPEN
            and not snapshot.is_draft
        ):
            policy_ids = [
                uuid.UUID(value) for value in cast(list[str], active_binding.policy_version_ids)
            ]
            trigger_key = content_hash(
                {
                    "provider": "github",
                    "binding_id": str(active_binding.id),
                    "pull_request_revision_input_hash": result.revision.input_hash,
                    "policy_version_ids": sorted(str(identifier) for identifier in policy_ids),
                    "work_item_revision_id": (
                        str(active_binding.work_item_revision_id)
                        if active_binding.work_item_revision_id is not None
                        else None
                    ),
                }
            )
            assurance = start_assurance(
                actor=actor,
                pull_request_revision_id=result.revision.id,
                policy_version_ids=policy_ids,
                reference_time=result.revision.created_at,
                deterministic_checks=[],
                work_item_revision_id=active_binding.work_item_revision_id,
                trigger_key=trigger_key,
            )
            run_id = str(assurance.run.id)
        final_snapshot = _validated_pull_request_snapshot(
            client.get_pull_request(
                repository=repository,
                pull_request_number=pull_request_number,
            ),
            expected_number=pull_request_number,
        )
        if final_snapshot != snapshot:
            raise GitHubClientError(
                "github_pull_request_changed_during_sync",
                transient=True,
                retry_after_seconds=1,
            )
    return {
        "status": "processed",
        "pull_request_id": str(result.pull_request.id),
        "pull_request_revision_id": str(result.revision.id),
        "assurance_run_id": run_id,
        "is_fork": snapshot.is_fork,
    }


@transaction.atomic
def _process_check_event(
    *,
    delivery: GitHubWebhookDelivery,
    binding: GitHubRepositoryBinding,
) -> dict[str, object]:
    active_binding = _lock_active_binding(binding.id)
    if active_binding is None:
        return {"status": "ignored", "reason": "inactive_repository"}
    check = cast(dict[str, object], delivery.normalized_payload["check"])
    payload_hash = content_hash(check)
    observation, created = GitHubCheckObservation.objects.get_or_create(
        organization=active_binding.organization,
        repository_binding=active_binding,
        kind=cast(str, check["kind"]),
        external_id=cast(int, check["external_id"]),
        payload_hash=payload_hash,
        defaults={
            "delivery": delivery,
            "name": cast(str, check["name"]),
            "head_commit": cast(str, check["head_commit"]),
            "status": cast(str, check["status"]),
            "conclusion": cast(str, check["conclusion"]),
            "details_url": cast(str, check["details_url"]),
            "pull_request_numbers": cast(list[int], check["pull_request_numbers"]),
        },
    )
    return {
        "status": "processed",
        "check_observation_id": str(observation.id),
        "created": created,
    }


@transaction.atomic
def suspend_installation(
    *,
    installation: GitHubInstallation,
    request_id: uuid.UUID,
    current_delivery_id: uuid.UUID | None = None,
) -> None:
    """Atomically stop a temporarily suspended installation and all derived work."""
    installation = (
        GitHubInstallation.objects.select_for_update()
        .select_related("organization", "service_identity")
        .get(id=installation.id)
    )
    if installation.state in {
        GitHubInstallation.State.SUSPENDED,
        GitHubInstallation.State.REVOKED,
    }:
        return
    actor = _installation_actor(installation, request_id=request_id)
    now = timezone.now()
    installation.state = GitHubInstallation.State.SUSPENDED
    installation.suspended_at = now
    installation.revision += 1
    installation.save(update_fields=["state", "suspended_at", "revision", "updated_at"])
    installation.service_identity.is_active = False
    installation.service_identity.revision += 1
    installation.service_identity.save(update_fields=["is_active", "revision", "updated_at"])
    for binding in list(
        GitHubRepositoryBinding.objects.select_for_update()
        .filter(installation=installation, revoked_at__isnull=True)
        .select_related("installation__service_identity", "repository", "organization")
    ):
        _suspend_binding_locked(
            binding=binding,
            actor=actor,
            now=now,
            current_delivery_id=current_delivery_id,
        )
    AccessGrant.objects.filter(
        organization=installation.organization,
        service_identity=installation.service_identity,
        revoked_at__isnull=True,
    ).update(revoked_at=now)
    _cancel_installation_delivery_work(
        installation=installation,
        now=now,
        error_code=GITHUB_INSTALLATION_SUSPENDED,
        current_delivery_id=current_delivery_id,
    )
    record_transition(
        organization=installation.organization,
        actor=actor,
        target_type="githubinstallation",
        target_id=installation.id,
        from_state=GitHubInstallation.State.ACTIVE,
        to_state=GitHubInstallation.State.SUSPENDED,
        revision=installation.revision,
        metadata={"installation_id": installation.external_id},
    )


@transaction.atomic
def reactivate_installation(
    *,
    installation: GitHubInstallation,
    request_id: uuid.UUID,
) -> None:
    """Explicitly restore reviewed grants, never cancelled work or revoked credentials."""
    installation = (
        GitHubInstallation.objects.select_for_update()
        .select_related("organization", "service_identity")
        .get(id=installation.id)
    )
    if installation.state != GitHubInstallation.State.SUSPENDED:
        return
    actor = _installation_actor(installation, request_id=request_id)
    installation.state = GitHubInstallation.State.ACTIVE
    installation.suspended_at = None
    installation.revision += 1
    installation.save(update_fields=["state", "suspended_at", "revision", "updated_at"])
    installation.service_identity.is_active = True
    installation.service_identity.revision += 1
    installation.service_identity.save(update_fields=["is_active", "revision", "updated_at"])
    for binding in list(
        GitHubRepositoryBinding.objects.select_for_update()
        .filter(
            installation=installation,
            is_active=False,
            is_archived=False,
            revoked_at__isnull=True,
        )
        .select_related("repository", "organization")
    ):
        binding.repository.is_active = True
        binding.repository.save(update_fields=["is_active", "updated_at"])
        binding.is_active = True
        binding.revision += 1
        binding.save(update_fields=["is_active", "revision", "updated_at"])
        AccessScopeServiceIdentity.objects.get_or_create(
            organization=binding.organization,
            access_scope=binding.access_scope,
            service_identity=installation.service_identity,
        )
        for action in GITHUB_SERVICE_ACTIONS:
            AccessGrant.objects.update_or_create(
                organization=binding.organization,
                service_identity=installation.service_identity,
                repository=binding.repository,
                source_connection=None,
                action=action.value,
                defaults={"revoked_at": None, "expires_at": None},
            )
        record_transition(
            organization=binding.organization,
            actor=actor,
            target_type="githubrepositorybinding",
            target_id=binding.id,
            from_state=GitHubInstallation.State.SUSPENDED,
            to_state=GitHubInstallation.State.ACTIVE,
            revision=binding.revision,
            metadata={
                "binding_id": str(binding.id),
                "external_repository_id": binding.external_repository_id,
                "repository_id": str(binding.repository_id),
            },
        )
    record_transition(
        organization=installation.organization,
        actor=actor,
        target_type="githubinstallation",
        target_id=installation.id,
        from_state=GitHubInstallation.State.SUSPENDED,
        to_state=GitHubInstallation.State.ACTIVE,
        revision=installation.revision,
        metadata={"installation_id": installation.external_id},
    )


@transaction.atomic
def revoke_installation(
    *,
    installation: GitHubInstallation,
    request_id: uuid.UUID,
) -> None:
    """Stop all access, work, and future writes for one installation."""
    installation = (
        GitHubInstallation.objects.select_for_update()
        .select_related("organization", "service_identity")
        .get(id=installation.id)
    )
    if installation.state == GitHubInstallation.State.REVOKED:
        return
    previous_state = installation.state
    actor = _installation_actor(installation, request_id=request_id)
    for binding in list(
        GitHubRepositoryBinding.objects.select_for_update()
        .filter(installation=installation)
        .select_related("repository")
    ):
        _revoke_binding_locked(binding=binding, actor=actor)
    installation.state = GitHubInstallation.State.REVOKED
    installation.revoked_at = timezone.now()
    installation.suspended_at = None
    installation.revision += 1
    installation.save()
    installation.service_identity.is_active = False
    installation.service_identity.revision += 1
    installation.service_identity.save(update_fields=["is_active", "revision", "updated_at"])
    AccessGrant.objects.filter(
        organization=installation.organization,
        service_identity=installation.service_identity,
        revoked_at__isnull=True,
    ).update(revoked_at=installation.revoked_at)
    record_transition(
        organization=installation.organization,
        actor=actor,
        target_type="githubinstallation",
        target_id=installation.id,
        from_state=previous_state,
        to_state=GitHubInstallation.State.REVOKED,
        revision=installation.revision,
        metadata={"installation_id": installation.external_id},
    )


@transaction.atomic
def revoke_repository_binding(
    *,
    binding: GitHubRepositoryBinding,
    request_id: uuid.UUID,
) -> None:
    binding = (
        GitHubRepositoryBinding.objects.select_for_update()
        .select_related("installation__service_identity", "repository", "organization")
        .get(id=binding.id)
    )
    actor = _installation_actor(binding.installation, request_id=request_id)
    _revoke_binding_locked(binding=binding, actor=actor)


def _revoke_binding_locked(
    *,
    binding: GitHubRepositoryBinding,
    actor: ActorContext,
) -> None:
    if not binding.is_active and binding.revoked_at is not None:
        return
    now = timezone.now()
    _stop_binding_work_locked(
        binding=binding,
        actor=actor,
        now=now,
        error_code=GITHUB_ACCESS_REVOKED,
    )
    binding.repository.is_active = False
    binding.repository.save(update_fields=["is_active", "updated_at"])
    binding.is_active = False
    binding.revoked_at = now
    binding.revision += 1
    binding.save(update_fields=["is_active", "revoked_at", "revision", "updated_at"])
    record_transition(
        organization=binding.organization,
        actor=actor,
        target_type="githubrepositorybinding",
        target_id=binding.id,
        from_state="ACTIVE",
        to_state="REVOKED",
        revision=binding.revision,
        metadata={
            "binding_id": str(binding.id),
            "external_repository_id": binding.external_repository_id,
            "repository_id": str(binding.repository_id),
        },
    )


def _suspend_binding_locked(
    *,
    binding: GitHubRepositoryBinding,
    actor: ActorContext,
    now: datetime,
    current_delivery_id: uuid.UUID | None,
) -> None:
    if binding.revoked_at is not None:
        return
    _stop_binding_work_locked(
        binding=binding,
        actor=actor,
        now=now,
        error_code=GITHUB_INSTALLATION_SUSPENDED,
        current_delivery_id=current_delivery_id,
    )
    was_active = binding.is_active
    binding.repository.is_active = False
    binding.repository.save(update_fields=["is_active", "updated_at"])
    binding.is_active = False
    binding.revision += 1
    binding.save(update_fields=["is_active", "revision", "updated_at"])
    if was_active:
        record_transition(
            organization=binding.organization,
            actor=actor,
            target_type="githubrepositorybinding",
            target_id=binding.id,
            from_state=GitHubInstallation.State.ACTIVE,
            to_state=GitHubInstallation.State.SUSPENDED,
            revision=binding.revision,
            metadata={
                "binding_id": str(binding.id),
                "external_repository_id": binding.external_repository_id,
                "repository_id": str(binding.repository_id),
            },
        )


def _stop_binding_work_locked(
    *,
    binding: GitHubRepositoryBinding,
    actor: ActorContext,
    now: datetime,
    error_code: str,
    current_delivery_id: uuid.UUID | None = None,
) -> None:
    active_runs = list(
        AssuranceRun.objects.select_for_update().filter(
            organization=binding.organization,
            repository=binding.repository,
            state__in=[
                AssuranceRun.State.REQUESTED,
                AssuranceRun.State.DEBOUNCING,
                AssuranceRun.State.FETCHING_PULL_REQUEST,
                AssuranceRun.State.COLLECTING_EVIDENCE,
                AssuranceRun.State.EVALUATING_POLICY,
                AssuranceRun.State.BUILDING_CONTEXT,
                AssuranceRun.State.MODEL_REVIEW,
                AssuranceRun.State.MAPPING_EVIDENCE,
                AssuranceRun.State.RENDERING_REPORT,
                AssuranceRun.State.PUBLISHING,
            ],
        )
    )
    for run in active_runs:
        run.failure_code = error_code
        run.save(update_fields=["failure_code", "updated_at"])
        transition_assurance_run(
            actor=actor,
            run_id=run.id,
            target_state=AssuranceRun.State.CANCELLED,
            expected_revision=run.revision,
        )
    EvaluatorTask.objects.filter(
        organization=binding.organization,
        repository=binding.repository,
        state__in=[EvaluatorTask.State.PENDING, EvaluatorTask.State.CLAIMED],
    ).update(
        state=EvaluatorTask.State.CANCELLED,
        failure_code=error_code,
        lease_expires_at=None,
        claim_token_hash="",
        revision=F("revision") + 1,
        updated_at=now,
    )
    pending_intents = GitHubWriteIntent.objects.filter(
        organization=binding.organization,
        publication__repository_binding=binding,
        state__in=[
            GitHubWriteIntent.State.PENDING,
            GitHubWriteIntent.State.RUNNING,
            GitHubWriteIntent.State.RETRY,
        ],
    )
    intent_ids = list(pending_intents.values_list("id", flat=True))
    pending_intents.update(
        state=GitHubWriteIntent.State.CANCELLED,
        completed_at=now,
        lease_owner="",
        lease_expires_at=None,
        last_error_code=error_code,
    )
    OutboxEvent.objects.filter(
        aggregate_type="githubwriteintent",
        aggregate_id__in=intent_ids,
        published_at__isnull=True,
    ).update(published_at=now)
    GitHubPublication.objects.filter(
        organization=binding.organization,
        repository_binding=binding,
        is_current=True,
    ).update(is_current=False, revision=F("revision") + 1, updated_at=now)
    deliveries = GitHubWebhookDelivery.objects.filter(
        organization=binding.organization,
        repository_binding=binding,
    )
    if current_delivery_id is not None:
        deliveries = deliveries.exclude(id=current_delivery_id)
    delivery_ids = list(deliveries.values_list("id", flat=True))
    _cancel_delivery_work(
        organization_id=binding.organization_id,
        delivery_ids=delivery_ids,
        now=now,
        error_code=error_code,
    )
    RepositoryAccessToken.objects.filter(
        organization=binding.organization,
        repository=binding.repository,
        revoked_at__isnull=True,
    ).update(revoked_at=now)
    SourceConnection.objects.filter(
        organization=binding.organization,
        repository=binding.repository,
    ).exclude(state=SourceConnection.State.REVOKED).update(
        state=SourceConnection.State.REVOKED,
        last_error_code=error_code.lower(),
        revision=F("revision") + 1,
        updated_at=now,
    )
    AccessGrant.objects.filter(
        organization=binding.organization,
        repository=binding.repository,
        service_identity=binding.installation.service_identity,
        revoked_at__isnull=True,
    ).update(revoked_at=now)


def _cancel_installation_delivery_work(
    *,
    installation: GitHubInstallation,
    now: datetime,
    error_code: str,
    current_delivery_id: uuid.UUID | None,
) -> None:
    delivery_ids = list(
        GitHubWebhookDelivery.objects.filter(
            organization=installation.organization,
            installation=installation,
        ).values_list("id", flat=True)
    )
    if current_delivery_id is not None:
        delivery_ids = [
            identifier for identifier in delivery_ids if identifier != current_delivery_id
        ]
    _cancel_delivery_work(
        organization_id=installation.organization_id,
        delivery_ids=delivery_ids,
        now=now,
        error_code=error_code,
    )


def _cancel_delivery_work(
    *,
    organization_id: uuid.UUID,
    delivery_ids: list[uuid.UUID],
    now: datetime,
    error_code: str,
) -> None:
    if not delivery_ids:
        return
    GitHubEventProcessing.objects.filter(
        organization_id=organization_id,
        delivery_id__in=delivery_ids,
        state__in=[
            GitHubEventProcessing.State.PENDING,
            GitHubEventProcessing.State.PROCESSING,
            GitHubEventProcessing.State.FAILED,
        ],
    ).update(
        state=GitHubEventProcessing.State.IGNORED,
        result_identifiers={
            "status": "ignored",
            "reason": "inactive_installation",
        },
        last_error_code=error_code.lower(),
        processed_at=now,
        revision=F("revision") + 1,
        updated_at=now,
    )
    BackgroundJob.objects.filter(
        organization_id=organization_id,
        kind=GITHUB_EVENT_JOB_KIND,
        payload__delivery_id__in=[str(identifier) for identifier in delivery_ids],
        state__in=[BackgroundJob.State.PENDING, BackgroundJob.State.RUNNING],
    ).update(
        state=BackgroundJob.State.CANCELLED,
        completed_at=now,
        lease_owner=None,
        lease_expires_at=None,
        last_error=error_code.lower(),
        updated_at=now,
    )


def _installation_actor(
    installation: GitHubInstallation,
    *,
    request_id: uuid.UUID,
) -> ActorContext:
    return ActorContext(
        organization_id=installation.organization_id,
        actor_type="SERVICE",
        actor_id=str(installation.service_identity_id),
        authorization_path=f"github-installation:{installation.id}",
        request_id=request_id,
    )
