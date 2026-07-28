"""Versioned work-item import and authority-checked approval operations."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, cast

from django.db import transaction
from django.utils import timezone

from anva.contracts import validate_payload
from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AcceptanceCriterion,
    AccessScope,
    Approval,
    ApprovalRevocation,
    Assumption,
    Decision,
    KnowledgeEntity,
    NonRequirement,
    Organization,
    Repository,
    Requirement,
    WorkItem,
    WorkItemRevision,
    WorkSummary,
    canonical_payload_bytes,
    content_hash,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.hostile_inputs import reject_secrets


@dataclass(frozen=True, slots=True)
class WorkImportResult:
    """Idempotent result of importing one exact normalized revision."""

    work_item: WorkItem
    work_item_revision: WorkItemRevision
    created: bool


def _uuid(payload: dict[str, object], key: str) -> uuid.UUID:
    return uuid.UUID(cast(str, payload[key]))


def _objects(payload: dict[str, object], key: str) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], payload[key])


def _normalized_work_payload(payload: dict[str, object]) -> dict[str, object]:
    """Remove envelope-only fields while preserving the author's statement ordering."""
    return {
        key: value
        for key, value in payload.items()
        if key not in {"schema_version", "organization_id"}
    }


def _validate_tenant_input(actor: ActorContext, payload: dict[str, object]) -> None:
    if _uuid(payload, "organization_id") != actor.organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)


def _validate_semantic_uniqueness(payload: dict[str, object]) -> None:
    """Reject schema-valid duplicates before they can surface as database errors."""
    for collection in (
        "requirements",
        "non_requirements",
        "assumptions",
        "acceptance_criteria",
        "decisions",
    ):
        codes = [cast(str, item["code"]) for item in _objects(payload, collection)]
        if len(codes) != len(set(codes)):
            raise ValueError(f"{collection} codes must be unique")
    summary_hashes = [
        content_hash(item["structured_data"]) for item in _objects(payload, "summaries")
    ]
    if len(summary_hashes) != len(set(summary_hashes)):
        raise ValueError("Work summaries must have unique structured content")


def _validate_required_approvals(payload: dict[str, object]) -> None:
    criteria_by_requirement: dict[str, list[dict[str, Any]]] = {}
    for criterion in _objects(payload, "acceptance_criteria"):
        requirement_code = cast(str | None, criterion["requirement_code"])
        if requirement_code is not None:
            criteria_by_requirement.setdefault(requirement_code, []).append(criterion)
    for requirement in _objects(payload, "requirements"):
        if not cast(bool, requirement["requires_approval"]):
            continue
        linked = criteria_by_requirement.get(cast(str, requirement["code"]), [])
        if not linked:
            raise ValueError("Approval-required requirements need an acceptance criterion")
        for criterion in linked:
            if not cast(bool, criterion["manual_approval_allowed"]) or (
                "MANUAL_APPROVAL" not in cast(list[str], criterion["required_evidence_types"])
            ):
                raise ValueError(
                    "Criteria for approval-required requirements must require "
                    "MANUAL_APPROVAL evidence"
                )


@transaction.atomic
def import_work_item(
    *,
    actor: ActorContext,
    payload: dict[str, object],
) -> WorkImportResult:
    """Persist an immutable complete revision after authorization and schema validation."""
    if len(canonical_payload_bytes(payload)) > 64 * 1024:
        raise ValueError("Work-item import exceeds the 64 KiB limit")
    validate_payload("work-item-import", payload)
    reject_secrets(payload)
    _validate_tenant_input(actor, payload)
    _validate_semantic_uniqueness(payload)
    _validate_required_approvals(payload)
    repository_id = _uuid(payload, "repository_id")
    access_scope_id = _uuid(payload, "access_scope_id")
    decision = authorize_action(
        actor=actor,
        action=Action.WORK_MANAGE,
        repository_id=repository_id,
        access_scope_id=access_scope_id,
    )
    if payload["status"] == WorkItem.Status.APPROVED:
        decision = authorize_action(
            actor=actor,
            action=Action.WORK_APPROVE,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
        )
    actor = replace(actor, authorization_path=decision.authorization_path)
    organization = Organization.objects.select_for_update().get(id=actor.organization_id)
    repository = get_tenant_record(
        queryset=Repository.objects.filter(is_active=True),
        record_id=repository_id,
        organization_id=actor.organization_id,
    )
    access_scope = get_tenant_record(
        queryset=AccessScope.objects.filter(is_active=True),
        record_id=access_scope_id,
        organization_id=actor.organization_id,
    )
    related_entity_ids = {
        uuid.UUID(value)
        for requirement in _objects(payload, "requirements")
        for value in cast(list[str], requirement["related_entity_ids"])
    }
    if related_entity_ids:
        visible_entity_ids = set(
            KnowledgeEntity.objects.filter(
                organization=organization,
                id__in=related_entity_ids,
                access_scope=access_scope,
                is_active=True,
            ).values_list("id", flat=True)
        )
        if visible_entity_ids != related_entity_ids:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

    work_item_id = _uuid(payload, "work_item_id")
    revision_number = cast(int, payload["revision"])
    normalized = _normalized_work_payload(payload)
    digest = content_hash(normalized)
    work_item = (
        WorkItem.objects.select_for_update()
        .filter(id=work_item_id, organization=organization)
        .first()
    )
    if work_item is None:
        if revision_number != 1:
            raise ValueError("The first work-item revision must be 1")
        work_item = WorkItem.objects.create(
            id=work_item_id,
            organization=organization,
            repository=repository,
            access_scope=access_scope,
            external_key=cast(str | None, payload["external_key"]),
            title=cast(str, payload["title"]),
            work_type=cast(str, payload["work_type"]),
            status=cast(str, payload["status"]),
            current_content_hash=digest,
        )
        previous_status = ""
    else:
        if work_item.repository_id != repository.id or work_item.access_scope_id != access_scope.id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        existing_revision = WorkItemRevision.objects.filter(
            organization=organization,
            work_item=work_item,
            revision=revision_number,
        ).first()
        if existing_revision is not None:
            if existing_revision.content_hash != digest:
                raise IdempotencyConflictError(
                    "Work-item revision was reused with different normalized content"
                )
            return WorkImportResult(work_item, existing_revision, False)
        if revision_number != work_item.revision + 1:
            raise ValueError("Work-item revisions must be sequential")
        previous_status = work_item.status
        work_item.revision = revision_number
        work_item.external_key = cast(str | None, payload["external_key"])
        work_item.title = cast(str, payload["title"])
        work_item.work_type = cast(str, payload["work_type"])
        work_item.status = cast(str, payload["status"])
        work_item.current_content_hash = digest
        work_item.save(
            update_fields=[
                "revision",
                "external_key",
                "title",
                "work_type",
                "status",
                "current_content_hash",
                "updated_at",
            ]
        )

    revision = WorkItemRevision.objects.create(
        organization=organization,
        work_item=work_item,
        revision=revision_number,
        title=cast(str, payload["title"]),
        work_type=cast(str, payload["work_type"]),
        status=cast(str, payload["status"]),
        summary=cast(str, payload["summary"]),
        origin=cast(str, payload["origin"]),
        source_references=payload["source_references"],
        normalized_payload=normalized,
        content_hash=digest,
        created_by_type=actor.actor_type,
        created_by_id=actor.actor_id,
    )
    requirements: dict[str, Requirement] = {}
    for position, item in enumerate(_objects(payload, "requirements"), start=1):
        requirement = Requirement.objects.create(
            organization=organization,
            work_item_revision=revision,
            position=position,
            code=item["code"],
            normalized_text=item["normalized_text"],
            origin=item["origin"],
            owner=item["owner"],
            status=item["status"],
            source_references=item["source_references"],
            related_entity_ids=item["related_entity_ids"],
            requires_approval=item["requires_approval"],
        )
        requirements[cast(str, item["code"])] = requirement
    NonRequirement.objects.bulk_create(
        [
            NonRequirement(
                organization=organization,
                work_item_revision=revision,
                position=position,
                code=item["code"],
                normalized_text=item["normalized_text"],
                rationale=item["rationale"],
            )
            for position, item in enumerate(
                _objects(payload, "non_requirements"),
                start=1,
            )
        ]
    )
    Assumption.objects.bulk_create(
        [
            Assumption(
                organization=organization,
                work_item_revision=revision,
                position=position,
                code=item["code"],
                normalized_text=item["normalized_text"],
                status=item["status"],
                validation_reference=item["validation_reference"],
            )
            for position, item in enumerate(_objects(payload, "assumptions"), start=1)
        ]
    )
    criteria: list[AcceptanceCriterion] = []
    for position, item in enumerate(_objects(payload, "acceptance_criteria"), start=1):
        requirement_code = cast(str | None, item["requirement_code"])
        if requirement_code is not None and requirement_code not in requirements:
            raise ValueError(f"Unknown requirement_code {requirement_code!r}")
        criteria.append(
            AcceptanceCriterion(
                organization=organization,
                work_item_revision=revision,
                position=position,
                requirement=requirements.get(requirement_code or ""),
                code=item["code"],
                normalized_text=item["normalized_text"],
                required_evidence_types=item["required_evidence_types"],
                manual_approval_allowed=item["manual_approval_allowed"],
            )
        )
    AcceptanceCriterion.objects.bulk_create(criteria)
    Decision.objects.bulk_create(
        [
            Decision(
                organization=organization,
                work_item_revision=revision,
                position=position,
                code=item["code"],
                title=item["title"],
                outcome=item["outcome"],
                rationale=item["rationale"],
                status=item["status"],
            )
            for position, item in enumerate(_objects(payload, "decisions"), start=1)
        ]
    )
    WorkSummary.objects.bulk_create(
        [
            WorkSummary(
                organization=organization,
                work_item_revision=revision,
                summary_type=item["summary_type"],
                structured_data=item["structured_data"],
                content_hash=content_hash(item["structured_data"]),
                producer=item["producer"],
            )
            for item in _objects(payload, "summaries")
        ]
    )
    record_transition(
        organization=organization,
        actor=actor,
        target_type="workitem",
        target_id=work_item.id,
        from_state=previous_status,
        to_state=work_item.status,
        revision=work_item.revision,
        metadata={"content_hash": digest, "repository_id": str(repository.id)},
    )
    return WorkImportResult(work_item, revision, True)


@transaction.atomic
def approve_work_item_revision(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    work_item_revision_id: uuid.UUID,
    status: str,
    target_kind: str,
    target_key: str,
    reason: str,
    expires_at: datetime | None = None,
) -> tuple[Approval, bool]:
    """Record an append-only approval bound to one exact work-item revision."""
    authorize_action(
        actor=actor,
        action=Action.WORK_APPROVE,
        repository_id=repository_id,
    )
    revision = get_tenant_record(
        queryset=WorkItemRevision.objects.select_related("work_item__repository"),
        record_id=work_item_revision_id,
        organization_id=actor.organization_id,
    )
    if revision.work_item.repository_id != repository_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    decision = authorize_action(
        actor=actor,
        action=Action.WORK_APPROVE,
        repository_id=repository_id,
        access_scope_id=revision.work_item.access_scope_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    if status not in Approval.Status.values:
        raise ValueError("Approval status is invalid")
    if not reason.strip():
        raise ValueError("Approval reason is required")
    reject_secrets(reason)
    if expires_at is not None and (expires_at.tzinfo is None or expires_at <= timezone.now()):
        raise ValueError("Approval expiry must be a future timezone-aware timestamp")
    if target_kind == "WORK_ITEM_REVISION":
        target_exists = target_key == str(revision.id)
    elif target_kind == "REQUIREMENT":
        target_exists = Requirement.objects.filter(
            work_item_revision=revision,
            code=target_key,
        ).exists()
    elif target_kind == "ACCEPTANCE_CRITERION":
        target_exists = AcceptanceCriterion.objects.filter(
            work_item_revision=revision,
            code=target_key,
        ).exists()
    elif target_kind == "DECISION":
        target_exists = Decision.objects.filter(
            work_item_revision=revision,
            code=target_key,
        ).exists()
    else:
        raise ValueError("Approval target_kind is invalid")
    if not target_exists:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    identity = {
        "revision_id": str(revision.id),
        "status": status,
        "target_kind": target_kind,
        "target_key": target_key,
        "actor_type": actor.actor_type,
        "actor_id": actor.actor_id,
        "reason": reason,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    idempotency_key = content_hash(identity)
    revision = get_tenant_record_for_update(
        queryset=WorkItemRevision.objects.select_related("work_item__repository"),
        record_id=revision.id,
        organization_id=actor.organization_id,
    )
    existing = Approval.objects.filter(
        organization_id=actor.organization_id,
        idempotency_key=idempotency_key,
    ).first()
    if existing is not None:
        return existing, False
    approval = Approval.objects.create(
        organization_id=actor.organization_id,
        work_item_revision=revision,
        repository_id=revision.work_item.repository_id,
        target_kind=target_kind,
        target_key=target_key,
        status=status,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        authority_action=Action.WORK_APPROVE.value,
        reason=reason,
        idempotency_key=idempotency_key,
        expires_at=expires_at,
    )
    record_transition(
        organization=revision.organization,
        actor=actor,
        target_type="approval",
        target_id=approval.id,
        from_state="",
        to_state=status,
        revision=1,
    )
    return approval, True


@transaction.atomic
def revoke_work_item_approval(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    approval_id: uuid.UUID,
    reason: str,
) -> tuple[ApprovalRevocation, bool]:
    """Withdraw an approval without rewriting the original authority decision."""
    authorize_action(
        actor=actor,
        action=Action.WORK_APPROVE,
        repository_id=repository_id,
    )
    approval = get_tenant_record(
        queryset=Approval.objects.select_related("work_item_revision__work_item"),
        record_id=approval_id,
        organization_id=actor.organization_id,
    )
    if approval.repository_id != repository_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    decision = authorize_action(
        actor=actor,
        action=Action.WORK_APPROVE,
        repository_id=repository_id,
        access_scope_id=approval.work_item_revision.work_item.access_scope_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    if not reason.strip():
        raise ValueError("Revocation reason is required")
    reject_secrets(reason)
    approval = get_tenant_record_for_update(
        queryset=Approval.objects.select_related("work_item_revision__work_item"),
        record_id=approval.id,
        organization_id=actor.organization_id,
    )
    existing = ApprovalRevocation.objects.filter(approval=approval).first()
    if existing is not None:
        return existing, False
    revocation = ApprovalRevocation.objects.create(
        organization_id=actor.organization_id,
        approval=approval,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        authority_path=actor.authorization_path,
        reason=reason,
    )
    record_transition(
        organization=approval.organization,
        actor=actor,
        target_type="approvalrevocation",
        target_id=revocation.id,
        from_state=approval.status,
        to_state="REVOKED",
        revision=1,
    )
    return revocation, True
