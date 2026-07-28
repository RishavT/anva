"""Nonexecuting evidence-manifest ingestion and deterministic criterion mapping."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, cast
from urllib.parse import parse_qsl, urlsplit

from django.db import transaction
from django.utils.dateparse import parse_datetime

from anva.contracts import validate_payload
from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AcceptanceCriterion,
    AccessScope,
    Approval,
    ApprovalRevocation,
    CriterionEvidence,
    Evidence,
    EvidenceManifest,
    EvidenceRetentionEvent,
    ImmutableArtifact,
    Organization,
    Repository,
    WorkItemRevision,
    canonical_payload_bytes,
    content_hash,
)
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.hostile_inputs import (
    is_secret_bearing_query_key,
    reject_secrets,
    validate_full_commit,
    validate_relative_artifact_path,
)

MAX_MANIFEST_BYTES = 64 * 1024
COMMAND_RESULT_KINDS = frozenset(
    {
        Evidence.Kind.TEST_RESULT,
        Evidence.Kind.BUILD_RESULT,
        Evidence.Kind.TYPECHECK_RESULT,
        Evidence.Kind.LINT_RESULT,
        Evidence.Kind.STATIC_ANALYSIS,
        Evidence.Kind.SECURITY_SCAN,
        Evidence.Kind.DEPENDENCY_SCAN,
        Evidence.Kind.MIGRATION_RESULT,
        Evidence.Kind.PERFORMANCE_RESULT,
        Evidence.Kind.ACCESSIBILITY_RESULT,
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceImportResult:
    manifest: EvidenceManifest
    evidence: tuple[Evidence, ...]
    created: bool


@dataclass(frozen=True, slots=True)
class CriterionMappingResult:
    """Idempotent mapping rows and whether this call created any history."""

    mappings: tuple[CriterionEvidence, ...]
    created: bool


def _uuid(payload: dict[str, object], key: str) -> uuid.UUID:
    return uuid.UUID(cast(str, payload[key]))


def _datetime(value: object, field: str) -> datetime:
    parsed = parse_datetime(cast(str, value))
    if parsed is None or parsed.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware ISO 8601 timestamp")
    return parsed


def _optional_datetime(value: object, field: str) -> datetime | None:
    return None if value is None else _datetime(value, field)


def validate_source_url(value: str | None) -> None:
    if value is None:
        return
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("source_url must be an HTTPS URL without user information")
    if any(
        is_secret_bearing_query_key(key)
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True)
    ):
        raise ValueError("source_url contains a secret-bearing query parameter")


def _validate_type_specific(
    *,
    entry: dict[str, Any],
    work_revision: WorkItemRevision | None,
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
) -> Approval | None:
    kind = cast(str, entry["kind"])
    status = cast(str, entry["status"])
    command = cast(str, entry["command"])
    if kind in COMMAND_RESULT_KINDS and not command.strip():
        raise ValueError(f"{kind} evidence requires a command")
    if (
        kind in {Evidence.Kind.SCREENSHOT, Evidence.Kind.VIDEO}
        and not cast(str, entry["scenario"]).strip()
    ):
        raise ValueError(f"{kind} evidence requires a scenario")
    if (
        kind in {Evidence.Kind.CONSOLE_LOG, Evidence.Kind.NETWORK_TRACE}
        and not cast(str, entry["environment"]).strip()
    ):
        raise ValueError(f"{kind} evidence requires an environment")

    approval_id = entry["approval_id"]
    if kind != Evidence.Kind.MANUAL_APPROVAL:
        if approval_id is not None:
            raise ValueError("approval_id is only valid for MANUAL_APPROVAL evidence")
        return None
    if approval_id is None or work_revision is None:
        raise ValueError("MANUAL_APPROVAL requires an exact work_item_revision_id")
    approval = get_tenant_record(
        queryset=Approval.objects.all(),
        record_id=uuid.UUID(cast(str, approval_id)),
        organization_id=organization_id,
    )
    completed_at = _datetime(entry["completed_at"], "completed_at")
    if (
        approval.repository_id != repository_id
        or approval.work_item_revision_id != work_revision.id
        or approval.status != Approval.Status.APPROVED
        or ApprovalRevocation.objects.filter(
            approval=approval,
            revoked_at__lte=completed_at,
        ).exists()
        or approval.decided_at > completed_at
        or (approval.expires_at is not None and approval.expires_at <= completed_at)
        or status != Evidence.Status.PASSED
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    criterion_codes = set(cast(list[str], entry["criterion_codes"]))
    if approval.target_kind == "ACCEPTANCE_CRITERION":
        if approval.target_key not in criterion_codes:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    elif approval.target_kind == "REQUIREMENT":
        if not AcceptanceCriterion.objects.filter(
            work_item_revision=work_revision,
            code__in=criterion_codes,
            requirement__code=approval.target_key,
        ).exists():
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    elif approval.target_kind == "WORK_ITEM_REVISION":
        if approval.target_key != str(work_revision.id):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    else:
        raise ValueError("Approval target kind cannot satisfy evidence")
    return approval


@transaction.atomic
def submit_evidence_manifest(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    pull_request_number: int,
    payload: dict[str, object],
) -> EvidenceImportResult:
    """Validate and materialize metadata only; never fetch, open, unpack, or execute."""
    if len(canonical_payload_bytes(payload)) > MAX_MANIFEST_BYTES:
        raise ValueError("Evidence manifest exceeds the 64 KiB limit")
    validate_payload("evidence-manifest", payload)
    reject_secrets(payload)
    commit_sha = cast(str, payload["commit_sha"])
    validate_full_commit(commit_sha)
    if (
        _uuid(payload, "organization_id") != actor.organization_id
        or _uuid(payload, "repository_id") != repository_id
        or cast(int, payload["pull_request_number"]) != pull_request_number
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    access_scope_id = _uuid(payload, "access_scope_id")
    decision = authorize_action(
        actor=actor,
        action=Action.EVIDENCE_SUBMIT,
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
    work_revision: WorkItemRevision | None = None
    raw_revision_id = payload["work_item_revision_id"]
    if raw_revision_id is not None:
        work_revision = get_tenant_record(
            queryset=WorkItemRevision.objects.select_related("work_item"),
            record_id=uuid.UUID(cast(str, raw_revision_id)),
            organization_id=actor.organization_id,
        )
        if (
            work_revision.work_item.repository_id != repository.id
            or work_revision.work_item.access_scope_id != access_scope.id
        ):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

    digest = content_hash(payload)
    manifest_id = _uuid(payload, "manifest_id")
    reused_manifest = EvidenceManifest.objects.filter(
        organization=organization,
        id=manifest_id,
    ).first()
    if reused_manifest is not None and reused_manifest.payload_hash != digest:
        raise IdempotencyConflictError("Evidence manifest ID was reused with different content")
    existing = EvidenceManifest.objects.filter(
        organization=organization,
        repository=repository,
        payload_hash=digest,
    ).first()
    if existing is not None:
        if existing.commit_sha != commit_sha or existing.pull_request_number != pull_request_number:
            raise IdempotencyConflictError(
                "Evidence manifest content identity conflicts with its target"
            )
        existing_records = tuple(Evidence.objects.filter(manifest=existing).order_by("id"))
        return EvidenceImportResult(existing, existing_records, False)

    entries = cast(list[dict[str, Any]], payload["entries"])
    evidence_ids = [uuid.UUID(cast(str, entry["evidence_id"])) for entry in entries]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("Evidence IDs must be unique within a manifest")
    evidence_identities = [
        (
            cast(str, entry["content_hash"]),
            cast(str, entry["kind"]),
            cast(str, entry["name"]),
        )
        for entry in entries
    ]
    if len(evidence_identities) != len(set(evidence_identities)):
        raise ValueError("Evidence content/kind/name identities must be unique")
    if Evidence.objects.filter(
        organization=organization,
        id__in=evidence_ids,
    ).exists():
        raise IdempotencyConflictError("Evidence ID was already used by another manifest")

    validated: list[tuple[dict[str, Any], Approval | None]] = []
    for entry in entries:
        if (
            entry["producer"] != payload["producer"]
            or entry["producer_version"] != payload["producer_version"]
        ):
            raise ValueError("Entry producer identity must match the manifest producer")
        validate_relative_artifact_path(cast(str, entry["artifact_reference"]))
        validate_source_url(cast(str | None, entry["source_url"]))
        started_at = _optional_datetime(entry["started_at"], "started_at")
        completed_at = _datetime(entry["completed_at"], "completed_at")
        retention_expires_at = _optional_datetime(
            entry["retention_expires_at"],
            "retention_expires_at",
        )
        if started_at is not None and completed_at < started_at:
            raise ValueError("Evidence completed_at cannot precede started_at")
        if retention_expires_at is not None and retention_expires_at <= completed_at:
            raise ValueError("Evidence retention must extend beyond completion")
        approval = _validate_type_specific(
            entry=entry,
            work_revision=work_revision,
            organization_id=organization.id,
            repository_id=repository.id,
        )
        validated.append((entry, approval))

    artifact = ImmutableArtifact.objects.create(
        organization=organization,
        access_scope=access_scope,
        kind=ImmutableArtifact.Kind.EVIDENCE_MANIFEST,
        schema_name="evidence-manifest",
        schema_version=cast(str, payload["schema_version"]),
        payload=payload,
        content_hash=digest,
    )
    manifest = EvidenceManifest.objects.create(
        id=manifest_id,
        organization=organization,
        repository=repository,
        access_scope=access_scope,
        artifact=artifact,
        work_item_revision=work_revision,
        pull_request_number=pull_request_number,
        commit_sha=commit_sha,
        schema_version=cast(str, payload["schema_version"]),
        producer=cast(str, payload["producer"]),
        producer_version=cast(str, payload["producer_version"]),
        producer_mode=cast(str, payload["producer_mode"]),
        payload_hash=digest,
        payload_size=len(canonical_payload_bytes(payload)),
    )
    records: list[Evidence] = []
    for entry, approval in validated:
        record = Evidence.objects.create(
            id=uuid.UUID(cast(str, entry["evidence_id"])),
            organization=organization,
            manifest=manifest,
            approval=approval,
            commit_sha=commit_sha,
            kind=entry["kind"],
            name=entry["name"],
            producer=entry["producer"],
            producer_version=entry["producer_version"],
            command=entry["command"],
            status=entry["status"],
            started_at=_optional_datetime(entry["started_at"], "started_at"),
            completed_at=_datetime(entry["completed_at"], "completed_at"),
            artifact_reference=entry["artifact_reference"],
            source_url=entry["source_url"] or "",
            content_hash=entry["content_hash"],
            limitations=entry["limitations"],
            criterion_codes=entry["criterion_codes"],
            retention_class=entry["retention_class"],
            retention_expires_at=_optional_datetime(
                entry["retention_expires_at"],
                "retention_expires_at",
            ),
            environment=entry["environment"],
            scenario=entry["scenario"],
        )
        EvidenceRetentionEvent.objects.create(
            organization=organization,
            evidence=record,
            state=Evidence.RetentionState.ACTIVE,
            reason="manifest_ingested",
            actor_type=actor.actor_type,
            actor_id=actor.actor_id,
        )
        records.append(record)
    record_transition(
        organization=organization,
        actor=actor,
        target_type="evidencemanifest",
        target_id=manifest.id,
        from_state="",
        to_state="INGESTED",
        revision=1,
        metadata={"content_hash": digest, "repository_id": str(repository.id)},
    )
    return EvidenceImportResult(manifest, tuple(records), True)


def _is_retained(evidence: Evidence, reference_time: datetime) -> bool:
    event = (
        EvidenceRetentionEvent.objects.filter(
            evidence=evidence,
            occurred_at__lte=reference_time,
        )
        .order_by("-occurred_at", "-id")
        .first()
    )
    return bool(
        event is not None
        and event.state == Evidence.RetentionState.ACTIVE
        and (
            evidence.retention_expires_at is None or evidence.retention_expires_at > reference_time
        )
    )


def _approval_applies_to_criterion(
    *,
    approval: Approval,
    criterion: AcceptanceCriterion,
    revision: WorkItemRevision,
) -> bool:
    if approval.target_kind == "WORK_ITEM_REVISION":
        return approval.target_key == str(revision.id)
    if approval.target_kind == "ACCEPTANCE_CRITERION":
        return approval.target_key == criterion.code
    requirement = criterion.requirement
    return (
        approval.target_kind == "REQUIREMENT"
        and requirement is not None
        and approval.target_key == requirement.code
    )


@transaction.atomic
def map_criterion_evidence(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    pull_request_number: int,
    work_item_revision_id: uuid.UUID,
    commit_sha: str,
    reference_time: datetime,
) -> CriterionMappingResult:
    """Map every exact criterion to eligible evidence or an explicit immutable gap."""
    validate_full_commit(commit_sha)
    if pull_request_number < 1:
        raise ValueError("pull_request_number must be positive")
    if reference_time.tzinfo is None:
        raise ValueError("reference_time must include a timezone")
    authorize_action(
        actor=actor,
        action=Action.EVIDENCE_VIEW,
        repository_id=repository_id,
    )
    authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=repository_id,
    )
    revision = get_tenant_record(
        queryset=WorkItemRevision.objects.select_related("work_item"),
        record_id=work_item_revision_id,
        organization_id=actor.organization_id,
    )
    if revision.work_item.repository_id != repository_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    authorize_action(
        actor=actor,
        action=Action.EVIDENCE_VIEW,
        repository_id=repository_id,
        access_scope_id=revision.work_item.access_scope_id,
    )
    decision = authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=repository_id,
        access_scope_id=revision.work_item.access_scope_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    criteria = (
        AcceptanceCriterion.objects.select_related("requirement")
        .filter(
            organization_id=actor.organization_id,
            work_item_revision=revision,
        )
        .order_by("position", "id")
    )
    exact_evidence = list(
        Evidence.objects.select_related("manifest", "approval")
        .filter(
            organization_id=actor.organization_id,
            manifest__repository_id=repository_id,
            manifest__pull_request_number=pull_request_number,
            manifest__work_item_revision=revision,
            commit_sha=commit_sha,
            status=Evidence.Status.PASSED,
        )
        .order_by("content_hash", "id")
    )
    other_commit_pairs = {
        (code, kind)
        for kind, codes in Evidence.objects.filter(
            organization_id=actor.organization_id,
            manifest__repository_id=repository_id,
            manifest__pull_request_number=pull_request_number,
            manifest__work_item_revision=revision,
        )
        .exclude(commit_sha=commit_sha)
        .filter(status=Evidence.Status.PASSED)
        .values_list("kind", "criterion_codes")
        for code in cast(list[str], codes)
    }
    mappings: list[CriterionEvidence] = []
    created_any = False
    for criterion in criteria:
        required_types = sorted(set(cast(list[str], criterion.required_evidence_types)))
        for required_type in required_types:
            candidates = [
                evidence
                for evidence in exact_evidence
                if criterion.code in cast(list[str], evidence.criterion_codes)
                and evidence.kind == required_type
                and evidence.completed_at <= reference_time
                and _is_retained(evidence, reference_time)
                and (
                    evidence.kind != Evidence.Kind.MANUAL_APPROVAL
                    or (
                        criterion.manual_approval_allowed
                        and evidence.approval is not None
                        and evidence.approval.work_item_revision_id == revision.id
                        and _approval_applies_to_criterion(
                            approval=evidence.approval,
                            criterion=criterion,
                            revision=revision,
                        )
                        and evidence.approval.decided_at <= reference_time
                        and (
                            evidence.approval.expires_at is None
                            or evidence.approval.expires_at > reference_time
                        )
                        and not ApprovalRevocation.objects.filter(
                            approval=evidence.approval,
                            revoked_at__lte=reference_time,
                        ).exists()
                    )
                )
            ]
            selected = candidates[0] if candidates else None
            gap_code = ""
            gap_description = ""
            if selected is None:
                if (criterion.code, required_type) in other_commit_pairs:
                    gap_code = "STALE_EVIDENCE_ONLY"
                    gap_description = "Evidence exists only for a different commit."
                else:
                    gap_code = "NO_ELIGIBLE_EVIDENCE"
                    gap_description = (
                        f"No eligible {required_type} evidence satisfies this criterion."
                    )
            mapping_input = {
                "criterion_id": str(criterion.id),
                "required_evidence_type": required_type,
                "target_commit": commit_sha,
                "pull_request_number": pull_request_number,
                "reference_time": reference_time.isoformat(),
                "mapping_engine": "criterion-evidence-v1",
            }
            identity = {
                **mapping_input,
                "evidence_id": str(selected.id) if selected else None,
                "gap_code": gap_code,
            }
            mapping_key = content_hash(identity)
            mapping, created = CriterionEvidence.objects.get_or_create(
                organization_id=actor.organization_id,
                mapping_key=mapping_key,
                defaults={
                    "access_scope_id": revision.work_item.access_scope_id,
                    "criterion": criterion,
                    "evidence": selected,
                    "target_commit": commit_sha,
                    "pull_request_number": pull_request_number,
                    "reference_time": reference_time,
                    "required_evidence_type": required_type,
                    "engine_version": "criterion-evidence-v1",
                    "input_hash": content_hash(mapping_input),
                    "classification": (
                        CriterionEvidence.Classification.DIRECT
                        if selected
                        else CriterionEvidence.Classification.GAP
                    ),
                    "assessment": (
                        CriterionEvidence.Assessment.SATISFIED
                        if selected
                        else CriterionEvidence.Assessment.GAP
                    ),
                    "verifier_type": actor.actor_type,
                    "verifier_id": actor.actor_id,
                    "limitations": selected.limitations if selected else [],
                    "confidence": 1.0 if selected else 0.0,
                    "gap_code": gap_code,
                    "gap_description": gap_description,
                },
            )
            created_any = created_any or created
            if created:
                record_transition(
                    organization=revision.organization,
                    actor=actor,
                    target_type="criterionevidence",
                    target_id=mapping.id,
                    from_state="",
                    to_state=mapping.assessment,
                    revision=1,
                )
            mappings.append(mapping)
    return CriterionMappingResult(tuple(mappings), created_any)
