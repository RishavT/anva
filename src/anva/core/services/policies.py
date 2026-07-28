"""Versioned deterministic policy import, matching, simulation, and overrides."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import cast

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from anva.contracts import validate_payload
from anva.core.exceptions import IdempotencyConflictError, ResourceNotFoundError
from anva.core.models import (
    AccessScope,
    KnowledgeEntity,
    Organization,
    Policy,
    PolicyBinding,
    PolicyEvaluation,
    PolicyOverride,
    PolicyOverrideRevocation,
    PolicyRequirement,
    PolicyVersion,
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
    reject_secrets,
    validate_full_commit,
    validate_relative_artifact_path,
)

POLICY_ENGINE_VERSION = "deterministic-policy-v1"
SCOPE_RANK: dict[str, int] = {
    PolicyBinding.ScopeLevel.ORGANIZATION: 0,
    PolicyBinding.ScopeLevel.PRODUCT: 1,
    PolicyBinding.ScopeLevel.SYSTEM: 2,
    PolicyBinding.ScopeLevel.REPOSITORY: 3,
    PolicyBinding.ScopeLevel.PATH: 4,
}


@dataclass(frozen=True, slots=True)
class PolicyImportResult:
    policy: Policy
    policy_version: PolicyVersion
    created: bool


def _uuid(payload: dict[str, object], key: str) -> uuid.UUID:
    return uuid.UUID(cast(str, payload[key]))


def _compile_path_pattern(pattern: str) -> re.Pattern[str]:
    """Compile the versioned POSIX glob grammar; single stars never cross `/`."""
    validate_relative_artifact_path(pattern)
    index = 0
    result = "^"
    while index < len(pattern):
        character = pattern[index]
        if character == "*" and index + 1 < len(pattern) and pattern[index + 1] == "*":
            result += ".*"
            index += 2
            continue
        if character == "*":
            result += "[^/]*"
        elif character == "?":
            result += "[^/]"
        else:
            result += re.escape(character)
        index += 1
    return re.compile(result + "$")


def path_pattern_matches(pattern: str, path: str) -> bool:
    """Match a safe repository-relative path using deterministic grammar."""
    validate_relative_artifact_path(path)
    return _compile_path_pattern(pattern).fullmatch(path) is not None


def _normalized_policy(payload: dict[str, object]) -> dict[str, object]:
    normalized = {
        key: value
        for key, value in payload.items()
        if key not in {"schema_version", "organization_id"}
    }
    binding = dict(cast(dict[str, object], payload["binding"]))
    for key in (
        "repository_ids",
        "entity_ids",
        "entity_types",
        "path_patterns",
        "work_item_types",
        "target_branches",
    ):
        binding[key] = sorted(cast(list[str], binding[key]))
    normalized["binding"] = binding
    requirements: list[dict[str, object]] = []
    for requirement in cast(list[dict[str, object]], payload["requirements"]):
        item = dict(requirement)
        for key in (
            "required_evidence",
            "required_reviewers",
            "report_sections",
        ):
            item[key] = sorted(cast(list[str], item[key]))
        requirements.append(item)
    normalized["requirements"] = sorted(
        requirements,
        key=lambda item: cast(str, item["code"]),
    )
    return normalized


@transaction.atomic
def import_policy(
    *,
    actor: ActorContext,
    payload: dict[str, object],
) -> PolicyImportResult:
    """Import an immutable policy version after central repository/scope authorization."""
    if len(canonical_payload_bytes(payload)) > 64 * 1024:
        raise ValueError("Policy import exceeds the 64 KiB limit")
    validate_payload("policy", payload)
    reject_secrets(payload)
    if _uuid(payload, "organization_id") != actor.organization_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    access_scope_id = _uuid(payload, "access_scope_id")
    binding_payload = cast(dict[str, object], payload["binding"])
    repository_ids = sorted(
        uuid.UUID(value) for value in cast(list[str], binding_payload["repository_ids"])
    )
    if actor.repository_id is not None and set(repository_ids) != {actor.repository_id}:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    authorization_repositories: list[uuid.UUID | None] = (
        list(repository_ids) if repository_ids else [actor.repository_id]
    )
    decisions = [
        authorize_action(
            actor=actor,
            action=Action.POLICY_MANAGE,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
        )
        for repository_id in authorization_repositories
    ]
    decision = decisions[-1]
    actor = replace(actor, authorization_path=decision.authorization_path)
    organization = Organization.objects.select_for_update().get(id=actor.organization_id)
    access_scope = get_tenant_record(
        queryset=AccessScope.objects.filter(is_active=True),
        record_id=access_scope_id,
        organization_id=actor.organization_id,
    )
    if repository_ids:
        found_ids = set(
            Repository.objects.filter(
                organization=organization,
                id__in=repository_ids,
                is_active=True,
            ).values_list("id", flat=True)
        )
        if found_ids != set(repository_ids):
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    for pattern in cast(list[str], binding_payload["path_patterns"]):
        _compile_path_pattern(pattern)
    entity_ids = {uuid.UUID(value) for value in cast(list[str], binding_payload["entity_ids"])}
    if entity_ids:
        visible_entity_ids = set(
            KnowledgeEntity.objects.filter(
                organization=organization,
                id__in=entity_ids,
                access_scope=access_scope,
                is_active=True,
            ).values_list("id", flat=True)
        )
        if visible_entity_ids != entity_ids:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    requirements_payload = cast(list[dict[str, object]], payload["requirements"])
    requirement_ids = [
        uuid.UUID(cast(str, item["requirement_id"])) for item in requirements_payload
    ]
    requirement_codes = [cast(str, item["code"]) for item in requirements_payload]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise ValueError("Policy requirement IDs must be unique")
    if len(requirement_codes) != len(set(requirement_codes)):
        raise ValueError("Policy requirement codes must be unique")

    policy_id = _uuid(payload, "policy_id")
    version_number = cast(int, payload["version"])
    normalized = _normalized_policy(payload)
    digest = content_hash(normalized)
    effective_at = datetime.fromisoformat(cast(str, payload["effective_at"]))
    expires_at = (
        datetime.fromisoformat(cast(str, payload["expires_at"]))
        if payload["expires_at"] is not None
        else None
    )
    if expires_at is not None and expires_at <= effective_at:
        raise ValueError("Policy expiry must be after effective_at")
    policy = (
        Policy.objects.select_for_update().filter(id=policy_id, organization=organization).first()
    )
    if policy is None:
        if version_number != 1:
            raise ValueError("The first policy version must be 1")
        policy = Policy.objects.create(
            id=policy_id,
            organization=organization,
            access_scope=access_scope,
            name=cast(str, payload["name"]),
            owner=cast(str, payload["owner"]),
            status=cast(str, payload["status"]),
            current_content_hash=digest,
        )
        previous_status = ""
    else:
        if policy.access_scope_id != access_scope.id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        existing = PolicyVersion.objects.filter(
            organization=organization,
            policy=policy,
            version=version_number,
        ).first()
        if existing is not None:
            if existing.content_hash != digest:
                raise IdempotencyConflictError(
                    "Policy version was reused with different normalized content"
                )
            return PolicyImportResult(policy, existing, False)
        if version_number != policy.revision + 1:
            raise ValueError("Policy versions must be sequential")
        previous_status = policy.status
        policy.revision = version_number
        policy.name = cast(str, payload["name"])
        policy.owner = cast(str, payload["owner"])
        policy.status = cast(str, payload["status"])
        policy.current_content_hash = digest
        policy.save(
            update_fields=[
                "revision",
                "name",
                "owner",
                "status",
                "current_content_hash",
                "updated_at",
            ]
        )

    version = PolicyVersion.objects.create(
        organization=organization,
        policy=policy,
        version=version_number,
        schema_version=cast(str, payload["schema_version"]),
        definition=normalized,
        content_hash=digest,
        effective_at=effective_at,
        expires_at=expires_at,
        created_by_type=actor.actor_type,
        created_by_id=actor.actor_id,
    )
    PolicyBinding.objects.create(
        organization=organization,
        policy_version=version,
        scope_level=cast(str, binding_payload["scope_level"]),
        mandatory=cast(bool, binding_payload["mandatory"]),
        repository_ids=binding_payload["repository_ids"],
        entity_ids=binding_payload["entity_ids"],
        entity_types=binding_payload["entity_types"],
        path_patterns=binding_payload["path_patterns"],
        work_item_types=binding_payload["work_item_types"],
        target_branches=binding_payload["target_branches"],
    )
    PolicyRequirement.objects.bulk_create(
        [
            PolicyRequirement(
                id=uuid.UUID(cast(str, item["requirement_id"])),
                organization=organization,
                policy_version=version,
                code=cast(str, item["code"]),
                description=cast(str, item["description"]),
                enforcement=cast(str, item["enforcement"]),
                check_type=cast(str, item["check_type"]),
                required_evidence=item["required_evidence"],
                required_reviewers=item["required_reviewers"],
                required_approval=cast(bool, item["required_approval"]),
                report_sections=item["report_sections"],
            )
            for item in requirements_payload
        ]
    )
    record_transition(
        organization=organization,
        actor=actor,
        target_type="policy",
        target_id=policy.id,
        from_state=previous_status,
        to_state=policy.status,
        revision=policy.revision,
        metadata={"content_hash": digest},
    )
    return PolicyImportResult(policy, version, True)


def _binding_matches(
    *,
    binding: PolicyBinding,
    repository_id: uuid.UUID,
    affected_paths: tuple[str, ...],
    affected_entities: tuple[tuple[str, str], ...],
    work_type: str | None,
    target_branch: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    dimensions: list[tuple[str, bool]] = []
    repository_ids = set(cast(list[str], binding.repository_ids))
    if repository_ids:
        dimensions.append(("repository", str(repository_id) in repository_ids))
    entity_ids = set(cast(list[str], binding.entity_ids))
    entity_types = set(cast(list[str], binding.entity_types))
    if entity_ids and entity_types:
        dimensions.append(
            (
                "entity",
                any(
                    entity_id in entity_ids and entity_type in entity_types
                    for entity_id, entity_type in affected_entities
                ),
            )
        )
    elif entity_ids:
        dimensions.append(
            ("entity_id", bool(entity_ids & {entity_id for entity_id, _ in affected_entities}))
        )
    elif entity_types:
        dimensions.append(
            ("entity_type", bool(entity_types & {kind for _, kind in affected_entities}))
        )
    patterns = cast(list[str], binding.path_patterns)
    if patterns:
        dimensions.append(
            (
                "path",
                any(
                    path_pattern_matches(pattern, path)
                    for pattern in patterns
                    for path in affected_paths
                ),
            )
        )
    work_types = set(cast(list[str], binding.work_item_types))
    if work_types:
        dimensions.append(("work_type", work_type in work_types))
    branches = set(cast(list[str], binding.target_branches))
    if branches:
        dimensions.append(("target_branch", target_branch in branches))
    for name, matched in dimensions:
        reasons.append(f"{name}:{'matched' if matched else 'not_matched'}")
    return all(matched for _, matched in dimensions), reasons


def _active_overrides(
    *,
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    pull_request_number: int,
    commit_sha: str,
    policy_version_ids: tuple[uuid.UUID, ...],
    reference_time: datetime,
) -> list[PolicyOverride]:
    return list(
        PolicyOverride.objects.filter(
            organization_id=organization_id,
            repository_id=repository_id,
            pull_request_number=pull_request_number,
            commit_sha=commit_sha,
            policy_version_id__in=policy_version_ids,
            created_at__lte=reference_time,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=reference_time))
        .exclude(
            policyoverriderevocation__revoked_at__lte=reference_time,
        )
        .order_by("id")
    )


@transaction.atomic
def evaluate_policy(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    pull_request_number: int,
    commit_sha: str,
    policy_version_ids: list[uuid.UUID],
    reference_time: datetime,
    affected_paths: list[str],
    affected_entities: list[dict[str, str]],
    target_branch: str,
    work_item_revision_id: uuid.UUID | None = None,
    is_simulation: bool = True,
) -> tuple[PolicyEvaluation, bool]:
    """Evaluate exact policy versions with deterministic additive semantics."""
    validate_full_commit(commit_sha)
    if not policy_version_ids or len(policy_version_ids) > 100:
        raise ValueError("Between 1 and 100 policy_version_ids are required")
    if len(policy_version_ids) != len(set(policy_version_ids)):
        raise ValueError("policy_version_ids must be unique")
    if pull_request_number < 1:
        raise ValueError("pull_request_number must be positive")
    if reference_time.tzinfo is None:
        raise ValueError("reference_time must include a timezone")
    if len(affected_paths) > 1_000 or len(affected_entities) > 1_000:
        raise ValueError("Evaluation input exceeds safety bounds")
    normalized_paths = tuple(sorted(set(affected_paths)))
    for path in normalized_paths:
        validate_relative_artifact_path(path)
    normalized_entities = tuple(
        sorted(
            {
                (str(uuid.UUID(item["id"])), item["type"])
                for item in affected_entities
                if set(item) == {"id", "type"}
            }
        )
    )
    if len(normalized_entities) != len(affected_entities):
        raise ValueError("affected_entities must contain unique id/type objects")
    if not target_branch or len(target_branch) > 300:
        raise ValueError("target_branch must be between 1 and 300 characters")

    authorize_action(
        actor=actor,
        action=Action.POLICY_VIEW,
        repository_id=repository_id,
    )
    authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=repository_id,
    )
    repository = get_tenant_record(
        queryset=Repository.objects.filter(is_active=True),
        record_id=repository_id,
        organization_id=actor.organization_id,
    )
    work_revision: WorkItemRevision | None = None
    work_type: str | None = None
    scope_ids: set[uuid.UUID] = set()
    if work_item_revision_id is not None:
        work_revision = get_tenant_record(
            queryset=WorkItemRevision.objects.select_related("work_item"),
            record_id=work_item_revision_id,
            organization_id=actor.organization_id,
        )
        if work_revision.work_item.repository_id != repository.id:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
        work_type = work_revision.work_type
        scope_ids.add(work_revision.work_item.access_scope_id)

    versions = list(
        PolicyVersion.objects.select_related("policy", "policybinding")
        .filter(
            id__in=policy_version_ids,
            organization_id=actor.organization_id,
            definition__status=Policy.Status.ACTIVE,
            effective_at__lte=reference_time,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=reference_time))
        .order_by("id")
    )
    if len(versions) != len(set(policy_version_ids)):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    for version in versions:
        authorize_action(
            actor=actor,
            action=Action.POLICY_VIEW,
            repository_id=repository.id,
            access_scope_id=version.policy.access_scope_id,
        )
        scope_ids.add(version.policy.access_scope_id)
    if len(scope_ids) != 1:
        raise ValueError(
            "MVP policy evaluation requires work and policies to share one access scope"
        )
    evaluation_scope_id = next(iter(scope_ids))
    evaluation_scope = get_tenant_record(
        queryset=AccessScope.objects.filter(is_active=True),
        record_id=evaluation_scope_id,
        organization_id=actor.organization_id,
    )
    decision = authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=repository.id,
        access_scope_id=evaluation_scope.id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    affected_entity_ids = {uuid.UUID(entity_id) for entity_id, _kind in normalized_entities}
    if affected_entity_ids:
        visible_entities = set(
            KnowledgeEntity.objects.filter(
                organization_id=actor.organization_id,
                id__in=affected_entity_ids,
                access_scope=evaluation_scope,
                is_active=True,
            ).values_list("id", "entity_type")
        )
        expected_entities = {
            (entity_id, entity_type) for entity_id, entity_type in normalized_entities
        }
        if {
            (str(entity_id), entity_type) for entity_id, entity_type in visible_entities
        } != expected_entities:
            raise ResourceNotFoundError(NOT_FOUND_MESSAGE)

    matched: list[tuple[PolicyVersion, PolicyBinding, list[str]]] = []
    considered: list[dict[str, object]] = []
    for version in versions:
        binding = version.policybinding
        applies, reasons = _binding_matches(
            binding=binding,
            repository_id=repository.id,
            affected_paths=normalized_paths,
            affected_entities=normalized_entities,
            work_type=work_type,
            target_branch=target_branch,
        )
        considered.append(
            {
                "policy_version_id": str(version.id),
                "binding_id": str(binding.id),
                "matched": applies,
                "reasons": reasons,
            }
        )
        if applies:
            matched.append((version, binding, reasons))
    matched.sort(key=lambda item: (SCOPE_RANK[item[1].scope_level], str(item[0].id)))

    exact_version_ids = tuple(version.id for version in versions)
    overrides = _active_overrides(
        organization_id=actor.organization_id,
        repository_id=repository.id,
        pull_request_number=pull_request_number,
        commit_sha=commit_sha,
        policy_version_ids=exact_version_ids,
        reference_time=reference_time,
    )
    override_keys = {
        (override.policy_version_id, override.requirement_code): override for override in overrides
    }
    controls: dict[str, dict[str, object]] = {}
    applied_overrides: list[dict[str, object]] = []
    for version, binding, _reasons in matched:
        requirements = PolicyRequirement.objects.filter(policy_version=version).order_by(
            "code",
            "id",
        )
        for requirement in requirements:
            source = {
                "policy_id": str(version.policy_id),
                "policy_version_id": str(version.id),
                "policy_version": version.version,
                "binding_id": str(binding.id),
                "scope_level": binding.scope_level,
                "mandatory": binding.mandatory,
                "requirement_id": str(requirement.id),
            }
            override = override_keys.get((version.id, requirement.code))
            if override is not None:
                applied_overrides.append(
                    {
                        "override_id": str(override.id),
                        "code": requirement.code,
                        "source": source,
                        "reason": override.reason,
                    }
                )
                continue
            control = controls.setdefault(
                requirement.code,
                {
                    "code": requirement.code,
                    "description": requirement.description,
                    "enforcement": requirement.enforcement,
                    "check_type": requirement.check_type,
                    "required_evidence": [],
                    "required_reviewers": [],
                    "required_approval": False,
                    "report_sections": [],
                    "sources": [],
                },
            )
            if control["check_type"] != requirement.check_type:
                raise ValueError(f"Incompatible policy check types for control {requirement.code}")
            if requirement.enforcement == PolicyRequirement.Enforcement.BLOCKING:
                control["enforcement"] = PolicyRequirement.Enforcement.BLOCKING
            for field, values in (
                ("required_evidence", requirement.required_evidence),
                ("required_reviewers", requirement.required_reviewers),
                ("report_sections", requirement.report_sections),
            ):
                control[field] = sorted(
                    set(cast(list[str], control[field])) | set(cast(list[str], values))
                )
            control["required_approval"] = bool(
                control["required_approval"] or requirement.required_approval
            )
            cast(list[dict[str, object]], control["sources"]).append(source)

    for control in controls.values():
        cast(list[dict[str, object]], control["sources"]).sort(
            key=lambda source: (
                SCOPE_RANK[cast(str, source["scope_level"])],
                cast(str, source["policy_version_id"]),
                cast(str, source["requirement_id"]),
            )
        )
    sorted_controls = sorted(controls.values(), key=lambda control: cast(str, control["code"]))
    applied_overrides.sort(key=lambda item: cast(str, item["override_id"]))
    considered.sort(key=lambda item: cast(str, item["policy_version_id"]))
    output: dict[str, object] = {
        "engine_version": POLICY_ENGINE_VERSION,
        "outcome": "CONTROLS_CALCULATED",
        "controls": sorted_controls,
        "matched_bindings": [
            {
                "policy_version_id": str(version.id),
                "binding_id": str(binding.id),
                "scope_level": binding.scope_level,
                "reasons": reasons,
            }
            for version, binding, reasons in matched
        ],
        "considered_bindings": considered,
        "applied_overrides": applied_overrides,
        "limitations": [],
        "reevaluation_conditions": [
            "commit_changed",
            "work_item_revision_changed",
            "policy_version_changed",
            "approval_or_override_changed",
            "evidence_or_retention_changed",
        ],
    }
    canonical_input: dict[str, object] = {
        "engine_version": POLICY_ENGINE_VERSION,
        "organization_id": str(actor.organization_id),
        "repository_id": str(repository.id),
        "pull_request_number": pull_request_number,
        "commit_sha": commit_sha,
        "work_item_revision_id": str(work_revision.id) if work_revision else None,
        "work_item_revision_hash": work_revision.content_hash if work_revision else None,
        "policy_versions": [
            {
                "id": str(version.id),
                "version": version.version,
                "content_hash": version.content_hash,
                "binding_id": str(version.policybinding.id),
            }
            for version in versions
        ],
        "active_override_ids": [str(override.id) for override in overrides],
        "reference_time": reference_time.isoformat(),
        "affected_paths": list(normalized_paths),
        "affected_entities": [
            {"id": entity_id, "type": entity_type} for entity_id, entity_type in normalized_entities
        ],
        "target_branch": target_branch,
        "is_simulation": is_simulation,
    }
    input_digest = content_hash(canonical_input)
    output_digest = content_hash(output)
    existing = PolicyEvaluation.objects.filter(
        organization_id=actor.organization_id,
        input_hash=input_digest,
    ).first()
    if existing is not None:
        if existing.output_hash != output_digest:
            raise IdempotencyConflictError(
                "Deterministic policy output changed for identical versioned input"
            )
        return existing, False
    evaluation = PolicyEvaluation.objects.create(
        organization_id=actor.organization_id,
        repository=repository,
        access_scope=evaluation_scope,
        work_item_revision=work_revision,
        pull_request_number=pull_request_number,
        commit_sha=commit_sha,
        reference_time=reference_time,
        is_simulation=is_simulation,
        input_payload=canonical_input,
        input_hash=input_digest,
        output_payload=output,
        output_hash=output_digest,
    )
    record_transition(
        organization=repository.organization,
        actor=actor,
        target_type="policyevaluation",
        target_id=evaluation.id,
        from_state="",
        to_state=cast(str, output["outcome"]),
        revision=1,
        metadata={"content_hash": output_digest, "repository_id": str(repository.id)},
    )
    return evaluation, True


@transaction.atomic
def create_policy_override(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    policy_id: uuid.UUID,
    policy_evaluation_id: uuid.UUID,
    policy_version_id: uuid.UUID,
    requirement_code: str,
    pull_request_number: int,
    commit_sha: str,
    reason: str,
    expires_at: datetime | None,
) -> tuple[PolicyOverride, bool]:
    """Create an immutable exception pinned to exact version/repository/PR/commit."""
    validate_full_commit(commit_sha)
    authorize_action(
        actor=actor,
        action=Action.POLICY_OVERRIDE,
        repository_id=repository_id,
    )
    evaluation = get_tenant_record(
        queryset=PolicyEvaluation.objects.select_related("repository", "access_scope"),
        record_id=policy_evaluation_id,
        organization_id=actor.organization_id,
    )
    version = get_tenant_record(
        queryset=PolicyVersion.objects.select_related("policy"),
        record_id=policy_version_id,
        organization_id=actor.organization_id,
    )
    if (
        evaluation.repository_id != repository_id
        or evaluation.pull_request_number != pull_request_number
        or evaluation.commit_sha != commit_sha
        or version.policy_id != policy_id
        or str(policy_version_id)
        not in {
            cast(str, item["id"])
            for item in cast(list[dict[str, object]], evaluation.input_payload["policy_versions"])
        }
        or not PolicyRequirement.objects.filter(
            policy_version=version,
            code=requirement_code,
        ).exists()
    ):
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if version.policy.access_scope_id != evaluation.access_scope_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    decision = authorize_action(
        actor=actor,
        action=Action.POLICY_OVERRIDE,
        repository_id=repository_id,
        access_scope_id=evaluation.access_scope_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    if not reason.strip():
        raise ValueError("Override reason is required")
    reject_secrets(reason)
    if expires_at is not None and (expires_at.tzinfo is None or expires_at <= timezone.now()):
        raise ValueError("Override expiry must be a future timezone-aware timestamp")
    identity = {
        "evaluation_id": str(evaluation.id),
        "policy_version_id": str(version.id),
        "repository_id": str(repository_id),
        "pull_request_number": pull_request_number,
        "commit_sha": commit_sha,
        "requirement_code": requirement_code,
        "actor_type": actor.actor_type,
        "actor_id": actor.actor_id,
        "reason": reason,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    idempotency_key = content_hash(identity)
    existing = PolicyOverride.objects.filter(
        organization_id=actor.organization_id,
        idempotency_key=idempotency_key,
    ).first()
    if existing is not None:
        return existing, False
    override = PolicyOverride.objects.create(
        organization_id=actor.organization_id,
        policy_evaluation=evaluation,
        policy_version=version,
        repository_id=repository_id,
        pull_request_number=pull_request_number,
        requirement_code=requirement_code,
        commit_sha=commit_sha,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        authority_path=actor.authorization_path,
        reason=reason,
        idempotency_key=idempotency_key,
        expires_at=expires_at,
    )
    record_transition(
        organization=evaluation.organization,
        actor=actor,
        target_type="policyoverride",
        target_id=override.id,
        from_state="",
        to_state="ACTIVE",
        revision=1,
    )
    return override, True


@transaction.atomic
def revoke_policy_override(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    policy_override_id: uuid.UUID,
    reason: str,
) -> tuple[PolicyOverrideRevocation, bool]:
    """Withdraw an override with an append-only, authority-checked record."""
    authorize_action(
        actor=actor,
        action=Action.POLICY_OVERRIDE,
        repository_id=repository_id,
    )
    override = get_tenant_record(
        queryset=PolicyOverride.objects.select_related(
            "repository",
            "policy_evaluation__access_scope",
            "policy_version__policy",
        ),
        record_id=policy_override_id,
        organization_id=actor.organization_id,
    )
    if override.repository_id != repository_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    if override.policy_version.policy.access_scope_id != override.policy_evaluation.access_scope_id:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    decision = authorize_action(
        actor=actor,
        action=Action.POLICY_OVERRIDE,
        repository_id=repository_id,
        access_scope_id=override.policy_evaluation.access_scope_id,
    )
    actor = replace(actor, authorization_path=decision.authorization_path)
    if not reason.strip():
        raise ValueError("Revocation reason is required")
    reject_secrets(reason)
    existing = PolicyOverrideRevocation.objects.filter(policy_override=override).first()
    if existing is not None:
        return existing, False
    revocation = PolicyOverrideRevocation.objects.create(
        organization_id=actor.organization_id,
        policy_override=override,
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        authority_path=actor.authorization_path,
        reason=reason,
    )
    record_transition(
        organization=override.organization,
        actor=actor,
        target_type="policyoverriderevocation",
        target_id=revocation.id,
        from_state="ACTIVE",
        to_state="REVOKED",
        revision=1,
    )
    return revocation, True
