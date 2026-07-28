"""Authoritative state transitions with audit, outbox, and tenant checks."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import cast

from django.db import transaction
from django.utils import timezone

from anva.core.exceptions import (
    InvalidStateTransitionError,
    OptimisticConcurrencyError,
    TenantBoundaryError,
)
from anva.core.models import (
    AssuranceRun,
    KnowledgeAssertion,
    KnowledgeProposal,
    RevisionedTenantModel,
    SyncRun,
)
from anva.core.services.artifacts import require_artifact_organization
from anva.core.services.authorization import get_tenant_record_for_update
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition

SYNC_TRANSITIONS: Mapping[str, frozenset[str]] = {
    SyncRun.State.REQUESTED: frozenset(
        {SyncRun.State.DISCOVERING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.DISCOVERING: frozenset(
        {SyncRun.State.FETCHING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.FETCHING: frozenset(
        {SyncRun.State.PARSING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.PARSING: frozenset(
        {SyncRun.State.INDEXING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.INDEXING: frozenset(
        {SyncRun.State.EXTRACTING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.EXTRACTING: frozenset(
        {SyncRun.State.RESOLVING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.RESOLVING: frozenset(
        {SyncRun.State.PUBLISHING, SyncRun.State.FAILED, SyncRun.State.CANCELLED}
    ),
    SyncRun.State.PUBLISHING: frozenset(
        {
            SyncRun.State.COMPLETED,
            SyncRun.State.PARTIALLY_COMPLETED,
            SyncRun.State.FAILED,
            SyncRun.State.CANCELLED,
        }
    ),
}

ASSERTION_TRANSITIONS: Mapping[str, frozenset[str]] = {
    KnowledgeAssertion.ReviewState.UNREVIEWED: frozenset(
        {
            KnowledgeAssertion.ReviewState.AUTO_ACCEPTED,
            KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
            KnowledgeAssertion.ReviewState.DISPUTED,
            KnowledgeAssertion.ReviewState.REJECTED,
            KnowledgeAssertion.ReviewState.STALE,
        }
    ),
    KnowledgeAssertion.ReviewState.AUTO_ACCEPTED: frozenset(
        {
            KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
            KnowledgeAssertion.ReviewState.DISPUTED,
            KnowledgeAssertion.ReviewState.SUPERSEDED,
            KnowledgeAssertion.ReviewState.STALE,
        }
    ),
    KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED: frozenset(
        {
            KnowledgeAssertion.ReviewState.DISPUTED,
            KnowledgeAssertion.ReviewState.SUPERSEDED,
            KnowledgeAssertion.ReviewState.STALE,
        }
    ),
    KnowledgeAssertion.ReviewState.DISPUTED: frozenset(
        {
            KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
            KnowledgeAssertion.ReviewState.REJECTED,
            KnowledgeAssertion.ReviewState.SUPERSEDED,
        }
    ),
    KnowledgeAssertion.ReviewState.REJECTED: frozenset({KnowledgeAssertion.ReviewState.SUPERSEDED}),
    KnowledgeAssertion.ReviewState.STALE: frozenset(
        {
            KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
            KnowledgeAssertion.ReviewState.SUPERSEDED,
        }
    ),
}

ASSURANCE_TRANSITIONS: Mapping[str, frozenset[str]] = {
    AssuranceRun.State.REQUESTED: frozenset(
        {
            AssuranceRun.State.DEBOUNCING,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.DEBOUNCING: frozenset(
        {
            AssuranceRun.State.FETCHING_PULL_REQUEST,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.FETCHING_PULL_REQUEST: frozenset(
        {
            AssuranceRun.State.COLLECTING_EVIDENCE,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.COLLECTING_EVIDENCE: frozenset(
        {
            AssuranceRun.State.EVALUATING_POLICY,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.EVALUATING_POLICY: frozenset(
        {
            AssuranceRun.State.BUILDING_CONTEXT,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.BUILDING_CONTEXT: frozenset(
        {
            AssuranceRun.State.MODEL_REVIEW,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.MODEL_REVIEW: frozenset(
        {
            AssuranceRun.State.MAPPING_EVIDENCE,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.MAPPING_EVIDENCE: frozenset(
        {
            AssuranceRun.State.RENDERING_REPORT,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.RENDERING_REPORT: frozenset(
        {
            AssuranceRun.State.PUBLISHING,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.PUBLISHING: frozenset(
        {
            AssuranceRun.State.COMPLETED,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
            AssuranceRun.State.STALE,
        }
    ),
    AssuranceRun.State.COMPLETED: frozenset({AssuranceRun.State.STALE}),
}

PROPOSAL_TRANSITIONS: Mapping[str, frozenset[str]] = {
    KnowledgeProposal.State.PROPOSED: frozenset(
        {KnowledgeProposal.State.VALIDATING, KnowledgeProposal.State.FAILED}
    ),
    KnowledgeProposal.State.VALIDATING: frozenset(
        {
            KnowledgeProposal.State.AWAITING_REVIEW,
            KnowledgeProposal.State.REJECTED,
            KnowledgeProposal.State.FAILED,
        }
    ),
    KnowledgeProposal.State.AWAITING_REVIEW: frozenset(
        {
            KnowledgeProposal.State.ACCEPTED,
            KnowledgeProposal.State.REJECTED,
            KnowledgeProposal.State.FAILED,
        }
    ),
    KnowledgeProposal.State.ACCEPTED: frozenset({KnowledgeProposal.State.SUPERSEDED}),
    KnowledgeProposal.State.REJECTED: frozenset({KnowledgeProposal.State.SUPERSEDED}),
}


def apply_transition(
    *,
    record: RevisionedTenantModel,
    actor: ActorContext,
    target_state: str,
    transitions: Mapping[str, frozenset[str]],
    expected_revision: int,
    state_field: str,
    metadata: dict[str, object] | None = None,
    extra_update_fields: list[str] | None = None,
) -> RevisionedTenantModel:
    """Apply one authorized edge to an already row-locked record."""
    if record.organization_id != actor.organization_id:
        raise TenantBoundaryError("Record belongs to another organization")
    current_state = cast(str, getattr(record, state_field))
    if current_state == target_state:
        return record
    if record.revision != expected_revision:
        raise OptimisticConcurrencyError(
            f"Expected revision {expected_revision}, found {record.revision}"
        )
    allowed = transitions.get(current_state, frozenset())
    if target_state not in allowed:
        raise InvalidStateTransitionError(current_state, target_state, allowed)

    setattr(record, state_field, target_state)
    record.revision += 1
    update_fields = [state_field, "revision", "updated_at", *(extra_update_fields or [])]
    record.save(update_fields=update_fields)
    record_transition(
        organization=record.organization,
        actor=actor,
        target_type=cast(str, record._meta.model_name),
        target_id=record.id,
        from_state=current_state,
        to_state=target_state,
        revision=record.revision,
        metadata=metadata,
    )
    return record


def transition_sync_run(
    *,
    actor: ActorContext,
    run_id: uuid.UUID,
    target_state: str,
    expected_revision: int,
    failure_code: str = "",
) -> SyncRun:
    """Transition one sync run and retain terminal history."""
    with transaction.atomic():
        run = get_tenant_record_for_update(
            queryset=SyncRun.objects.select_related("organization"),
            record_id=run_id,
            organization_id=actor.organization_id,
        )
        if run.state == target_state:
            return run
        terminal = target_state in {
            SyncRun.State.COMPLETED,
            SyncRun.State.PARTIALLY_COMPLETED,
            SyncRun.State.FAILED,
            SyncRun.State.CANCELLED,
        }
        run.completed_at = timezone.now() if terminal else None
        run.failure_code = failure_code
        return cast(
            SyncRun,
            apply_transition(
                record=run,
                actor=actor,
                target_state=target_state,
                transitions=SYNC_TRANSITIONS,
                expected_revision=expected_revision,
                state_field="state",
                metadata={"failure_code": failure_code} if failure_code else None,
                extra_update_fields=["completed_at", "failure_code"],
            ),
        )


def transition_assertion_review(
    *,
    actor: ActorContext,
    assertion_id: uuid.UUID,
    target_state: str,
    expected_revision: int,
) -> KnowledgeAssertion:
    """Review an assertion using optimistic concurrency."""
    with transaction.atomic():
        assertion = get_tenant_record_for_update(
            queryset=KnowledgeAssertion.objects.select_related("organization"),
            record_id=assertion_id,
            organization_id=actor.organization_id,
        )
        return cast(
            KnowledgeAssertion,
            apply_transition(
                record=assertion,
                actor=actor,
                target_state=target_state,
                transitions=ASSERTION_TRANSITIONS,
                expected_revision=expected_revision,
                state_field="review_state",
            ),
        )


def transition_assurance_run(
    *,
    actor: ActorContext,
    run_id: uuid.UUID,
    target_state: str,
    expected_revision: int,
    evaluated_commit: str | None = None,
    report_commit: str | None = None,
    context_artifact_id: uuid.UUID | None = None,
) -> AssuranceRun:
    """Transition assurance without allowing commit or tenant drift."""
    with transaction.atomic():
        run = get_tenant_record_for_update(
            queryset=AssuranceRun.objects.select_related("organization"),
            record_id=run_id,
            organization_id=actor.organization_id,
        )
        if run.state == target_state:
            return run
        if evaluated_commit is not None:
            run.evaluated_commit = evaluated_commit
        if report_commit is not None:
            run.report_commit = report_commit
        if context_artifact_id is not None:
            artifact = require_artifact_organization(context_artifact_id, actor.organization_id)
            run.context_artifact = artifact
        terminal = target_state in {
            AssuranceRun.State.COMPLETED,
            AssuranceRun.State.STALE,
            AssuranceRun.State.FAILED,
            AssuranceRun.State.CANCELLED,
        }
        run.completed_at = timezone.now() if terminal else None
        if target_state == AssuranceRun.State.COMPLETED and (
            run.evaluated_commit != run.head_commit or run.report_commit != run.head_commit
        ):
            raise InvalidStateTransitionError(
                str(run.state),
                target_state,
                frozenset({"evaluated_commit and report_commit must match head_commit"}),
            )
        return cast(
            AssuranceRun,
            apply_transition(
                record=run,
                actor=actor,
                target_state=target_state,
                transitions=ASSURANCE_TRANSITIONS,
                expected_revision=expected_revision,
                state_field="state",
                metadata={"head_commit": run.head_commit},
                extra_update_fields=[
                    "evaluated_commit",
                    "report_commit",
                    "context_artifact",
                    "completed_at",
                ],
            ),
        )


def transition_knowledge_proposal(
    *,
    actor: ActorContext,
    proposal_id: uuid.UUID,
    target_state: str,
    expected_revision: int,
) -> KnowledgeProposal:
    """Transition a proposal without directly changing approved knowledge."""
    with transaction.atomic():
        proposal = get_tenant_record_for_update(
            queryset=KnowledgeProposal.objects.select_related("organization"),
            record_id=proposal_id,
            organization_id=actor.organization_id,
        )
        if proposal.state == target_state:
            return proposal
        proposal.decided_at = (
            timezone.now()
            if target_state
            in {
                KnowledgeProposal.State.ACCEPTED,
                KnowledgeProposal.State.REJECTED,
                KnowledgeProposal.State.SUPERSEDED,
                KnowledgeProposal.State.FAILED,
            }
            else None
        )
        return cast(
            KnowledgeProposal,
            apply_transition(
                record=proposal,
                actor=actor,
                target_state=target_state,
                transitions=PROPOSAL_TRANSITIONS,
                expected_revision=expected_revision,
                state_field="state",
                extra_update_fields=["decided_at"],
            ),
        )
