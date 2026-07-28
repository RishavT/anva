"""Authoritative creation paths for governed records and their initial audit events."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import replace

from django.db import transaction
from django.utils import timezone

from anva.core.models import (
    AssuranceRun,
    KnowledgeAssertion,
    KnowledgeProposal,
    Organization,
    Repository,
    SourceConnection,
    SyncRun,
)
from anva.core.services.authorization import (
    Action,
    authorize_action,
    get_tenant_record_for_update,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.core.services.transitions import ASSURANCE_TRANSITIONS, apply_transition

ACTIVE_SYNC_STATES = (
    SyncRun.State.REQUESTED,
    SyncRun.State.DISCOVERING,
    SyncRun.State.FETCHING,
    SyncRun.State.PARSING,
    SyncRun.State.INDEXING,
    SyncRun.State.EXTRACTING,
    SyncRun.State.RESOLVING,
    SyncRun.State.PUBLISHING,
)

ACTIVE_ASSURANCE_STATES = (
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
)


def _organization_for_actor(actor: ActorContext) -> Organization:
    return Organization.objects.select_for_update().get(id=actor.organization_id)


def _record_created(
    *,
    organization: Organization,
    actor: ActorContext,
    target_type: str,
    target_id: uuid.UUID,
    initial_state: str,
    revision: int,
) -> None:
    record_transition(
        organization=organization,
        actor=actor,
        target_type=target_type,
        target_id=target_id,
        from_state="",
        to_state=initial_state,
        revision=revision,
    )


def request_sync_run(
    *,
    actor: ActorContext,
    source_connection_id: uuid.UUID,
) -> tuple[SyncRun, bool]:
    """Create one active run per source connection, returning an existing active run."""
    with transaction.atomic():
        decision = authorize_action(
            actor=actor,
            action=Action.SOURCE_SYNC,
            repository_id=actor.repository_id,
            source_connection_id=source_connection_id,
        )
        actor = replace(actor, authorization_path=decision.authorization_path)
        source_connection = get_tenant_record_for_update(
            queryset=SourceConnection.objects.all(),
            record_id=source_connection_id,
            organization_id=actor.organization_id,
        )
        organization = _organization_for_actor(actor)
        existing = (
            SyncRun.objects.select_for_update()
            .filter(
                organization=organization,
                source_connection=source_connection,
                state__in=ACTIVE_SYNC_STATES,
            )
            .first()
        )
        if existing is not None:
            return existing, False
        run = SyncRun.objects.create(
            organization=organization,
            source_connection=source_connection,
        )
        _record_created(
            organization=organization,
            actor=actor,
            target_type="syncrun",
            target_id=run.id,
            initial_state=run.state,
            revision=run.revision,
        )
        return run, True


def create_assertion(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID,
    subject_key: str,
    predicate: str,
    value: object,
    provenance: Sequence[dict[str, object]],
    is_inferred: bool = False,
) -> KnowledgeAssertion:
    """Create a provenance-bearing assertion without silently replacing another."""
    with transaction.atomic():
        decision = authorize_action(
            actor=actor,
            action=Action.KNOWLEDGE_REVIEW,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
        )
        actor = replace(actor, authorization_path=decision.authorization_path)
        if not provenance:
            raise ValueError("Assertion provenance must contain at least one source")
        organization = _organization_for_actor(actor)
        assertion = KnowledgeAssertion.objects.create(
            organization=organization,
            subject_key=subject_key,
            predicate=predicate,
            value=value,
            provenance=list(provenance),
            is_inferred=is_inferred,
            access_scope_id=access_scope_id,
        )
        _record_created(
            organization=organization,
            actor=actor,
            target_type="knowledgeassertion",
            target_id=assertion.id,
            initial_state=assertion.review_state,
            revision=assertion.revision,
        )
        return assertion


def request_assurance_run(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    pull_request_number: int,
    head_commit: str,
    policy_version: int,
) -> tuple[AssuranceRun, bool]:
    """Create the one summary for a head commit and stale active older heads."""
    with transaction.atomic():
        decision = authorize_action(
            actor=actor,
            action=Action.ASSURANCE_EXECUTE,
            repository_id=repository_id,
        )
        actor = replace(actor, authorization_path=decision.authorization_path)
        repository = get_tenant_record_for_update(
            queryset=Repository.objects.filter(is_active=True),
            record_id=repository_id,
            organization_id=actor.organization_id,
        )
        organization = _organization_for_actor(actor)
        existing = (
            AssuranceRun.objects.select_for_update()
            .filter(
                organization=organization,
                repository_external_id=repository.external_id,
                pull_request_number=pull_request_number,
                head_commit=head_commit,
            )
            .first()
        )
        if existing is not None:
            return existing, False

        now = timezone.now()
        older_runs = (
            AssuranceRun.objects.select_for_update()
            .filter(
                organization=organization,
                repository_external_id=repository.external_id,
                pull_request_number=pull_request_number,
                state__in=ACTIVE_ASSURANCE_STATES,
            )
            .order_by("created_at")
        )
        for older_run in older_runs:
            older_run.completed_at = now
            apply_transition(
                record=older_run,
                actor=actor,
                target_state=AssuranceRun.State.STALE,
                transitions=ASSURANCE_TRANSITIONS,
                expected_revision=older_run.revision,
                state_field="state",
                metadata={"superseded_by_head_commit": head_commit},
                extra_update_fields=["completed_at"],
            )

        run = AssuranceRun.objects.create(
            organization=organization,
            repository_external_id=repository.external_id,
            pull_request_number=pull_request_number,
            head_commit=head_commit,
            policy_version=policy_version,
        )
        _record_created(
            organization=organization,
            actor=actor,
            target_type="assurancerun",
            target_id=run.id,
            initial_state=run.state,
            revision=run.revision,
        )
        return run, True


def submit_knowledge_proposal(
    *,
    actor: ActorContext,
    summary: str,
    proposed_changes: Sequence[dict[str, object]],
    anva_sources: Sequence[dict[str, object]],
) -> KnowledgeProposal:
    """Submit a proposal without mutating accepted organizational knowledge."""
    if not proposed_changes:
        raise ValueError("A proposal must contain at least one change")
    if not anva_sources:
        raise ValueError("A proposal must cite at least one anva_sources entry")
    with transaction.atomic():
        organization = _organization_for_actor(actor)
        proposal = KnowledgeProposal.objects.create(
            organization=organization,
            summary=summary,
            proposed_changes=list(proposed_changes),
            anva_sources=list(anva_sources),
        )
        _record_created(
            organization=organization,
            actor=actor,
            target_type="knowledgeproposal",
            target_id=proposal.id,
            initial_state=proposal.state,
            revision=proposal.revision,
        )
        return proposal
