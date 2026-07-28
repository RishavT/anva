"""Authorization-owning wrappers around sensitive domain mutations."""

from __future__ import annotations

import uuid
from dataclasses import replace

from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import AssuranceRun, KnowledgeAssertion, Repository
from anva.core.services.authorization import (
    NOT_FOUND_MESSAGE,
    Action,
    authorize_action,
    get_tenant_record,
)
from anva.core.services.context import ActorContext
from anva.core.services.retrieval import get_authorized_assertion
from anva.core.services.transitions import transition_assertion_review, transition_assurance_run


def review_assertion(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    assertion_id: uuid.UUID,
    target_state: str,
    expected_revision: int,
) -> KnowledgeAssertion:
    """Review knowledge only after repository and assertion-scope authorization."""
    assertion = get_authorized_assertion(
        actor=actor,
        repository_id=repository_id,
        assertion_id=assertion_id,
        action=Action.KNOWLEDGE_REVIEW,
    )
    decision = authorize_action(
        actor=actor,
        action=Action.KNOWLEDGE_REVIEW,
        repository_id=repository_id,
        access_scope_id=assertion.access_scope_id,
    )
    authorized_actor = replace(actor, authorization_path=decision.authorization_path)
    return transition_assertion_review(
        actor=authorized_actor,
        assertion_id=assertion.id,
        target_state=target_state,
        expected_revision=expected_revision,
    )


def authorize_sensitive_placeholder(
    *,
    actor: ActorContext,
    repository_id: uuid.UUID,
    action: Action,
) -> str:
    """Authorize a future finding or policy mutation without pretending to perform it."""
    return authorize_action(
        actor=actor,
        action=action,
        repository_id=repository_id,
    ).authorization_path


def execute_assurance_transition(
    *,
    actor: ActorContext,
    run_id: uuid.UUID,
    target_state: str,
    expected_revision: int,
    evaluated_commit: str | None = None,
    report_commit: str | None = None,
    context_artifact_id: uuid.UUID | None = None,
) -> AssuranceRun:
    """Authorize the repository before invoking the internal assurance state machine."""
    run = get_tenant_record(
        queryset=AssuranceRun.objects.all(),
        record_id=run_id,
        organization_id=actor.organization_id,
    )
    repository = Repository.objects.filter(
        organization_id=actor.organization_id,
        external_id=run.repository_external_id,
        is_active=True,
    ).first()
    if repository is None:
        raise ResourceNotFoundError(NOT_FOUND_MESSAGE)
    decision = authorize_action(
        actor=actor,
        action=Action.ASSURANCE_EXECUTE,
        repository_id=repository.id,
    )
    authorized_actor = replace(actor, authorization_path=decision.authorization_path)
    return transition_assurance_run(
        actor=authorized_actor,
        run_id=run.id,
        target_state=target_state,
        expected_revision=expected_revision,
        evaluated_commit=evaluated_commit,
        report_commit=report_commit,
        context_artifact_id=context_artifact_id,
    )
