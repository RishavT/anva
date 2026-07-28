"""Authorization-order and non-disclosure tests for every state machine."""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
from django.utils import timezone

from anva.core.exceptions import ResourceNotFoundError
from anva.core.models import (
    AssuranceRun,
    KnowledgeAssertion,
    KnowledgeProposal,
    Organization,
    SourceConnection,
    SyncRun,
)
from anva.core.services.authorization import NOT_FOUND_MESSAGE
from anva.core.services.context import ActorContext
from anva.core.services.transitions import (
    transition_assertion_review,
    transition_assurance_run,
    transition_knowledge_proposal,
    transition_sync_run,
)


def actor_for(organization: Organization) -> ActorContext:
    return ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id="reviewer",
        authorization_path="rbac:reviewer",
        request_id=uuid.uuid4(),
    )


def hidden_error(operation: Callable[[], object]) -> tuple[type[Exception], str, str]:
    """Capture the intentionally identical foreign-or-missing error contract."""
    with pytest.raises(ResourceNotFoundError) as captured:
        operation()
    error = captured.value
    assert str(error) == NOT_FOUND_MESSAGE
    assert error.code == "resource_not_found"
    return type(error), error.code, str(error)


@pytest.mark.integration
@pytest.mark.django_db
def test_sync_transition_authorizes_before_every_return_or_validation() -> None:
    owner = Organization.objects.create(slug="sync-owner", name="Sync Owner")
    caller = Organization.objects.create(slug="sync-caller", name="Sync Caller")
    foreign_connection = SourceConnection.objects.create(
        organization=owner,
        external_key="github:owner/sync",
    )
    foreign_initial = SyncRun.objects.create(
        organization=owner,
        source_connection=foreign_connection,
    )
    foreign_terminal = SyncRun.objects.create(
        organization=owner,
        source_connection=foreign_connection,
        state=SyncRun.State.FAILED,
        failure_code="FETCH_FAILED",
        completed_at=timezone.now(),
    )
    actor = actor_for(caller)
    missing_id = uuid.uuid4()

    errors = [
        hidden_error(
            lambda: transition_sync_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=SyncRun.State.REQUESTED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_sync_run(
                actor=actor,
                run_id=foreign_terminal.id,
                target_state=SyncRun.State.FAILED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_sync_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=SyncRun.State.COMPLETED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_sync_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=SyncRun.State.DISCOVERING,
                expected_revision=999,
            )
        ),
        hidden_error(
            lambda: transition_sync_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=SyncRun.State.DISCOVERING,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_sync_run(
                actor=actor,
                run_id=missing_id,
                target_state=SyncRun.State.REQUESTED,
                expected_revision=1,
            )
        ),
    ]
    assert len(set(errors)) == 1

    own_connection = SourceConnection.objects.create(
        organization=caller,
        external_key="github:caller/sync",
    )
    own_run = SyncRun.objects.create(organization=caller, source_connection=own_connection)
    transitioned = transition_sync_run(
        actor=actor,
        run_id=own_run.id,
        target_state=SyncRun.State.DISCOVERING,
        expected_revision=1,
    )
    assert transitioned.state == SyncRun.State.DISCOVERING
    assert transitioned.revision == 2


@pytest.mark.integration
@pytest.mark.django_db
def test_assertion_transition_authorizes_before_every_return_or_validation() -> None:
    owner = Organization.objects.create(slug="assert-owner", name="Assertion Owner")
    caller = Organization.objects.create(slug="assert-caller", name="Assertion Caller")
    common = {
        "organization": owner,
        "subject_key": "service:checkout",
        "predicate": "owned_by",
        "value": {"team": "payments"},
        "provenance": [{"source_id": str(uuid.uuid4())}],
    }
    foreign_initial = KnowledgeAssertion.objects.create(**common)
    foreign_terminal = KnowledgeAssertion.objects.create(
        **common,
        review_state=KnowledgeAssertion.ReviewState.REJECTED,
    )
    actor = actor_for(caller)
    missing_id = uuid.uuid4()

    errors = [
        hidden_error(
            lambda: transition_assertion_review(
                actor=actor,
                assertion_id=foreign_initial.id,
                target_state=KnowledgeAssertion.ReviewState.UNREVIEWED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assertion_review(
                actor=actor,
                assertion_id=foreign_terminal.id,
                target_state=KnowledgeAssertion.ReviewState.REJECTED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assertion_review(
                actor=actor,
                assertion_id=foreign_initial.id,
                target_state=KnowledgeAssertion.ReviewState.SUPERSEDED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assertion_review(
                actor=actor,
                assertion_id=foreign_initial.id,
                target_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
                expected_revision=999,
            )
        ),
        hidden_error(
            lambda: transition_assertion_review(
                actor=actor,
                assertion_id=foreign_initial.id,
                target_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assertion_review(
                actor=actor,
                assertion_id=missing_id,
                target_state=KnowledgeAssertion.ReviewState.UNREVIEWED,
                expected_revision=1,
            )
        ),
    ]
    assert len(set(errors)) == 1

    own = KnowledgeAssertion.objects.create(
        organization=caller,
        subject_key="service:search",
        predicate="owned_by",
        value={"team": "platform"},
        provenance=[{"source_id": str(uuid.uuid4())}],
    )
    transitioned = transition_assertion_review(
        actor=actor,
        assertion_id=own.id,
        target_state=KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
        expected_revision=1,
    )
    assert transitioned.review_state == KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED
    assert transitioned.revision == 2


@pytest.mark.integration
@pytest.mark.django_db
def test_assurance_transition_authorizes_before_every_return_or_validation() -> None:
    owner = Organization.objects.create(slug="assure-owner", name="Assurance Owner")
    caller = Organization.objects.create(slug="assure-caller", name="Assurance Caller")
    foreign_initial = AssuranceRun.objects.create(
        organization=owner,
        repository_external_id="github:owner/repository",
        pull_request_number=7,
        head_commit="a" * 40,
        policy_version=1,
    )
    foreign_terminal = AssuranceRun.objects.create(
        organization=owner,
        repository_external_id="github:owner/repository",
        pull_request_number=7,
        head_commit="b" * 40,
        policy_version=1,
        state=AssuranceRun.State.FAILED,
        completed_at=timezone.now(),
    )
    actor = actor_for(caller)
    missing_id = uuid.uuid4()

    errors = [
        hidden_error(
            lambda: transition_assurance_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=AssuranceRun.State.REQUESTED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assurance_run(
                actor=actor,
                run_id=foreign_terminal.id,
                target_state=AssuranceRun.State.FAILED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assurance_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=AssuranceRun.State.PUBLISHING,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assurance_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=AssuranceRun.State.DEBOUNCING,
                expected_revision=999,
            )
        ),
        hidden_error(
            lambda: transition_assurance_run(
                actor=actor,
                run_id=foreign_initial.id,
                target_state=AssuranceRun.State.DEBOUNCING,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_assurance_run(
                actor=actor,
                run_id=missing_id,
                target_state=AssuranceRun.State.REQUESTED,
                expected_revision=1,
            )
        ),
    ]
    assert len(set(errors)) == 1

    own = AssuranceRun.objects.create(
        organization=caller,
        repository_external_id="github:caller/repository",
        pull_request_number=9,
        head_commit="c" * 40,
        policy_version=1,
    )
    transitioned = transition_assurance_run(
        actor=actor,
        run_id=own.id,
        target_state=AssuranceRun.State.DEBOUNCING,
        expected_revision=1,
    )
    assert transitioned.state == AssuranceRun.State.DEBOUNCING
    assert transitioned.revision == 2


@pytest.mark.integration
@pytest.mark.django_db
def test_proposal_transition_authorizes_before_every_return_or_validation() -> None:
    owner = Organization.objects.create(slug="proposal-owner", name="Proposal Owner")
    caller = Organization.objects.create(slug="proposal-caller", name="Proposal Caller")
    common = {
        "organization": owner,
        "summary": "Correct ownership",
        "proposed_changes": [{"operation": "CORRECT"}],
        "anva_sources": [{"source_id": str(uuid.uuid4())}],
    }
    foreign_initial = KnowledgeProposal.objects.create(**common)
    foreign_terminal = KnowledgeProposal.objects.create(
        **common,
        state=KnowledgeProposal.State.REJECTED,
        decided_at=timezone.now(),
    )
    actor = actor_for(caller)
    missing_id = uuid.uuid4()

    errors = [
        hidden_error(
            lambda: transition_knowledge_proposal(
                actor=actor,
                proposal_id=foreign_initial.id,
                target_state=KnowledgeProposal.State.PROPOSED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_knowledge_proposal(
                actor=actor,
                proposal_id=foreign_terminal.id,
                target_state=KnowledgeProposal.State.REJECTED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_knowledge_proposal(
                actor=actor,
                proposal_id=foreign_initial.id,
                target_state=KnowledgeProposal.State.ACCEPTED,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_knowledge_proposal(
                actor=actor,
                proposal_id=foreign_initial.id,
                target_state=KnowledgeProposal.State.VALIDATING,
                expected_revision=999,
            )
        ),
        hidden_error(
            lambda: transition_knowledge_proposal(
                actor=actor,
                proposal_id=foreign_initial.id,
                target_state=KnowledgeProposal.State.VALIDATING,
                expected_revision=1,
            )
        ),
        hidden_error(
            lambda: transition_knowledge_proposal(
                actor=actor,
                proposal_id=missing_id,
                target_state=KnowledgeProposal.State.PROPOSED,
                expected_revision=1,
            )
        ),
    ]
    assert len(set(errors)) == 1

    own = KnowledgeProposal.objects.create(
        organization=caller,
        summary="Add ownership",
        proposed_changes=[{"operation": "ADD"}],
        anva_sources=[{"source_id": str(uuid.uuid4())}],
    )
    transitioned = transition_knowledge_proposal(
        actor=actor,
        proposal_id=own.id,
        target_state=KnowledgeProposal.State.VALIDATING,
        expected_revision=1,
    )
    assert transitioned.state == KnowledgeProposal.State.VALIDATING
    assert transitioned.revision == 2
