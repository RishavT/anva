"""Fast checks for exact evaluator reviewer identity and credential matching."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import cast

from anva.core.models import EvaluatorTask
from anva.core.services.assurance import _task_reviewer_binding_matches
from anva.core.services.context import ActorContext


def _actor(*, actor_id: uuid.UUID, credential_id: uuid.UUID) -> ActorContext:
    return ActorContext(
        organization_id=uuid.uuid4(),
        actor_type="SERVICE",
        actor_id=str(actor_id),
        authorization_path=f"credential:{credential_id}",
        request_id=uuid.uuid4(),
        repository_id=uuid.uuid4(),
        credential_id=credential_id,
        credential_actions=frozenset({"assurance.review"}),
    )


def _task(*, reviewer_id: uuid.UUID | None, reviewer_token_id: uuid.UUID | None) -> EvaluatorTask:
    return cast(
        EvaluatorTask,
        SimpleNamespace(
            reviewer_service_identity_id=reviewer_id,
            reviewer_token_id=reviewer_token_id,
        ),
    )


def test_legacy_unbound_task_preserves_existing_actor_behavior() -> None:
    actor = _actor(actor_id=uuid.uuid4(), credential_id=uuid.uuid4())

    assert _task_reviewer_binding_matches(
        actor=actor,
        task=_task(reviewer_id=None, reviewer_token_id=None),
    )


def test_bound_task_requires_exact_service_identity_and_token_id() -> None:
    reviewer_id = uuid.uuid4()
    reviewer_token_id = uuid.uuid4()
    exact_actor = _actor(actor_id=reviewer_id, credential_id=reviewer_token_id)

    assert _task_reviewer_binding_matches(
        actor=exact_actor,
        task=_task(reviewer_id=reviewer_id, reviewer_token_id=reviewer_token_id),
    )
    assert not _task_reviewer_binding_matches(
        actor=_actor(actor_id=uuid.uuid4(), credential_id=reviewer_token_id),
        task=_task(reviewer_id=reviewer_id, reviewer_token_id=reviewer_token_id),
    )
    assert not _task_reviewer_binding_matches(
        actor=_actor(actor_id=reviewer_id, credential_id=uuid.uuid4()),
        task=_task(reviewer_id=reviewer_id, reviewer_token_id=reviewer_token_id),
    )


def test_partially_bound_task_fails_closed() -> None:
    reviewer_id = uuid.uuid4()
    reviewer_token_id = uuid.uuid4()
    actor = _actor(actor_id=reviewer_id, credential_id=reviewer_token_id)

    assert not _task_reviewer_binding_matches(
        actor=actor,
        task=_task(reviewer_id=reviewer_id, reviewer_token_id=None),
    )
    assert not _task_reviewer_binding_matches(
        actor=actor,
        task=_task(reviewer_id=None, reviewer_token_id=reviewer_token_id),
    )
