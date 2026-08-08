"""Durable exact-head GitHub Check/comment publication integration tests."""

from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from django.db import close_old_connections, connections
from django.utils import timezone

from anva.contracts.catalog import EXAMPLES
from anva.core.models import (
    AccessScope,
    AssuranceRun,
    GitHubInstallation,
    GitHubPublication,
    GitHubRepositoryBinding,
    GitHubWriteAttempt,
    GitHubWriteIntent,
    Membership,
    Organization,
    OutboxEvent,
    PullRequest,
    Repository,
    Role,
    User,
    content_hash,
)
from anva.core.services.assurance import (
    claim_evaluator_task,
    ingest_manual_diff,
    start_assurance,
    submit_evaluator_result,
)
from anva.core.services.context import ActorContext
from anva.core.services.evaluators import FakeEvaluator, FakeScenario
from anva.core.services.policies import import_policy
from anva.integrations.github.client import (
    AmbiguousGitHubWriteError,
    FakeGitHubClient,
    GitHubRateLimitError,
    GitHubWriteResult,
    RepositoryReference,
)
from anva.integrations.github.publication import (
    claim_next_write,
    dispatch_next_write,
    queue_assurance_publications,
    queue_completed_assurance_publications,
)
from anva.integrations.github.service import (
    configure_repository_binding,
    reactivate_installation,
    revoke_repository_binding,
    suspend_installation,
)

REFERENCE_TIME = datetime(2026, 7, 30, 10, tzinfo=UTC)
MANUAL_DIFF = """diff --git a/src/payments.py b/src/payments.py
--- a/src/payments.py
+++ b/src/payments.py
@@ -1,1 +1,1 @@
-old
+new
"""


def _completed_bound_run() -> tuple[AssuranceRun, FakeGitHubClient]:
    organization = Organization.objects.create(
        slug=f"github-publication-{uuid.uuid4()}",
        name="GitHub publication",
    )
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"github:publication:{uuid.uuid4()}",
        name="Publication repository",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="Publication scope",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Org admin",
    )
    user = User.objects.create(
        email=f"github-publication-{uuid.uuid4()}@example.test",
        display_name="Publication admin",
    )
    Membership.objects.create(
        organization=organization,
        user=user,
        role=role,
    )
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="test",
        request_id=uuid.uuid4(),
    )
    policy_payload = deepcopy(EXAMPLES["policy"])
    policy_payload.update(
        {
            "organization_id": str(organization.id),
            "access_scope_id": str(scope.id),
            "policy_id": str(uuid.uuid4()),
            "version": 1,
            "effective_at": "2026-07-01T00:00:00Z",
        }
    )
    policy_payload["binding"]["repository_ids"] = [str(repository.id)]  # type: ignore[index]
    policy_payload["requirements"][0]["requirement_id"] = str(uuid.uuid4())  # type: ignore[index]
    policy_version = import_policy(actor=actor, payload=policy_payload).policy_version
    configure_repository_binding(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        installation_external_id=77001,
        account_id=99001,
        account_login="anva-publication",
        account_type="Organization",
        repository_selection="selected",
        permissions={
            "actions": "read",
            "checks": "write",
            "contents": "read",
            "issues": "write",
            "metadata": "read",
            "pull_requests": "read",
        },
        external_repository_id=88001,
        full_name="anva/publication",
        default_branch="main",
        is_private=True,
        is_archived=False,
        auto_assurance=False,
        policy_version_ids=[policy_version.id],
        work_item_revision_id=None,
    )
    ingested = ingest_manual_diff(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        pull_request_number=42,
        base_commit="a" * 40,
        head_commit="b" * 40,
        title="Production readiness",
        description="Review this untrusted pull-request body.",
        target_branch="main",
        is_draft=False,
        state=PullRequest.State.OPEN,
        unified_diff=MANUAL_DIFF,
    )
    evaluator = FakeEvaluator(FakeScenario.SUCCESS_WITH_ADVISORY)
    started = start_assurance(
        actor=actor,
        pull_request_revision_id=ingested.revision.id,
        policy_version_ids=[policy_version.id],
        reference_time=REFERENCE_TIME,
        deterministic_checks=[],
        evaluator_version=evaluator.version,
        prompt_version="github-publication-test",
        trigger_key="7" * 64,
    )
    reviewer_role = Role.objects.create(
        organization=organization,
        code=Role.Code.REVIEWER,
        name="Independent reviewer",
    )
    reviewer_user = User.objects.create(
        email=f"github-reviewer-{uuid.uuid4()}@example.test",
        display_name="Independent publication reviewer",
    )
    Membership.objects.create(
        organization=organization,
        user=reviewer_user,
        role=reviewer_role,
    )
    reviewer = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(reviewer_user.id),
        authorization_path="test-independent-reviewer",
        request_id=uuid.uuid4(),
    )
    claim = claim_evaluator_task(
        actor=reviewer,
        repository_id=repository.id,
        claimant="independent-reviewer",
    )
    assert claim is not None
    completion = submit_evaluator_result(
        actor=reviewer,
        task_id=started.evaluator_task.id,
        claimant="independent-reviewer",
        claim_token=claim.claim_token,
        result=evaluator.evaluate(claim.request),
    )
    return completion.run, FakeGitHubClient()


@pytest.mark.integration
@pytest.mark.django_db
def test_exact_head_queue_is_idempotent_bounded_and_secret_free() -> None:
    run, _fake = _completed_bound_run()
    queued = queue_assurance_publications(run_id=run.id)
    replay = queue_assurance_publications(run_id=run.id)

    assert queued.created_count == 2
    assert replay.created_count == 0
    assert {publication.kind for publication in queued.publications} == {
        GitHubPublication.Kind.CHECK,
        GitHubPublication.Kind.COMMENT,
    }
    assert all(publication.head_commit == run.head_commit for publication in queued.publications)
    assert GitHubPublication.objects.filter(is_current=True).count() == 2
    assert GitHubWriteIntent.objects.count() == 2
    check_intent = GitHubWriteIntent.objects.get(publication__kind=GitHubPublication.Kind.CHECK)
    check = cast(dict[str, object], check_intent.rendered_payload)
    output = cast(dict[str, object], check["output"])
    assert check["status"] == "completed"
    assert check["conclusion"] in {"success", "neutral", "failure"}
    assert run.head_commit in cast(str, output["summary"])
    assert len(cast(list[object], output["annotations"])) <= 50
    pull_request_revision = run.pull_request_revision
    assert pull_request_revision is not None
    comment = cast(
        dict[str, object],
        GitHubWriteIntent.objects.get(
            publication__kind=GitHubPublication.Kind.COMMENT
        ).rendered_payload,
    )
    assert cast(str, comment["body"]).startswith(
        f"<!-- anva:pr={pull_request_revision.pull_request_id} "
        f"report=assurance commit={run.head_commit} -->"
    )
    serialized = json.dumps(
        list(GitHubWriteIntent.objects.values("rendered_payload", "idempotency_key"))
    ).lower()
    assert "authorization" not in serialized
    assert "private_key" not in serialized
    assert "installation_token" not in serialized


@pytest.mark.integration
@pytest.mark.django_db
def test_ambiguous_write_is_adopted_and_rate_limit_is_persisted() -> None:
    run, fake = _completed_bound_run()
    queue_assurance_publications(run_id=run.id)
    dispatch_time = timezone.now() + timedelta(seconds=1)
    fake.queue_failure(
        "upsert_check",
        AmbiguousGitHubWriteError(request_id="ambiguous-request"),
        after_write=True,
    )
    pull_request_revision = run.pull_request_revision
    assert pull_request_revision is not None
    fake.add_human_comment(
        repository=RepositoryReference(88001, "anva/publication"),
        pull_request_number=42,
        body=(
            f"<!-- anva:pr={pull_request_revision.pull_request_id} "
            f"report=assurance commit={run.head_commit} -->\nspoof"
        ),
    )

    def factory(_installation_id: int) -> FakeGitHubClient:
        return fake

    first = dispatch_next_write(
        worker_id="github-worker-1",
        client_for_installation=factory,
        now=dispatch_time,
    )
    assert first is not None
    assert first.state == GitHubWriteIntent.State.RETRY
    second = dispatch_next_write(
        worker_id="github-worker-1",
        client_for_installation=factory,
        now=dispatch_time,
    )
    assert second is not None
    assert second.state == GitHubWriteIntent.State.SUCCEEDED
    third = dispatch_next_write(
        worker_id="github-worker-1",
        client_for_installation=factory,
        now=dispatch_time + timedelta(seconds=10),
    )
    assert third is not None
    assert third.state == GitHubWriteIntent.State.SUCCEEDED
    assert len(fake.checks) == 1
    assert (
        len(
            fake.app_comments(
                repository=RepositoryReference(88001, "anva/publication"),
                pull_request_number=42,
            )
        )
        == 1
    )
    assert GitHubWriteAttempt.objects.filter(outcome="RETRY").count() == 1
    assert GitHubWriteAttempt.objects.filter(outcome="SUCCEEDED").count() == 2

    # A same-head re-render is idempotent and cannot create another external object.
    assert queue_assurance_publications(run_id=run.id).created_count == 0

    # Exercise provider-directed backoff on a newly queued exact-head payload.
    comment_publication = GitHubPublication.objects.get(kind=GitHubPublication.Kind.COMMENT)
    # Existing payload remains consumed; rate-limit behavior is covered by a direct retry
    # on a fresh write intent created from its frozen payload.
    prior = GitHubWriteIntent.objects.get(publication=comment_publication)
    fresh_payload = {**cast(dict[str, object], prior.rendered_payload), "generation": 2}
    fresh_hash = content_hash(fresh_payload)
    fresh = GitHubWriteIntent.objects.create(
        organization=prior.organization,
        publication=comment_publication,
        assurance_run=prior.assurance_run,
        head_commit=prior.head_commit,
        rendered_payload=fresh_payload,
        payload_hash=fresh_hash,
        idempotency_key=f"github-write:{comment_publication.id}:{fresh_hash}",
    )
    OutboxEvent.objects.create(
        organization=prior.organization,
        aggregate_type="githubwriteintent",
        aggregate_id=fresh.id,
        event_type="github.write.requested",
        payload={
            "intent_id": str(fresh.id),
            "head_commit": fresh.head_commit,
            "payload_hash": fresh.payload_hash,
        },
        idempotency_key=f"outbox:{fresh.idempotency_key}",
    )
    fake.queue_failure(
        "upsert_comment",
        GitHubRateLimitError(retry_after_seconds=120, request_id="rate-request"),
    )
    limited = dispatch_next_write(
        worker_id="github-worker-1",
        client_for_installation=factory,
        now=dispatch_time + timedelta(seconds=20),
    )
    assert limited is not None
    assert limited.id == fresh.id
    assert limited.state == GitHubWriteIntent.State.RETRY
    assert limited.available_at == dispatch_time + timedelta(seconds=140)


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_concurrent_workers_claim_each_outbound_intent_at_most_once() -> None:
    run, _fake = _completed_bound_run()
    queued = queue_assurance_publications(run_id=run.id)
    assert len(queued.intents) == 2
    claim_time = timezone.now() + timedelta(seconds=1)
    selected = queued.intents[0]
    GitHubWriteIntent.objects.update(available_at=claim_time + timedelta(days=1))
    GitHubWriteIntent.objects.filter(id=selected.id).update(
        available_at=claim_time - timedelta(seconds=1)
    )
    barrier = threading.Barrier(4)

    def claim(worker_id: str) -> uuid.UUID | None:
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            intent = claim_next_write(worker_id=worker_id, now=claim_time)
            return intent.id if intent is not None else None
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=4) as executor:
        claimed = list(executor.map(claim, [f"github-worker-{index}" for index in range(4)]))

    assert [identifier for identifier in claimed if identifier is not None] == [selected.id]
    selected.refresh_from_db()
    assert selected.state == GitHubWriteIntent.State.RUNNING
    assert selected.attempt_count == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_revocation_retires_all_pending_writes_without_network() -> None:
    run, fake = _completed_bound_run()
    queue_assurance_publications(run_id=run.id)
    AssuranceRun.objects.filter(id=run.id).update(
        state=AssuranceRun.State.PUBLISHING,
        completed_at=None,
    )
    run.refresh_from_db()
    binding = GitHubRepositoryBinding.objects.get(repository=run.repository)

    revoke_repository_binding(binding=binding, request_id=uuid.uuid4())
    dispatched = dispatch_next_write(
        worker_id="github-worker-revoked",
        client_for_installation=lambda _installation_id: fake,
        now=timezone.now() + timedelta(seconds=1),
    )

    assert dispatched is None
    run.refresh_from_db()
    assert run.state == AssuranceRun.State.CANCELLED
    assert run.failure_code == "GITHUB_ACCESS_REVOKED"
    assert set(GitHubWriteIntent.objects.values_list("state", flat=True)) == {
        GitHubWriteIntent.State.CANCELLED
    }
    assert not GitHubPublication.objects.filter(is_current=True).exists()
    assert not OutboxEvent.objects.filter(
        aggregate_type="githubwriteintent",
        published_at__isnull=True,
    ).exists()
    assert fake.calls == []


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_suspension_drains_an_authorized_inflight_write_before_returning() -> None:
    run, _unused = _completed_bound_run()
    queued = queue_assurance_publications(run_id=run.id)
    check_intent = next(
        intent
        for intent in queued.intents
        if intent.publication.kind == GitHubPublication.Kind.CHECK
    )
    dispatch_time = timezone.now() + timedelta(seconds=1)
    GitHubWriteIntent.objects.update(available_at=dispatch_time + timedelta(days=1))
    GitHubWriteIntent.objects.filter(id=check_intent.id).update(
        available_at=dispatch_time - timedelta(seconds=1)
    )
    write_started = threading.Event()
    release_write = threading.Event()
    suspension_started = threading.Event()
    suspension_finished = threading.Event()
    failures: list[BaseException] = []

    class BlockingWriteClient(FakeGitHubClient):
        def upsert_check(
            self,
            *,
            repository: RepositoryReference,
            head_commit: str,
            check_name: str,
            payload: dict[str, object],
            external_id: str,
            idempotency_key: str,
        ) -> GitHubWriteResult:
            write_started.set()
            if not release_write.wait(timeout=10):
                raise TimeoutError("test did not release provider write")
            return super().upsert_check(
                repository=repository,
                head_commit=head_commit,
                check_name=check_name,
                payload=payload,
                external_id=external_id,
                idempotency_key=idempotency_key,
            )

    client = BlockingWriteClient()
    binding = GitHubRepositoryBinding.objects.get(repository=run.repository)
    installation_id = binding.installation_id

    def dispatch() -> None:
        close_old_connections()
        try:
            dispatch_next_write(
                worker_id="github-worker-suspend-race",
                client_for_installation=lambda _installation_id: client,
                now=dispatch_time,
            )
        except BaseException as error:
            failures.append(error)
        finally:
            connections.close_all()

    def suspend() -> None:
        close_old_connections()
        try:
            installation = GitHubInstallation.objects.get(id=installation_id)
            suspension_started.set()
            suspend_installation(
                installation=installation,
                request_id=uuid.uuid4(),
            )
            suspension_finished.set()
        except BaseException as error:
            failures.append(error)
        finally:
            connections.close_all()

    dispatch_worker = threading.Thread(target=dispatch)
    dispatch_worker.start()
    assert write_started.wait(timeout=10)
    suspension_worker = threading.Thread(target=suspend)
    suspension_worker.start()
    assert suspension_started.wait(timeout=10)
    assert not suspension_finished.wait(timeout=0.2)
    release_write.set()
    dispatch_worker.join(timeout=20)
    suspension_worker.join(timeout=20)

    assert not dispatch_worker.is_alive()
    assert not suspension_worker.is_alive()
    assert failures == []
    assert suspension_finished.is_set()
    assert len(client.checks) == 1
    assert (
        dispatch_next_write(
            worker_id="github-worker-after-suspend",
            client_for_installation=lambda _installation_id: client,
            now=dispatch_time + timedelta(days=2),
        )
        is None
    )
    check_intent.refresh_from_db()
    assert check_intent.state == GitHubWriteIntent.State.SUCCEEDED
    assert set(GitHubWriteIntent.objects.values_list("state", flat=True)) == {
        GitHubWriteIntent.State.SUCCEEDED,
        GitHubWriteIntent.State.CANCELLED,
    }


@pytest.mark.integration
@pytest.mark.django_db
def test_unsuspend_does_not_materialize_an_unqueued_pre_suspension_run() -> None:
    run, _fake = _completed_bound_run()
    binding = GitHubRepositoryBinding.objects.select_related("installation").get(
        repository=run.repository
    )

    suspend_installation(
        installation=binding.installation,
        request_id=uuid.uuid4(),
    )
    reactivate_installation(
        installation=binding.installation,
        request_id=uuid.uuid4(),
    )

    assert queue_assurance_publications(run_id=run.id).created_count == 0
    assert queue_completed_assurance_publications(limit=100) == 0
    assert not GitHubPublication.objects.filter(assurance_run=run).exists()
    assert not GitHubWriteIntent.objects.filter(assurance_run=run).exists()


@pytest.mark.integration
@pytest.mark.django_db
def test_new_head_before_claim_cancels_every_old_write_without_network() -> None:
    run, fake = _completed_bound_run()
    queue_assurance_publications(run_id=run.id)
    pull_request_revision = run.pull_request_revision
    assert pull_request_revision is not None
    PullRequest.objects.filter(
        id=pull_request_revision.pull_request_id,
    ).update(current_head_commit="c" * 40)

    def factory(_installation_id: int) -> FakeGitHubClient:
        return fake

    now = timezone.now() + timedelta(seconds=1)

    first = dispatch_next_write(
        worker_id="github-worker-stale",
        client_for_installation=factory,
        now=now,
    )
    second = dispatch_next_write(
        worker_id="github-worker-stale",
        client_for_installation=factory,
        now=now,
    )

    assert first is not None and first.state == GitHubWriteIntent.State.CANCELLED
    assert second is not None and second.state == GitHubWriteIntent.State.CANCELLED
    assert {first.last_error_code, second.last_error_code} == {"STALE_HEAD"}
    assert fake.calls == []
