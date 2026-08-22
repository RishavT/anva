"""Upgrade coverage for fail-closed evaluator selector bindings."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

PREVIOUS = ("core", "0023_acceptance_recovery")
TARGET = ("core", "0024_evaluator_claim_selector")


def _digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_0024_binds_ambiguous_existing_claims_fail_closed_and_is_reversible() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([PREVIOUS])
    old_apps = executor.loader.project_state([PREVIOUS]).apps
    organization_model = old_apps.get_model("core", "Organization")
    repository_model = old_apps.get_model("core", "Repository")
    access_scope_model = old_apps.get_model("core", "AccessScope")
    artifact_model = old_apps.get_model("core", "ImmutableArtifact")
    assurance_run_model = old_apps.get_model("core", "AssuranceRun")
    evaluator_task_model = old_apps.get_model("core", "EvaluatorTask")

    organization = organization_model.objects.create(
        slug=f"selector-migration-{uuid.uuid4()}",
        name="Selector migration",
    )
    repository = repository_model.objects.create(
        organization=organization,
        external_id=f"github:selector-migration/{uuid.uuid4()}",
        name="Selector migration repository",
    )
    access_scope = access_scope_model.objects.create(
        organization=organization,
        name="selector-migration-scope",
        all_memberships=True,
        all_repositories=True,
    )
    request_artifact = artifact_model.objects.create(
        organization=organization,
        access_scope=access_scope,
        kind="EVALUATOR_REQUEST",
        schema_name="assurance-evaluator-request",
        schema_version="1.0.0",
        payload={"request": "pre-selector-binding"},
        content_hash="a" * 64,
    )
    assurance_run = assurance_run_model.objects.create(
        organization=organization,
        repository_external_id=repository.external_id,
        initiated_by_actor_type="USER",
        initiated_by_actor_id="pre-selector-initiator",
        pull_request_number=1,
        head_commit="b" * 40,
        policy_version=1,
        repository=repository,
        input_hash="c" * 64,
        state="MODEL_REVIEW",
    )
    idempotency_digest = "d" * 64
    task = evaluator_task_model.objects.create(
        organization=organization,
        assurance_run=assurance_run,
        repository=repository,
        request_artifact=request_artifact,
        state="CLAIMED",
        claimant="pre-selector-reviewer",
        claimed_by_actor_type="USER",
        claimed_by_actor_id="pre-selector-reviewer-id",
        claim_idempotency_sha256=idempotency_digest,
        claim_token_hash="e" * 64,
        lease_expires_at=timezone.now() + timedelta(minutes=5),
        attempt_count=1,
    )

    unknown_digest = _digest({"mode": "PRE_SELECTOR_BINDING_UNKNOWN"})
    legacy_digest = _digest({"mode": "LEGACY"})
    exact_digest = _digest(
        {
            "mode": "EXACT",
            "task_id": str(task.id),
            "assurance_run_id": str(assurance_run.id),
            "input_hash": assurance_run.input_hash,
            "head_commit": assurance_run.head_commit,
        }
    )

    try:
        executor = MigrationExecutor(connection)
        executor.migrate([TARGET])
        target_apps = executor.loader.project_state([TARGET]).apps
        migrated_task = target_apps.get_model("core", "EvaluatorTask").objects.get(id=task.id)

        assert migrated_task.claim_selector_sha256 == unknown_digest
        assert migrated_task.claim_selector_sha256 != legacy_digest
        assert migrated_task.claim_selector_sha256 != exact_digest
        assert migrated_task.claim_idempotency_sha256 == idempotency_digest

        executor = MigrationExecutor(connection)
        executor.migrate([PREVIOUS])
        reversed_apps = executor.loader.project_state([PREVIOUS]).apps
        reversed_task = reversed_apps.get_model("core", "EvaluatorTask").objects.get(id=task.id)
        assert reversed_task.claim_idempotency_sha256 == idempotency_digest

        executor = MigrationExecutor(connection)
        executor.migrate([TARGET])
        reapplied_apps = executor.loader.project_state([TARGET]).apps
        rebound_task = reapplied_apps.get_model("core", "EvaluatorTask").objects.get(id=task.id)
        assert rebound_task.claim_selector_sha256 == unknown_digest
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
