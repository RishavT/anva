"""Optional Compose acceptance test against the sibling anva-test corpus."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import pytest

from anva.core.models import (
    AccessScope,
    BackgroundJob,
    Membership,
    Organization,
    Repository,
    Role,
    SourceConnection,
    SourceDocument,
    SourceRevision,
    User,
)
from anva.core.services.context import ActorContext
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.jobs import claim_next_job

CORPUS_ROOT = Path(os.getenv("ANVA_TEST_CORPUS_ROOT", "/fixtures/anva-test"))


def _fingerprint(paths: list[Path]) -> dict[str, str]:
    return {
        str(path.relative_to(CORPUS_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


@pytest.mark.corpus
@pytest.mark.integration
@pytest.mark.django_db
@pytest.mark.skipif(not CORPUS_ROOT.exists(), reason="read-only anva-test corpus is not mounted")
def test_anva_test_corpus_ingests_without_mutation_or_execution() -> None:
    representative = [
        CORPUS_ROOT / ".github" / "CODEOWNERS",
        CORPUS_ROOT / ".github" / "workflows" / "ci.yml",
        CORPUS_ROOT / "openapi.yaml",
        CORPUS_ROOT / "pyproject.toml",
    ]
    assert all(path.is_file() for path in representative)
    assert os.statvfs(CORPUS_ROOT).f_flag & os.ST_RDONLY
    before = _fingerprint(representative)

    organization = Organization.objects.create(slug="external-corpus", name="External corpus")
    repository = Repository.objects.create(
        organization=organization,
        external_id="filesystem:anva-test",
        name="anva-test",
    )
    scope = AccessScope.objects.create(
        organization=organization,
        name="external corpus",
        all_memberships=True,
        all_repositories=True,
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Administrator",
    )
    user = User.objects.create(
        email="external-corpus@example.test",
        display_name="Corpus operator",
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
        authorization_path="untrusted-corpus-test",
        request_id=uuid.uuid4(),
        repository_id=repository.id,
    )
    source, _created = connect_filesystem_source(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        external_key="filesystem:anva-test",
        display_name="anva-test corpus",
        root=str(CORPUS_ROOT),
    )
    run, _created = request_ingestion_sync(
        actor=actor,
        source_connection_id=source.id,
    )
    job = claim_next_job(worker_id="corpus-worker", lease_seconds=3_600)
    assert job is not None

    result = execute_ingestion_job(job=job, worker_id="corpus-worker")

    assert result.discovered_count >= 100
    assert result.processed_count >= 90
    assert (
        SourceRevision.objects.filter(
            organization=organization,
            source_document__source_container__source_connection=source,
        ).count()
        >= 90
    )
    kinds = set(
        SourceDocument.objects.filter(
            organization=organization,
            source_container__source_connection=source,
        ).values_list("document_kind", flat=True)
    )
    assert {
        SourceDocument.Kind.CODEOWNERS,
        SourceDocument.Kind.WORKFLOW,
        SourceDocument.Kind.OPENAPI,
        SourceDocument.Kind.MANIFEST,
        SourceDocument.Kind.MARKDOWN,
        SourceDocument.Kind.MIGRATION,
    } <= kinds
    assert _fingerprint(representative) == before
    assert BackgroundJob.objects.get(id=job.id).state == BackgroundJob.State.RUNNING
    assert SourceConnection.objects.get(id=source.id).state == SourceConnection.State.ACTIVE
