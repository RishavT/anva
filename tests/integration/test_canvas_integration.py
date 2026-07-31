"""Database-backed authorization and mutation coverage for Organizational Canvas."""

from __future__ import annotations

import json
import math
import os
import platform
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from anva.core.exceptions import (
    IdempotencyConflictError,
    OptimisticConcurrencyError,
    ResourceNotFoundError,
)
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AccessScopeMembership,
    CanvasNodePlacement,
    CanvasView,
    CanvasViewRevision,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeRelationship,
    Membership,
    Organization,
    Repository,
    Role,
    ServiceIdentity,
    SourceConnection,
    User,
)
from anva.core.services.authorization import Action
from anva.core.services.canvas import (
    CanvasQuery,
    _canvas_payload_size,
    canvas_entity_detail,
    canvas_path,
    canvas_projection,
    create_canvas_share,
    create_canvas_view,
    list_canvas_views,
    propose_canvas_relationship,
    resolve_canvas_share,
    save_canvas_revision,
)
from anva.core.services.context import ActorContext
from anva.core.services.ingestion import (
    connect_filesystem_source,
    execute_ingestion_job,
    request_ingestion_sync,
)
from anva.core.services.jobs import claim_next_job, complete_job
from anva.core.services.tokens import issue_bootstrap_repository_token

PERFORMANCE_ROOT = Path("docs/evidence/issue-012/performance")


def _metric_summary(samples: list[float]) -> dict[str, object]:
    ordered = sorted(samples)
    percentile_95 = ordered[math.ceil(len(ordered) * 0.95) - 1]
    middle = len(ordered) // 2
    percentile_50 = (ordered[middle - 1] + ordered[middle]) / 2
    return {
        "raw": [round(value, 3) for value in samples],
        "p50": round(percentile_50, 3),
        "p95": round(percentile_95, 3),
        "max": round(max(samples), 3),
        "sample_count": len(samples),
    }


def _cpu_model() -> str:
    for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("model name"):
            return line.partition(":")[2].strip()
    return "unavailable"


def _tenant(*, slug: str = "canvas") -> tuple[Organization, Repository, ActorContext, User]:
    organization = Organization.objects.create(slug=slug, name=f"{slug} organization")
    repository = Repository.objects.create(
        organization=organization,
        external_id=f"filesystem:{slug}:one",
        name=f"{slug}-one",
    )
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.ORG_ADMIN,
        name="Organization administrator",
    )
    user = User.objects.create(
        email=f"admin-{slug}@example.test",
        display_name="Canvas Administrator",
    )
    Membership.objects.create(organization=organization, user=user, role=role)
    actor = ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="test:canvas",
        request_id=uuid.uuid4(),
    )
    return organization, repository, actor, user


def _viewer(
    *, organization: Organization, membership_scope: AccessScope, label: str
) -> ActorContext:
    role = Role.objects.create(
        organization=organization,
        code=Role.Code.VIEWER,
        name="Viewer",
    )
    user = User.objects.create(
        email=f"{label}@example.test",
        display_name=label,
    )
    membership = Membership.objects.create(organization=organization, user=user, role=role)
    AccessScopeMembership.objects.create(
        organization=organization,
        access_scope=membership_scope,
        membership=membership,
    )
    return ActorContext(
        organization_id=organization.id,
        actor_type="USER",
        actor_id=str(user.id),
        authorization_path="test:canvas-viewer",
        request_id=uuid.uuid4(),
    )


def _ingest(
    *,
    actor: ActorContext,
    repository: Repository,
    scope: AccessScope,
    root: Path,
    key: str,
) -> SourceConnection:
    source, created = connect_filesystem_source(
        actor=actor,
        repository_id=repository.id,
        access_scope_id=scope.id,
        external_key=f"filesystem:{key}",
        display_name=key,
        root=str(root),
    )
    assert created
    run, created = request_ingestion_sync(actor=actor, source_connection_id=source.id)
    assert created
    job = claim_next_job(worker_id=f"canvas-{key}", lease_seconds=600)
    assert job is not None
    completed = execute_ingestion_job(job=job, worker_id=f"canvas-{key}")
    complete_job(
        actor=ActorContext(
            organization_id=actor.organization_id,
            actor_type="SERVICE",
            actor_id=f"canvas-{key}",
            authorization_path="internal:test-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=job.id,
        worker_id=f"canvas-{key}",
    )
    assert completed.state in {completed.State.COMPLETED, completed.State.PARTIALLY_COMPLETED}
    source.refresh_from_db()
    return source


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_unions_only_strict_per_repository_authorized_graphs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository_one, admin, _user = _tenant(slug="canvas-union")
    repository_two = Repository.objects.create(
        organization=organization,
        external_id="filesystem:canvas-union:two",
        name="canvas-two",
    )
    public_scope = AccessScope.objects.create(
        organization=organization,
        name="public canvas",
        all_repositories=True,
    )
    viewer = _viewer(
        organization=organization,
        membership_scope=public_scope,
        label="canvas-limited-viewer",
    )
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    hidden_root = tmp_path / "hidden"
    first_root.mkdir()
    second_root.mkdir()
    hidden_root.mkdir()
    (first_root / "service.json").write_text(
        json.dumps({"service": "payments", "owner": "platform"})
    )
    (second_root / "service.json").write_text(
        json.dumps({"service": "catalog", "owner": "commerce"})
    )
    (hidden_root / "service.json").write_text(
        json.dumps(
            {
                "service": "CANARY-HIDDEN-ACQUISITION",
                "owner": "CANARY-HIDDEN-EXECUTIVE",
            }
        )
    )
    _ingest(
        actor=admin,
        repository=repository_one,
        scope=public_scope,
        root=first_root,
        key="canvas-public-one",
    )
    _ingest(
        actor=admin,
        repository=repository_two,
        scope=public_scope,
        root=second_root,
        key="canvas-public-two",
    )

    before = canvas_projection(actor=viewer, query=CanvasQuery())
    repositories = cast(list[dict[str, object]], before["repositories"])
    assert {row["name"] for row in repositories} == {
        "canvas-union-one",
        "canvas-two",
    }
    assert before["nodes"]
    assert before["edges"]

    hidden_scope = AccessScope.objects.create(
        organization=organization,
        name="hidden executive canvas",
        all_repositories=True,
    )
    _ingest(
        actor=admin,
        repository=repository_one,
        scope=hidden_scope,
        root=hidden_root,
        key="canvas-hidden",
    )
    after = canvas_projection(actor=viewer, query=CanvasQuery())

    for key in ("nodes", "edges", "counts", "truncated", "limitations", "layout"):
        assert after[key] == before[key]
    assert "CANARY" not in json.dumps(after, sort_keys=True)
    hidden_id = KnowledgeEntity.objects.get(
        organization=organization,
        canonical_key__contains="CANARY-HIDDEN-ACQUISITION",
    ).id
    nodes = cast(list[dict[str, object]], before["nodes"])
    public_id = uuid.UUID(str(nodes[0]["id"]))
    with pytest.raises(ResourceNotFoundError):
        canvas_path(actor=viewer, source_id=public_id, target_id=hidden_id)


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_is_deterministic_and_hard_caps_authorized_nodes() -> None:
    organization, repository, actor, _user = _tenant(slug="canvas-cap")
    scope = AccessScope.objects.create(
        organization=organization,
        name="all canvas nodes",
        all_memberships=True,
        all_repositories=True,
    )
    KnowledgeEntity.objects.bulk_create(
        [
            KnowledgeEntity(
                organization=organization,
                entity_type=KnowledgeEntity.EntityType.COMPONENT,
                canonical_key=f"component:{index:03d}",
                display_name=f"Component {index:03d}",
                access_scope=scope,
            )
            for index in reversed(range(305))
        ]
    )

    started = time.perf_counter()
    first = canvas_projection(
        actor=actor,
        query=CanvasQuery(repository_ids=(repository.id,)),
    )
    elapsed = time.perf_counter() - started
    second = canvas_projection(
        actor=actor,
        query=CanvasQuery(repository_ids=(repository.id,)),
    )

    assert first["counts"] == {"nodes": 300, "edges": 0}
    assert first["truncated"] is True
    assert first["nodes"] == second["nodes"]
    assert first["layout"] == second["layout"]
    assert any("capped at 300" in message for message in cast(list[str], first["limitations"]))
    assert _canvas_payload_size(first) <= 750 * 1024
    assert elapsed < 5


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_performance_report_has_30_warm_strict_samples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_FILESYSTEM_ALLOWED_ROOTS", str(tmp_path))
    organization, repository, actor, _user = _tenant(slug="canvas-performance")
    scope = AccessScope.objects.create(
        organization=organization,
        name="performance scope",
        all_memberships=True,
        all_repositories=True,
    )
    source_root = tmp_path / "strict-source"
    source_root.mkdir()
    (source_root / "service.json").write_text(
        json.dumps({"service": "performance-runtime", "owner": "platform"}),
        encoding="utf-8",
    )
    _ingest(
        actor=actor,
        repository=repository,
        scope=scope,
        root=source_root,
        key="canvas-performance-source",
    )
    remaining = 300 - KnowledgeEntity.objects.filter(organization=organization).count()
    KnowledgeEntity.objects.bulk_create(
        [
            KnowledgeEntity(
                organization=organization,
                entity_type=KnowledgeEntity.EntityType.COMPONENT,
                canonical_key=f"component:performance:{index:03d}",
                display_name=f"Performance component {index:03d}",
                attributes={"owner": "Performance", "status": "ACTIVE", "risk": "LOW"},
                access_scope=scope,
            )
            for index in range(remaining)
        ]
    )
    relationship = KnowledgeRelationship.objects.get(organization=organization)
    query = CanvasQuery(repository_ids=(repository.id,))

    warm_projection = canvas_projection(actor=actor, query=query)
    warm_path = canvas_path(
        actor=actor,
        source_id=relationship.source_entity_id,
        target_id=relationship.target_entity_id,
        repository_ids=(repository.id,),
    )
    assert warm_projection["counts"] == {"nodes": 300, "edges": 1}
    assert warm_path["found"] is True

    projection_ms: list[float] = []
    projection_queries: list[int] = []
    path_ms: list[float] = []
    path_queries: list[int] = []
    last_projection = warm_projection
    for _sample in range(30):
        with CaptureQueriesContext(connection) as captured:
            started = time.perf_counter()
            last_projection = canvas_projection(actor=actor, query=query)
            projection_ms.append((time.perf_counter() - started) * 1_000)
        projection_queries.append(len(captured))
        with CaptureQueriesContext(connection) as captured:
            started = time.perf_counter()
            path = canvas_path(
                actor=actor,
                source_id=relationship.source_entity_id,
                target_id=relationship.target_entity_id,
                repository_ids=(repository.id,),
            )
            path_ms.append((time.perf_counter() - started) * 1_000)
        path_queries.append(len(captured))
        assert path["found"] is True

    projection_summary = _metric_summary(projection_ms)
    path_summary = _metric_summary(path_ms)
    assert cast(float, projection_summary["p95"]) <= 400
    assert cast(float, path_summary["p95"]) <= 1_000
    assert max(projection_queries) == min(projection_queries)
    assert max(path_queries) == min(path_queries)
    assert max(projection_queries) <= 30
    assert max(path_queries) <= 30
    payload_bytes = _canvas_payload_size(last_projection)
    assert payload_bytes <= 750 * 1024

    report = {
        "schema_version": "1",
        "metadata": {
            "commit": os.environ.get(
                "ANVA_PERFORMANCE_COMMIT",
                "fbb79960f96518a51cc8cf0e4f3ffb3090798378+working-tree",
            ),
            "environment": "Docker Compose test profile",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_model": _cpu_model(),
            "cpu_count": os.cpu_count(),
            "postgres_server_version": cast(Any, connection).pg_version,
            "fixture": {
                "visible_nodes": 300,
                "strict_source_relationships": 1,
                "repositories": 1,
                "semantic_depth": 2,
                "fixture_key": "canvas-performance-v1",
            },
        },
        "targets": {
            "strict_query_hydration_p95_ms": 400,
            "path_p95_ms": 1_000,
            "payload_bytes": 750 * 1024,
        },
        "metrics": {
            "strict_query_hydration_ms": projection_summary,
            "strict_query_hydration_query_count": {
                **_metric_summary([float(value) for value in projection_queries]),
                "bounded_and_constant": True,
            },
            "path_round_trip_service_ms": path_summary,
            "path_query_count": {
                **_metric_summary([float(value) for value in path_queries]),
                "bounded_and_constant": True,
            },
            "payload_bytes": payload_bytes,
        },
        "notes": [
            "Each metric contains 30 samples after one discarded warm call.",
            (
                "Strict query/hydration includes authorization, strict provenance CTE, "
                "ORM hydration, deterministic layout, and payload construction in-process."
            ),
            (
                "Query-count equality across all samples is the N+1 regression gate; "
                "the fixture contains a real ingested strict relationship."
            ),
        ],
    }
    PERFORMANCE_ROOT.mkdir(parents=True, exist_ok=True)
    (PERFORMANCE_ROOT / "database.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_canvas_revisions_are_append_only_idempotent_and_tenant_safe() -> None:
    organization, repository, actor, _user = _tenant(slug="canvas-revision")
    scope = AccessScope.objects.create(
        organization=organization,
        name="canvas revision scope",
        all_memberships=True,
        all_repositories=True,
    )
    product = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.PRODUCT,
        canonical_key="product:storefront",
        display_name="Storefront",
        access_scope=scope,
    )
    repository_entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.REPOSITORY,
        canonical_key="repository:storefront",
        display_name="Storefront repository",
        access_scope=scope,
    )
    view, created = create_canvas_view(
        actor=actor,
        name="Storefront system",
        description="A semantic system view",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={"repository_ids": [str(repository.id)]},
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="create-storefront-view",
    )
    assert created is True
    initial_hash = CanvasViewRevision.objects.get(canvas_view=view, revision=1).content_hash
    canonical_revision = product.revision
    assert [item.id for item in list_canvas_views(actor=actor)] == [view.id]
    detail = canvas_entity_detail(
        actor=actor,
        entity_id=product.id,
        repository_ids=(repository.id,),
    )
    assert detail["id"] == str(product.id)
    assert detail["summary"] == "No governed summary is available."
    assert detail["sources"] == []
    assert detail["permitted_actions"] == {
        "view": True,
        "move_in_view": True,
        "propose_relationship": True,
        "delete_canonical": False,
    }

    owner_membership = Membership.objects.get(organization=organization, user_id=actor.actor_id)
    with pytest.raises(ValueError, match="expiry must be in the future"):
        create_canvas_share(
            actor=actor,
            view_id=view.id,
            recipient_membership_id=owner_membership.id,
            expires_at=timezone.now() - timedelta(seconds=1),
            idempotency_key="expired-storefront-share",
        )
    share, created = create_canvas_share(
        actor=actor,
        view_id=view.id,
        recipient_membership_id=owner_membership.id,
        expires_at=timezone.now() + timedelta(hours=1),
        idempotency_key="storefront-share",
    )
    assert created is True
    retry_share, created = create_canvas_share(
        actor=actor,
        view_id=view.id,
        recipient_membership_id=owner_membership.id,
        expires_at=share.expires_at,
        idempotency_key="storefront-share",
    )
    assert created is False
    assert retry_share.id == share.id
    shared_view, shared_revision = resolve_canvas_share(actor=actor, share_id=share.id)
    assert shared_view.id == view.id
    assert shared_revision.revision == 1

    presentation = [
        {
            "entity_id": str(product.id),
            "x": 160.5,
            "y": 80.25,
            "is_pinned": True,
            "is_hidden": False,
            "group_index": 0,
        }
    ]
    filters: list[dict[str, object]] = [
        {"field": "status", "operator": "EQUALS", "value": "ACTIVE"}
    ]
    layers = [
        {"key": "execution", "label": "Execution", "is_visible": True},
        {"key": "ownership", "label": "Ownership", "is_visible": False},
    ]
    groups = [
        {
            "label": "Storefront group",
            "x": 20,
            "y": 30,
            "width": 600,
            "height": 400,
        }
    ]
    annotations = [
        {
            "entity_id": str(product.id),
            "body": "Presentation-only note",
            "x": 180,
            "y": 110,
        }
    ]
    revision, created = save_canvas_revision(
        actor=actor,
        view_id=view.id,
        expected_revision=1,
        semantic_query={"repository_ids": [str(repository.id)]},
        placements=presentation,
        filters=filters,
        layers=layers,
        groups=groups,
        annotations=annotations,
        idempotency_key="save-storefront-layout",
    )
    assert created is True
    retry, created = save_canvas_revision(
        actor=actor,
        view_id=view.id,
        expected_revision=1,
        semantic_query={"repository_ids": [str(repository.id)]},
        placements=presentation,
        filters=filters,
        layers=layers,
        groups=groups,
        annotations=annotations,
        idempotency_key="save-storefront-layout",
    )
    assert created is False
    assert retry.id == revision.id
    product.refresh_from_db()
    assert product.revision == canonical_revision
    assert CanvasViewRevision.objects.get(canvas_view=view, revision=1).content_hash == initial_hash
    _shared_view, exact_shared_revision = resolve_canvas_share(actor=actor, share_id=share.id)
    assert exact_shared_revision.revision == 1

    with pytest.raises(IdempotencyConflictError):
        save_canvas_revision(
            actor=actor,
            view_id=view.id,
            expected_revision=1,
            semantic_query={"search": "different"},
            placements=presentation,
            filters=filters,
            layers=layers,
            groups=groups,
            annotations=annotations,
            idempotency_key="save-storefront-layout",
        )
    with pytest.raises(OptimisticConcurrencyError):
        save_canvas_revision(
            actor=actor,
            view_id=view.id,
            expected_revision=1,
            semantic_query={},
            placements=[],
            filters=[],
            layers=[],
            groups=[],
            annotations=[],
            idempotency_key="stale-storefront-layout",
        )

    with pytest.raises(DatabaseError):
        with transaction.atomic():
            CanvasViewRevision.objects.filter(id=revision.id).update(layout_version="changed")
    placement = CanvasNodePlacement.objects.get(view_revision=revision)
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            CanvasNodePlacement.objects.filter(id=placement.id).update(x=999)

    foreign = Organization.objects.create(slug="canvas-foreign", name="Foreign")
    foreign_scope = AccessScope.objects.create(
        organization=foreign,
        name="foreign",
        all_memberships=True,
        all_repositories=True,
    )
    foreign_entity = KnowledgeEntity.objects.create(
        organization=foreign,
        entity_type=KnowledgeEntity.EntityType.COMPONENT,
        canonical_key="component:foreign",
        display_name="Foreign",
        access_scope=foreign_scope,
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            CanvasNodePlacement.objects.create(
                organization=foreign,
                view_revision=revision,
                entity=foreign_entity,
                x=0,
                y=0,
            )
            with connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")

    relationship_count = KnowledgeRelationship.objects.count()
    proposal, created = propose_canvas_relationship(
        actor=actor,
        source_id=product.id,
        target_id=repository_entity.id,
        relationship_type=KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY,
        repository_id=repository.id,
        expected_source_revision=product.revision,
        expected_target_revision=repository_entity.revision,
        rationale="The storefront is implemented in this governed repository.",
        idempotency_key="storefront-relationship",
    )
    assert created is True
    retry_proposal, created = propose_canvas_relationship(
        actor=actor,
        source_id=product.id,
        target_id=repository_entity.id,
        relationship_type=KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY,
        repository_id=repository.id,
        expected_source_revision=product.revision,
        expected_target_revision=repository_entity.revision,
        rationale="The storefront is implemented in this governed repository.",
        idempotency_key="storefront-relationship",
    )
    assert created is False
    assert retry_proposal.id == proposal.id
    assert proposal.state == KnowledgeProposal.State.PROPOSED
    assert KnowledgeRelationship.objects.count() == relationship_count
    with pytest.raises(OptimisticConcurrencyError):
        propose_canvas_relationship(
            actor=actor,
            source_id=product.id,
            target_id=repository_entity.id,
            relationship_type=(
                KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY
            ),
            repository_id=repository.id,
            expected_source_revision=product.revision + 1,
            expected_target_revision=repository_entity.revision,
            rationale="A stale retry must not create canonical or proposed state.",
            idempotency_key="stale-storefront-relationship",
        )


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_http_query_requires_csrf_and_never_requires_javascript() -> None:
    organization, repository, _actor, user = _tenant(slug="canvas-http")
    scope = AccessScope.objects.create(
        organization=organization,
        name="http scope",
        all_memberships=True,
        all_repositories=True,
    )
    product = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.PRODUCT,
        canonical_key="product:http-storefront",
        display_name="HTTP storefront",
        attributes={"owner": "Product", "status": "ACTIVE"},
        access_scope=scope,
    )
    repository_entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.REPOSITORY,
        canonical_key="repository:http-storefront",
        display_name="HTTP storefront repository",
        access_scope=scope,
    )
    client = Client(enforce_csrf_checks=True)
    session = client.session
    session["anva_web_user_id"] = str(user.id)
    session["anva_web_organization_id"] = str(organization.id)
    session.save()

    page = client.get("/app/canvas")
    assert page.status_code == 200
    rendered = page.content.decode()
    assert "Keyboard and no-JS equivalent" in rendered
    assert "Permitted nodes" in rendered
    assert "HTTP storefront" in rendered
    assert "HTTP storefront repository" in rendered

    missing = client.post(
        "/app/canvas/query",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert missing.status_code == 403
    csrf = client.cookies["csrftoken"].value
    allowed = client.post(
        "/app/canvas/query",
        data=json.dumps({}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert allowed.status_code == 200
    assert allowed.json()["schema_version"] == "1"

    detail = client.get(
        f"/app/canvas/entities/{product.id}",
        {"repository": str(repository.id)},
    )
    assert detail.status_code == 200
    assert detail.json()["id"] == str(product.id)
    no_path = client.post(
        "/app/canvas/path",
        data=json.dumps(
            {
                "source_id": str(product.id),
                "target_id": str(repository_entity.id),
                "repository_ids": [str(repository.id)],
                "max_depth": 3,
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert no_path.status_code == 200
    assert no_path.json()["found"] is False

    created_view = client.post(
        "/app/canvas/views",
        data={
            "name": "HTTP storefront map",
            "description": "Saved without requiring client-side JavaScript",
            "view_type": CanvasView.ViewType.PRODUCT_SYSTEM,
            "repository_id": str(repository.id),
            "entity_type": [KnowledgeEntity.EntityType.PRODUCT],
            "idempotency_key": "http-storefront-view",
        },
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert created_view.status_code == 302
    view = CanvasView.objects.get(name="HTTP storefront map")
    saved_revision = client.post(
        f"/app/canvas/views/{view.id}/revisions",
        data=json.dumps(
            {
                "expected_revision": 1,
                "semantic_query": {"repository_ids": [str(repository.id)]},
                "presentation": {
                    "placements": [
                        {
                            "entity_id": str(product.id),
                            "x": 10,
                            "y": 20,
                            "is_pinned": True,
                            "is_hidden": False,
                            "group_index": None,
                        }
                    ],
                    "filters": [],
                    "layers": [],
                    "groups": [],
                    "annotations": [],
                },
                "idempotency_key": "http-storefront-revision",
            }
        ),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert saved_revision.status_code == 201
    assert saved_revision.json()["revision"] == 2
    shared = client.post(
        f"/app/canvas/views/{view.id}/shares",
        data=json.dumps({"idempotency_key": "http-storefront-share"}),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert shared.status_code == 201
    assert shared.json()["authorization_required"] is True
    shared_page = client.get(shared.json()["deep_link"])
    assert shared_page.status_code == 200
    assert "HTTP storefront map" in shared_page.content.decode()

    proposed = client.post(
        "/app/canvas/relationship-proposals",
        data={
            "source_id": str(product.id),
            "target_id": str(repository_entity.id),
            "relationship_type": (
                KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY
            ),
            "repository_id": str(repository.id),
            "expected_source_revision": product.revision,
            "expected_target_revision": repository_entity.revision,
            "rationale": "The product is implemented by this repository.",
            "idempotency_key": "http-storefront-proposal",
        },
        HTTP_X_CSRFTOKEN=csrf,
    )
    assert proposed.status_code == 302
    assert KnowledgeProposal.objects.filter(organization=organization).count() == 1


@pytest.mark.integration
@pytest.mark.django_db
def test_canvas_api_is_bearer_authenticated_and_closed() -> None:
    organization, repository, admin, _user = _tenant(slug="canvas-api")
    scope = AccessScope.objects.create(
        organization=organization,
        name="service canvas scope",
        all_service_identities=True,
        all_repositories=True,
    )
    entity = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.PRODUCT,
        canonical_key="product:api-visible",
        display_name="API visible product",
        access_scope=scope,
    )
    target = KnowledgeEntity.objects.create(
        organization=organization,
        entity_type=KnowledgeEntity.EntityType.REPOSITORY,
        canonical_key="repository:api-visible",
        display_name="API visible repository",
        access_scope=scope,
    )
    view, created = create_canvas_view(
        actor=admin,
        name="Bearer API view",
        description="A service-readable and manageable view",
        view_type=CanvasView.ViewType.CUSTOM,
        semantic_query={"repository_ids": [str(repository.id)]},
        repository_id=repository.id,
        access_scope_id=None,
        idempotency_key="bearer-api-view",
    )
    assert created is True
    service = ServiceIdentity.objects.create(
        organization=organization,
        name="canvas-api-client",
        issuer="anva-test",
        audience="anva-test-api",
    )
    AccessGrant.objects.create(
        organization=organization,
        service_identity=service,
        repository=repository,
        action=Action.CANVAS_VIEW.value,
    )
    AccessGrant.objects.create(
        organization=organization,
        service_identity=service,
        repository=repository,
        action=Action.CANVAS_MANAGE.value,
    )
    AccessGrant.objects.create(
        organization=organization,
        service_identity=service,
        repository=repository,
        action=Action.KNOWLEDGE_PROPOSE.value,
    )
    issued = issue_bootstrap_repository_token(
        organization=organization,
        repository=repository,
        service_identity=service,
        actions=frozenset({Action.CANVAS_VIEW, Action.CANVAS_MANAGE, Action.KNOWLEDGE_PROPOSE}),
        expires_at=timezone.now() + timedelta(hours=1),
    )
    client = Client()

    unauthenticated = client.post(
        "/api/v1/canvas/query",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert unauthenticated.status_code == 401
    invalid = client.post(
        "/api/v1/canvas/query",
        data=json.dumps({"unknown": True}),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {issued.plaintext}",
    )
    assert invalid.status_code == 400
    allowed = client.post(
        "/api/v1/canvas/query",
        data=json.dumps({"repository_ids": [str(repository.id)]}),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {issued.plaintext}",
    )
    assert allowed.status_code == 200
    assert {node["id"] for node in allowed.json()["nodes"]} == {
        str(entity.id),
        str(target.id),
    }

    authorization = f"Bearer {issued.plaintext}"
    listed = client.get(
        "/api/v1/canvas/views",
        HTTP_AUTHORIZATION=authorization,
    )
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["views"]] == [str(view.id)]
    service_create = client.post(
        "/api/v1/canvas/views",
        data=json.dumps(
            {
                "name": "Service-owned views are unsupported",
                "view_type": CanvasView.ViewType.CUSTOM,
                "semantic_query": {},
                "idempotency_key": "service-owned-view",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert service_create.status_code == 404

    detail = client.get(
        f"/api/v1/canvas/entities/{entity.id}",
        {"repository_id": str(repository.id)},
        HTTP_AUTHORIZATION=authorization,
    )
    assert detail.status_code == 200
    assert detail.json()["id"] == str(entity.id)
    no_path = client.post(
        "/api/v1/canvas/path",
        data=json.dumps(
            {
                "source_id": str(entity.id),
                "target_id": str(target.id),
                "repository_ids": [str(repository.id)],
                "max_depth": 4,
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert no_path.status_code == 200
    assert no_path.json()["found"] is False

    revision = client.post(
        f"/api/v1/canvas/views/{view.id}/revisions",
        data=json.dumps(
            {
                "expected_revision": 1,
                "semantic_query": {"repository_ids": [str(repository.id)]},
                "presentation": {
                    "placements": [],
                    "filters": [],
                    "layers": [],
                    "groups": [],
                    "annotations": [],
                },
                "idempotency_key": "bearer-api-revision",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert revision.status_code == 201
    assert revision.json()["revision"] == 2
    expires_at = (timezone.now() + timedelta(hours=1)).isoformat()
    shared = client.post(
        f"/api/v1/canvas/views/{view.id}/shares",
        data=json.dumps(
            {
                "expires_at": expires_at,
                "idempotency_key": "bearer-api-share",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert shared.status_code == 201
    assert shared.json()["view_revision"] == 2
    proposed = client.post(
        "/api/v1/canvas/relationship-proposals",
        data=json.dumps(
            {
                "source_id": str(entity.id),
                "target_id": str(target.id),
                "relationship_type": (
                    KnowledgeRelationship.RelationshipType.PRODUCT_IMPLEMENTED_BY_REPOSITORY
                ),
                "repository_id": str(repository.id),
                "expected_source_revision": entity.revision,
                "expected_target_revision": target.revision,
                "rationale": "The API product is implemented by the API repository.",
                "idempotency_key": "bearer-api-proposal",
            }
        ),
        content_type="application/json",
        HTTP_AUTHORIZATION=authorization,
    )
    assert proposed.status_code == 201
    assert proposed.json()["state"] == KnowledgeProposal.State.PROPOSED
