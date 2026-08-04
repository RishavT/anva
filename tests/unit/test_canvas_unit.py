"""Deterministic Canvas model, query, ontology, and safety contracts."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from anva.core.models import (
    CanvasFilter,
    CanvasViewRevision,
    KnowledgeEntity,
    KnowledgeRelationship,
)
from anva.core.services.canvas import (
    CANVAS_LAYOUT_VERSION,
    CANVAS_PATH_DEPTH,
    CANVAS_PAYLOAD_LIMIT_BYTES,
    RELATIONSHIP_ENDPOINTS,
    AuthorizedCanvasEdge,
    CanvasQuery,
    _bounded_integer,
    _canonical_filter_value,
    _canonical_presentation,
    _canvas_payload_size,
    _coordinate,
    _dimension,
    _enforce_canvas_payload_budget,
    _filter_field,
    _filter_operator,
    _focused_ids,
    _layer_key,
    _layout,
    _normalized_semantic_query,
    _safe_text,
    _semantic_query,
)


@pytest.mark.unit
def test_canvas_query_caps_and_allowlists_are_closed() -> None:
    assert CanvasQuery().node_limit == 300
    assert CanvasQuery().edge_limit == 600
    assert CANVAS_PATH_DEPTH == 6
    assert CANVAS_PAYLOAD_LIMIT_BYTES == 750 * 1024

    with pytest.raises(ValueError, match="node limit"):
        CanvasQuery(node_limit=301)
    with pytest.raises(ValueError, match="repositories"):
        CanvasQuery(repository_ids=tuple(uuid.uuid4() for _index in range(101)))
    with pytest.raises(ValueError, match="depth"):
        CanvasQuery(depth=5)
    with pytest.raises(ValueError, match="edge limit"):
        CanvasQuery(edge_limit=0)
    with pytest.raises(ValueError, match="entity type"):
        CanvasQuery(entity_types=("EMPLOYEE_RANKING",))
    with pytest.raises(ValueError, match="layer"):
        CanvasQuery(layers=("private_source_titles",))
    with pytest.raises(ValueError, match="freshness"):
        CanvasQuery(freshness="SECRET")
    with pytest.raises(ValueError, match="revision"):
        CanvasQuery(view_revision=0)
    with pytest.raises(ValueError, match="secret"):
        CanvasQuery(search="Bearer abcdefghijklmnopqrstuvwxyz")


@pytest.mark.unit
def test_saved_semantic_query_is_typed_closed_and_canonical() -> None:
    repository_id = uuid.uuid4()
    normalized = _normalized_semantic_query(
        {
            "repository_ids": [str(repository_id), str(repository_id)],
            "entity_types": ["SERVICE", "GOAL", "SERVICE"],
            "layers": ["ownership", "execution"],
            "freshness": "FRESH",
            "as_of": "2026-07-31T12:30:00Z",
            "depth": 4,
        }
    )

    assert normalized == {
        "repository_ids": [str(repository_id)],
        "entity_types": ["GOAL", "SERVICE"],
        "layers": ["execution", "ownership"],
        "freshness": "FRESH",
        "as_of": "2026-07-31T12:30:00+00:00",
        "depth": 4,
    }
    with pytest.raises(ValueError, match="unknown value"):
        _normalized_semantic_query({"layers": ["private_source_titles"]})
    with pytest.raises(ValueError, match="list of strings"):
        _normalized_semantic_query({"entity_types": "SERVICE"})
    with pytest.raises(ValueError, match="unsupported fields"):
        _normalized_semantic_query({"private": "field"})
    with pytest.raises(ValueError, match="root entity"):
        _normalized_semantic_query({"root_entity_id": 123})
    with pytest.raises(ValueError, match="repositories must"):
        _normalized_semantic_query({"repository_ids": "not-a-list"})
    with pytest.raises(ValueError, match="100 repositories"):
        _normalized_semantic_query({"repository_ids": [str(uuid.uuid4()) for _index in range(101)]})
    with pytest.raises(ValueError, match="owner must"):
        _normalized_semantic_query({"owner": 42})
    with pytest.raises(ValueError, match="freshness state"):
        _normalized_semantic_query({"freshness": "SECRET"})
    with pytest.raises(ValueError, match="secret"):
        _normalized_semantic_query({"search": "ghp_abcdefghijklmnopqrstuvwxyz123456"})
    with pytest.raises(ValueError, match="timezone-aware"):
        _normalized_semantic_query({"as_of": "2026-07-31T12:30:00"})
    with pytest.raises(ValueError, match="timezone-aware"):
        CanvasQuery(as_of=datetime(2026, 7, 31, 12, 30, tzinfo=UTC).replace(tzinfo=None))
    assert CanvasQuery(as_of=datetime(2026, 7, 31, 12, 30, tzinfo=UTC)).as_of is not None


@pytest.mark.unit
def test_saved_semantic_constraints_use_explicit_presence_to_clear() -> None:
    root_id = uuid.uuid4()
    saved = {
        "repository_ids": [str(uuid.uuid4())],
        "root_entity_id": str(root_id),
        "entity_types": ["PRODUCT"],
        "owner": "Product",
        "status": "ACTIVE",
        "risk": "HIGH",
        "freshness": "FRESH",
        "as_of": "2026-07-31T12:30:00+00:00",
        "search": "storefront",
        "layers": ["provenance"],
        "depth": 3,
    }
    revision = SimpleNamespace(semantic_query=saved)
    view = SimpleNamespace(view_type="CUSTOM")
    retained = _semantic_query(
        query=CanvasQuery(),
        view=cast(Any, view),
        revision=cast(Any, revision),
    )
    assert retained == saved

    cleared = _semantic_query(
        query=CanvasQuery(
            provided_semantic_fields=frozenset(
                {
                    "root_entity_id",
                    "entity_types",
                    "owner",
                    "status",
                    "risk",
                    "freshness",
                    "as_of",
                    "search",
                    "layers",
                }
            )
        ),
        view=cast(Any, view),
        revision=cast(Any, revision),
    )
    assert cleared == {"repository_ids": saved["repository_ids"], "depth": 3}


@pytest.mark.unit
def test_canvas_focus_walk_is_undirected_deterministic_and_depth_bounded() -> None:
    repository_id = uuid.uuid4()
    first, second, third, fourth = (uuid.UUID(int=index) for index in range(1, 5))

    def edge(source: uuid.UUID, target: uuid.UUID) -> AuthorizedCanvasEdge:
        return AuthorizedCanvasEdge(
            repository_id=repository_id,
            edge=cast(
                Any,
                SimpleNamespace(source_entity_id=source, target_entity_id=target),
            ),
        )

    edges = [edge(first, second), edge(third, second), edge(third, fourth)]
    assert _focused_ids(root_id=first, edges=edges, depth=2) == {first, second, third}
    assert _focused_ids(root_id=fourth, edges=list(reversed(edges)), depth=1) == {
        third,
        fourth,
    }
    assert _focused_ids(root_id=first, edges=[], depth=4) == {first}


@pytest.mark.unit
def test_canvas_payload_budget_is_hard_and_deterministic() -> None:
    payload: dict[str, object] = {
        "nodes": [
            {
                "id": str(uuid.UUID(int=index + 1)),
                "position": {"x": index, "y": index},
                "label": "界" * 3_000,
            }
            for index in range(300)
        ],
        "edges": [],
        "counts": {"nodes": 300, "edges": 0},
        "limitations": [],
        "layout": {"checksum": "a" * 64},
        "truncated": False,
    }

    limited = _enforce_canvas_payload_budget(payload)

    assert _canvas_payload_size(limited) <= CANVAS_PAYLOAD_LIMIT_BYTES
    assert limited["truncated"] is True
    assert len(limited["nodes"]) < 300  # type: ignore[arg-type]
    assert "750 KiB" in str(limited["limitations"])


@pytest.mark.unit
def test_canvas_payload_budget_trims_edges_before_nodes() -> None:
    first_id = str(uuid.UUID(int=1))
    second_id = str(uuid.UUID(int=2))
    payload: dict[str, object] = {
        "nodes": [
            {"id": first_id, "position": {"x": 0, "y": 0}},
            {"id": second_id, "position": {"x": 1, "y": 1}},
        ],
        "edges": [
            {
                "id": str(uuid.UUID(int=index + 10)),
                "source": first_id,
                "target": second_id,
                "explanation": "界" * 1_000,
            }
            for index in range(600)
        ],
        "counts": {"nodes": 2, "edges": 600},
        "limitations": [],
        "layout": {"checksum": "a" * 64},
        "truncated": False,
    }

    limited = _enforce_canvas_payload_budget(payload)

    assert _canvas_payload_size(limited) <= CANVAS_PAYLOAD_LIMIT_BYTES
    assert len(cast(list[object], limited["nodes"])) == 2
    assert 0 < len(cast(list[object], limited["edges"])) < 600
    assert limited["counts"] == {
        "nodes": 2,
        "edges": len(cast(list[object], limited["edges"])),
    }


@pytest.mark.unit
def test_canvas_presentation_scalar_validators_reject_closed_boundaries() -> None:
    assert _bounded_integer(2, name="depth", minimum=1, maximum=4) == 2
    with pytest.raises(ValueError, match="integer"):
        _bounded_integer(True, name="depth", minimum=1, maximum=4)
    with pytest.raises(ValueError, match="bounded range"):
        _bounded_integer(5, name="depth", minimum=1, maximum=4)
    with pytest.raises(ValueError, match="size budget"):
        _safe_text("too long", maximum=2)
    with pytest.raises(ValueError, match="dimension"):
        _dimension(0)
    with pytest.raises(ValueError, match="filter field"):
        _filter_field("secret")
    with pytest.raises(ValueError, match="filter operator"):
        _filter_operator("EXECUTE")
    with pytest.raises(ValueError, match="layer"):
        _layer_key("private")
    assert _filter_operator(CanvasFilter.Operator.EQUALS) == CanvasFilter.Operator.EQUALS


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        {"nested": ["safe", {"token": "ghp_abcdefghijklmnopqrstuvwxyz123456"}]},
        {"Bearer abcdefghijklmnopqrstuvwxyz": "nested key"},
        ["-----BEGIN PRIVATE KEY-----"],
        {"cookie": {"value": "sessionid=super-secret-session"}},
    ],
)
def test_canvas_filter_values_recursively_reject_secret_shaped_strings(
    value: object,
) -> None:
    with pytest.raises(ValueError, match="secret"):
        _canonical_presentation(
            placements=[],
            filters=[
                {
                    "field": "status",
                    "operator": CanvasFilter.Operator.EQUALS,
                    "value": value,
                }
            ],
            layers=[],
            groups=[],
            annotations=[],
        )


@pytest.mark.unit
def test_canvas_filter_values_preserve_recursive_integer_and_fractional_json() -> None:
    value = {"integer": 1, "fractional": 1.5, "nested": [2, 2.5]}
    assert _canonical_filter_value(value) == value


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "item", "message"),
    [
        (
            "placements",
            {
                "entity_id": str(uuid.uuid4()),
                "x": 0,
                "y": 0,
                "is_pinned": "false",
                "is_hidden": False,
                "group_index": None,
            },
            "boolean",
        ),
        (
            "filters",
            {"field": "status", "operator": "EQUALS", "value": "ACTIVE", "extra": 1},
            "fields",
        ),
        (
            "layers",
            {"key": "execution", "label": 7, "is_visible": True},
            "text",
        ),
        (
            "groups",
            {"label": "Group", "x": "0", "y": 0, "width": 10, "height": 10},
            "coordinate",
        ),
        (
            "annotations",
            {"entity_id": None, "body": [], "x": 0, "y": 0},
            "text",
        ),
    ],
)
def test_canvas_presentation_children_are_closed_and_strictly_typed(
    field: str,
    item: dict[str, object],
    message: str,
) -> None:
    presentation: dict[str, list[dict[str, object]]] = {
        "placements": [],
        "filters": [],
        "layers": [],
        "groups": [],
        "annotations": [],
    }
    presentation[field].append(item)
    with pytest.raises(ValueError, match=message):
        _canonical_presentation(**presentation)


@pytest.mark.unit
def test_canvas_revision_hash_covers_every_presentation_child() -> None:
    base = {
        "organization_id": uuid.uuid4(),
        "canvas_view_id": uuid.uuid4(),
        "revision": 2,
        "semantic_query": {"entity_types": ["GOAL"]},
        "layout_algorithm": "deterministic-semantic-columns",
        "layout_version": CANVAS_LAYOUT_VERSION,
        "created_by_type": "USER",
        "created_by_id": str(uuid.uuid4()),
        "idempotency_key": "a" * 64,
        "request_hash": "b" * 64,
    }
    first = CanvasViewRevision(
        **base,
        presentation={"placements": [{"entity_id": str(uuid.uuid4()), "x": 1, "y": 2}]},
    )
    second = CanvasViewRevision(
        **base,
        presentation={"placements": [{"entity_id": str(uuid.uuid4()), "x": 1, "y": 2}]},
    )

    with patch("django.db.models.Model.save"):
        first.save()
        second.save()

    assert first.content_hash != second.content_hash
    assert len(first.content_hash) == 64


@pytest.mark.unit
def test_v3_canvas_ontology_and_relationship_endpoint_rules_are_explicit() -> None:
    assert {
        "GOAL",
        "OWNER",
        "ENVIRONMENT",
        "CUSTOMER_COMMITMENT",
        "ARCHITECTURAL_DECISION",
        "ACCEPTANCE_CRITERION",
        "RELEASE",
    } <= set(KnowledgeEntity.EntityType.values)
    assert set(RELATIONSHIP_ENDPOINTS) <= set(KnowledgeRelationship.RelationshipType.values)
    assert RELATIONSHIP_ENDPOINTS["GOAL_MEASURED_BY_METRIC"] == (
        frozenset({"GOAL"}),
        frozenset({"METRIC"}),
    )
    assert KnowledgeRelationship._meta.get_field("relationship_type").max_length == 64


@pytest.mark.unit
def test_canvas_layout_is_deterministic_and_pins_win() -> None:
    first_id = uuid.UUID("00000000-0000-4000-8000-000000000001")
    second_id = uuid.UUID("00000000-0000-4000-8000-000000000002")
    entities = [
        KnowledgeEntity(
            id=second_id,
            entity_type="SERVICE",
            canonical_key="service:b",
            display_name="B",
        ),
        KnowledgeEntity(
            id=first_id,
            entity_type="GOAL",
            canonical_key="goal:a",
            display_name="A",
        ),
    ]
    first = _layout(entities, {})
    second = _layout(list(reversed(entities)), {})

    assert first == second
    assert first[first_id][0] < first[second_id][0]


@pytest.mark.unit
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 1_000_001])
def test_canvas_rejects_nonfinite_and_unbounded_coordinates(value: float) -> None:
    with pytest.raises(ValueError, match="coordinate"):
        _coordinate(value)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "ghp_abcdefghijklmnopqrstuvwxyz123456",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "-----BEGIN PRIVATE KEY-----",
        "sessionid=super-secret-session",
    ],
)
def test_canvas_rejects_secret_shaped_text(value: str) -> None:
    with pytest.raises(ValueError, match="secret"):
        _safe_text(value, maximum=1_000)
