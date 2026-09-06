"""Contract coverage for the permission-safe Organizational Canvas API."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from anva.contract_limits import (
    MAX_CANVAS_QUERY_DEPTH,
    MAX_CANVAS_QUERY_EDGES,
    MAX_CANVAS_QUERY_NODES,
)
from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.generate import openapi_document


@pytest.mark.contract
def test_canvas_openapi_surfaces_are_authenticated_bounded_and_closed() -> None:
    paths = cast(dict[str, object], openapi_document()["paths"])
    expected = {
        "/canvas/query",
        "/canvas/path",
        "/canvas/entities/{resource_id}",
        "/canvas/views",
        "/canvas/views/{resource_id}/revisions",
        "/canvas/views/{resource_id}/shares",
        "/canvas/shares/{resource_id}/revoke",
        "/canvas/relationship-proposals",
    }
    assert expected <= paths.keys()
    query = cast(dict[str, object], paths["/canvas/query"])["post"]
    query_body = cast(dict[str, object], cast(dict[str, object], query)["requestBody"])
    query_content = cast(dict[str, object], query_body["content"])
    query_schema = cast(
        dict[str, object], cast(dict[str, object], query_content["application/json"])["schema"]
    )
    assert query_schema["additionalProperties"] is False
    assert cast(dict[str, object], query_schema["properties"])["node_limit"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": MAX_CANVAS_QUERY_NODES,
    }
    assert cast(dict[str, object], query_schema["properties"])["edge_limit"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": MAX_CANVAS_QUERY_EDGES,
    }

    assert cast(dict[str, object], query_schema["properties"])["as_of"] == {
        "oneOf": [
            {"type": "string", "format": "date-time"},
            {"type": "null"},
        ]
    }

    revision = cast(dict[str, object], paths["/canvas/views/{resource_id}/revisions"])["post"]
    revision_body = cast(dict[str, object], cast(dict[str, object], revision)["requestBody"])
    revision_content = cast(dict[str, object], revision_body["content"])
    revision_schema = cast(
        dict[str, object],
        cast(dict[str, object], revision_content["application/json"])["schema"],
    )
    presentation = cast(dict[str, object], revision_schema["properties"])["presentation"]
    presentation_properties = cast(
        dict[str, object], cast(dict[str, object], presentation)["properties"]
    )
    for child in ("placements", "filters", "layers", "groups", "annotations"):
        items = cast(dict[str, object], presentation_properties[child])["items"]
        assert cast(dict[str, object], items)["additionalProperties"] is False

    proposal = cast(dict[str, object], paths["/canvas/relationship-proposals"])["post"]
    proposal_body = cast(dict[str, object], cast(dict[str, object], proposal)["requestBody"])
    proposal_content = cast(dict[str, object], proposal_body["content"])
    proposal_schema = cast(
        dict[str, object],
        cast(dict[str, object], proposal_content["application/json"])["schema"],
    )
    assert proposal_schema["additionalProperties"] is False
    assert "DELETE" not in str(proposal_schema)
    assert "never writes a canonical edge" in cast(
        str, cast(dict[str, object], proposal)["description"]
    )


@pytest.mark.contract
@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("depth", MAX_CANVAS_QUERY_DEPTH),
        ("node_limit", MAX_CANVAS_QUERY_NODES),
        ("edge_limit", MAX_CANVAS_QUERY_EDGES),
    ],
)
def test_acceptance_canvas_bounds_exactly_match_live_query_contract(
    field: str, maximum: int
) -> None:
    acceptance_canvas = cast(
        dict[str, object],
        cast(dict[str, object], SCHEMAS["acceptance-case"]["properties"])["canvas"],
    )
    acceptance_property = cast(
        dict[str, object], cast(dict[str, object], acceptance_canvas["properties"])[field]
    )
    paths = cast(dict[str, object], openapi_document()["paths"])
    operation = cast(dict[str, object], cast(dict[str, object], paths["/canvas/query"])["post"])
    request_body = cast(dict[str, object], operation["requestBody"])
    media = cast(
        dict[str, object],
        cast(dict[str, object], request_body["content"])["application/json"],
    )
    live_property = cast(dict[str, object], cast(dict[str, object], media["schema"])["properties"])[
        field
    ]

    assert (
        acceptance_property
        == live_property
        == {
            "type": "integer",
            "minimum": 1,
            "maximum": maximum,
        }
    )

    validator = Draft202012Validator(SCHEMAS["acceptance-case"])
    for accepted in (1, maximum):
        case = deepcopy(EXAMPLES["acceptance-case"])
        cast(dict[str, object], case["canvas"])[field] = accepted
        validator.validate(case)
    for rejected in (-1, 0, maximum + 1):
        case = deepcopy(EXAMPLES["acceptance-case"])
        cast(dict[str, object], case["canvas"])[field] = rejected
        with pytest.raises(ValidationError):
            validator.validate(case)


@pytest.mark.contract
def test_canvas_filter_value_schema_accepts_recursive_integer_and_fractional_json() -> None:
    document = openapi_document()
    components = cast(dict[str, object], document["components"])
    schemas = cast(dict[str, object], components["schemas"])
    filter_value = cast(dict[str, object], schemas["canvas-filter-value"])
    numeric_branches = [
        branch
        for branch in cast(list[dict[str, object]], filter_value["oneOf"])
        if branch.get("type") in {"integer", "number"}
    ]
    assert numeric_branches == [{"type": "number"}]
    validator = Draft202012Validator(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/components/schemas/canvas-filter-value",
            "components": components,
        }
    )
    for value in (1, 1.5, {"nested": [1, 2.5]}):
        validator.validate(value)
