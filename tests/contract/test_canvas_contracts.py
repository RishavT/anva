"""Contract coverage for the permission-safe Organizational Canvas API."""

from __future__ import annotations

from typing import cast

import pytest

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
        "maximum": 300,
    }
    assert cast(dict[str, object], query_schema["properties"])["edge_limit"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 600,
    }

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
