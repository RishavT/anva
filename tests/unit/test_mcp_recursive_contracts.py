"""Exhaustive recursive closure and concrete instance checks for MCP v1."""

from __future__ import annotations

from copy import deepcopy
from typing import cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.core.services.mcp_gateway import (
    MCPGatewayError,
    _normalize_public_output,
    _reject_private_output_material,
)
from anva.mcp.contracts import (
    PUBLIC_ASSERTION_VALUE,
    RESOURCE_CONTRACTS,
    TOOL_BY_NAME,
    TOOL_CONTRACTS,
    mcp_contract_document,
)

UUIDS = tuple(f"00000000-0000-4000-8000-{index:012d}" for index in range(1, 40))
NOW = "2026-08-22T00:00:00Z"
SHA256 = "a" * 64


def _citation(offset: int = 0) -> dict[str, object]:
    return {
        "source_location_id": UUIDS[offset],
        "source_observation_id": UUIDS[offset + 1],
        "access_snapshot_id": UUIDS[offset + 2],
        "canonical_url": f"https://example.test/source-{offset}.md",
        "locator": f"/source-{offset}.md#L1-L2",
        "source_content_hash": SHA256,
        "observed_at": NOW,
    }


def _ranking() -> dict[str, object]:
    return {
        "lexical_rank": 1,
        "semantic_rank": 2,
        "reciprocal_rank_score": 0.75,
        "phase": "PREPARE",
        "phase_terms": ["implementation", "policy"],
    }


def _context_item(*, kind: str, payload: dict[str, object], offset: int) -> dict[str, object]:
    return {
        "item_id": UUIDS[offset],
        "kind": kind,
        "item_key": f"{kind.casefold()}:{UUIDS[offset]}",
        "summary": f"Public {kind.casefold()} context",
        "freshness": "CURRENT",
        "is_inferred": False,
        "selection_reason": "Authorized exact public context",
        "rank_score": 0.9,
        "payload": payload,
        "anva_sources": [_citation(offset + 1)],
    }


def _context_packet() -> dict[str, object]:
    public_object_value = {
        "team": "payments",
        "owner": "platform",
        "rule": "Two reviewers are required.",
        "service": "checkout",
        "component": "gateway",
        "name": "Checkout gateway",
        "id": "checkout-gateway",
        "status": "ACTIVE",
        "risk": "MEDIUM",
        "text": "Governed public assertion text.",
        "authentication": True,
        "enabled": True,
        "required": True,
    }
    items = [
        _context_item(
            kind="POLICY",
            offset=1,
            payload={
                "assertion_id": UUIDS[10],
                "subject_key": "policy:review",
                "predicate": "required_policy",
                "value": public_object_value,
                "review_state": "HUMAN_CONFIRMED",
                "staleness_state": "FRESH",
                "confidence": 1.0,
            },
        ),
        _context_item(
            kind="DECISION",
            offset=5,
            payload={"assertion_id": UUIDS[14]},
        ),
        _context_item(
            kind="RELATIONSHIP",
            offset=9,
            payload={
                "relationship_id": UUIDS[18],
                "relationship_type": "SERVICE_DEPENDS_ON_SERVICE",
                "source_entity_id": UUIDS[19],
                "target_entity_id": UUIDS[20],
                "review_state": "CONFIRMED",
                "confidence": 0.9,
            },
        ),
        _context_item(
            kind="SOURCE_EXCERPT",
            offset=13,
            payload={
                "chunk_id": UUIDS[22],
                "content_hash": SHA256,
                "ranking": _ranking(),
                "search_position": 1,
            },
        ),
        _context_item(
            kind="CONFLICT",
            offset=17,
            payload={
                "conflict_id": UUIDS[26],
                "left_assertion_id": UUIDS[27],
                "right_assertion_id": UUIDS[28],
                "predicate": "service.owner",
            },
        ),
    ]
    return {
        "schema_version": "1.0",
        "packet_id": UUIDS[0],
        "organization_id": UUIDS[1],
        "repository_id": UUIDS[2],
        "work_item_id": UUIDS[3],
        "revision": 1,
        "generated_at": NOW,
        "content_hash": SHA256,
        "phase": "PREPARE",
        "request": {
            "task": "Implement the governed checkout change",
            "phase": "PREPARE",
            "budget": {
                "max_items": 50,
                "max_tokens": 8_000,
                "max_bytes": 100_000,
                "max_citations": 100,
            },
        },
        "authorization_hash": "b" * 64,
        "selection_hash": "c" * 64,
        "retrieval_watermark": 1,
        "retrieval_algorithm_version": "rrf-v1",
        "index_version": "fts-v1",
        "embedding_version": "hash-v1",
        "budget": {
            "max_items": 50,
            "max_tokens": 8_000,
            "max_bytes": 100_000,
            "max_citations": 100,
            "selected_items": len(items),
            "selected_tokens": 100,
            "selected_bytes": 1_000,
            "selected_citations": len(items),
        },
        "items": items,
        "limitations": ["Public context is bounded to currently authorized sources."],
    }


def _base_input() -> dict[str, object]:
    return {"contract_version": "1", "repository_id": UUIDS[2]}


def _proposal_input() -> dict[str, object]:
    return {
        **_base_input(),
        "access_scope_id": UUIDS[3],
        "summary": "Create a review-only public proposal.",
        "source_references": [{"kind": "ENTITY", "id": UUIDS[4]}],
        "idempotency_key": "mcp-contract-idempotency",
    }


def _input_samples() -> dict[str, dict[str, object]]:
    base = _base_input()
    proposal = _proposal_input()
    return {
        "anva.resolve_repository": base,
        "anva.resolve_work_item": {**base, "external_key": "ANVA-35"},
        "anva.get_context_packet": {
            **base,
            "task": "Implement ANVA-35",
            "phase": "PREPARE",
            "budget": {
                "max_items": 50,
                "max_tokens": 8_000,
                "max_bytes": 100_000,
                "max_citations": 100,
            },
        },
        "anva.search": {
            **base,
            "query": "public contracts",
            "phase": "PREPARE",
            "limit": 20,
            "cursor": None,
        },
        "anva.get_entity": {**base, "entity_id": UUIDS[4]},
        "anva.get_relationships": {
            **base,
            "entity_id": UUIDS[4],
            "limit": 20,
            "cursor": None,
        },
        "anva.get_repository_profile": base,
        "anva.get_policy_bundle": {**base, "limit": 20, "cursor": None},
        "anva.get_requirements": {
            **base,
            "work_item_id": UUIDS[5],
            "limit": 20,
            "cursor": None,
        },
        "anva.explain_assertion": {**base, "assertion_id": UUIDS[6]},
        "anva.get_source_excerpt": {
            **base,
            "chunk_id": UUIDS[7],
            "offset": 5,
            "max_characters": 2_000,
        },
        "anva.propose_correction": {
            **proposal,
            "assertion_id": UUIDS[6],
            "correction": {"value": "payments"},
        },
        "anva.propose_relationship": {
            **proposal,
            "source_entity_id": UUIDS[4],
            "target_entity_id": UUIDS[5],
            "relationship_type": "OWNED_BY",
            "rationale": "The governed source records this ownership.",
        },
        "anva.propose_decision": {
            **proposal,
            "work_item_id": UUIDS[5],
            "title": "Adopt exact public contracts",
            "outcome": "Use closed operation-specific schemas.",
            "rationale": "Fail closed on persisted output drift.",
        },
        "anva.submit_work_summary": {
            **proposal,
            "work_item_id": UUIDS[5],
            "summary_data": {"status": "complete"},
        },
        "anva.submit_preflight_summary": {
            **proposal,
            "work_item_id": UUIDS[5],
            "commit_sha": "d" * 40,
            "checks": [{"name": "contract-tests", "passed": True}],
            "limitations": ["Human review remains required."],
        },
    }


def _proposal_data(kind: str) -> dict[str, object]:
    return {
        "proposal_id": UUIDS[8],
        "submission_id": UUIDS[9],
        "proposal_kind": kind,
        "review_state": "PROPOSED",
        "approved": False,
        "review_required": True,
        "created": True,
    }


def _output_samples() -> dict[str, dict[str, object]]:
    relationship = {
        "relationship_id": UUIDS[10],
        "relationship_type": "SERVICE_DEPENDS_ON_SERVICE",
        "source": {
            "id": UUIDS[11],
            "type": "SERVICE",
            "key": "service:checkout",
            "name": "Checkout",
        },
        "target": {
            "id": UUIDS[12],
            "type": "SERVICE",
            "key": "service:payments",
            "name": "Payments",
        },
        "assertion_id": UUIDS[13],
        "source_location_id": UUIDS[14],
        "source_observation_id": UUIDS[15],
        "access_snapshot_id": UUIDS[16],
        "observed_at": NOW,
        "confidence": 0.95,
        "depth": 1,
    }
    policy = {
        "policy_id": UUIDS[17],
        "policy_version_id": UUIDS[18],
        "name": "Production readiness",
        "owner": "platform-security",
        "version": 2,
        "schema_version": "1.0",
        "content_hash": "e" * 64,
        "effective_at": NOW,
        "expires_at": None,
        "binding": {
            "scope_level": "REPOSITORY",
            "mandatory": True,
            "repository_ids": [UUIDS[2]],
            "path_patterns": ["src/**"],
            "target_branches": ["main"],
        },
        "requirements": [
            {
                "code": "SEC_1",
                "description": "Run the security checks.",
                "enforcement": "BLOCKING",
                "check_type": "EVIDENCE",
                "required_evidence": ["SECURITY_SCAN"],
                "required_approval": True,
            }
        ],
    }
    requirement = {
        "requirement_id": UUIDS[19],
        "code": "REQ_1",
        "text": "The gateway must reject undocumented fields.",
        "origin": "WORK_ITEM",
        "owner": "platform",
        "status": "CONFIRMED",
        "requires_approval": False,
        "source_references": ["docs/requirements.md#REQ_1"],
        "related_entity_ids": [UUIDS[11]],
        "acceptance_criteria": [
            {
                "id": UUIDS[20],
                "code": "AC_1",
                "normalized_text": "Nested private control material is rejected.",
                "required_evidence_types": ["TEST_RESULT"],
                "manual_approval_allowed": False,
            }
        ],
    }
    data: dict[str, dict[str, object]] = {
        "anva.resolve_repository": {
            "repository_id": UUIDS[2],
            "organization_id": UUIDS[1],
            "external_id": "github:anva/example",
            "name": "Example",
            "active": True,
        },
        "anva.resolve_work_item": {
            "work_item_id": UUIDS[5],
            "repository_id": UUIDS[2],
            "external_key": "ANVA-35",
            "title": "Close MCP contracts",
            "work_type": "SECURITY",
            "status": "READY",
            "revision": 2,
            "content_hash": SHA256,
        },
        "anva.get_context_packet": {
            "packet_id": UUIDS[0],
            "created": True,
            "packet": _context_packet(),
        },
        "anva.search": {
            "results": [
                {
                    "chunk_id": UUIDS[7],
                    "text": "Public inert source text.",
                    "content_hash": SHA256,
                    "pointer": "/requirements.md",
                    "canonical_url": "https://example.test/requirements.md",
                    "access_scope_id": UUIDS[3],
                    "source_location_id": UUIDS[14],
                    "source_observation_id": UUIDS[15],
                    "access_snapshot_id": UUIDS[16],
                    "observed_at": NOW,
                    "explanation": _ranking(),
                }
            ]
        },
        "anva.get_entity": {
            "entity_id": UUIDS[11],
            "entity_type": "SERVICE",
            "canonical_key": "service:checkout",
            "display_name": "Checkout",
            "attributes": {
                "owner": "platform",
                "status": "ACTIVE",
                "risk": "MEDIUM",
                "freshness": "CURRENT",
                "tier": 1,
            },
            "revision": 3,
        },
        "anva.get_relationships": {
            "entity_id": UUIDS[11],
            "relationships": [relationship],
        },
        "anva.get_repository_profile": {
            "repository_id": UUIDS[2],
            "organization_id": UUIDS[1],
            "external_id": "github:anva/example",
            "name": "Example",
            "active": True,
            "profile_version": 1,
            "limitations": ["The v1 profile contains identity and activation state."],
        },
        "anva.get_policy_bundle": {"policies": [policy]},
        "anva.get_requirements": {
            "work_item_id": UUIDS[5],
            "revision": 2,
            "requirements": [requirement],
        },
        "anva.explain_assertion": {
            "assertion_id": UUIDS[13],
            "summary": "service:checkout owned_by platform",
            "freshness": "FRESH",
            "is_inferred": False,
            "review_state": "HUMAN_CONFIRMED",
            "sources": [_citation(14)],
        },
        "anva.get_source_excerpt": {
            "chunk_id": UUIDS[7],
            "text": "Public inert source text.",
            "content_hash": SHA256,
            "offset": 0,
            "truncated": False,
            "provenance": {
                "pointer": "/requirements.md",
                "canonical_url": "https://example.test/requirements.md",
                "source_location_id": UUIDS[14],
                "source_observation_id": UUIDS[15],
                "access_snapshot_id": UUIDS[16],
                "observed_at": NOW,
            },
            "trust": "UNTRUSTED_INERT_SOURCE_TEXT",
        },
        "anva.propose_correction": _proposal_data("CORRECTION"),
        "anva.propose_relationship": _proposal_data("RELATIONSHIP"),
        "anva.propose_decision": _proposal_data("DECISION"),
        "anva.submit_work_summary": _proposal_data("WORK_SUMMARY"),
        "anva.submit_preflight_summary": _proposal_data("PREFLIGHT_SUMMARY"),
    }
    paginated = {
        "anva.search",
        "anva.get_relationships",
        "anva.get_policy_bundle",
        "anva.get_requirements",
    }
    return {
        tool_name: {
            "contract_version": "1",
            "tool": tool_name,
            "data": tool_data,
            **({"next_cursor": None} if tool_name in paginated else {}),
        }
        for tool_name, tool_data in data.items()
    }


def _walk_schema(schema: object, *, path: str) -> None:
    assert schema is not True, f"permissive true schema at {path}"
    assert schema is not False, f"uninhabitable false schema at {path}"
    assert isinstance(schema, dict), f"schema must be an object at {path}"
    assert schema, f"empty schema at {path}"
    if schema.get("type") == "object":
        assert schema.get("additionalProperties") is False, f"open object at {path}"
        assert isinstance(schema.get("properties"), dict), f"missing properties at {path}"
    if schema.get("type") == "array":
        assert "items" in schema, f"array without items at {path}"
        assert schema["items"] not in ({}, True, False), f"permissive array items at {path}"
    assert "patternProperties" not in schema
    assert "unevaluatedProperties" not in schema
    for keyword in ("properties", "$defs"):
        values = schema.get(keyword)
        if isinstance(values, dict):
            for name, child in values.items():
                _walk_schema(child, path=f"{path}.{keyword}.{name}")
    if "items" in schema:
        _walk_schema(schema["items"], path=f"{path}.items")
    for keyword in ("oneOf", "anyOf", "allOf"):
        branches = schema.get(keyword)
        if branches is not None:
            assert isinstance(branches, list) and branches, f"empty {keyword} at {path}"
            for index, child in enumerate(branches):
                _walk_schema(child, path=f"{path}.{keyword}[{index}]")
    negated = schema.get("not")
    if negated is not None:
        _walk_schema(negated, path=f"{path}.not")


def _object_paths(value: object, path: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    paths: list[tuple[object, ...]] = []
    if isinstance(value, dict):
        paths.append(path)
        for key, child in value.items():
            paths.extend(_object_paths(child, (*path, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_object_paths(child, (*path, index)))
    return paths


def _inject_at(value: dict[str, object], path: tuple[object, ...]) -> dict[str, object]:
    changed = deepcopy(value)
    target: object = changed
    for part in path:
        if isinstance(part, str):
            assert isinstance(target, dict)
            target = target[part]
        else:
            assert isinstance(part, int)
            assert isinstance(target, list)
            target = target[part]
    assert isinstance(target, dict)
    target["private_oracle"] = {"grader": "must-not-cross-public-boundary"}
    return changed


@pytest.mark.unit
def test_every_mcp_direction_has_a_closed_non_permissive_recursive_schema() -> None:
    assert len(TOOL_CONTRACTS) == 16
    for contract in TOOL_CONTRACTS:
        for direction in ("input_schema", "output_schema"):
            schema = contract[direction]
            Draft202012Validator.check_schema(schema)
            _walk_schema(schema, path=f"{contract['name']}.{direction}")
            assert "$ref" not in str(schema)
            assert "bounded_json_value" not in str(schema)
    for resource in RESOURCE_CONTRACTS:
        for direction in ("input_schema", "output_schema"):
            schema = cast(dict[str, object], resource[direction])
            Draft202012Validator.check_schema(schema)
            _walk_schema(schema, path=f"{resource['name']}.{direction}")


@pytest.mark.unit
def test_generated_mcp_artifact_is_exact_closed_public_runtime_document() -> None:
    artifact = mcp_contract_document()
    rendered = str(artifact).casefold()
    assert "bounded_json_value" not in rendered
    assert "private_oracle" not in rendered
    assert "grader" not in rendered
    for tool in cast(list[dict[str, object]], artifact["tools"]):
        _walk_schema(
            cast(dict[str, object], tool["inputSchema"]),
            path=f"artifact.{tool['name']}.input",
        )
        _walk_schema(
            cast(dict[str, object], tool["outputSchema"]),
            path=f"artifact.{tool['name']}.output",
        )


@pytest.mark.unit
def test_every_tool_validates_concrete_non_empty_input_and_output_instances() -> None:
    inputs = _input_samples()
    outputs = _output_samples()
    assert set(inputs) == set(TOOL_BY_NAME) == set(outputs)
    for name, contract in TOOL_BY_NAME.items():
        Draft202012Validator(contract["input_schema"], format_checker=FormatChecker()).validate(
            inputs[name]
        )
        Draft202012Validator(contract["output_schema"], format_checker=FormatChecker()).validate(
            outputs[name]
        )


@pytest.mark.unit
def test_every_concrete_nested_object_rejects_private_oracle_injection() -> None:
    for name, contract in TOOL_BY_NAME.items():
        for direction, sample in (
            ("input_schema", _input_samples()[name]),
            ("output_schema", _output_samples()[name]),
        ):
            schema = (
                contract["input_schema"]
                if direction == "input_schema"
                else contract["output_schema"]
            )
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            validator.validate(sample)
            for path in _object_paths(sample):
                with pytest.raises(ValidationError):
                    validator.validate(_inject_at(sample, path))


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "public",
        1.5,
        True,
        None,
        ["public", 1, False, None],
        {
            "team": "payments",
            "owner": "platform",
            "rule": "Review is required.",
            "service": "checkout",
            "component": "gateway",
            "name": "Checkout",
            "id": "checkout",
            "status": "ACTIVE",
            "risk": "LOW",
            "text": "Public context",
            "authentication": True,
            "enabled": True,
            "required": True,
        },
    ],
)
def test_public_assertion_value_supports_each_explicit_non_empty_variant(value: object) -> None:
    Draft202012Validator(PUBLIC_ASSERTION_VALUE).validate(value)


@pytest.mark.unit
def test_nested_assertion_json_gets_a_deterministic_closed_public_representation() -> None:
    raw_value = {
        "dependencies": [
            {"tier": 1, "name": "payments"},
            {"name": "ledger", "tier": 2},
        ]
    }
    result: dict[str, object] = {"data": {"packet": {"items": [{"payload": {"value": raw_value}}]}}}

    _reject_private_output_material(result)
    normalized = _normalize_public_output("anva.get_context_packet", result)
    normalized_data = cast(dict[str, object], normalized["data"])
    normalized_packet = cast(dict[str, object], normalized_data["packet"])
    normalized_items = cast(list[dict[str, object]], normalized_packet["items"])
    normalized_payload = cast(dict[str, object], normalized_items[0]["payload"])
    public_value = normalized_payload["value"]

    assert public_value == {
        "format": "CANONICAL_JSON",
        "json": ('{"dependencies":[{"name":"payments","tier":1},{"name":"ledger","tier":2}]}'),
    }
    assert cast(dict[str, object], cast(dict[str, object], result["data"])["packet"])["items"] == [
        {"payload": {"value": raw_value}}
    ]
    Draft202012Validator(PUBLIC_ASSERTION_VALUE).validate(public_value)


@pytest.mark.unit
def test_conflict_side_values_get_the_same_closed_public_representation() -> None:
    raw_left = {"claim": "Current governed claim", "metadata": {"revision": 2}}
    raw_right = {"claim": "Stale contradictory claim", "metadata": {"revision": 1}}
    result: dict[str, object] = {
        "data": {
            "packet": {
                "items": [
                    {
                        "kind": "CONFLICT",
                        "payload": {
                            "left": {"value": raw_left},
                            "right": {"value": raw_right},
                        },
                    }
                ]
            }
        }
    }

    normalized = _normalize_public_output("anva.get_context_packet", result)
    item = cast(
        list[dict[str, object]],
        cast(dict[str, object], cast(dict[str, object], normalized["data"])["packet"])["items"],
    )[0]
    payload = cast(dict[str, object], item["payload"])
    assert cast(dict[str, object], payload["left"])["value"] == {
        "format": "CANONICAL_JSON",
        "json": '{"claim":"Current governed claim","metadata":{"revision":2}}',
    }
    assert cast(dict[str, object], payload["right"])["value"] == {
        "format": "CANONICAL_JSON",
        "json": '{"claim":"Stale contradictory claim","metadata":{"revision":1}}',
    }
    assert result["data"] == {
        "packet": {
            "items": [
                {
                    "kind": "CONFLICT",
                    "payload": {
                        "left": {"value": raw_left},
                        "right": {"value": raw_right},
                    },
                }
            ]
        }
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "public",
        1.5,
        True,
        None,
        ["public", 1, False, None],
        {"team": "payments", "required": True},
    ],
)
def test_native_public_assertion_values_are_not_reencoded(value: object) -> None:
    result: dict[str, object] = {"data": {"packet": {"items": [{"payload": {"value": value}}]}}}
    assert _normalize_public_output("anva.get_context_packet", result) == result


@pytest.mark.unit
def test_public_assertion_value_and_runtime_guard_reject_nested_control_material() -> None:
    validator = Draft202012Validator(PUBLIC_ASSERTION_VALUE)
    with pytest.raises(ValidationError):
        validator.validate({"team": "payments", "private_oracle": {"verdict": "BLOCKED"}})
    with pytest.raises(ValidationError):
        validator.validate([{"oracle": "BLOCKED"}])
    with pytest.raises(MCPGatewayError) as rejected:
        _reject_private_output_material(
            {"data": {"packet": {"items": [{"payload": {"oracle": "BLOCKED"}}]}}}
        )
    assert rejected.value.code == "invalid_tool_output"
    assert rejected.value.reason == "private_control_material"


@pytest.mark.unit
def test_runtime_guard_rejects_nested_credentials_but_allows_public_auth_metadata() -> None:
    _reject_private_output_material({"authorization_hash": SHA256, "access_snapshot_id": UUIDS[1]})
    with pytest.raises(MCPGatewayError) as rejected:
        _reject_private_output_material({"data": {"attributes": {"owner": f"ghp_{'A' * 36}"}}})
    assert rejected.value.reason == "secret_material"
    secret_key = f"ghp_{'B' * 36}"
    with pytest.raises(MCPGatewayError) as rejected_key:
        _reject_private_output_material({"data": {"attributes": {secret_key: "owner"}}})
    assert rejected_key.value.reason == "secret_material"
    assert secret_key not in str(rejected_key.value)
