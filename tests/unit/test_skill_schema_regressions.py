"""Negative schema cases for material claims and review-only proposals."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from anva.skills.contracts import SkillContractError, validate_skill_output

FIXTURES = Path(__file__).parents[1] / "fixtures" / "skill-evals"


def _fixture_output(name: str) -> dict[str, object]:
    payload = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    output = payload["structured_output"]
    assert isinstance(output, dict)
    return output


@pytest.mark.unit
def test_prepare_rejects_uuid_invocation_as_material_provenance() -> None:
    malicious = {
        "status": "GROUNDED",
        "problem": "Ship a material access-control change",
        "facts": [
            {
                "summary": "The organization requires MFA.",
                "material": True,
                "source_refs": ["7aa9c30c-0774-4e61-98ef-93d8d551be9f"],
            }
        ],
        "requirements": [],
        "out_of_scope": [],
        "assumptions": [],
        "conflicts": [],
        "acceptance_criteria": [],
        "affected_systems_and_owners": [],
        "decisions_and_policies": [],
        "implementation_plan": [],
        "verification_plan": [],
        "unresolved_questions": [],
        "limitations": [],
        "anva_sources": [],
    }

    with pytest.raises(SkillContractError, match="output|provenance"):
        validate_skill_output("anva-prepare", malicious)


@pytest.mark.unit
def test_learn_rejects_contradictory_or_untraceable_proposed_state() -> None:
    contradictory = {
        "proposal_type": "update",
        "target": {},
        "proposed_content": {},
        "rationale": "Update organizational guidance.",
        "source_references": [],
        "explicit_approval": False,
        "submission_status": "PROPOSED",
        "review_state": "DRAFT",
        "approved": False,
        "review_required": False,
        "limitations": [],
    }

    with pytest.raises(SkillContractError, match="output"):
        validate_skill_output("anva-learn", contradictory)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("workflow", "fixture", "array_field"),
    [
        ("anva-prepare", "messy-knowledge", "requirements"),
        ("anva-build", "prompt-injection", "scope"),
        ("anva-preflight", "preflight-advisory", "checks"),
        ("anva-learn", "proposal-idempotency", "limitations"),
    ],
)
def test_every_output_schema_rejects_untyped_array_items(
    workflow: str,
    fixture: str,
    array_field: str,
) -> None:
    output = _fixture_output(fixture)
    validate_skill_output(workflow, output)
    malicious = copy.deepcopy(output)
    items = malicious[array_field]
    assert isinstance(items, list)
    items.append("untyped item")

    with pytest.raises(SkillContractError, match="output"):
        validate_skill_output(workflow, malicious)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", "not-an-absolute-url"),
        ("content_hash", "invocation-uuid-not-a-content-hash"),
        ("observed_at", "not-a-timestamp"),
    ],
)
def test_normalized_sources_require_url_hash_and_observation_time(
    field: str,
    value: str,
) -> None:
    malicious = _fixture_output("messy-knowledge")
    sources = malicious["anva_sources"]
    assert isinstance(sources, list)
    first = sources[0]
    assert isinstance(first, dict)
    first[field] = value

    with pytest.raises(SkillContractError, match="output"):
        validate_skill_output("anva-prepare", malicious)


@pytest.mark.unit
def test_source_reference_must_resolve_to_normalized_source() -> None:
    malicious = _fixture_output("prompt-injection")
    scope = malicious["scope"]
    assert isinstance(scope, list)
    first = scope[0]
    assert isinstance(first, dict)
    first["source_refs"] = ["S2"]

    with pytest.raises(SkillContractError, match="normalized provenance"):
        validate_skill_output("anva-build", malicious)


@pytest.mark.unit
def test_duplicate_source_reference_with_mismatched_identity_is_rejected() -> None:
    output = _fixture_output("messy-knowledge")
    sources = output["anva_sources"]
    assert isinstance(sources, list)
    duplicate = copy.deepcopy(sources[0])
    assert isinstance(duplicate, dict)
    duplicate["url"] = "https://knowledge.invalid/different-identity"
    sources.append(duplicate)

    with pytest.raises(SkillContractError, match="source references must be unique"):
        validate_skill_output("anva-prepare", output)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("fixture", "workflow", "source_ref", "url", "locator", "content_hash"),
    [
        (
            "prompt-injection",
            "anva-build",
            "S2",
            "https://knowledge.invalid/notes/original-hostile",
            "payload/original",
            "9" * 64,
        ),
        (
            "messy-knowledge",
            "anva-prepare",
            "S3",
            "https://knowledge.invalid/reference/benign-but-irrelevant",
            "appendix/unrelated",
            "8" * 64,
        ),
        (
            "messy-knowledge",
            "anva-prepare",
            "S4",
            "https://knowledge.invalid/notes/novel-hostile",
            "injection/novel",
            "7" * 64,
        ),
    ],
)
def test_normalized_sources_are_exactly_the_referenced_minimal_closure(
    fixture: str,
    workflow: str,
    source_ref: str,
    url: str,
    locator: str,
    content_hash: str,
) -> None:
    output = _fixture_output(fixture)
    sources = output["anva_sources"]
    assert isinstance(sources, list)
    sources.append(
        {
            "source_ref": source_ref,
            "url": url,
            "locator": locator,
            "content_hash": content_hash,
            "observed_at": "2026-07-31T00:00:00Z",
        }
    )

    with pytest.raises(SkillContractError, match="not referenced by retained material"):
        validate_skill_output(workflow, output)


@pytest.mark.unit
def test_invocation_identifiers_do_not_satisfy_source_reference_closure() -> None:
    output = _fixture_output("prompt-injection")
    sources = output["anva_sources"]
    assert isinstance(sources, list)
    sources.append(
        {
            "source_ref": "S2",
            "url": "https://knowledge.invalid/notes/irrelevant",
            "locator": "packet/invocation-only",
            "content_hash": "6" * 64,
            "observed_at": "2026-07-31T00:00:00Z",
        }
    )
    assumptions = output["assumptions"]
    assert isinstance(assumptions, list)
    assumptions.append(
        {
            "summary": "Invocation packet_id S2 and tool_invocation_id S2 were recorded.",
            "basis": "TOOL",
            "material": False,
        }
    )

    with pytest.raises(SkillContractError, match="not referenced by retained material"):
        validate_skill_output("anva-build", output)


@pytest.mark.unit
def test_original_v2_native_orphan_output_is_rejected_by_runtime_validation() -> None:
    original = (
        Path(__file__).parents[2]
        / "docs"
        / "evidence"
        / "issue-010"
        / "native-v2-a55dc7f-20260730"
        / "runs"
        / "claude"
        / "structured-output.json"
    )
    output = json.loads(original.read_text(encoding="utf-8"))

    with pytest.raises(SkillContractError, match="not referenced by retained material"):
        validate_skill_output("anva-prepare", output)


@pytest.mark.unit
def test_learn_preview_and_nested_objects_are_closed_and_exact() -> None:
    output = _fixture_output("proposal-idempotency")
    mismatched = copy.deepcopy(output)
    preview = mismatched["preview"]
    assert isinstance(preview, dict)
    preview["rationale"] = "Different from the submitted proposal."
    with pytest.raises(SkillContractError, match="preview"):
        validate_skill_output("anva-learn", mismatched)

    unknown = copy.deepcopy(output)
    target = unknown["target"]
    assert isinstance(target, dict)
    target["invocation_id"] = "7aa9c30c-0774-4e61-98ef-93d8d551be9f"
    with pytest.raises(SkillContractError, match="output"):
        validate_skill_output("anva-learn", unknown)
