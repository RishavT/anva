"""Fail-closed public acceptance case loading and binding tests."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from anva.acceptance.case import (
    MAX_CASE_BYTES,
    AcceptanceCaseError,
    acceptance_case,
    load_acceptance_case,
)
from anva.contract_limits import (
    ACCEPTANCE_CASE_BYTE_LIMIT_SCOPE,
    ACCEPTANCE_CASE_ENCODING,
    ACCEPTANCE_CASE_MEDIA_TYPE,
    ACCEPTANCE_CASE_SERIALIZATION,
    MAX_ACCEPTANCE_UNIFIED_DIFF_CHARACTERS,
)
from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.validation import ContractValidationError, contract_input_byte_limit


def _case() -> dict[str, object]:
    return deepcopy(EXAMPLES["acceptance-case"])


@pytest.mark.unit
def test_case_hash_is_canonical_and_distinguishes_material_inputs() -> None:
    first = _case()
    reordered = dict(reversed(list(first.items())))
    second = _case()
    second["case_id"] = "tst-009.scn-lantern"

    assert acceptance_case(first).sha256 == acceptance_case(reordered).sha256
    assert acceptance_case(first).sha256 != acceptance_case(second).sha256


@pytest.mark.unit
@pytest.mark.parametrize(
    "mutation",
    [
        lambda case: case.update({"unknown": True}),
        lambda case: cast(dict[str, object], case["change"]).update(
            {"head_commit": cast(dict[str, object], case["change"])["base_commit"]}
        ),
        lambda case: cast(dict[str, object], case["evidence"]).update(
            {"criterion_codes": ["UNKNOWN_CRITERION"]}
        ),
        lambda case: cast(dict[str, object], case["evidence"]).update({"kind": "SECURITY_SCAN"}),
        lambda case: cast(dict[str, object], case["evidence"]).update({"content_base64": "%%%%"}),
    ],
)
def test_case_rejects_unknown_or_cross_pinned_material(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    case = _case()
    mutation(case)

    with pytest.raises((AcceptanceCaseError, ContractValidationError)):
        acceptance_case(case)


@pytest.mark.unit
def test_case_rejects_recursive_private_markers_even_in_public_text() -> None:
    case = _case()
    cast(dict[str, object], case["work_item"])["summary"] = (
        "Attempt to smuggle oracle_label through an otherwise public field."
    )

    with pytest.raises(AcceptanceCaseError, match="private evaluation material"):
        acceptance_case(case)


@pytest.mark.unit
def test_case_rejects_json_evidence_for_a_different_head() -> None:
    case = _case()
    evidence = cast(dict[str, object], case["evidence"])
    evidence["content_base64"] = base64.b64encode(
        json.dumps(
            {
                "checks": [{"name": "TESTS_PASS", "status": "PASSED"}],
                "head_sha": "f" * 40,
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).decode()

    with pytest.raises(AcceptanceCaseError, match="exact head"):
        acceptance_case(case)


@pytest.mark.unit
def test_case_loader_rejects_links_oversize_and_unsafe_source_paths(tmp_path: Path) -> None:
    valid = tmp_path / "case.json"
    valid.write_text(json.dumps(_case()), encoding="utf-8")
    assert load_acceptance_case(valid).case_id == "tst-009.scn-ember"

    link = tmp_path / "linked.json"
    link.symlink_to(valid)
    with pytest.raises(AcceptanceCaseError, match="unsafe"):
        load_acceptance_case(link)

    linked_directory = tmp_path / "linked-directory"
    actual_directory = tmp_path / "actual-directory"
    actual_directory.mkdir()
    nested = actual_directory / "case.json"
    nested.write_text(json.dumps(_case()), encoding="utf-8")
    linked_directory.symlink_to(actual_directory, target_is_directory=True)
    with pytest.raises(AcceptanceCaseError, match="unsafe"):
        load_acceptance_case(linked_directory / "case.json")

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * MAX_CASE_BYTES + b"}")
    with pytest.raises(AcceptanceCaseError, match="unsafe|bound"):
        load_acceptance_case(oversized)

    traversal = _case()
    cast(dict[str, object], traversal["semantic_assertions"])["source_paths"] = [
        "../private/oracle.json"
    ]
    with pytest.raises(ContractValidationError):
        acceptance_case(traversal)


@pytest.mark.unit
def test_case_input_metadata_exposes_loader_wire_semantics() -> None:
    input_metadata = cast(dict[str, object], SCHEMAS["acceptance-case"]["x-anva-input"])
    byte_limit = cast(dict[str, object], input_metadata["byte_limit"])

    assert input_metadata == {
        "media_type": ACCEPTANCE_CASE_MEDIA_TYPE,
        "encoding": ACCEPTANCE_CASE_ENCODING,
        "serialization": ACCEPTANCE_CASE_SERIALIZATION,
        "byte_limit": {
            "maximum": MAX_CASE_BYTES,
            "applies_to": ACCEPTANCE_CASE_BYTE_LIMIT_SCOPE,
            "includes": ["insignificant-whitespace", "escape-sequences"],
        },
    }
    assert byte_limit["maximum"] == contract_input_byte_limit("acceptance-case")


@pytest.mark.unit
def test_multibyte_diff_schema_bound_stays_inside_loader_byte_limit(tmp_path: Path) -> None:
    accepted = _case()
    cast(dict[str, object], accepted["change"])["unified_diff"] = (
        "💡" * MAX_ACCEPTANCE_UNIFIED_DIFF_CHARACTERS
    )
    path = tmp_path / "multibyte-case.json"
    path.write_text(json.dumps(accepted, ensure_ascii=False), encoding="utf-8")

    assert path.stat().st_size < MAX_CASE_BYTES
    assert load_acceptance_case(path).case_id == accepted["case_id"]

    schema = SCHEMAS["acceptance-case"]
    escaped_path = tmp_path / "escaped-multibyte-case.json"
    escaped_path.write_text(json.dumps(accepted), encoding="utf-8")
    Draft202012Validator(schema).validate(accepted)
    assert escaped_path.stat().st_size > MAX_CASE_BYTES
    with pytest.raises(AcceptanceCaseError, match="unsafe|bound"):
        load_acceptance_case(escaped_path)

    cumulative = deepcopy(accepted)
    cast(dict[str, object], cumulative["change"])["description"] = "💡" * 50_000
    cast(dict[str, object], cumulative["work_item"])["summary"] = "💡" * 20_000
    cast(dict[str, object], cumulative["retrieval"])["context_task"] = "💡" * 2_000
    cast(dict[str, object], cumulative["evidence"])["limitations"] = [
        "💡" * 2_000 for _index in range(20)
    ]
    Draft202012Validator(schema).validate(cumulative)
    cumulative_path = tmp_path / "cumulative-multibyte-case.json"
    cumulative_path.write_text(json.dumps(cumulative, ensure_ascii=False), encoding="utf-8")
    assert cumulative_path.stat().st_size > MAX_CASE_BYTES
    with pytest.raises(AcceptanceCaseError, match="unsafe|bound"):
        load_acceptance_case(cumulative_path)

    rejected = _case()
    cast(dict[str, object], rejected["change"])["unified_diff"] = "é" * 500_000
    with pytest.raises(ContractValidationError):
        acceptance_case(rejected)


@pytest.mark.unit
def test_loader_counts_whitespace_and_requires_declared_encoding(tmp_path: Path) -> None:
    case = _case()
    schema = SCHEMAS["acceptance-case"]
    Draft202012Validator(schema).validate(case)
    encoded = json.dumps(case, ensure_ascii=False).encode(ACCEPTANCE_CASE_ENCODING)

    padded_path = tmp_path / "whitespace-padded-case.json"
    padded_path.write_bytes(encoded + b" " * (MAX_CASE_BYTES - len(encoded) + 1))
    assert padded_path.stat().st_size == MAX_CASE_BYTES + 1
    with pytest.raises(AcceptanceCaseError, match="unsafe|bound"):
        load_acceptance_case(padded_path)

    wrong_encoding_path = tmp_path / "utf-16-case.json"
    wrong_encoding_path.write_bytes(json.dumps(case).encode("utf-16"))
    with pytest.raises(AcceptanceCaseError, match="invalid JSON"):
        load_acceptance_case(wrong_encoding_path)


@pytest.mark.unit
def test_runner_has_no_embedded_legacy_pr_numbers() -> None:
    runner_source = (Path(__file__).parents[2] / "src/anva/acceptance/runner.py").read_text()
    assert "817" not in runner_source
    assert "818" not in runner_source
