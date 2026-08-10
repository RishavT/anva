"""Fail-closed public acceptance case loading and binding tests."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from anva.acceptance.case import (
    MAX_CASE_BYTES,
    AcceptanceCaseError,
    acceptance_case,
    load_acceptance_case,
)
from anva.contracts.catalog import EXAMPLES
from anva.contracts.validation import ContractValidationError


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
def test_runner_has_no_embedded_legacy_pr_numbers() -> None:
    runner_source = (Path(__file__).parents[2] / "src/anva/acceptance/runner.py").read_text()
    assert "817" not in runner_source
    assert "818" not in runner_source
