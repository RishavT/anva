"""Fail-closed public acceptance case loading and binding tests."""

from __future__ import annotations

import base64
import json
import re
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
from anva.contracts.bootstrap_scope import ACCEPTANCE_INITIATOR_ACTIONS
from anva.contracts.catalog import EXAMPLES, SCHEMAS
from anva.contracts.validation import ContractValidationError, contract_input_byte_limit


def _case() -> dict[str, object]:
    return deepcopy(EXAMPLES["acceptance-case"])


def _set_check_code(case: dict[str, object], code: str) -> None:
    assurance = cast(dict[str, object], case["assurance"])
    checks = cast(list[dict[str, object]], assurance["deterministic_checks"])
    checks[0]["code"] = code


def _add_policy_only_check(case: dict[str, object]) -> None:
    policy = cast(dict[str, object], case["policy"])
    requirements = cast(list[dict[str, object]], policy["requirements"])
    requirements.append({**requirements[0], "code": "POLICY_ONLY"})
    _set_check_code(case, "POLICY_ONLY")


@pytest.mark.unit
def test_case_declares_exact_acceptance_principal_actions() -> None:
    case = _case()
    organization = cast(dict[str, object], case["organization"])
    scope = cast(dict[str, object], organization["bootstrap_scope"])
    identities = {
        cast(str, identity["key"]): identity
        for identity in cast(list[dict[str, object]], scope["service_identities"])
    }
    initiator_grants = cast(list[dict[str, object]], identities["initiator"]["grants"])
    reviewer_grants = cast(list[dict[str, object]], identities["reviewer"]["grants"])

    assert cast(list[str], initiator_grants[0]["actions"]) == [
        "artifact.create",
        "artifact.view",
        "assurance.execute",
        "canvas.view",
        "evidence.submit",
        "evidence.view",
        "knowledge.view",
        "mcp.context",
        "policy.manage",
        "policy.view",
        "search.query",
        "source.sync",
        "source.view",
        "work.manage",
    ]
    assert cast(list[str], reviewer_grants[0]["actions"]) == ["assurance.review"]


@pytest.mark.unit
def test_runbook_declares_exact_acceptance_initiator_actions() -> None:
    runbook = (Path(__file__).parents[2] / "docs/runbooks/acceptance-corpus.md").read_text()
    paragraph = runbook.split("initiator has only the actions needed", 1)[1].split(
        ") on that repository",
        1,
    )[0]
    documented_actions = {value for value in re.findall(r"`([^`]+)`", paragraph) if "." in value}

    assert documented_actions == set(ACCEPTANCE_INITIATOR_ACTIONS)


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
@pytest.mark.parametrize(
    ("mutate", "code", "path", "reference"),
    [
        (
            lambda case: cast(dict[str, object], case["evidence"]).update(
                {"criterion_codes": ["ORPHAN_EVIDENCE"]}
            ),
            "acceptance_evidence_criterion_not_governed",
            "evidence.criterion_codes",
            "work_item.acceptance_criteria[].code",
        ),
        (
            lambda case: _set_check_code(case, "ORPHAN_CHECK"),
            "acceptance_check_policy_not_governed",
            "assurance.deterministic_checks[].code",
            "policy.requirements[].code",
        ),
        (
            _add_policy_only_check,
            "acceptance_check_criterion_not_governed",
            "assurance.deterministic_checks[].code",
            "work_item.acceptance_criteria[].code",
        ),
    ],
)
def test_case_governance_diagnostics_identify_each_cross_section_failure(
    mutate: Callable[[dict[str, object]], object],
    code: str,
    path: str,
    reference: str,
) -> None:
    case = _case()
    mutate(case)

    with pytest.raises(AcceptanceCaseError) as captured:
        acceptance_case(case)

    assert captured.value.diagnostic() == {
        "code": code,
        "message": str(captured.value),
        "path": path,
        "reference": reference,
    }


@pytest.mark.unit
def test_case_accepts_codes_governed_by_both_work_and_policy() -> None:
    validated = acceptance_case(_case())

    assert validated.case_id == "tst-009.scn-ember"


@pytest.mark.unit
@pytest.mark.parametrize(
    "unified_diff",
    [
        (
            "diff --git a/src/a.py b/src/a.py\n"
            "--- a/src/a.py\n"
            "+++ b/src/a.py\n"
            "@@ -18,7 +18,9 @@ def deliver(row, gateway, store, now):\n"
            + "".join(f" line {index}\n" for index in range(13))
            + "+extra one\n+extra two\n"
        ),
        (
            "diff --git a/src/a.py b/src/a.py\n"
            "--- a/src/a.py\n"
            "+++ b/src/a.py\n"
            "@@ -1 +1 @@\n"
            " unchanged\n"
        ),
    ],
)
def test_case_rejects_diff_that_runtime_ingestion_rejects(unified_diff: str) -> None:
    case = _case()
    cast(dict[str, object], case["change"])["unified_diff"] = unified_diff

    with pytest.raises(AcceptanceCaseError) as captured:
        acceptance_case(case)

    assert captured.value.diagnostic() == {
        "code": "acceptance_case_diff_invalid",
        "message": "Acceptance case unified diff is invalid: " + str(captured.value.__cause__),
        "path": "change.unified_diff",
        "reference": "manual-diff ingestion",
    }
    assert captured.value.schema_valid is True


@pytest.mark.unit
@pytest.mark.parametrize(
    ("section", "field", "message"),
    [
        ("work_item", "requirements", "requirement codes must be unique"),
        ("work_item", "acceptance_criteria", "criterion codes must be unique"),
        ("policy", "requirements", "policy requirement codes must be unique"),
    ],
)
def test_case_rejects_duplicate_governance_codes(section: str, field: str, message: str) -> None:
    case = _case()
    container = cast(dict[str, object], case[section])
    entries = cast(list[dict[str, object]], container[field])
    entries.append({**entries[0]})

    with pytest.raises(AcceptanceCaseError, match=message):
        acceptance_case(case)


@pytest.mark.unit
def test_case_rejects_orphaned_work_requirement_reference() -> None:
    case = _case()
    work = cast(dict[str, object], case["work_item"])
    criteria = cast(list[dict[str, object]], work["acceptance_criteria"])
    criteria[0]["requirement_code"] = "MISSING_REQUIREMENT"

    with pytest.raises(AcceptanceCaseError, match="unknown requirement"):
        acceptance_case(case)


@pytest.mark.unit
@pytest.mark.parametrize(
    "mutation",
    [
        lambda scope: scope.pop("service_identities"),
        lambda scope: scope.update({"unexpected": []}),
        lambda scope: scope["roles"].append(dict(scope["roles"][0])),
        lambda scope: scope["memberships"][0].update({"role_key": "missing"}),
        lambda scope: scope["service_identities"][0]["grants"][0]["actions"].append(
            "github.manage"
        ),
        lambda scope: scope["service_identities"][1]["grants"][0]["actions"].append(
            "assurance.view"
        ),
        lambda scope: scope["access_scope"].update({"service_identity_keys": ["initiator"]}),
    ],
)
def test_case_rejects_omitted_extra_duplicate_or_overprivileged_scope(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    case = _case()
    organization = cast(dict[str, object], case["organization"])
    scope = cast(dict[str, object], organization["bootstrap_scope"])
    mutation(scope)

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
def test_valid_multibyte_diff_stays_inside_loader_byte_limit(tmp_path: Path) -> None:
    accepted = _case()
    cast(dict[str, object], accepted["change"])["unified_diff"] = (
        "diff --git a/a.py b/a.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/a.py\n"
        "@@ -0,0 +1 @@\n+" + "💡" * 90_000 + "\n"
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

    assert (
        len(cast(str, cast(dict[str, object], accepted["change"])["unified_diff"]))
        < MAX_ACCEPTANCE_UNIFIED_DIFF_CHARACTERS
    )

    cumulative = deepcopy(accepted)
    cast(dict[str, object], cumulative["change"])["description"] = "💡" * 50_000
    cast(dict[str, object], cumulative["change"])["affected_paths"] = [
        f"{index:04d}" + "💡" * 496 for index in range(200)
    ]
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
