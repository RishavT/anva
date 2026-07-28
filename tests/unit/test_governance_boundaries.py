"""Unit coverage for deterministic matching and hostile manifest boundaries."""

from __future__ import annotations

from copy import deepcopy

import pytest

from anva.contracts import ContractValidationError, validate_payload
from anva.contracts.catalog import EXAMPLES
from anva.core.services.evidence import validate_source_url
from anva.core.services.hostile_inputs import (
    reject_secrets,
    validate_full_commit,
    validate_relative_artifact_path,
)
from anva.core.services.policies import path_pattern_matches


@pytest.mark.unit
def test_versioned_posix_glob_has_stable_separator_semantics() -> None:
    assert path_pattern_matches("src/**/*.py", "src/anva/core/models.py")
    assert path_pattern_matches("src/*.py", "src/models.py")
    assert not path_pattern_matches("src/*.py", "src/anva/models.py")
    assert not path_pattern_matches("docs/**", "src/anva/models.py")


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    ["/etc/passwd", "../secret", "artifacts/../secret", r"artifacts\secret", "a//b"],
)
def test_unsafe_artifact_paths_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="Artifact reference"):
        validate_relative_artifact_path(value)


@pytest.mark.unit
def test_only_full_lowercase_commit_is_accepted() -> None:
    validate_full_commit("a" * 40)
    for invalid in ("a" * 7, "A" * 40, "a" * 39, "g" * 40):
        with pytest.raises(ValueError, match="full 40-character"):
            validate_full_commit(invalid)


@pytest.mark.unit
def test_secret_canaries_are_rejected_before_persistence() -> None:
    with pytest.raises(ValueError, match="credential material"):
        reject_secrets({"command": "curl -H 'Authorization: Bearer secret-value'"})
    with pytest.raises(ValueError, match="secret-bearing field"):
        reject_secrets({"access_token": "plain"})


@pytest.mark.unit
def test_evidence_contract_rejects_traversal_and_abbreviated_commits() -> None:
    traversal = deepcopy(EXAMPLES["evidence-manifest"])
    traversal["entries"][0]["artifact_reference"] = "../result.json"  # type: ignore[index]
    with pytest.raises(ContractValidationError, match="artifact_reference"):
        validate_payload("evidence-manifest", traversal)

    abbreviated = deepcopy(EXAMPLES["evidence-manifest"])
    abbreviated["commit_sha"] = "a" * 7
    with pytest.raises(ContractValidationError, match="commit_sha"):
        validate_payload("evidence-manifest", abbreviated)


@pytest.mark.unit
def test_work_contract_rejects_unknown_required_evidence_types() -> None:
    payload = deepcopy(EXAMPLES["work-item-import"])
    payload["acceptance_criteria"][0]["required_evidence_types"] = [  # type: ignore[index]
        "CLAIMED_BY_PROSE"
    ]

    with pytest.raises(ContractValidationError, match="required_evidence_types"):
        validate_payload("work-item-import", payload)


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "file:///etc/passwd",
        "https://user:password@example.test/result",
        "https://example.test/result?access_token=secret",
    ],
)
def test_evidence_source_url_rejects_unsafe_or_secret_bearing_urls(value: str) -> None:
    with pytest.raises(ValueError, match="source_url"):
        validate_source_url(value)
