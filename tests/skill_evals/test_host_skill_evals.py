"""Deterministic grading for host-specific skill traces and safety behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from anva.skills.evals import evaluate_fixture

FIXTURES = Path(__file__).parents[1] / "fixtures" / "skill-evals"


@pytest.mark.skill_eval
@pytest.mark.parametrize("host", ["codex", "claude"])
@pytest.mark.parametrize(
    "scenario",
    [
        "messy-knowledge",
        "prompt-injection",
        "scope-expansion",
        "revoked-source",
        "unreachable-anva",
        "read-only",
        "preflight-advisory",
        "proposal-idempotency",
    ],
)
def test_host_fixture_meets_grounding_scope_and_safety_contract(
    host: str,
    scenario: str,
) -> None:
    result = evaluate_fixture(FIXTURES / f"{scenario}.json", host=host)
    assert result.passed, result.failures


@pytest.mark.skill_eval
@pytest.mark.parametrize(
    "scenario",
    [
        "messy-knowledge",
        "prompt-injection",
        "scope-expansion",
        "revoked-source",
        "unreachable-anva",
        "read-only",
        "preflight-advisory",
        "proposal-idempotency",
    ],
)
def test_codex_and_claude_fixture_semantics_are_equivalent(scenario: str) -> None:
    codex = evaluate_fixture(FIXTURES / f"{scenario}.json", host="codex")
    claude = evaluate_fixture(FIXTURES / f"{scenario}.json", host="claude")
    assert codex.semantic_digest == claude.semantic_digest
