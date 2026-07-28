"""Deterministic retrieval evaluation fixture and metric tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from anva.core.services.context import ActorContext
from anva.core.services.ranking import RankingExplanation
from anva.core.services.retrieval_evals import (
    RetrievalEvalCase,
    load_eval_cases,
    run_retrieval_eval,
)
from anva.core.services.search import SearchResponse, SearchResult


def _result(content_hash: str) -> SearchResult:
    return SearchResult(
        chunk_id=uuid.uuid4(),
        text="policy",
        content_hash=content_hash,
        pointer="/policy",
        canonical_url="https://example.test/policy",
        source_location_id=uuid.uuid4(),
        source_observation_id=uuid.uuid4(),
        access_snapshot_id=uuid.uuid4(),
        observed_at=datetime(2026, 7, 28, tzinfo=UTC),
        explanation=RankingExplanation(1, 1, 0.1, "PREFLIGHT", ("policy",)),
    )


def test_checked_in_retrieval_eval_fixture_is_bounded_and_parseable() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "retrieval-eval.jsonl"
    cases = load_eval_cases(fixture)

    assert len(cases) == 1
    assert cases[0].case_id == "policy-preflight"
    assert cases[0].limit == 10


def test_retrieval_eval_reports_quality_leakage_staleness_and_citations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "a" * 64
    prohibited = "b" * 64
    stale = "c" * 64
    responses = iter(
        (
            SearchResponse("first", "d" * 64, (_result(expected),)),
            SearchResponse(
                "second",
                "e" * 64,
                (_result(stale), _result(expected), _result(prohibited)),
            ),
        )
    )
    monkeypatch.setattr(
        "anva.core.services.retrieval_evals.search_chunks",
        lambda **_kwargs: next(responses),
    )
    repository_id = uuid.uuid4()
    cases = (
        RetrievalEvalCase(
            "good",
            repository_id,
            "policy",
            "PREFLIGHT",
            frozenset({expected}),
            frozenset({prohibited}),
            frozenset({stale}),
            10,
        ),
        RetrievalEvalCase(
            "leak-and-stale",
            repository_id,
            "policy",
            "PREFLIGHT",
            frozenset({expected}),
            frozenset({prohibited}),
            frozenset({stale}),
            10,
        ),
    )
    actor = ActorContext(
        organization_id=uuid.uuid4(),
        actor_type="SERVICE",
        actor_id="retrieval-eval",
        authorization_path="test",
        request_id=uuid.uuid4(),
        repository_id=repository_id,
    )

    metrics = run_retrieval_eval(actor=actor, cases=cases)

    assert metrics.recall_at_k == 1.0
    assert metrics.precision_at_k == (1.0 + 1 / 3) / 2
    assert metrics.prohibited_leakage_rate == 0.5
    assert metrics.stale_preference_rate == 0.5
    assert metrics.citation_coverage == 1.0
