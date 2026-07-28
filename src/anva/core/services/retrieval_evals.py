"""Offline, deterministic retrieval evaluation with leakage-aware metrics."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from anva.core.services.context import ActorContext
from anva.core.services.search import SearchResult, search_chunks


@dataclass(frozen=True, slots=True)
class RetrievalEvalCase:
    case_id: str
    repository_id: uuid.UUID
    query: str
    phase: str | None
    expected_content_hashes: frozenset[str]
    prohibited_content_hashes: frozenset[str]
    stale_content_hashes: frozenset[str]
    limit: int = 20


@dataclass(frozen=True, slots=True)
class RetrievalEvalMetrics:
    cases: int
    recall_at_k: float
    precision_at_k: float
    prohibited_leakage_rate: float
    stale_preference_rate: float
    citation_coverage: float

    def as_dict(self) -> dict[str, int | float]:
        return {
            "cases": self.cases,
            "recall_at_k": self.recall_at_k,
            "precision_at_k": self.precision_at_k,
            "prohibited_leakage_rate": self.prohibited_leakage_rate,
            "stale_preference_rate": self.stale_preference_rate,
            "citation_coverage": self.citation_coverage,
        }


def load_eval_cases(path: Path) -> tuple[RetrievalEvalCase, ...]:
    """Load a bounded JSONL fixture without executing untrusted content."""
    cases: list[RetrievalEvalCase] = []
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        if not raw_line.strip():
            continue
        if len(raw_line) > 100_000:
            raise ValueError(f"eval line {line_number} is too large")
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise ValueError(f"eval line {line_number} must be an object")
        cases.append(
            RetrievalEvalCase(
                case_id=str(payload["case_id"]),
                repository_id=uuid.UUID(str(payload["repository_id"])),
                query=str(payload["query"]),
                phase=str(payload["phase"]) if payload.get("phase") else None,
                expected_content_hashes=frozenset(
                    str(value) for value in payload.get("expected_content_hashes", [])
                ),
                prohibited_content_hashes=frozenset(
                    str(value) for value in payload.get("prohibited_content_hashes", [])
                ),
                stale_content_hashes=frozenset(
                    str(value) for value in payload.get("stale_content_hashes", [])
                ),
                limit=int(payload.get("limit", 20)),
            )
        )
        if len(cases) > 10_000:
            raise ValueError("eval fixture exceeds 10000 cases")
    return tuple(cases)


def _has_citation(result: SearchResult) -> bool:
    return bool(
        result.canonical_url
        and result.content_hash
        and result.source_location_id
        and result.source_observation_id
        and result.access_snapshot_id
    )


def run_retrieval_eval(
    *,
    actor: ActorContext,
    cases: tuple[RetrievalEvalCase, ...],
) -> RetrievalEvalMetrics:
    """Evaluate live permission-first search with reproducible aggregate metrics."""
    if not cases:
        return RetrievalEvalMetrics(0, 0.0, 0.0, 0.0, 0.0, 0.0)
    recall_total = 0.0
    precision_total = 0.0
    leakage_cases = 0
    stale_preference_cases = 0
    citation_hits = 0
    result_count = 0
    for case in cases:
        response = search_chunks(
            actor=actor,
            repository_id=case.repository_id,
            query=case.query,
            phase=case.phase,
            limit=case.limit,
        )
        returned = [result.content_hash for result in response.results]
        returned_set = set(returned)
        relevant = returned_set & case.expected_content_hashes
        if case.expected_content_hashes:
            recall_total += len(relevant) / len(case.expected_content_hashes)
        else:
            recall_total += 1.0
        precision_total += len(relevant) / len(returned) if returned else 0.0
        if returned_set & case.prohibited_content_hashes:
            leakage_cases += 1
        current_positions = [
            index
            for index, content_hash in enumerate(returned)
            if content_hash in case.expected_content_hashes
        ]
        stale_positions = [
            index
            for index, content_hash in enumerate(returned)
            if content_hash in case.stale_content_hashes
        ]
        if stale_positions and (
            not current_positions or min(stale_positions) < min(current_positions)
        ):
            stale_preference_cases += 1
        citation_hits += sum(_has_citation(result) for result in response.results)
        result_count += len(response.results)
    case_count = len(cases)
    return RetrievalEvalMetrics(
        cases=case_count,
        recall_at_k=recall_total / case_count,
        precision_at_k=precision_total / case_count,
        prohibited_leakage_rate=leakage_cases / case_count,
        stale_preference_rate=stale_preference_cases / case_count,
        citation_coverage=citation_hits / result_count if result_count else 1.0,
    )
