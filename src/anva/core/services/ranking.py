"""Stable retrieval scoring constants and phase-aware explanations."""

from __future__ import annotations

from dataclasses import dataclass

RRF_K = 60
RETRIEVAL_ALGORITHM_VERSION = "permission-first-rrf-v1"

PHASE_TERMS: dict[str, tuple[str, ...]] = {
    "PREPARE": ("requirement", "policy", "decision", "owner", "dependency"),
    "BUILD": ("component", "api", "pattern", "dependency", "decision"),
    "PREFLIGHT": ("policy", "check", "risk", "incident", "requirement"),
    "ASSURANCE": ("evidence", "policy", "incident", "control", "decision"),
}


@dataclass(frozen=True, slots=True)
class RankingExplanation:
    """Machine-readable explanation of a selected retrieval candidate."""

    lexical_rank: int | None
    semantic_rank: int | None
    reciprocal_rank_score: float
    phase: str | None
    phase_terms: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "lexical_rank": self.lexical_rank,
            "semantic_rank": self.semantic_rank,
            "reciprocal_rank_score": self.reciprocal_rank_score,
            "phase": self.phase,
            "phase_terms": list(self.phase_terms),
        }


def phase_terms(phase: str | None) -> tuple[str, ...]:
    """Return a stable, bounded term preference for a retrieval phase."""
    if phase is None:
        return ()
    return PHASE_TERMS.get(phase.upper(), ())
