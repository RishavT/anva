"""Public semantic rules that Draft 2020-12 cannot express for acceptance cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class AcceptanceCaseGovernanceRule:
    """One cross-array reference required for a semantically valid public case."""

    code: str
    source: str
    reference: str

    def contract(self) -> dict[str, str]:
        return {"code": self.code, "from": self.source, "mustReference": self.reference}


ACCEPTANCE_CASE_GOVERNANCE_RULES: Final = (
    AcceptanceCaseGovernanceRule(
        "acceptance_evidence_criterion_not_governed",
        "evidence.criterion_codes[]",
        "work_item.acceptance_criteria[].code",
    ),
    AcceptanceCaseGovernanceRule(
        "acceptance_check_policy_not_governed",
        "assurance.deterministic_checks[].code",
        "policy.requirements[].code",
    ),
    AcceptanceCaseGovernanceRule(
        "acceptance_check_criterion_not_governed",
        "assurance.deterministic_checks[].code",
        "work_item.acceptance_criteria[].code",
    ),
)

ACCEPTANCE_CASE_DIFF_RULE: Final[dict[str, str]] = {
    "code": "acceptance_case_diff_invalid",
    "from": "change.unified_diff",
    "mustSatisfy": "manual-diff ingestion parser",
}
