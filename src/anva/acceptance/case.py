"""Validated public case configuration for scenario-aware acceptance runs."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from anva.contracts.validation import validate_payload

MAX_CASE_BYTES = 1_000_000
MAX_EVIDENCE_BYTES = 4_096
FORBIDDEN_PRIVATE_KEYS = frozenset(
    {
        "oracle",
        "oracle_label",
        "grader",
        "private_grader",
        "private_manifest",
        "private_canary",
        "expected_readiness",
        "expected_finding",
        "expected_findings",
        "expected_non_finding",
        "expected_non_findings",
        "expected_score",
        "score",
    }
)
FORBIDDEN_PRIVATE_MARKERS = (
    "private_canary",
    "oracle_label",
    "grader_only",
    "expected_readiness",
)


class AcceptanceCaseError(ValueError):
    """A public case was unsafe, ambiguous, or internally inconsistent."""


def canonical_case_bytes(payload: dict[str, object]) -> bytes:
    """Return the deterministic byte identity used for state and export binding."""
    return (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _private_material(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).casefold() in FORBIDDEN_PRIVATE_KEYS or _private_material(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_private_material(item) for item in value)
    if isinstance(value, str):
        normalized = value.casefold()
        return any(marker in normalized for marker in FORBIDDEN_PRIVATE_MARKERS)
    return False


def _object(payload: dict[str, object], key: str) -> dict[str, object]:
    value = payload[key]
    if not isinstance(value, dict):
        raise AcceptanceCaseError("Acceptance case section is invalid")
    return cast(dict[str, object], value)


def _string(payload: dict[str, object], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise AcceptanceCaseError("Acceptance case field is invalid")
    return value


@dataclass(frozen=True, slots=True)
class AcceptanceCase:
    """One public case plus its canonical input identity and decoded evidence."""

    payload: dict[str, object]
    sha256: str
    evidence_bytes: bytes
    legacy_default: bool = False

    @property
    def case_id(self) -> str:
        return _string(self.payload, "case_id")

    def section(self, name: str) -> dict[str, object]:
        return _object(self.payload, name)


def _validate_cross_section(payload: dict[str, object]) -> bytes:
    if _private_material(payload):
        raise AcceptanceCaseError("Acceptance case contains private evaluation material")
    change = _object(payload, "change")
    base_commit = _string(change, "base_commit")
    head_commit = _string(change, "head_commit")
    if base_commit == head_commit:
        raise AcceptanceCaseError("Acceptance case base and head commits must differ")
    stale_probe = change["stale_probe"]
    if isinstance(stale_probe, dict):
        probe = cast(dict[str, object], stale_probe)
        if probe["pull_request_number"] == change["pull_request_number"]:
            raise AcceptanceCaseError("Stale probe must use a distinct pull request number")
        if probe["new_head_commit"] in {base_commit, head_commit}:
            raise AcceptanceCaseError("Stale probe head must be distinct")
    work = _object(payload, "work_item")
    criteria = work["acceptance_criteria"]
    if not isinstance(criteria, list):
        raise AcceptanceCaseError("Acceptance criteria are invalid")
    criterion_codes = {
        _string(cast(dict[str, object], item), "code")
        for item in criteria
        if isinstance(item, dict)
    }
    if len(criterion_codes) != len(criteria):
        raise AcceptanceCaseError("Acceptance criterion codes must be unique")
    requirements = work["requirements"]
    if not isinstance(requirements, list):
        raise AcceptanceCaseError("Acceptance requirements are invalid")
    requirement_codes = {
        _string(cast(dict[str, object], item), "code")
        for item in requirements
        if isinstance(item, dict)
    }
    if len(requirement_codes) != len(requirements):
        raise AcceptanceCaseError("Acceptance requirement codes must be unique")
    for raw in criteria:
        criterion = cast(dict[str, object], raw)
        linked = criterion.get("requirement_code")
        if linked is not None and linked not in requirement_codes:
            raise AcceptanceCaseError("Acceptance criterion references an unknown requirement")
    policy = _object(payload, "policy")
    policy_requirements = policy["requirements"]
    if not isinstance(policy_requirements, list):
        raise AcceptanceCaseError("Acceptance policy requirements are invalid")
    policy_codes = {
        _string(cast(dict[str, object], item), "code")
        for item in policy_requirements
        if isinstance(item, dict)
    }
    if len(policy_codes) != len(policy_requirements):
        raise AcceptanceCaseError("Acceptance policy requirement codes must be unique")
    evidence = _object(payload, "evidence")
    raw_evidence_codes = evidence["criterion_codes"]
    assurance = _object(payload, "assurance")
    checks = assurance["deterministic_checks"]
    if not isinstance(raw_evidence_codes, list) or not isinstance(checks, list):
        raise AcceptanceCaseError("Acceptance evidence or checks are invalid")
    evidence_codes = set(cast(list[str], raw_evidence_codes))
    check_codes = {
        _string(cast(dict[str, object], item), "code") for item in checks if isinstance(item, dict)
    }
    if (
        not evidence_codes <= criterion_codes
        or not check_codes <= policy_codes
        or not check_codes <= criterion_codes
    ):
        raise AcceptanceCaseError("Acceptance evidence/check codes are not governed")
    evidence_kind = _string(evidence, "kind")
    for raw in criteria:
        criterion = cast(dict[str, object], raw)
        if criterion["code"] in evidence_codes and evidence_kind not in cast(
            list[str], criterion["required_evidence_types"]
        ):
            raise AcceptanceCaseError("Acceptance evidence kind does not satisfy its criterion")
    try:
        evidence_bytes = base64.b64decode(
            _string(evidence, "content_base64"),
            validate=True,
        )
    except (ValueError, binascii.Error) as error:
        raise AcceptanceCaseError("Acceptance evidence encoding is invalid") from error
    if not 1 <= len(evidence_bytes) <= MAX_EVIDENCE_BYTES:
        raise AcceptanceCaseError("Acceptance evidence size is outside its bound")
    try:
        evidence_payload = json.loads(evidence_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        evidence_payload = None
    if isinstance(evidence_payload, dict) and evidence_payload.get("head_sha") != head_commit:
        raise AcceptanceCaseError("Acceptance JSON evidence must match the exact head commit")
    semantic = _object(payload, "semantic_assertions")
    source_paths = semantic["source_paths"]
    if not isinstance(source_paths, list) or len(set(cast(list[str], source_paths))) != len(
        source_paths
    ):
        raise AcceptanceCaseError("Acceptance semantic source paths are invalid")
    return evidence_bytes


def acceptance_case(payload: dict[str, object]) -> AcceptanceCase:
    """Validate an already-decoded public case and derive its immutable identity."""
    validate_payload("acceptance-case", payload)
    evidence_bytes = _validate_cross_section(payload)
    rendered = canonical_case_bytes(payload)
    return AcceptanceCase(
        payload=deepcopy_case(payload),
        sha256=hashlib.sha256(rendered).hexdigest(),
        evidence_bytes=evidence_bytes,
    )


def deepcopy_case(payload: dict[str, object]) -> dict[str, object]:
    """Copy through canonical JSON so callers cannot retain mutable aliases."""
    return cast(dict[str, object], json.loads(canonical_case_bytes(payload)))


def load_acceptance_case(path: Path) -> AcceptanceCase:
    """Load one bounded regular public case without following filesystem links."""
    if any(parent.is_symlink() for parent in path.parents):
        raise AcceptanceCaseError("Acceptance case path is unsafe")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(descriptor)
    except FileNotFoundError as error:
        raise AcceptanceCaseError("Acceptance case is unavailable") from error
    except OSError as error:
        raise AcceptanceCaseError("Acceptance case path is unsafe") from error
    try:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_CASE_BYTES:
            raise AcceptanceCaseError("Acceptance case path is unsafe")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(MAX_CASE_BYTES + 1)
        if len(raw) > MAX_CASE_BYTES:
            raise AcceptanceCaseError("Acceptance case exceeds its bound")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceCaseError("Acceptance case is invalid JSON") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise AcceptanceCaseError("Acceptance case must be an object")
    return acceptance_case(cast(dict[str, object], value))


def legacy_acceptance_case(
    *,
    corpus_id: str,
    source_fingerprint: str,
    base_commit: str,
    head_commit: str,
    new_head_commit: str,
    source_paths_and_text: tuple[tuple[str, str], ...],
) -> AcceptanceCase:
    """Build the explicit compatibility case for the original TST-008 journey."""
    fragments = ["organization goals products decisions systems requirements"]
    for relative, text in source_paths_and_text:
        fragments.append(relative.replace("/", " "))
        fragments.append(" ".join(text.split())[:240])
    query = " ".join(fragments)[:500]
    evidence_bytes = (
        json.dumps(
            {
                "checks": [{"name": "EXACT_HEAD_PROOF", "status": "PASSED"}],
                "head_sha": head_commit,
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    slug = f"anva-acceptance-{source_fingerprint[:12]}"
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "case_id": corpus_id,
        "organization": {
            "slug": slug,
            "name": f"Anva Acceptance {corpus_id}",
            "admin_email": f"{slug}@anva.invalid",
            "admin_display_name": "Anva acceptance operator",
            "repository_external_id": f"acceptance:{source_fingerprint}",
            "repository_name": corpus_id,
            "independent_reviewer_name": "Independent acceptance evaluator",
        },
        "source": {
            "external_key": f"acceptance:{source_fingerprint}",
            "display_name": corpus_id,
        },
        "retrieval": {
            "search_query": query,
            "search_phase": "PREPARE",
            "search_limit": 50,
            "context_task": (
                "Review an exact-head acceptance change against connected organization context"
            ),
            "context_phase": "ASSURANCE",
            "budget": {
                "max_items": 50,
                "max_tokens": 8_000,
                "max_bytes": 100_000,
                "max_citations": 100,
            },
        },
        "canvas": {
            "layers": ["execution", "dependencies", "governance", "provenance"],
            "depth": 4,
            "node_limit": 300,
            "edge_limit": 600,
        },
        "work_item": {
            "external_key": f"ACCEPTANCE-{source_fingerprint[:16]}",
            "origin": "sealed-acceptance",
            "work_type": "FEATURE",
            "title": "Exercise exact-head production acceptance",
            "summary": "Validate connected context, governance, evidence, and assurance.",
            "status": "READY",
            "source_references": [f"acceptance:{source_fingerprint}"],
            "requirements": [
                {
                    "code": "REQ_EXACT_HEAD",
                    "normalized_text": (
                        "Readiness uses only evidence for the exact pull request head."
                    ),
                    "origin": "acceptance",
                    "owner": "platform",
                    "status": "CONFIRMED",
                    "source_references": [f"acceptance:{source_fingerprint}"],
                    "related_entity_ids": [],
                    "requires_approval": False,
                }
            ],
            "acceptance_criteria": [
                {
                    "code": "EXACT_HEAD_PROOF",
                    "requirement_code": "REQ_EXACT_HEAD",
                    "normalized_text": "Exact-head acceptance evidence is present.",
                    "required_evidence_types": ["TEST_RESULT"],
                    "manual_approval_allowed": False,
                }
            ],
        },
        "policy": {
            "name": "Exact-head acceptance",
            "owner": "platform",
            "status": "ACTIVE",
            "binding": {
                "scope_level": "REPOSITORY",
                "mandatory": True,
                "entity_ids": [],
                "entity_types": [],
                "path_patterns": [],
                "work_item_types": [],
                "target_branches": ["main"],
            },
            "requirements": [
                {
                    "code": "EXACT_HEAD_PROOF",
                    "description": "Exact-head acceptance evidence is required.",
                    "enforcement": "BLOCKING",
                    "check_type": "EVIDENCE",
                    "required_evidence": ["TEST_RESULT"],
                    "required_reviewers": [],
                    "required_approval": False,
                    "report_sections": ["tests"],
                }
            ],
        },
        "change": {
            "pull_request_number": 817,
            "base_commit": base_commit,
            "head_commit": head_commit,
            "title": "Acceptance exact-head change",
            "description": "Bounded synthetic diff supplied through the public manual-diff API.",
            "target_branch": "main",
            "is_draft": False,
            "state": "OPEN",
            "unified_diff": (
                "diff --git a/acceptance/candidate.py b/acceptance/candidate.py\n"
                "--- a/acceptance/candidate.py\n"
                "+++ b/acceptance/candidate.py\n"
                "@@ -1,1 +1,2 @@\n"
                " value = 1\n"
                f"+head = '{head_commit}'\n"
            ),
            "affected_paths": ["acceptance/candidate.py"],
            "affected_entities": [],
            "stale_probe": {
                "pull_request_number": 818,
                "new_head_commit": new_head_commit,
                "title_suffix": "stale probe",
            },
        },
        "evidence": {
            "filename": "exact-head-result.json",
            "content_base64": base64.b64encode(evidence_bytes).decode(),
            "kind": "TEST_RESULT",
            "name": "Exact-head public boundary acceptance",
            "status": "PASSED",
            "command": "anva acceptance start",
            "artifact_reference": "accepted/exact-head-result.json",
            "source_url": None,
            "producer": "anva-acceptance-runner",
            "producer_version": "1",
            "producer_mode": "MANUAL",
            "retention_class": "ASSURANCE_1Y",
            "retention_days": 365,
            "limitations": ["External provider execution is outside this runner."],
            "criterion_codes": ["EXACT_HEAD_PROOF"],
            "environment": "sealed-acceptance",
            "scenario": "TST-007",
        },
        "assurance": {
            "deterministic_checks": [
                {
                    "code": "EXACT_HEAD_PROOF",
                    "status": "PASSED",
                    "blocking": True,
                    "summary": "Exact-head evidence was accepted through public boundaries.",
                    "include_evidence": True,
                }
            ],
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "reviewer_claimant": "independent-acceptance-evaluator",
            "review_lease_seconds": 3_600,
        },
        "semantic_assertions": {
            "source_paths": [relative for relative, _text in source_paths_and_text],
            "require_source_backed_canvas": True,
        },
    }
    validated = acceptance_case(payload)
    return AcceptanceCase(
        payload=validated.payload,
        sha256=validated.sha256,
        evidence_bytes=validated.evidence_bytes,
        legacy_default=True,
    )
