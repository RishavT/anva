"""Fast assurance parser, evaluator, and hostile-input behavior."""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

from anva.contracts import ContractValidationError, validate_payload
from anva.contracts.catalog import EXAMPLES
from anva.core.models import AssuranceCheck, AssuranceRun, CriterionEvidence, Finding
from anva.core.services.assurance import (
    _finding_fingerprint,
    _fingerprinted_payloads,
    _mapping_payload,
    _markdown_escape,
    _normalized_text,
    _readiness,
    _render_report,
    _requirement_payload,
    _safe_report_text,
    _validate_checks,
    _validate_result_references,
)
from anva.core.services.diffs import (
    ParsedDiffChunk,
    citation_in_diff,
    classify_path,
    parse_unified_diff,
)
from anva.core.services.evaluators import (
    EvaluatorRateLimitedError,
    EvaluatorTimeoutError,
    FakeEvaluator,
    FakeScenario,
    request_identifier,
)

VALID_DIFF = """diff --git a/src/auth/service.py b/src/auth/service.py
--- a/src/auth/service.py
+++ b/src/auth/service.py
@@ -10,2 +10,3 @@
 keep
-old
+new
+extra
diff --git a/tests/test_service.py b/tests/test_service.py
--- a/tests/test_service.py
+++ b/tests/test_service.py
@@ -1,1 +1,1 @@
-old
+new
"""


@pytest.mark.unit
def test_manual_diff_is_classified_chunked_and_citation_bounded() -> None:
    first = parse_unified_diff(VALID_DIFF)
    second = parse_unified_diff(VALID_DIFF)

    assert first == second
    assert first.changed_paths == ("src/auth/service.py", "tests/test_service.py")
    assert first.classifications == {"SECURITY_SENSITIVE": 1, "TEST": 1}
    assert citation_in_diff(
        chunks=list(first.chunks),
        path="src/auth/service.py",
        side="NEW",
        line=12,
    )
    assert not citation_in_diff(
        chunks=list(first.chunks),
        path="src/auth/service.py",
        side="NEW",
        line=13,
    )
    assert not citation_in_diff(
        chunks=list(first.chunks),
        path="src/not-changed.py",
        side="NEW",
        line=12,
    )
    assert citation_in_diff(
        chunks=first.chunks,
        path="src/auth/service.py",
        side="OLD",
        line=10,
    )
    assert not citation_in_diff(
        chunks=first.chunks,
        path="src/auth/service.py",
        side="SIDEWAYS",
        line=10,
    )
    assert not citation_in_diff(
        chunks=first.chunks,
        path="src/auth/service.py",
        side="OLD",
        line=0,
    )
    assert first.chunks[0].as_dict()["content_hash"] == first.chunks[0].content_hash


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("db/migrations/0001_initial.py", "MIGRATION"),
        ("schema/tables.sql", "MIGRATION"),
        ("pyproject.toml", "DEPENDENCY"),
        ("vendor/packages.lock", "DEPENDENCY"),
        (".github/workflows/ci.yml", "CI"),
        ("containers/Dockerfile.worker", "CI"),
        ("docs/assurance.md", "DOCUMENTATION"),
        ("notes/release.rst", "DOCUMENTATION"),
        ("src/domain/service.py", "SOURCE"),
    ],
)
def test_changed_path_classification_is_ordered_and_provider_neutral(
    path: str,
    expected: str,
) -> None:
    assert classify_path(path) == expected


@pytest.mark.unit
def test_rename_diff_preserves_destination_and_zero_count_citations_are_invalid() -> None:
    parsed = parse_unified_diff(
        "diff --git a/old.py b/new.py\n"
        "similarity index 90%\n"
        "rename from old.py\n"
        "rename to new.py\n"
        "--- a/old.py\n"
        "+++ b/new.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+new\n"
    )

    assert parsed.changed_paths == ("new.py",)
    assert parsed.chunks[0].old_count == 0
    assert not citation_in_diff(chunks=parsed.chunks, path="new.py", side="OLD", line=1)
    assert citation_in_diff(chunks=parsed.chunks, path="new.py", side="NEW", line=1)


@pytest.mark.unit
@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "diff --git a/a.py b/a.py",
        "diff --raw a.py\n",
        'diff --git a/"a.py" b/"a.py"\n@@ -1 +1 @@\n-old\n+new\n',
        "diff --git a/-a.py b/-a.py\n@@ -1 +1 @@\n-old\n+new\n",
        "diff --git a/a//b.py b/a//b.py\n@@ -1 +1 @@\n-old\n+new\n",
        "@@ -1 +1 @@\n-old\n+new\n",
        "diff --git a/a.py b/a.py\n@@ -1 +1 @@\n?bad\n+new\n",
        "diff --git a/a.py b/a.py\r\n@@ -1 +1 @@\r\n-old\r\n+new\r\n",
        "diff --git a/a.py b/a.py\nBinary files a/a.py and b/a.py differ\n",
    ],
)
def test_manual_diff_rejects_malformed_structure(invalid: str) -> None:
    with pytest.raises(ValueError):
        parse_unified_diff(invalid)


@pytest.mark.unit
def test_manual_diff_enforces_configured_size_and_count_bounds() -> None:
    with patch("anva.core.services.diffs.MAX_DIFF_BYTES", 1):
        with pytest.raises(ValueError, match="1,000,000"):
            parse_unified_diff(VALID_DIFF)
    with patch("anva.core.services.diffs.MAX_DIFF_LINES", 1):
        with pytest.raises(ValueError, match="line limit"):
            parse_unified_diff(VALID_DIFF)
    with patch("anva.core.services.diffs.MAX_CHANGED_PATHS", 1):
        with pytest.raises(ValueError, match="changed-path"):
            parse_unified_diff(VALID_DIFF)
    with patch("anva.core.services.diffs.MAX_CHUNKS", 0):
        with pytest.raises(ValueError, match="hunk limit"):
            parse_unified_diff(VALID_DIFF)
    with patch("anva.core.services.diffs.MAX_CHUNK_CHARS", 1):
        with pytest.raises(ValueError, match="chunk limit"):
            parse_unified_diff(VALID_DIFF)

    with pytest.raises(ValueError, match="must be text"):
        parse_unified_diff(cast(str, b"not-text"))


@pytest.mark.unit
@pytest.mark.parametrize(
    "hostile",
    [
        VALID_DIFF.replace("src/auth/service.py", "../service.py"),
        VALID_DIFF.replace(
            "@@ -10,2 +10,3 @@\n keep\n-old\n+new\n+extra\n",
            "GIT binary patch\nliteral 0\n",
        ),
        VALID_DIFF.replace("@@ -10,2 +10,3 @@", "@@ -10,20 +10,3 @@"),
        VALID_DIFF.replace("+new", "+Authorization: Bearer secret-value"),
        "diff --cc src/auth/service.py\n",
    ],
)
def test_manual_diff_rejects_unsafe_or_unverifiable_input(hostile: str) -> None:
    with pytest.raises(ValueError):
        parse_unified_diff(hostile)


@pytest.mark.unit
def test_fake_evaluator_emits_observations_not_readiness() -> None:
    request = deepcopy(EXAMPLES["evaluator-request"])
    result = FakeEvaluator(FakeScenario.SUCCESS_WITH_BLOCKING).evaluate(request)

    assert result["completion"] == "COMPLETE"
    assert "outcome" not in result
    assert "readiness" not in result
    validate_payload("evaluator-result", result)


@pytest.mark.unit
@pytest.mark.parametrize(
    "scenario",
    [
        FakeScenario.SUCCESS_NO_FINDINGS,
        FakeScenario.SUCCESS_WITH_ADVISORY,
        FakeScenario.SUCCESS_WITH_BLOCKING,
        FakeScenario.PARTIAL_OUTPUT,
        FakeScenario.UNSUPPORTED_CITATION,
        FakeScenario.INJECTION_COMPLIANCE_ATTEMPT,
    ],
)
def test_fake_evaluator_success_scenarios_are_schema_valid(scenario: FakeScenario) -> None:
    result = FakeEvaluator(scenario).evaluate(deepcopy(EXAMPLES["evaluator-request"]))
    validate_payload("evaluator-result", result)


@pytest.mark.unit
def test_fake_evaluator_failure_scenarios_are_explicit() -> None:
    request = deepcopy(EXAMPLES["evaluator-request"])
    with pytest.raises(ContractValidationError):
        validate_payload(
            "evaluator-result",
            FakeEvaluator(FakeScenario.MALFORMED_OUTPUT).evaluate(request),
        )
    with pytest.raises(EvaluatorTimeoutError):
        FakeEvaluator(FakeScenario.TIMEOUT).evaluate(request)
    with pytest.raises(EvaluatorRateLimitedError):
        FakeEvaluator(FakeScenario.RATE_LIMITED).evaluate(request)


@pytest.mark.unit
def test_evaluator_request_identifier_validates_before_returning_identity() -> None:
    request = deepcopy(EXAMPLES["evaluator-request"])

    assert request_identifier(request) == uuid.UUID(cast(str, request["request_id"]))
    request["commit_sha"] = "short"
    with pytest.raises(ContractValidationError):
        request_identifier(request)


@pytest.mark.unit
def test_malicious_evaluator_prose_remains_data_and_report_claims_are_removed() -> None:
    request = deepcopy(EXAMPLES["evaluator-request"])
    result = FakeEvaluator(FakeScenario.INJECTION_COMPLIANCE_ATTEMPT).evaluate(request)
    finding = result["findings"][0]  # type: ignore[index]

    assert "<script>" in finding["title"]
    assert "safe to deploy" in finding["explanation"]
    assert "safe to deploy" not in _safe_report_text(finding["explanation"]).casefold()


@pytest.mark.unit
def test_evaluator_contract_rejects_model_readiness_and_proven_confidence() -> None:
    result = deepcopy(EXAMPLES["evaluator-result"])
    result["readiness"] = "READY_FOR_HUMAN_REVIEW"
    with pytest.raises(ContractValidationError):
        validate_payload("evaluator-result", result)


@pytest.mark.unit
def test_deterministic_check_validation_normalizes_order_and_rejects_ambiguity() -> None:
    first_evidence = uuid.uuid4()
    second_evidence = uuid.uuid4()
    checks = _validate_checks(
        [
            {
                "code": "Z_CHECK",
                "status": AssuranceCheck.Status.PASSED,
                "blocking": False,
                "summary": "Secondary check",
                "evidence_ids": [str(second_evidence), str(first_evidence)],
            },
            {
                "code": "A_CHECK",
                "status": AssuranceCheck.Status.FAILED,
                "blocking": True,
                "summary": "Primary check",
                "evidence_ids": [],
            },
        ]
    )

    assert [item["code"] for item in checks] == ["A_CHECK", "Z_CHECK"]
    assert checks[1]["evidence_ids"] == sorted([str(first_evidence), str(second_evidence)])

    invalid_checks = [
        [{"code": "ONLY"}],
        [
            {
                "code": "",
                "status": AssuranceCheck.Status.PASSED,
                "blocking": False,
                "summary": "summary",
                "evidence_ids": [],
            }
        ],
        [
            {
                "code": "DUPLICATE_EVIDENCE",
                "status": AssuranceCheck.Status.PASSED,
                "blocking": False,
                "summary": "summary",
                "evidence_ids": [str(first_evidence), str(first_evidence)],
            }
        ],
        [
            {
                "code": "BAD_UUID",
                "status": AssuranceCheck.Status.PASSED,
                "blocking": False,
                "summary": "summary",
                "evidence_ids": ["not-a-uuid"],
            }
        ],
        [
            {
                "code": "SECRET_SUMMARY",
                "status": AssuranceCheck.Status.PASSED,
                "blocking": False,
                "summary": "Authorization: Bearer hidden-token",
                "evidence_ids": [],
            }
        ],
    ]
    for invalid in invalid_checks:
        with pytest.raises(ValueError):
            _validate_checks(invalid)

    with patch("anva.core.services.assurance.MAX_CHECKS", 0):
        with pytest.raises(ValueError, match="exceeds"):
            _validate_checks(checks)


@pytest.mark.unit
def test_mapping_payload_and_fingerprint_are_stable_under_presentation_changes() -> None:
    later = SimpleNamespace(
        id=uuid.uuid4(),
        criterion_id=uuid.uuid4(),
        criterion=SimpleNamespace(code="Z_CRITERION"),
        required_evidence_type="TEST_RESULT",
        assessment="SATISFIED",
        classification="DIRECT",
        evidence_id=uuid.uuid4(),
        gap_code="",
        limitations=["second", "first"],
        input_hash="a" * 64,
        engine_version="mapping-v1",
        reference_time=datetime(2026, 7, 28, 12, tzinfo=UTC),
    )
    earlier = SimpleNamespace(
        id=uuid.uuid4(),
        criterion_id=uuid.uuid4(),
        criterion=SimpleNamespace(code="A_CRITERION"),
        required_evidence_type="SCREENSHOT",
        assessment="GAP",
        classification="GAP",
        evidence_id=None,
        gap_code="NO_ELIGIBLE_EVIDENCE",
        limitations=[],
        input_hash="b" * 64,
        engine_version="mapping-v1",
        reference_time=datetime(2026, 7, 28, 12, tzinfo=UTC),
    )

    payload = _mapping_payload(cast(tuple[CriterionEvidence, ...], (later, earlier)))
    assert [item["criterion_code"] for item in payload] == ["A_CRITERION", "Z_CRITERION"]
    assert payload[1]["limitations"] == ["first", "second"]
    assert _requirement_payload(None) == []

    finding = deepcopy(EXAMPLES["evaluator-result"]["findings"][0])  # type: ignore[index]
    baseline = _finding_fingerprint(finding)
    finding["title"] = "Entirely different wording"
    finding["explanation"] = "Different prose"
    assert _finding_fingerprint(finding) == baseline
    finding["citations"][0]["line"] += 100  # type: ignore[index]
    assert _finding_fingerprint(finding) != baseline
    finding["citations"][0]["line"] -= 100  # type: ignore[index]
    finding["citations"][0]["path"] = "different/path.py"  # type: ignore[index]
    assert _finding_fingerprint(finding) != baseline

    source_finding = deepcopy(EXAMPLES["evaluator-result"]["findings"][0])  # type: ignore[index]
    source_finding["citations"] = [
        {
            "type": "ANVA_SOURCE",
            "context_citation_id": str(uuid.uuid4()),
        }
    ]
    assert _finding_fingerprint(source_finding)
    assert _fingerprinted_payloads([source_finding, finding]) == sorted(
        _fingerprinted_payloads([finding, source_finding]),
        key=lambda item: item[0],
    )
    with pytest.raises(ValueError, match="duplicate semantic findings"):
        _fingerprinted_payloads([source_finding, deepcopy(source_finding)])


@pytest.mark.unit
def test_evaluator_references_are_limited_to_exact_diff_context_and_evidence() -> None:
    context_citation_id = uuid.uuid4()
    mapped_evidence_id = uuid.uuid4()
    check_evidence_id = uuid.uuid4()
    revision = SimpleNamespace(id=uuid.uuid4())
    run = cast(
        AssuranceRun,
        SimpleNamespace(
            pull_request_revision=revision,
            context_packet_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            work_item_revision_id=uuid.uuid4(),
        ),
    )
    chunks = [
        ParsedDiffChunk(
            position=1,
            path="src/service.py",
            classification="SOURCE",
            old_start=1,
            old_count=1,
            new_start=1,
            new_count=2,
            text="@@ -1 +1,2 @@\n-old\n+new\n+extra\n",
        )
    ]
    mapping = cast(
        CriterionEvidence,
        SimpleNamespace(evidence_id=mapped_evidence_id),
    )
    diff_finding = {
        "evidence_ids": [str(mapped_evidence_id)],
        "criterion_codes": ["CRIT"],
        "citations": [
            {
                "type": "DIFF",
                "path": "src/service.py",
                "side": "NEW",
                "line": 2,
            }
        ],
    }
    source_finding = {
        "evidence_ids": [str(check_evidence_id)],
        "criterion_codes": [],
        "citations": [
            {
                "type": "ANVA_SOURCE",
                "context_citation_id": str(context_citation_id),
            }
        ],
    }

    with (
        patch(
            "anva.core.services.assurance._parsed_chunks",
            return_value=chunks,
        ),
        patch("anva.core.services.assurance.ContextPacketCitation.objects.filter") as citations,
        patch("anva.core.services.assurance.AssuranceCheck.objects.filter") as checks,
        patch("anva.core.services.assurance.AcceptanceCriterion.objects.filter") as criteria,
    ):
        citations.return_value.values_list.return_value = [context_citation_id]
        checks.return_value.values_list.return_value = [[str(check_evidence_id)]]
        criteria.return_value.values_list.return_value = ["CRIT"]
        assert _validate_result_references(
            run=run,
            result={"findings": [diff_finding, source_finding]},
            mappings=(mapping,),
        ) == [diff_finding, source_finding]

        invalid_evidence = deepcopy(diff_finding)
        invalid_evidence["evidence_ids"] = [str(uuid.uuid4())]
        with pytest.raises(ValueError, match="evidence outside"):
            _validate_result_references(
                run=run,
                result={"findings": [invalid_evidence]},
                mappings=(mapping,),
            )

        invalid_criterion = deepcopy(diff_finding)
        invalid_criterion["criterion_codes"] = ["FOREIGN"]
        with pytest.raises(ValueError, match="criterion outside"):
            _validate_result_references(
                run=run,
                result={"findings": [invalid_criterion]},
                mappings=(mapping,),
            )

        invalid_diff = deepcopy(diff_finding)
        invalid_diff["citations"][0]["line"] = 99  # type: ignore[index]
        with pytest.raises(ValueError, match="location outside"):
            _validate_result_references(
                run=run,
                result={"findings": [invalid_diff]},
                mappings=(mapping,),
            )

        invalid_source = deepcopy(source_finding)
        invalid_source["citations"][0]["context_citation_id"] = (  # type: ignore[index]
            str(uuid.uuid4())
        )
        with pytest.raises(ValueError, match="unauthorized context"):
            _validate_result_references(
                run=run,
                result={"findings": [invalid_source]},
                mappings=(mapping,),
            )

    missing_inputs = cast(
        AssuranceRun,
        SimpleNamespace(pull_request_revision=None, context_packet_id=None),
    )
    with pytest.raises(ValueError, match="exact review inputs"):
        _validate_result_references(
            run=missing_inputs,
            result={"findings": []},
            mappings=(),
        )


def _run_for_readiness(**overrides: object) -> AssuranceRun:
    values: dict[str, object] = {
        "pull_request_revision": SimpleNamespace(
            pull_request=SimpleNamespace(current_head_commit="a" * 40)
        ),
        "state": AssuranceRun.State.MODEL_REVIEW,
        "failure_code": "",
        "organization": SimpleNamespace(id=uuid.uuid4()),
        "head_commit": "a" * 40,
        "pull_request_number": 7,
        "work_item_revision_id": uuid.uuid4(),
        "policy_evaluation": None,
    }
    values.update(overrides)
    return cast(AssuranceRun, SimpleNamespace(**values))


@pytest.mark.unit
def test_readiness_fails_closed_for_missing_stale_and_failed_run_inputs() -> None:
    result = {"completion": "COMPLETE", "limitations": []}

    assert _readiness(
        run=_run_for_readiness(pull_request_revision=None),
        result=result,
        findings=(),
        mappings=(),
    ) == ("FAILED", ["MISSING_PULL_REQUEST_REVISION"])
    assert _readiness(
        run=_run_for_readiness(state=AssuranceRun.State.STALE),
        result=result,
        findings=(),
        mappings=(),
    ) == ("STALE", ["SUPERSEDED_HEAD"])
    assert _readiness(
        run=_run_for_readiness(failure_code="EVALUATOR_FAILED"),
        result=result,
        findings=(),
        mappings=(),
    ) == ("FAILED", ["EVALUATOR_FAILED"])


@pytest.mark.unit
def test_readiness_preserves_deterministic_dominance_and_warning_reasons() -> None:
    checks = [
        SimpleNamespace(code="TESTS", status=AssuranceCheck.Status.FAILED, blocking=True),
        SimpleNamespace(
            code="DOCS",
            status=AssuranceCheck.Status.NOT_AVAILABLE,
            blocking=False,
        ),
        SimpleNamespace(code="MANUAL_OK", status=AssuranceCheck.Status.PASSED, blocking=True),
    ]
    mappings = [
        SimpleNamespace(
            criterion=SimpleNamespace(code="EVIDENCE_OK"),
            assessment=CriterionEvidence.Assessment.SATISFIED,
        ),
        SimpleNamespace(
            criterion=SimpleNamespace(code="EVIDENCE_MISSING"),
            assessment=CriterionEvidence.Assessment.GAP,
        ),
    ]
    policy = SimpleNamespace(
        output_payload={
            "controls": [
                {
                    "code": "TESTS",
                    "enforcement": "BLOCKING",
                    "check_type": "DETERMINISTIC",
                },
                {
                    "code": "MANUAL_OK",
                    "enforcement": "BLOCKING",
                    "check_type": "MANUAL_APPROVAL",
                },
                {
                    "code": "EVIDENCE_OK",
                    "enforcement": "BLOCKING",
                    "check_type": "EVIDENCE",
                },
                {
                    "code": "MODEL_REVIEW",
                    "enforcement": "BLOCKING",
                    "check_type": "MODEL_REVIEW",
                },
                {
                    "code": "ADVISORY_MISSING",
                    "enforcement": "ADVISORY",
                    "check_type": "DETERMINISTIC",
                },
            ]
        }
    )
    findings = cast(
        tuple[Finding, ...],
        (
            SimpleNamespace(severity=Finding.Severity.BLOCKING, state=Finding.State.OPEN),
            SimpleNamespace(severity=Finding.Severity.HIGH, state=Finding.State.OPEN),
        ),
    )
    with patch("anva.core.services.assurance.AssuranceCheck.objects.filter") as check_filter:
        check_filter.return_value.order_by.return_value = checks
        status, reasons = _readiness(
            run=_run_for_readiness(policy_evaluation=policy),
            result={"completion": "PARTIAL", "limitations": ["bounded review"]},
            findings=findings,
            mappings=cast(tuple[CriterionEvidence, ...], tuple(mappings)),
        )

    assert status == "BLOCKED"
    assert {
        "CHECK_TESTS",
        "CHECK_DOCS",
        "EVIDENCE_GAP_EVIDENCE_MISSING",
        "POLICY_GAP_TESTS",
        "POLICY_GAP_MODEL_REVIEW",
        "POLICY_GAP_ADVISORY_MISSING",
        "SUPPORTED_MODEL_BLOCKER",
        "MODEL_CONCERNS",
        "PARTIAL_MODEL_COVERAGE",
        "LIMITATIONS_PRESENT",
    } <= set(reasons)
    assert "POLICY_GAP_MANUAL_OK" not in reasons
    assert "POLICY_GAP_EVIDENCE_OK" not in reasons


@pytest.mark.unit
def test_readiness_distinguishes_warning_only_and_clean_results() -> None:
    with patch("anva.core.services.assurance.AssuranceCheck.objects.filter") as check_filter:
        check_filter.return_value.order_by.return_value = []
        warning = _readiness(
            run=_run_for_readiness(),
            result={"completion": "PARTIAL", "limitations": ["bounded"]},
            findings=cast(
                tuple[Finding, ...],
                (
                    SimpleNamespace(
                        severity=Finding.Severity.ADVISORY,
                        state=Finding.State.OPEN,
                    ),
                ),
            ),
            mappings=(),
        )
        clean = _readiness(
            run=_run_for_readiness(),
            result={"completion": "COMPLETE", "limitations": []},
            findings=(),
            mappings=(),
        )

    assert warning == (
        "READY_WITH_WARNINGS",
        ["LIMITATIONS_PRESENT", "MODEL_CONCERNS", "PARTIAL_MODEL_COVERAGE"],
    )
    assert clean == ("READY_FOR_HUMAN_REVIEW", [])


@pytest.mark.unit
def test_text_normalization_and_markdown_escaping_remove_unsafe_claims() -> None:
    assert _normalized_text("  review   boundary ", name="title", maximum=100) == (
        "review boundary"
    )
    assert _normalized_text("  lines\nremain  ", name="description", maximum=100) == (
        "lines\nremain"
    )
    with pytest.raises(ValueError):
        _normalized_text(cast(str, 42), name="title", maximum=100)
    with pytest.raises(ValueError):
        _normalized_text("", name="title", maximum=100)
    with pytest.raises(ValueError):
        _normalized_text("too long", name="title", maximum=2)
    with pytest.raises(ValueError):
        _normalized_text("api_key=hidden-value", name="title", maximum=100)

    rendered = _markdown_escape(r"safe_to_merge *value* <tag>")
    assert "safe_to_merge" not in rendered.casefold()
    assert r"\*value\*" in rendered
    assert r"\<tag\>" in rendered

    result = deepcopy(EXAMPLES["evaluator-result"])
    result["findings"][0]["confidence"] = "PROVEN"  # type: ignore[index]
    with pytest.raises(ContractValidationError):
        validate_payload("evaluator-result", result)


@pytest.mark.unit
def test_report_markdown_and_html_match_deterministic_goldens() -> None:
    run = cast(
        AssuranceRun,
        SimpleNamespace(
            pull_request_number=7,
            head_commit="b" * 40,
            diff_artifact=SimpleNamespace(content_hash="d" * 64),
            context_artifact=SimpleNamespace(content_hash="c" * 64),
            requirements_hash="a" * 64,
            policy_bundle_hash="e" * 64,
            evidence_bundle_hash="f" * 64,
            evaluator_version="fake-evaluator-v1",
            prompt_version="assurance-prompt-v1",
        ),
    )
    finding = cast(
        Finding,
        SimpleNamespace(
            severity="ADVISORY",
            title="Review <boundary>",
            path="src/auth.py",
            line=4,
            fingerprint="9" * 64,
        ),
    )
    markdown, rendered_html = _render_report(
        run=run,
        status="READY_WITH_WARNINGS",
        reasons=["MODEL_CONCERNS"],
        findings=(finding,),
        limitations=["No code was executed."],
    )
    root = Path(__file__).parents[1] / "fixtures"

    assert markdown == (root / "assurance-report-golden.md").read_text()
    assert rendered_html == (root / "assurance-report-golden.html").read_text()


@pytest.mark.unit
def test_report_renders_blockers_and_empty_sections_without_html_injection() -> None:
    run = cast(
        AssuranceRun,
        SimpleNamespace(
            pull_request_number=9,
            head_commit="c" * 40,
            diff_artifact=None,
            context_artifact=None,
            requirements_hash="a" * 64,
            policy_bundle_hash="b" * 64,
            evidence_bundle_hash="d" * 64,
            evaluator_version="<manual>",
            prompt_version="prompt_v1",
        ),
    )
    blocker = cast(
        Finding,
        SimpleNamespace(
            severity=Finding.Severity.BLOCKING,
            title="<script>unsafe</script>",
            path="",
            line=None,
            fingerprint="f" * 64,
        ),
    )

    markdown, rendered_html = _render_report(
        run=run,
        status="BLOCKED",
        reasons=[],
        findings=(blocker,),
        limitations=[],
    )

    assert r"\<script\>unsafe\</script\>" in markdown
    assert "<script>unsafe</script>" not in rendered_html
    assert "&lt;manual&gt;" not in rendered_html  # versions are intentionally omitted from HTML.
    assert "None recorded." in markdown
    assert "<li>None recorded.</li>" in rendered_html
    assert "No evaluator concerns recorded." in rendered_html
