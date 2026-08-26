"""Focused regressions for the independent assurance review fixes."""

from __future__ import annotations

import uuid
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

import pytest

from anva.contracts import ContractValidationError, validate_knowledge_changes
from anva.contracts.catalog import KNOWLEDGE_CHANGE
from anva.contracts.generate import openapi_document
from anva.core.models import AssuranceRun, Finding, WorkItemRevision
from anva.core.services.assurance import (
    MAX_LIMITATIONS,
    REPORT_DETAIL_LIMITATION_PREFIX,
    REQUIREMENT_TRACEABILITY_LIMITATION,
    _bounded_limitations,
    _finding_fingerprint,
    _fingerprinted_payloads,
    _render_report,
    _requirement_payload,
    _safe_report_text,
)
from anva.core.services.diffs import citation_in_diff, parse_unified_diff

NORMAL_DIFF = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1 @@
-old
+new
"""

NEW_FILE_DIFF = """diff --git a/src/new.py b/src/new.py
new file mode 100644
--- /dev/null
+++ b/src/new.py
@@ -0,0 +1,2 @@
+first
+second
"""

DELETED_FILE_DIFF = """diff --git a/src/auth/credentials.py b/src/auth/credentials.py
deleted file mode 100644
--- a/src/auth/credentials.py
+++ /dev/null
@@ -1,2 +0,0 @@
-first
-second
"""

RENAMED_FILE_DIFF = """diff --git a/src/old.py b/docs/new.md
similarity index 80%
rename from src/old.py
rename to docs/new.md
--- a/src/old.py
+++ b/docs/new.md
@@ -1 +1 @@
-old
+new
"""


def _modify_diff_for(path: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("unified_diff", "expected_path", "expected_classification"),
    [
        (NORMAL_DIFF, "src/app.py", "SOURCE"),
        (NEW_FILE_DIFF, "src/new.py", "SOURCE"),
        (DELETED_FILE_DIFF, "src/auth/credentials.py", "SECURITY_SENSITIVE"),
        (RENAMED_FILE_DIFF, "docs/new.md", "DOCUMENTATION"),
    ],
)
def test_diff_identity_is_coherent_for_modify_add_delete_and_rename(
    unified_diff: str,
    expected_path: str,
    expected_classification: str,
) -> None:
    parsed = parse_unified_diff(unified_diff)

    assert parsed.changed_paths == (expected_path,)
    assert parsed.chunks[0].path == expected_path
    assert parsed.chunks[0].classification == expected_classification


@pytest.mark.unit
def test_deleted_file_citations_use_the_validated_old_path() -> None:
    parsed = parse_unified_diff(DELETED_FILE_DIFF)

    assert citation_in_diff(
        chunks=parsed.chunks,
        path="src/auth/credentials.py",
        side="OLD",
        line=1,
    )
    assert not citation_in_diff(
        chunks=parsed.chunks,
        path="docs/readme.md",
        side="OLD",
        line=1,
    )
    assert not citation_in_diff(
        chunks=parsed.chunks,
        path="src/auth/credentials.py",
        side="NEW",
        line=1,
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "unified_diff",
    [
        NORMAL_DIFF.replace("--- a/src/app.py", "--- a/src/other.py"),
        NORMAL_DIFF.replace("+++ b/src/app.py", "+++ b/src/other.py"),
        NORMAL_DIFF.replace("--- a/src/app.py", "--- /dev/null").replace(
            "+++ b/src/app.py",
            "+++ /dev/null",
        ),
        NORMAL_DIFF.replace("+++ b/src/app.py\n", ""),
        NEW_FILE_DIFF.replace("@@ -0,0 +1,2 @@", "@@ -1 +1,2 @@").replace(
            "+first\n",
            " first\n",
        ),
        DELETED_FILE_DIFF.replace("@@ -1,2 +0,0 @@", "@@ -1,2 +1 @@").replace(
            "-first\n",
            " first\n",
        ),
        DELETED_FILE_DIFF.replace(
            "b/src/auth/credentials.py",
            "b/docs/readme.md",
        ),
        NEW_FILE_DIFF.replace(
            "a/src/new.py",
            "a/docs/advertised.md",
        ),
        RENAMED_FILE_DIFF.replace("rename from src/old.py", "rename from docs/old.md"),
        RENAMED_FILE_DIFF.replace("rename to docs/new.md\n", ""),
        NORMAL_DIFF.replace(
            "--- a/src/app.py",
            "new file mode 100644\n--- a/src/app.py",
        ),
        NORMAL_DIFF.replace(
            "--- a/src/app.py",
            "deleted file mode 100644\n--- a/src/app.py",
        ),
        _modify_diff_for("C:/temp/app.py"),
        _modify_diff_for("C:temp/app.py"),
        _modify_diff_for("//server/share/app.py"),
        _modify_diff_for(r"src\\hostile.py"),
        _modify_diff_for("src/../docs/app.py"),
        _modify_diff_for("."),
    ],
)
def test_diff_identity_rejects_mismatch_evasion_and_unsafe_paths(
    unified_diff: str,
) -> None:
    with pytest.raises(ValueError):
        parse_unified_diff(unified_diff)


@pytest.mark.unit
@pytest.mark.parametrize(
    "claim",
    [
        "safe-to-deploy",
        "approved for production deployment",
        "deployment_authorized",
        "ready for deployment",
        "defect_free",
        "Deployment is safe and merge can proceed",
        "deployment_is_safe and merge-can-proceed",
        "safe to be deployed",
        "can safely merge",
        "merge should proceed",
        "Deployment can go ahead",
        "Merging is risk-free",
        "Green light for deployment",
        "Merging poses no risk",
    ],
)
def test_report_sanitizer_neutralizes_deployment_claim_variants(claim: str) -> None:
    assert claim.casefold() not in _safe_report_text(f"Result: {claim}.").casefold()
    assert "[deployment-claim removed]" in _safe_report_text(f"Result: {claim}.")


@pytest.mark.unit
def test_report_sanitizer_preserves_legitimate_deployment_and_merge_context() -> None:
    context = "Review deployment rollback evidence and merge conflict handling."

    assert _safe_report_text(context) == context


@pytest.mark.unit
def test_report_uses_neutral_reason_label_and_escapes_untrusted_finding_text() -> None:
    finding = SimpleNamespace(
        severity=Finding.Severity.ADVISORY,
        title="safe-to-deploy <script>alert(1)</script>",
        fingerprint="f" * 64,
        path="src/<unsafe>.py",
        line=9,
        explanation="Deployment is safe and merge can proceed <detail>.",
        uncertainty="Merging is risk-free <uncertainty>.",
        suggested_resolution="Deployment can go ahead after <staging>.",
        citations=[],
    )
    run = cast(
        AssuranceRun,
        SimpleNamespace(
            pull_request_number=7,
            head_commit="a" * 40,
            diff_artifact=SimpleNamespace(content_hash="b" * 64),
            context_artifact=SimpleNamespace(content_hash="c" * 64),
            requirements_hash="d" * 64,
            policy_bundle_hash="e" * 64,
            evidence_bundle_hash="f" * 64,
            evaluator_version="evaluator-v1",
            prompt_version="prompt-v1",
        ),
    )

    markdown, rendered_html, report_limitations = _render_report(
        run=run,
        status="READY_WITH_WARNINGS",
        reasons=["MODEL_CONCERNS", "deployment-authorized"],
        findings=cast(tuple[Finding, ...], (finding,)),
        limitations=[],
    )

    assert "Readiness reasons" in markdown
    assert "Blocking reasons" not in markdown
    assert "MODEL\\_CONCERNS" in markdown
    assert "safe-to-deploy" not in markdown.casefold()
    assert "deployment-authorized" not in markdown.casefold()
    assert "<script" not in rendered_html.casefold()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered_html
    assert "Deployment is safe" not in markdown
    assert "merge can proceed" not in rendered_html
    assert "risk-free" not in markdown.casefold()
    assert "risk-free" not in rendered_html.casefold()
    assert "can go ahead" not in markdown.casefold()
    assert "can go ahead" not in rendered_html.casefold()
    assert "src/\\<unsafe\\>.py:9" in markdown
    assert "src/&lt;unsafe&gt;.py:9" in rendered_html
    assert "Readiness reasons" in rendered_html
    assert not any(
        limitation.startswith(REPORT_DETAIL_LIMITATION_PREFIX) for limitation in report_limitations
    )


@pytest.mark.unit
def test_required_traceability_limitation_survives_saturated_limit() -> None:
    optional = [f"000 evaluator limitation {index:03d}" for index in range(MAX_LIMITATIONS + 5)]

    bounded = _bounded_limitations(
        optional,
        required=(REQUIREMENT_TRACEABILITY_LIMITATION,),
    )
    replay = _bounded_limitations(
        list(reversed(optional)),
        required=(REQUIREMENT_TRACEABILITY_LIMITATION,),
    )

    assert len(bounded) == MAX_LIMITATIONS
    assert REQUIREMENT_TRACEABILITY_LIMITATION in bounded
    assert bounded == replay


@pytest.mark.unit
def test_requirement_payload_includes_linked_and_standalone_acceptance_criteria() -> None:
    requirement_id = uuid.uuid4()
    linked = SimpleNamespace(
        id=uuid.uuid4(),
        code="AC_LINKED",
        normalized_text="Linked acceptance",
        required_evidence_types=["TEST_RESULT", "SCREENSHOT"],
        manual_approval_allowed=False,
        requirement_id=requirement_id,
    )
    standalone = SimpleNamespace(
        id=uuid.uuid4(),
        code="AC_STANDALONE",
        normalized_text="Standalone acceptance",
        required_evidence_types=["LOG"],
        manual_approval_allowed=True,
        requirement_id=None,
    )
    requirement = SimpleNamespace(
        id=requirement_id,
        code="REQ_ONE",
        normalized_text="The system shall behave",
        status="ACTIVE",
        requires_approval=True,
    )
    criteria_queryset = Mock()
    criteria_queryset.order_by.return_value = [linked, standalone]
    requirements_queryset = Mock()
    requirements_queryset.order_by.return_value = [requirement]
    revision = cast(
        WorkItemRevision,
        SimpleNamespace(organization=SimpleNamespace(id=uuid.uuid4())),
    )

    with (
        patch(
            "anva.core.services.assurance.AcceptanceCriterion.objects.filter",
            return_value=criteria_queryset,
        ),
        patch(
            "anva.core.services.assurance.Requirement.objects.filter",
            return_value=requirements_queryset,
        ),
    ):
        payload = _requirement_payload(revision)

    assert payload[0]["kind"] == "REQUIREMENT"
    assert payload[0]["acceptance_criteria"] == [
        {
            "id": str(linked.id),
            "code": "AC_LINKED",
            "text": "Linked acceptance",
            "required_evidence_types": ["SCREENSHOT", "TEST_RESULT"],
            "manual_approval_allowed": False,
        }
    ]
    assert payload[1] == {
        "kind": "STANDALONE_ACCEPTANCE_CRITERION",
        "id": str(standalone.id),
        "code": "AC_STANDALONE",
        "text": "Standalone acceptance",
        "required_evidence_types": ["LOG"],
        "manual_approval_allowed": True,
    }


def _finding_payload() -> dict[str, object]:
    return {
        "code": "MODEL_CONCERN",
        "category": "CORRECTNESS",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "title": "Concern",
        "explanation": "Explanation",
        "citations": [
            {
                "type": "DIFF",
                "path": "src/app.py",
                "side": "NEW",
                "line": 7,
            },
            {
                "type": "ANVA_SOURCE",
                "context_citation_id": str(uuid.uuid4()),
            },
        ],
        "evidence_ids": [],
        "criterion_codes": ["CRIT_TWO", "CRIT_ONE"],
        "uncertainty": "None",
        "suggested_resolution": "Review it",
    }


@pytest.mark.unit
def test_finding_fingerprint_uses_exact_anchors_and_is_order_independent() -> None:
    finding = _finding_payload()
    baseline = _finding_fingerprint(finding)
    reordered = deepcopy(finding)
    reordered["citations"] = list(reversed(cast(list[object], reordered["citations"])))
    reordered["criterion_codes"] = ["CRIT_ONE", "CRIT_TWO"]

    assert _finding_fingerprint(reordered) == baseline

    different_line = deepcopy(finding)
    cast(list[dict[str, object]], different_line["citations"])[0]["line"] = 8
    assert _finding_fingerprint(different_line) != baseline

    different_source = deepcopy(finding)
    cast(list[dict[str, object]], different_source["citations"])[1]["context_citation_id"] = str(
        uuid.uuid4()
    )
    assert _finding_fingerprint(different_source) != baseline


@pytest.mark.unit
def test_duplicate_semantic_finding_fingerprints_are_rejected_before_merge() -> None:
    finding = _finding_payload()
    duplicate_with_different_prose = deepcopy(finding)
    duplicate_with_different_prose["title"] = "Different prose, same semantic anchor"

    with pytest.raises(ValueError, match="duplicate semantic findings"):
        _fingerprinted_payloads([finding, duplicate_with_different_prose])


@pytest.mark.unit
def test_post_merge_changes_use_the_canonical_knowledge_change_contract() -> None:
    valid_change = {
        "operation": "ADD",
        "target_id": None,
        "predicate": "service.owner",
        "value": {"team": "platform"},
        "is_inferred": False,
    }
    validate_knowledge_changes([valid_change])

    for invalid_change in (
        {key: value for key, value in valid_change.items() if key != "predicate"},
        {**valid_change, "operation": "DELETE"},
        {**valid_change, "unexpected": True},
    ):
        with pytest.raises(ContractValidationError):
            validate_knowledge_changes([invalid_change])

    document = cast(dict[str, Any], openapi_document())
    dismiss = document["paths"]["/findings/{resource_id}/dismiss"]["post"]
    dismiss_schema = dismiss["requestBody"]["content"]["application/json"]["schema"]
    post_merge_schema = document["paths"]["/assurance-runs/{resource_id}/post-merge-proposals"][
        "post"
    ]["requestBody"]["content"]["application/json"]["schema"]

    assert dismiss_schema["additionalProperties"] is False
    assert dismiss_schema["required"] == ["repository_id"]
    assert "requestBody" not in document["paths"]["/work-items/{resource_id}"]["get"]
    assert (
        post_merge_schema["properties"]["proposals"]["items"]["properties"]["changes"]["items"]
        == KNOWLEDGE_CHANGE
    )
