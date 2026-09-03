from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

CLASSIFIER = Path(__file__).parents[2] / "scripts" / "classify_release_source_scan.py"


def _report(*findings: tuple[str, str]) -> dict[str, object]:
    result: dict[str, Any] = {"Target": "fixture"}
    for kind, severity in findings:
        if kind == "vulnerability":
            result.setdefault("Vulnerabilities", []).append(
                {"VulnerabilityID": f"CVE-{severity}", "Severity": severity}
            )
        elif kind == "secret":
            result.setdefault("Secrets", []).append(
                {
                    "RuleID": f"SECRET-{severity}",
                    "Severity": severity,
                    "Match": "never-retain-secret-value",
                    "Code": {"Lines": [{"Content": "never-retain-source-line"}]},
                }
            )
        else:
            result.setdefault("Misconfigurations", []).append(
                {"ID": f"MISCONFIG-{severity}", "Severity": severity}
            )
    return {"SchemaVersion": 2, "Results": [result]}


def _classify(
    tmp_path: Path,
    report: object,
    *,
    engine_exit: int = 0,
    log: str = "scanner ok",
    report_kind: str = "source",
) -> tuple[subprocess.CompletedProcess[str], dict[str, object], dict[str, object], str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    report_path = tmp_path / "raw.json"
    report_path.write_text(json.dumps(report))
    log_path = tmp_path / "raw.log"
    log_path.write_text(log)
    database_path = tmp_path / "db.json"
    database_path.write_text('{"UpdatedAt":"fixture"}')
    sanitized_report = tmp_path / "sanitized.json"
    sanitized_log = tmp_path / "sanitized.log"
    diagnostic = tmp_path / "diagnostic.json"
    result = subprocess.run(  # noqa: S603 - repository-owned classifier.
        [
            sys.executable,
            str(CLASSIFIER),
            "--report",
            str(report_path),
            "--report-kind",
            report_kind,
            "--raw-log",
            str(log_path),
            "--sanitized-report",
            str(sanitized_report),
            "--sanitized-log",
            str(sanitized_log),
            "--diagnostic",
            str(diagnostic),
            "--database-metadata",
            str(database_path),
            "--scanner-image",
            "trivy@sha256:fixture",
            "--scanner-version",
            "Version: 0.64.1",
            "--engine-exit",
            str(engine_exit),
            "--run-id",
            "12345",
            "--run-attempt",
            "2",
            "--source-commit",
            "d" * 40,
            "--tag",
            "v0.1.2",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    return (
        result,
        json.loads(diagnostic.read_text()),
        json.loads(sanitized_report.read_text()),
        sanitized_log.read_text(),
    )


def test_engine_failure_is_distinct_and_never_passes(tmp_path: Path) -> None:
    result, diagnostic, _, _ = _classify(tmp_path, _report(), engine_exit=17)
    assert result.returncode == 20
    assert diagnostic["classification"] == "engine_error"
    assert diagnostic["engine_exit_code"] == 17
    assert diagnostic["github_run_id"] == "12345"
    assert diagnostic["github_run_attempt"] == 2
    assert diagnostic["source_commit"] == "d" * 40
    assert diagnostic["tag"] == "v0.1.2"


def test_high_or_critical_finding_fails_policy(tmp_path: Path) -> None:
    result, diagnostic, _, _ = _classify(
        tmp_path,
        _report(
            ("vulnerability", "HIGH"),
            ("secret", "CRITICAL"),
            ("misconfiguration", "HIGH"),
        ),
    )
    assert result.returncode == 22
    assert diagnostic["classification"] == "policy_findings"
    assert diagnostic["blocking_findings"] == [
        {"identifier": "MISCONFIG-HIGH", "kind": "misconfigurations", "severity": "HIGH"},
        {"identifier": "SECRET-CRITICAL", "kind": "secrets", "severity": "CRITICAL"},
        {"identifier": "CVE-HIGH", "kind": "vulnerabilities", "severity": "HIGH"},
    ]


def test_clean_and_allowed_findings_pass(tmp_path: Path) -> None:
    result, diagnostic, _, _ = _classify(
        tmp_path,
        _report(("vulnerability", "MEDIUM"), ("misconfiguration", "LOW")),
    )
    assert result.returncode == 0
    assert diagnostic["classification"] == "passed"
    assert diagnostic["blocking_findings"] == []


def test_diagnostics_retain_evidence_but_redact_secret_material(tmp_path: Path) -> None:
    match_marker = "never-retain-secret-value"
    raw_source = "never-retain-source-line"
    result, diagnostic, sanitized, log = _classify(
        tmp_path,
        _report(("secret", "LOW")),
        log=(
            "token=plain-text-token\n"
            "Authorization: Bearer should-not-remain\n"
            "github_pat_should_not_remain\n"
        ),
    )
    assert result.returncode == 0
    serialized = json.dumps(sanitized)
    assert match_marker not in serialized
    assert raw_source not in serialized
    assert "Match" not in serialized
    assert "Code" not in serialized
    assert "plain-text-token" not in log
    assert "should-not-remain" not in log
    assert diagnostic["sanitized_report_sha256"]
    assert diagnostic["sanitized_log_sha256"]
    assert diagnostic["database_metadata_sha256"]


def test_invalid_report_fails_closed_with_machine_readable_outputs(tmp_path: Path) -> None:
    result, diagnostic, sanitized, _ = _classify(tmp_path, {"SchemaVersion": 1})
    assert result.returncode == 21
    assert diagnostic["classification"] == "invalid_report"
    assert sanitized == {
        "reason": "invalid_or_missing",
        "schema_version": 1,
        "status": "unavailable",
    }


def test_malformed_nested_report_fails_closed_instead_of_losing_diagnostics(
    tmp_path: Path,
) -> None:
    result, diagnostic, sanitized, _ = _classify(
        tmp_path, {"SchemaVersion": 2, "Results": [{"Secrets": ["malformed"]}]}
    )
    assert result.returncode == 21
    assert diagnostic["classification"] == "invalid_report"
    assert sanitized["status"] == "unavailable"


def test_sanitized_report_is_deterministic_across_finding_order(tmp_path: Path) -> None:
    first = _report(("vulnerability", "LOW"), ("vulnerability", "MEDIUM"))
    second = _report(("vulnerability", "MEDIUM"), ("vulnerability", "LOW"))
    first["CreatedAt"] = "first timestamp"
    second["CreatedAt"] = "second timestamp"
    first_result, _, first_sanitized, _ = _classify(tmp_path / "first", first)
    second_result, _, second_sanitized, _ = _classify(tmp_path / "second", second)
    assert first_result.returncode == second_result.returncode == 0
    assert first_sanitized == second_sanitized
    assert "CreatedAt" not in first_sanitized


def test_canonical_order_is_total_for_duplicate_ids_and_results(tmp_path: Path) -> None:
    a = {"VulnerabilityID": "CVE-DUP", "Severity": "LOW", "PkgName": "z"}
    b = {"VulnerabilityID": "CVE-DUP", "Severity": "LOW", "PkgName": "a"}
    first: dict[str, Any] = {
        "SchemaVersion": 2,
        "Results": [
            {"Target": "same", "Vulnerabilities": [a, b], "marker": "z"},
            {"Target": "same", "Vulnerabilities": [b, a], "marker": "a"},
        ],
    }
    second = {"SchemaVersion": 2, "Results": list(reversed(first["Results"]))}
    first_result, first_diag, _, _ = _classify(tmp_path / "first-total", first)
    second_result, second_diag, _, _ = _classify(tmp_path / "second-total", second)
    assert first_result.returncode == second_result.returncode == 0
    assert (tmp_path / "first-total/sanitized.json").read_bytes() == (
        tmp_path / "second-total/sanitized.json"
    ).read_bytes()
    assert first_diag["sanitized_report_sha256"] == second_diag["sanitized_report_sha256"]


def test_image_findings_are_evidence_not_source_policy_failure(tmp_path: Path) -> None:
    result, diagnostic, _, _ = _classify(
        tmp_path,
        _report(("vulnerability", "CRITICAL")),
        report_kind="image-vulnerability",
    )
    assert result.returncode == 0
    assert diagnostic["classification"] == "passed"


def test_sbom_schemas_fail_closed(tmp_path: Path) -> None:
    for kind in ("spdx", "cyclonedx"):
        result, diagnostic, _, _ = _classify(tmp_path / kind, {}, report_kind=kind)
        assert result.returncode == 21
        assert diagnostic["classification"] == "invalid_report"


def test_valid_sbom_schemas_pass(tmp_path: Path) -> None:
    spdx = {"spdxVersion": "SPDX-2.3", "documentNamespace": "urn:fixture", "packages": []}
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    assert _classify(tmp_path / "spdx", spdx, report_kind="spdx")[0].returncode == 0
    assert _classify(tmp_path / "cdx", cdx, report_kind="cyclonedx")[0].returncode == 0
