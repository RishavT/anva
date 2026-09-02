#!/usr/bin/env python3
"""Classify a release source scan without retaining secret match contents."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, cast

POLICY_SEVERITIES = {"HIGH", "CRITICAL"}
SECRET_FIELDS = {"Code", "Match"}
MAX_LOG_BYTES = 64 * 1024
SENSITIVE_VALUE = re.compile(
    r"(?im)\b(authorization|password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*)[^\r\n]*"
)
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b")


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sanitize_log(raw: bytes) -> tuple[str, bool]:
    truncated = len(raw) > MAX_LOG_BYTES
    text = raw[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
    text = SENSITIVE_VALUE.sub(r"\1\2[REDACTED]", text)
    text = GITHUB_TOKEN.sub("[REDACTED_GITHUB_TOKEN]", text)
    if truncated:
        text += "\n[truncated at 65536 bytes]\n"
    return text, truncated


def _canonicalize(value: Any) -> Any:
    """Return JSON whose arrays have a total, content-derived ordering."""
    if isinstance(value, dict):
        return {key: _canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        items = [_canonicalize(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    return value


def _sanitize_report(report: dict[str, Any]) -> dict[str, Any]:
    sanitized = json.loads(json.dumps(report))
    sanitized.pop("CreatedAt", None)
    for result in sanitized.get("Results", []):
        for secret in result.get("Secrets") or []:
            for field in SECRET_FIELDS:
                secret.pop(field, None)
    return cast(dict[str, Any], _canonicalize(sanitized))


def _validate_trivy_report(report: dict[str, Any]) -> None:
    results = report.get("Results")
    if report.get("SchemaVersion") != 2:
        raise ValueError("report SchemaVersion must equal 2")
    if not isinstance(results, list):
        raise ValueError("report Results must be an array")
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("every report result must be an object")
        for field in ("Vulnerabilities", "Secrets", "Misconfigurations"):
            findings = result.get(field)
            if findings is not None and not isinstance(findings, list):
                raise ValueError(f"report {field} must be an array or null")
            if findings is not None and not all(isinstance(item, dict) for item in findings):
                raise ValueError(f"every report {field} entry must be an object")


def _validate_report_shape(report: dict[str, Any], report_kind: str) -> None:
    if report_kind in {"source", "image-vulnerability"}:
        _validate_trivy_report(report)
    elif report_kind == "spdx":
        if report.get("spdxVersion") != "SPDX-2.3":
            raise ValueError("SPDX report spdxVersion must equal SPDX-2.3")
        if not isinstance(report.get("documentNamespace"), str):
            raise ValueError("SPDX report documentNamespace must be a string")
        if not isinstance(report.get("packages"), list) or not all(
            isinstance(item, dict) for item in report["packages"]
        ):
            raise ValueError("SPDX report packages must be an array of objects")
    elif report_kind == "cyclonedx":
        if report.get("bomFormat") != "CycloneDX":
            raise ValueError("CycloneDX report bomFormat must equal CycloneDX")
        if not isinstance(report.get("specVersion"), str):
            raise ValueError("CycloneDX report specVersion must be a string")
        if not isinstance(report.get("components"), list) or not all(
            isinstance(item, dict) for item in report["components"]
        ):
            raise ValueError("CycloneDX report components must be an array of objects")


def _findings(report: dict[str, Any]) -> tuple[dict[str, dict[str, int]], list[dict[str, str]]]:
    counts: dict[str, Counter[str]] = {
        "vulnerabilities": Counter(),
        "secrets": Counter(),
        "misconfigurations": Counter(),
    }
    blocked: list[dict[str, str]] = []
    fields = (
        ("Vulnerabilities", "vulnerabilities", "VulnerabilityID"),
        ("Secrets", "secrets", "RuleID"),
        ("Misconfigurations", "misconfigurations", "ID"),
    )
    for result in report.get("Results", []):
        for source_field, kind, identifier_field in fields:
            for finding in result.get(source_field) or []:
                severity = str(finding.get("Severity") or "UNKNOWN").upper()
                counts[kind][severity] += 1
                if severity in POLICY_SEVERITIES:
                    blocked.append(
                        {
                            "kind": kind,
                            "identifier": str(finding.get(identifier_field) or "UNKNOWN"),
                            "severity": severity,
                        }
                    )
    blocked.sort(key=lambda item: (item["kind"], item["identifier"], item["severity"]))
    return ({kind: dict(sorted(values.items())) for kind, values in counts.items()}, blocked)


def classify(args: argparse.Namespace) -> int:
    report_path = Path(args.report)
    raw_log_path = Path(args.raw_log)
    sanitized_report_path = Path(args.sanitized_report)
    sanitized_log_path = Path(args.sanitized_log)
    diagnostic_path = Path(args.diagnostic)
    database_metadata_path = Path(args.database_metadata)

    raw_log = raw_log_path.read_bytes() if raw_log_path.is_file() else b""
    sanitized_log, log_truncated = _sanitize_log(raw_log)
    sanitized_log_path.write_text(sanitized_log, encoding="utf-8")

    report: dict[str, Any] | None = None
    report_error: str | None = None
    try:
        candidate = json.loads(report_path.read_bytes())
        if not isinstance(candidate, dict):
            raise ValueError("report root must be an object")
        _validate_report_shape(candidate, args.report_kind)
        report = candidate
    except (OSError, json.JSONDecodeError, ValueError) as error:
        report_error = str(error)

    counts: dict[str, dict[str, int]] = {
        "vulnerabilities": {},
        "secrets": {},
        "misconfigurations": {},
    }
    blocked: list[dict[str, str]] = []
    if report is None:
        sanitized_report_path.write_text(
            json.dumps(
                {"schema_version": 1, "status": "unavailable", "reason": "invalid_or_missing"},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        if args.report_kind in {"source", "image-vulnerability"}:
            counts, blocked = _findings(report)
        sanitized_report_path.write_text(
            json.dumps(_sanitize_report(report), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    if args.engine_exit != 0:
        classification = "engine_error"
        status = 20
    elif report_error is not None:
        classification = "invalid_report"
        status = 21
    elif args.report_kind == "source" and blocked:
        classification = "policy_findings"
        status = 22
    else:
        classification = "passed"
        status = 0

    diagnostic = {
        "schema_version": 1,
        "kind": "anva.release-scan-diagnostic",
        "stage": args.report_kind,
        "github_run_id": args.run_id,
        "github_run_attempt": args.run_attempt,
        "source_commit": args.source_commit,
        "tag": args.tag,
        "classification": classification,
        "engine_exit_code": args.engine_exit,
        "scanner_image": args.scanner_image,
        "scanner_version": args.scanner_version,
        "database_metadata_sha256": _sha256(database_metadata_path),
        "raw_report_sha256": _sha256(report_path),
        "sanitized_report_sha256": _sha256(sanitized_report_path),
        "sanitized_log_sha256": _sha256(sanitized_log_path),
        "log_truncated": log_truncated,
        "report_error": report_error,
        "finding_counts_by_severity": counts,
        "blocking_findings": blocked,
    }
    diagnostic_path.write_text(
        json.dumps(diagnostic, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(classification)
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument(
        "--report-kind",
        choices=("source", "image-vulnerability", "spdx", "cyclonedx"),
        default="source",
    )
    parser.add_argument("--raw-log", required=True)
    parser.add_argument("--sanitized-report", required=True)
    parser.add_argument("--sanitized-log", required=True)
    parser.add_argument("--diagnostic", required=True)
    parser.add_argument("--database-metadata", required=True)
    parser.add_argument("--scanner-image", required=True)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--engine-exit", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag", required=True)
    return classify(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
