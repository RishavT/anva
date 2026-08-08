"""Deterministic, atomic public acceptance result sealing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import cast

from anva.contracts.validation import validate_payload

HASH_PATTERN = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")
FORBIDDEN_MARKERS = (
    "private-oracle",
    "private_oracle",
    "private-grader",
    "private_grader",
    "grader-manifest",
    "oracle-manifest",
    "test_only_tst_008_private_oracle",
)


class AcceptanceExportError(ValueError):
    """The public export could not be sealed without crossing a private boundary."""


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _assert_public(value: bytes) -> None:
    lowered = value.lower()
    if any(marker.encode() in lowered for marker in FORBIDDEN_MARKERS):
        raise AcceptanceExportError("Public acceptance output contains a private marker")


def _write_new(path: Path, value: bytes) -> None:
    _assert_public(value)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _jsonl(records: Iterable[Mapping[str, object]]) -> bytes:
    return b"".join(canonical_bytes(dict(record)) for record in records)


def _artifact(path: str, kind: str, value: bytes) -> dict[str, object]:
    return {
        "kind": kind,
        "path": path,
        "sha256": sha256_bytes(value),
        "size_bytes": len(value),
    }


def _normalized_search_records(payload: Mapping[str, object]) -> list[dict[str, object]]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise AcceptanceExportError("MCP search output is invalid")
    results = data.get("results")
    if not isinstance(results, list):
        raise AcceptanceExportError("MCP search output is invalid")
    normalized: list[dict[str, object]] = []
    for rank, raw in enumerate(results, start=1):
        if not isinstance(raw, dict):
            raise AcceptanceExportError("MCP search output is invalid")
        allowed = {
            key: raw[key]
            for key in (
                "id",
                "source_chunk_id",
                "source_revision_id",
                "content_hash",
                "path",
                "locator",
                "score",
                "freshness",
                "citation_id",
            )
            if key in raw
        }
        allowed["rank"] = rank
        normalized.append(allowed)
    return normalized


def _normalized_canvas(payload: Mapping[str, object]) -> dict[str, object]:
    nodes = payload.get("nodes")
    edges = payload.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise AcceptanceExportError("Canvas output is invalid")

    def fields(record: object, names: tuple[str, ...]) -> dict[str, object]:
        if not isinstance(record, dict):
            raise AcceptanceExportError("Canvas output is invalid")
        return {name: record[name] for name in names if name in record}

    return {
        "nodes": sorted(
            (fields(item, ("id", "type", "label", "repository_id", "freshness")) for item in nodes),
            key=lambda item: (str(item.get("type", "")), str(item.get("id", ""))),
        ),
        "edges": sorted(
            (
                fields(item, ("id", "source", "target", "type", "source_id", "target_id"))
                for item in edges
            ),
            key=lambda item: (
                str(item.get("type", "")),
                str(item.get("source", item.get("source_id", ""))),
                str(item.get("target", item.get("target_id", ""))),
            ),
        ),
        "truncated": bool(payload.get("truncated", False)),
    }


def seal_results(
    *,
    output_root: Path,
    corpus_id: str,
    manifest_sha256: str,
    source_fingerprint: str,
    run_id: str,
    started_at: str,
    completed_at: str,
    product_version: str,
    product_commit: str,
    corpus_commit: str,
    canonical_input_sha256: str,
    head_commit: str,
    assurance_input_sha256: str,
    reference_time_sha256: str,
    search_output: Mapping[str, object],
    context_output: Mapping[str, object],
    canvas_output: Mapping[str, object],
    report_output: Mapping[str, object],
    findings_output: Mapping[str, object],
) -> str:
    """Seal a public result directory once; private readers only see the final rename."""
    if output_root.exists() or output_root.is_symlink():
        raise AcceptanceExportError("Acceptance output already exists")
    for digest in (
        manifest_sha256,
        source_fingerprint,
        product_commit,
        corpus_commit,
        canonical_input_sha256,
        head_commit,
        assurance_input_sha256,
        reference_time_sha256,
    ):
        if HASH_PATTERN.fullmatch(digest) is None:
            raise AcceptanceExportError("Acceptance provenance hash is invalid")
    parent = output_root.parent.resolve()
    if not parent.is_dir() or output_root.parent.is_symlink():
        raise AcceptanceExportError("Acceptance output parent is unsafe")
    temporary = parent / f".{output_root.name}.{uuid.uuid4().hex}.sealing"
    temporary.mkdir(mode=0o700)
    try:
        retrieval = _jsonl(_normalized_search_records(search_output))
        context = canonical_bytes(
            {
                "content_hash": sha256_bytes(canonical_bytes(dict(context_output))),
                "tool": context_output.get("tool"),
                "contract_version": context_output.get("contract_version"),
            }
        )
        canvas = canonical_bytes(_normalized_canvas(canvas_output))
        report = canonical_bytes(
            {
                key: report_output[key]
                for key in (
                    "assurance_run_id",
                    "readiness",
                    "head_commit",
                    "renderer_version",
                    "content_hash",
                    "limitations",
                )
                if key in report_output
            }
        )
        findings = canonical_bytes(
            {
                "assurance_run_id": findings_output.get("assurance_run_id"),
                "findings_sha256": sha256_bytes(canonical_bytes(dict(findings_output))),
                "finding_count": len(cast(list[object], findings_output.get("findings", []))),
            }
        )
        metadata = canonical_bytes(
            {
                "schema_version": 1,
                "product": {"name": "anva", "version": product_version, "commit": product_commit},
                "corpus": {
                    "id": corpus_id,
                    "commit": corpus_commit,
                    "manifest_sha256": manifest_sha256,
                    "source_fingerprint": source_fingerprint,
                    "canonical_input_sha256": canonical_input_sha256,
                },
                "assurance_head_commit": head_commit,
                "run": {
                    "id": run_id,
                    "reference_time": started_at,
                    "reference_time_sha256": reference_time_sha256,
                    "assurance_input_sha256": assurance_input_sha256,
                },
                "ranking": {
                    "order": "server-returned-rank",
                    "result_count": len(_normalized_search_records(search_output)),
                    "content_minimized": True,
                },
            }
        )
        values: list[tuple[str, str, bytes]] = [
            ("results/knowledge-retrieval-results.jsonl", "knowledge_retrieval_results", retrieval),
            ("results/context-metadata.json", "structured_agent_output", context),
            ("results/canvas.json", "browser_capture", canvas),
            ("results/assurance-report.json", "assurance_report", report),
            ("results/findings.json", "findings", findings),
            ("results/run-metadata.json", "run_metadata", metadata),
        ]
        artifacts: list[dict[str, object]] = []
        for relative, kind, value in values:
            _write_new(temporary / relative, value)
            artifacts.append(_artifact(relative, kind, value))
        manifest = {
            "schema_version": "1.0",
            "corpus_id": corpus_id,
            "manifest_sha256": manifest_sha256,
            "source_fingerprint": source_fingerprint,
            "run_id": run_id,
            "status": "COMPLETE",
            "started_at": started_at,
            "completed_at": completed_at,
            "artifacts": artifacts,
            "error": None,
        }
        validate_payload("acceptance-result", manifest)
        manifest_bytes = canonical_bytes(manifest)
        _write_new(temporary / "acceptance-result.json", manifest_bytes)
        sums = [(sha256_bytes(value), relative) for relative, _kind, value in values] + [
            (sha256_bytes(manifest_bytes), "acceptance-result.json")
        ]
        sums_bytes = "".join(f"{digest}  {path}\n" for digest, path in sorted(sums)).encode()
        _write_new(temporary / "SHA256SUMS", sums_bytes)
        for directory in sorted(
            (path for path in temporary.rglob("*") if path.is_dir()), reverse=True
        ):
            directory.chmod(0o500)
        for path in temporary.rglob("*"):
            if path.is_file():
                path.chmod(0o400)
        temporary.chmod(0o500)
        directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        temporary.replace(output_root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return sha256_bytes(manifest_bytes)
    except BaseException:
        if temporary.exists():
            for path in temporary.rglob("*"):
                if path.is_file():
                    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                elif path.is_dir():
                    path.chmod(stat.S_IRWXU)
            temporary.chmod(stat.S_IRWXU)
            shutil.rmtree(temporary)
        raise
