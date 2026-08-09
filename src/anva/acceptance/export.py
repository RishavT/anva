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
SEALED_ARTIFACTS = {
    "results/knowledge-retrieval-results.jsonl": "knowledge_retrieval_results",
    "results/context-metadata.json": "structured_agent_output",
    "results/canvas.json": "browser_capture",
    "results/assurance-report.json": "assurance_report",
    "results/findings.json": "findings",
    "results/run-metadata.json": "run_metadata",
}


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
    if not results:
        raise AcceptanceExportError("MCP search output must contain public retrieval evidence")
    normalized: list[dict[str, object]] = []
    for rank, raw in enumerate(results, start=1):
        if not isinstance(raw, dict):
            raise AcceptanceExportError("MCP search output is invalid")
        allowed = {
            key: raw[key]
            for key in (
                "chunk_id",
                "content_hash",
                "pointer",
                "canonical_url",
                "source_location_id",
                "source_observation_id",
                "access_snapshot_id",
                "observed_at",
                "explanation",
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
    if not nodes:
        raise AcceptanceExportError("Canvas output must contain a public organizational node")

    def fields(record: object, names: tuple[str, ...]) -> dict[str, object]:
        if not isinstance(record, dict):
            raise AcceptanceExportError("Canvas output is invalid")
        return {name: record[name] for name in names if name in record}

    return {
        "nodes": sorted(
            (
                fields(
                    item,
                    (
                        "id",
                        "type",
                        "label",
                        "canonical_key",
                        "repository_ids",
                        "freshness",
                        "provenance",
                    ),
                )
                for item in nodes
            ),
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
    product_image_sha256: str,
    product_package_sha256: str,
    corpus_commit: str,
    canonical_manifest_sha256: str,
    canonical_input_sha256: str,
    head_commit: str,
    assurance_input_sha256: str,
    reference_time_sha256: str,
    review_result_sha256: str,
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
        product_image_sha256,
        product_package_sha256,
        corpus_commit,
        canonical_manifest_sha256,
        canonical_input_sha256,
        head_commit,
        assurance_input_sha256,
        reference_time_sha256,
        review_result_sha256,
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
        context_data = context_output.get("data")
        packet = context_data.get("packet") if isinstance(context_data, dict) else None
        items = packet.get("items") if isinstance(packet, dict) else None
        if not isinstance(items, list) or not items:
            raise AcceptanceExportError("Context output must contain public context items")
        citations = [
            citation
            for item in items
            if isinstance(item, dict)
            for citation in cast(list[object], item.get("anva_sources", []))
            if isinstance(citation, dict)
        ]
        if not citations:
            raise AcceptanceExportError("Context output must contain public source citations")
        context = canonical_bytes(
            {
                "content_hash": sha256_bytes(canonical_bytes(dict(context_output))),
                "tool": context_output.get("tool"),
                "contract_version": context_output.get("contract_version"),
                "item_count": len(items),
                "citations": [
                    {
                        key: citation[key]
                        for key in (
                            "canonical_url",
                            "locator",
                            "source_content_hash",
                            "source_location_id",
                            "source_observation_id",
                            "access_snapshot_id",
                        )
                        if key in citation
                    }
                    for citation in citations
                ],
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
                "product": {
                    "name": "anva",
                    "version": product_version,
                    "commit": product_commit,
                    "image_sha256": product_image_sha256,
                    "package_sha256": product_package_sha256,
                },
                "corpus": {
                    "id": corpus_id,
                    "commit": corpus_commit,
                    "manifest_sha256": manifest_sha256,
                    "source_fingerprint": source_fingerprint,
                    "canonical_input_sha256": canonical_input_sha256,
                    "canonical_manifest_sha256": canonical_manifest_sha256,
                },
                "assurance_head_commit": head_commit,
                "run": {
                    "id": run_id,
                    "reference_time": started_at,
                    "reference_time_sha256": reference_time_sha256,
                    "assurance_input_sha256": assurance_input_sha256,
                    "external_review_result_sha256": review_result_sha256,
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
        sums_bytes = "".join(
            f"{digest}  {path}\n" for digest, path in sorted(sums, key=lambda item: item[1])
        ).encode()
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


def _sealed_file(root: Path, relative: str, *, maximum: int = 2_000_000) -> bytes:
    path = root / relative
    if (
        path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) & 0o222
        or path.stat().st_size > maximum
    ):
        raise AcceptanceExportError("Existing sealed acceptance output is unsafe")
    raw = path.read_bytes()
    _assert_public(raw)
    return raw


def verify_sealed_results(
    *,
    output_root: Path,
    corpus_id: str,
    manifest_sha256: str,
    source_fingerprint: str,
    run_id: str,
    reference_time: str,
    product_version: str,
    product_commit: str,
    product_image_sha256: str,
    product_package_sha256: str,
    corpus_commit: str,
    canonical_input_sha256: str,
    canonical_manifest_sha256: str,
    head_commit: str,
    assurance_input_sha256: str,
    reference_time_sha256: str,
    review_result_sha256: str,
) -> str:
    """Verify and adopt only the exact immutable tree a prior finalize published."""
    if (
        output_root.is_symlink()
        or not output_root.is_dir()
        or stat.S_IMODE(output_root.stat().st_mode) & 0o222
    ):
        raise AcceptanceExportError("Existing sealed acceptance output is unsafe")
    expected_files = {*SEALED_ARTIFACTS, "acceptance-result.json", "SHA256SUMS"}
    observed_files = {
        path.relative_to(output_root).as_posix()
        for path in output_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if observed_files != expected_files:
        raise AcceptanceExportError("Existing sealed acceptance inventory is invalid")
    values = {relative: _sealed_file(output_root, relative) for relative in expected_files}
    expected_sums = "".join(
        f"{sha256_bytes(values[relative])}  {relative}\n"
        for relative in sorted(expected_files - {"SHA256SUMS"})
    ).encode()
    if values["SHA256SUMS"] != expected_sums:
        raise AcceptanceExportError("Existing sealed acceptance checksums are invalid")
    try:
        envelope = json.loads(values["acceptance-result.json"])
        metadata = json.loads(values["results/run-metadata.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceExportError("Existing sealed acceptance metadata is invalid") from error
    if not isinstance(envelope, dict) or not isinstance(metadata, dict):
        raise AcceptanceExportError("Existing sealed acceptance metadata is invalid")
    validate_payload("acceptance-result", envelope)
    expected_envelope = {
        "corpus_id": corpus_id,
        "manifest_sha256": manifest_sha256,
        "source_fingerprint": source_fingerprint,
        "run_id": run_id,
        "status": "COMPLETE",
        "started_at": reference_time,
        "completed_at": reference_time,
        "error": None,
    }
    if any(envelope.get(key) != value for key, value in expected_envelope.items()):
        raise AcceptanceExportError("Existing sealed acceptance identity is invalid")
    artifacts = envelope.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(SEALED_ARTIFACTS):
        raise AcceptanceExportError("Existing sealed acceptance artifacts are invalid")
    expected_artifacts = {
        relative: {
            "kind": kind,
            "path": relative,
            "sha256": sha256_bytes(values[relative]),
            "size_bytes": len(values[relative]),
        }
        for relative, kind in SEALED_ARTIFACTS.items()
    }
    observed_artifacts = {
        str(item.get("path")): item for item in artifacts if isinstance(item, dict)
    }
    if observed_artifacts != expected_artifacts:
        raise AcceptanceExportError("Existing sealed acceptance artifacts are invalid")
    expected_metadata = {
        "schema_version": 1,
        "product": {
            "name": "anva",
            "version": product_version,
            "commit": product_commit,
            "image_sha256": product_image_sha256,
            "package_sha256": product_package_sha256,
        },
        "corpus": {
            "id": corpus_id,
            "commit": corpus_commit,
            "manifest_sha256": manifest_sha256,
            "source_fingerprint": source_fingerprint,
            "canonical_input_sha256": canonical_input_sha256,
            "canonical_manifest_sha256": canonical_manifest_sha256,
        },
        "assurance_head_commit": head_commit,
        "run": {
            "id": run_id,
            "reference_time": reference_time,
            "reference_time_sha256": reference_time_sha256,
            "assurance_input_sha256": assurance_input_sha256,
            "external_review_result_sha256": review_result_sha256,
        },
    }
    if any(metadata.get(key) != value for key, value in expected_metadata.items()):
        raise AcceptanceExportError("Existing sealed acceptance provenance is invalid")
    ranking = metadata.get("ranking")
    if not isinstance(ranking, dict) or ranking.get("result_count", 0) < 1:
        raise AcceptanceExportError("Existing sealed acceptance retrieval is invalid")
    return sha256_bytes(values["acceptance-result.json"])
