"""Integration of canonical acceptance output with the supported filesystem connector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from anva.acceptance.corpus import canonicalize_corpus
from anva.ingestion.filesystem import FilesystemConnector


@pytest.mark.integration
def test_supported_connector_observes_only_canonical_payload(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    payload = raw / "payload" / "sources"
    canonical = tmp_path / "canonical"
    payload.mkdir(parents=True)
    canonical.mkdir()
    source = payload / "decision.md"
    source.write_bytes(b"# Canonical public source\n")
    manifest = {
        "schema_version": "1.0",
        "corpus_id": "connector-corpus",
        "generated_at": "2026-08-07T00:00:00Z",
        "source_commit": "a" * 40,
        "files": [
            {
                "path": "payload/sources/decision.md",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "size_bytes": source.stat().st_size,
            }
        ],
        "limits": {
            "max_files": 1,
            "max_total_bytes": 1024,
            "max_file_bytes": 1024,
            "max_depth": 2,
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (raw / "acceptance-corpus.json").write_bytes(manifest_bytes)

    try:
        canonicalize_corpus(
            raw_root=raw,
            canonical_root=canonical,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )
        connector = FilesystemConnector(canonical / "payload")
        page = connector.discover(cursor=None, limit=10)

        assert [document.relative_path.as_posix() for document in page.documents] == [
            "sources/decision.md"
        ]
        assert connector.fetch(page.documents[0], max_bytes=1024).content == (
            b"# Canonical public source\n"
        )
        assert all("canonical-manifest" not in item.external_id for item in page.documents)
    finally:
        for path in canonical.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        canonical.chmod(0o700)
