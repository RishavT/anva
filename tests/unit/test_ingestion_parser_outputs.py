"""Unit coverage for deterministic parser and extractor outputs."""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from anva.ingestion.extractors import MechanicalExtractor, default_extractors
from anva.ingestion.interfaces import (
    DocumentDescriptor,
    DocumentFormat,
    FetchedContent,
    SourceObjectKind,
    choose_parser,
)
from anva.ingestion.parsers import default_parsers


def _content(
    path: str, document_format: DocumentFormat, body: str, media_type: str = "text/plain"
) -> FetchedContent:
    descriptor = DocumentDescriptor(
        external_id=path,
        relative_path=PurePosixPath(path),
        canonical_url=f"file:///fixture/{path}",
        source_object_kind=SourceObjectKind.FILE,
        document_format=document_format,
        media_type=media_type,
    )
    return FetchedContent(descriptor=descriptor, content=body.encode())


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "document_format", "body", "expected"),
    [
        (
            "README.md",
            DocumentFormat.MARKDOWN,
            "# Service\n[Runbook](docs/runbook.md)\n",
            {"headings": [{"level": 1, "text": "Service", "line": 1}]},
        ),
        (
            "CODEOWNERS",
            DocumentFormat.CODEOWNERS,
            "# comment\n/api @platform @security\n",
            {"rules": [{"pattern": "/api", "owners": ["@platform", "@security"], "line": 2}]},
        ),
        (
            "migrations/0001.py",
            DocumentFormat.MIGRATION,
            "CreateModel('Thing')\nAddField('Thing')\n",
            {
                "operations": [
                    {"operation": "CreateModel", "line": 1},
                    {"operation": "AddField", "line": 2},
                ]
            },
        ),
        ("notes.txt", DocumentFormat.TEXT, "one\ntwo\n", {"text": "one\ntwo\n", "line_count": 3}),
    ],
)
def test_textual_parsers_preserve_structured_source_facts(
    path: str, document_format: DocumentFormat, body: str, expected: dict[str, object]
) -> None:
    content = _content(path, document_format, body)
    parsed = choose_parser(content.descriptor, default_parsers()).parse(content)
    for key, value in expected.items():
        assert parsed.normalized[key] == value


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "body", "expected"),
    [
        (
            "service.json",
            '{"name":"payments","dependencies":["ledger"],"owners":["platform"]}',
            {"name": "payments"},
        ),
        ("service.yaml", "name: payments\ncreated: 2025-01-02\n", {"created": "2025-01-02"}),
        ("pyproject.toml", "[project]\nname = 'anva'\n", {"project": {"name": "anva"}}),
        ("opaque.lock", "opaque\n", {"text": "opaque\n"}),
    ],
)
def test_structured_parsers_normalize_json_yaml_and_manifest_data(
    path: str, body: str, expected: dict[str, object]
) -> None:
    document_format = (
        DocumentFormat.JSON
        if path.endswith(".json")
        else DocumentFormat.YAML
        if path.endswith(".yaml")
        else DocumentFormat.MANIFEST
    )
    content = _content(
        path, document_format, body, "application/json" if path.endswith(".json") else "text/plain"
    )
    parsed = choose_parser(content.descriptor, default_parsers()).parse(content)
    data = parsed.normalized["data"]
    assert isinstance(data, dict)
    for key, value in expected.items():
        assert data[key] == value


@pytest.mark.unit
def test_mechanical_extractor_emits_only_explicit_claims_for_each_parser_family() -> None:
    parser_set = default_parsers()
    extractor = MechanicalExtractor()
    structured = choose_parser(
        _content(
            "service.json",
            DocumentFormat.JSON,
            '{"service":"billing","owner":"platform","nested":{"maintainer":"core"}}',
            "application/json",
        ).descriptor,
        parser_set,
    ).parse(
        _content(
            "service.json",
            DocumentFormat.JSON,
            '{"service":"billing","owner":"platform","nested":{"maintainer":"core"}}',
            "application/json",
        )
    )
    markdown = choose_parser(
        _content("README.md", DocumentFormat.MARKDOWN, "# Overview\n").descriptor, parser_set
    ).parse(_content("README.md", DocumentFormat.MARKDOWN, "# Overview\n"))
    codeowners = choose_parser(
        _content("CODEOWNERS", DocumentFormat.CODEOWNERS, "/api @platform\n").descriptor, parser_set
    ).parse(_content("CODEOWNERS", DocumentFormat.CODEOWNERS, "/api @platform\n"))
    migration = choose_parser(
        _content(
            "migrations/0001.py", DocumentFormat.MIGRATION, "CreateModel('Thing')\n"
        ).descriptor,
        parser_set,
    ).parse(_content("migrations/0001.py", DocumentFormat.MIGRATION, "CreateModel('Thing')\n"))

    assert [
        (claim.subject_key, claim.predicate, claim.value)
        for claim in extractor.extract(structured).claims
    ] == [
        ("service:billing", "owned_by", "platform"),
        ("service:billing", "declares_service", "billing"),
        ("service:billing", "maintained_by", "core"),
    ]
    assert extractor.extract(markdown).claims[0].predicate == "documents_heading"
    assert extractor.extract(codeowners).claims[0].subject_key == "path:/api"
    assert extractor.extract(migration).claims[0].predicate == "performs_migration_operation"
    defaults = default_extractors()
    assert len(defaults) == 1
    assert isinstance(defaults[0], MechanicalExtractor)
