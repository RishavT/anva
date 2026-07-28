"""Deterministic bounded parsers for untrusted organization source files."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Mapping
from datetime import date, datetime
from typing import Any

import yaml
from yaml.tokens import AliasToken, AnchorToken

from anva.ingestion.errors import IngestionError, UnsafeSourceError
from anva.ingestion.interfaces import (
    DocumentDescriptor,
    DocumentFormat,
    FetchedContent,
    JSONValue,
    ParsedDocument,
    Parser,
    ParserKind,
)
from anva.ingestion.limits import IngestionLimits

_MARKDOWN_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_MIGRATION_OPERATION = re.compile(
    r"\b(CreateModel|AddField|AlterField|RemoveField|RunSQL|CREATE TABLE|ALTER TABLE|DROP TABLE)\b",
    re.IGNORECASE,
)
_REMOTE_REFERENCE_SCHEMES = ("http://", "https://", "file://")


class _Yaml12SafeLoader(yaml.SafeLoader):
    """Safe loader with YAML 1.2 boolean behavior required by workflow files."""


_Yaml12SafeLoader.yaml_implicit_resolvers = {
    key: [(tag, expression) for tag, expression in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Yaml12SafeLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


def _decode(content: FetchedContent, limits: IngestionLimits) -> str:
    if len(content.content) > limits.max_file_bytes:
        raise IngestionError("file_too_large", "Parser input exceeds byte limit")
    try:
        text = content.content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IngestionError("invalid_utf8", "Source document is not valid UTF-8") from error
    if text.count("\n") + 1 > limits.max_text_lines:
        raise IngestionError("line_limit_exceeded", "Source document line limit exceeded")
    return text


def _normalize_value(value: Any) -> JSONValue:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, list | tuple):
        return [_normalize_value(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, JSONValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise IngestionError(
                    "unsupported_mapping_key",
                    "Structured source keys must be strings",
                )
            normalized[key] = _normalize_value(item)
        return normalized
    raise IngestionError(
        "unsupported_structured_value",
        "Structured source contains an unsupported value",
    )


def _validate_tree(value: JSONValue, limits: IngestionLimits) -> None:
    nodes = 0
    stack: list[tuple[JSONValue, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_parse_nodes:
            raise IngestionError("parse_node_limit_exceeded", "Structured node limit exceeded")
        if depth > limits.max_parse_depth:
            raise IngestionError("parse_depth_exceeded", "Structured depth limit exceeded")
        if isinstance(item, str) and len(item.encode()) > limits.max_scalar_bytes:
            raise IngestionError("scalar_limit_exceeded", "Structured scalar limit exceeded")
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())


def _reject_remote_references(value: JSONValue) -> None:
    stack: list[JSONValue] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            reference = item.get("$ref")
            if isinstance(reference, str) and reference.lower().startswith(
                _REMOTE_REFERENCE_SCHEMES
            ):
                raise UnsafeSourceError(
                    "remote_reference_forbidden",
                    "Remote and filesystem references are not fetched",
                )
            stack.extend(item.values())


def _pointer_locations(value: JSONValue) -> tuple[Mapping[str, JSONValue], ...]:
    locations: list[Mapping[str, JSONValue]] = []
    stack: list[tuple[str, JSONValue]] = [("", value)]
    while stack:
        pointer, item = stack.pop()
        if isinstance(item, dict):
            for key, child in reversed(tuple(item.items())):
                escaped = key.replace("~", "~0").replace("/", "~1")
                stack.append((f"{pointer}/{escaped}", child))
        elif isinstance(item, list):
            for index in range(len(item) - 1, -1, -1):
                stack.append((f"{pointer}/{index}", item[index]))
        else:
            locations.append({"pointer": pointer or "/"})
    return tuple(locations)


def _load_json(text: str) -> JSONValue:
    try:
        value = json.loads(
            text,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite numbers are forbidden")
            ),
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise IngestionError("malformed_json", "Source document contains malformed JSON") from error
    return _normalize_value(value)


def _load_yaml(text: str, limits: IngestionLimits) -> JSONValue:
    token_count = 0
    try:
        for token in yaml.scan(text):
            token_count += 1
            if token_count > limits.max_yaml_tokens:
                raise IngestionError("yaml_token_limit_exceeded", "YAML token limit exceeded")
            if isinstance(token, AnchorToken | AliasToken):
                raise UnsafeSourceError(
                    "yaml_alias_forbidden",
                    "YAML anchors and aliases are not supported",
                )
        loader = _Yaml12SafeLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()  # type: ignore[no-untyped-call]
    except IngestionError:
        raise
    except yaml.YAMLError as error:
        raise IngestionError("malformed_yaml", "Source document contains malformed YAML") from error
    return _normalize_value(value)


def _load_toml(text: str) -> JSONValue:
    try:
        return _normalize_value(tomllib.loads(text))
    except tomllib.TOMLDecodeError as error:
        raise IngestionError("malformed_toml", "Source document contains malformed TOML") from error


class _BaseParser:
    kind: ParserKind
    implementation_name: str
    implementation_version = "1"

    def __init__(self, *, limits: IngestionLimits | None = None) -> None:
        self.limits = limits or IngestionLimits()

    def _result(
        self,
        content: FetchedContent,
        normalized: Mapping[str, JSONValue],
        locations: tuple[Mapping[str, JSONValue], ...],
    ) -> ParsedDocument:
        return ParsedDocument(
            parser_kind=self.kind,
            parser_name=self.implementation_name,
            parser_version=self.implementation_version,
            document_format=content.descriptor.document_format,
            normalized=normalized,
            locations=locations,
        )


class MarkdownParser(_BaseParser):
    """Extract Markdown structure while preserving all text as inert data."""

    kind = ParserKind.MARKDOWN
    implementation_name = "markdown"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.MARKDOWN

    def parse(self, content: FetchedContent) -> ParsedDocument:
        text = _decode(content, self.limits)
        headings: list[JSONValue] = []
        links: list[JSONValue] = []
        locations: list[Mapping[str, JSONValue]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            heading = _MARKDOWN_HEADING.match(line)
            if heading:
                headings.append(
                    {
                        "level": len(heading.group(1)),
                        "text": heading.group(2),
                        "line": line_number,
                    }
                )
                locations.append(
                    {
                        "pointer": f"/headings/{len(headings) - 1}",
                        "start_line": line_number,
                        "end_line": line_number,
                    }
                )
            for label, target in _MARKDOWN_LINK.findall(line):
                links.append({"label": label, "target": target, "line": line_number})
        return self._result(
            content,
            {"headings": headings, "links": links, "text": text},
            tuple(locations),
        )


class CodeownersParser(_BaseParser):
    """Parse CODEOWNERS patterns without interpreting them as filesystem paths."""

    kind = ParserKind.CODEOWNERS
    implementation_name = "codeowners"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.CODEOWNERS

    def parse(self, content: FetchedContent) -> ParsedDocument:
        text = _decode(content, self.limits)
        rules: list[JSONValue] = []
        locations: list[Mapping[str, JSONValue]] = []
        for line_number, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                raise IngestionError(
                    "malformed_codeowners",
                    "CODEOWNERS contains a rule without an owner",
                )
            owners: list[JSONValue] = list(parts[1:])
            rule: dict[str, JSONValue] = {
                "pattern": parts[0],
                "owners": owners,
                "line": line_number,
            }
            rules.append(rule)
            locations.append(
                {
                    "pointer": f"/rules/{len(rules) - 1}",
                    "start_line": line_number,
                    "end_line": line_number,
                }
            )
        return self._result(content, {"rules": rules}, tuple(locations))


class MigrationParser(_BaseParser):
    """Recognize migration operations from source text without importing or executing it."""

    kind = ParserKind.MIGRATION
    implementation_name = "migration-text"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.MIGRATION

    def parse(self, content: FetchedContent) -> ParsedDocument:
        text = _decode(content, self.limits)
        operations: list[JSONValue] = []
        locations: list[Mapping[str, JSONValue]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            for match in _MIGRATION_OPERATION.finditer(line):
                operations.append({"operation": match.group(1), "line": line_number})
                locations.append(
                    {
                        "pointer": f"/operations/{len(operations) - 1}",
                        "start_line": line_number,
                        "end_line": line_number,
                    }
                )
        return self._result(content, {"operations": operations, "text": text}, tuple(locations))


class _StructuredParser(_BaseParser):
    reject_remote_references = False

    def _load(self, content: FetchedContent, text: str) -> JSONValue:
        raise NotImplementedError

    def parse(self, content: FetchedContent) -> ParsedDocument:
        text = _decode(content, self.limits)
        value = self._load(content, text)
        _validate_tree(value, self.limits)
        if self.reject_remote_references:
            _reject_remote_references(value)
        return self._result(content, {"data": value}, _pointer_locations(value))


class JsonParser(_StructuredParser):
    kind = ParserKind.JSON
    implementation_name = "json"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.JSON

    def _load(self, content: FetchedContent, text: str) -> JSONValue:
        return _load_json(text)


class YamlParser(_StructuredParser):
    kind = ParserKind.YAML
    implementation_name = "yaml-safe"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.YAML

    def _load(self, content: FetchedContent, text: str) -> JSONValue:
        return _load_yaml(text, self.limits)


class WorkflowParser(YamlParser):
    kind = ParserKind.WORKFLOW
    implementation_name = "github-workflow-safe"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.WORKFLOW


class OpenAPIParser(_StructuredParser):
    kind = ParserKind.OPENAPI
    implementation_name = "openapi-data"
    reject_remote_references = True

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.OPENAPI

    def _load(self, content: FetchedContent, text: str) -> JSONValue:
        if content.descriptor.media_type == "application/json":
            return _load_json(text)
        return _load_yaml(text, self.limits)


class ManifestParser(_StructuredParser):
    kind = ParserKind.MANIFEST
    implementation_name = "manifest-data"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.MANIFEST

    def _load(self, content: FetchedContent, text: str) -> JSONValue:
        name = content.descriptor.relative_path.name.lower()
        suffix = content.descriptor.relative_path.suffix.lower()
        if suffix == ".json":
            return _load_json(text)
        if suffix in {".yaml", ".yml"}:
            return _load_yaml(text, self.limits)
        if suffix == ".toml" or name == "uv.lock":
            return _load_toml(text)
        return {"text": text}


class TextParser(_BaseParser):
    kind = ParserKind.TEXT
    implementation_name = "plain-text"

    def supports(self, document: DocumentDescriptor) -> bool:
        return document.document_format == DocumentFormat.TEXT

    def parse(self, content: FetchedContent) -> ParsedDocument:
        text = _decode(content, self.limits)
        return self._result(
            content,
            {"text": text, "line_count": text.count("\n") + 1},
            (),
        )


def default_parsers(*, limits: IngestionLimits | None = None) -> tuple[Parser, ...]:
    """Return one explicit parser implementation for every supported document format."""
    effective_limits = limits or IngestionLimits()
    return (
        MarkdownParser(limits=effective_limits),
        YamlParser(limits=effective_limits),
        JsonParser(limits=effective_limits),
        TextParser(limits=effective_limits),
        CodeownersParser(limits=effective_limits),
        ManifestParser(limits=effective_limits),
        MigrationParser(limits=effective_limits),
        WorkflowParser(limits=effective_limits),
        OpenAPIParser(limits=effective_limits),
    )
