"""Stable boundaries between source transport, parsing, and claim extraction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Protocol, runtime_checkable

type JSONScalar = str | int | float | bool | None
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]


class ConnectorKind(StrEnum):
    """Taxonomy for source transport implementations."""

    FILESYSTEM = "FILESYSTEM"


class SourceObjectKind(StrEnum):
    """Taxonomy for objects exposed by a connector."""

    FILE = "FILE"


class DocumentFormat(StrEnum):
    """Connector-neutral classification of a discovered document."""

    MARKDOWN = "MARKDOWN"
    YAML = "YAML"
    JSON = "JSON"
    TEXT = "TEXT"
    CODEOWNERS = "CODEOWNERS"
    MANIFEST = "MANIFEST"
    MIGRATION = "MIGRATION"
    WORKFLOW = "WORKFLOW"
    OPENAPI = "OPENAPI"


class ParserKind(StrEnum):
    """Taxonomy for parser implementation families, separate from source transport."""

    MARKDOWN = "MARKDOWN"
    YAML = "YAML"
    JSON = "JSON"
    TEXT = "TEXT"
    CODEOWNERS = "CODEOWNERS"
    MANIFEST = "MANIFEST"
    MIGRATION = "MIGRATION"
    WORKFLOW = "WORKFLOW"
    OPENAPI = "OPENAPI"


class ExtractionClass(StrEnum):
    """Taxonomy for how a claim was obtained, separate from parser families."""

    MECHANICAL = "MECHANICAL"
    INTERPRETIVE = "INTERPRETIVE"
    HUMAN = "HUMAN"


@dataclass(frozen=True, slots=True)
class ContainerDescriptor:
    """Stable connector-owned container identity."""

    external_id: str
    name: str
    canonical_url: str


@dataclass(frozen=True, slots=True)
class DocumentDescriptor:
    """Stable document identity discovered without reading its content."""

    external_id: str
    relative_path: PurePosixPath
    canonical_url: str
    source_object_kind: SourceObjectKind
    document_format: DocumentFormat
    media_type: str
    source_modified_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryPage:
    """Bounded discovery result and opaque resume cursor."""

    containers: tuple[ContainerDescriptor, ...]
    documents: tuple[DocumentDescriptor, ...]
    next_cursor: Mapping[str, JSONValue] | None
    failures: tuple[DiscoveryFailure, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveryFailure:
    """One unsafe or unreadable discovery entry isolated from safe siblings."""

    item_key: str
    error_code: str
    safe_message: str
    is_transient: bool = False


@dataclass(frozen=True, slots=True)
class FetchedContent:
    """Untrusted bytes returned by a read-only connector."""

    descriptor: DocumentDescriptor
    content: bytes


@dataclass(frozen=True, slots=True)
class ParsedDocument:
    """Version-addressed structured data produced from untrusted bytes."""

    parser_kind: ParserKind
    parser_name: str
    parser_version: str
    document_format: DocumentFormat
    normalized: Mapping[str, JSONValue]
    locations: tuple[Mapping[str, JSONValue], ...]


@dataclass(frozen=True, slots=True)
class ExtractedClaim:
    """One claim with the mechanical or interpretive method made explicit."""

    subject_key: str
    predicate: str
    value: JSONValue
    location_pointer: str
    extraction_class: ExtractionClass
    extraction_method: str
    confidence: float
    is_inferred: bool


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Version-addressed claim output from a parser derivation."""

    extractor_name: str
    extractor_version: str
    claims: tuple[ExtractedClaim, ...]


@runtime_checkable
class Connector(Protocol):
    """Read-only transport boundary.

    Implementations must treat source data as inert bytes. They may discover and fetch,
    but never execute source content, follow unsafe links, or mutate the source.
    """

    kind: ConnectorKind
    implementation_name: str
    implementation_version: str

    def discover(
        self,
        *,
        cursor: Mapping[str, JSONValue] | None,
        limit: int,
    ) -> DiscoveryPage:
        """Return at most ``limit`` source objects and an opaque continuation cursor."""

    def fetch(self, document: DocumentDescriptor, *, max_bytes: int) -> FetchedContent:
        """Read one bounded regular file without mutating the source."""


@runtime_checkable
class Parser(Protocol):
    """Pure parser boundary for untrusted source bytes."""

    kind: ParserKind
    implementation_name: str
    implementation_version: str

    def supports(self, document: DocumentDescriptor) -> bool:
        """Return whether this parser handles the document classification."""

    def parse(self, content: FetchedContent) -> ParsedDocument:
        """Parse bytes as data without performing imports, includes, or remote access."""


@runtime_checkable
class Extractor(Protocol):
    """Pure extraction boundary over a normalized parser derivation."""

    implementation_name: str
    implementation_version: str

    def supports(self, document: ParsedDocument) -> bool:
        """Return whether this extractor handles the normalized document."""

    def extract(self, document: ParsedDocument) -> ExtractionResult:
        """Return deterministic claims without executing source instructions."""


def choose_parser(document: DocumentDescriptor, parsers: Sequence[Parser]) -> Parser:
    """Select exactly one parser so ambiguous routing fails closed."""
    matches = [parser for parser in parsers if parser.supports(document)]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one parser for {document.relative_path}, found {len(matches)}"
        )
    return matches[0]
