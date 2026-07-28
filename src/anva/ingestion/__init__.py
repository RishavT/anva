"""Connector-neutral source ingestion primitives."""

from anva.ingestion.interfaces import (
    Connector,
    ConnectorKind,
    ContainerDescriptor,
    DiscoveryPage,
    DocumentDescriptor,
    DocumentFormat,
    ExtractedClaim,
    ExtractionClass,
    ExtractionResult,
    Extractor,
    FetchedContent,
    ParsedDocument,
    Parser,
    ParserKind,
    SourceObjectKind,
)

__all__ = [
    "Connector",
    "ConnectorKind",
    "ContainerDescriptor",
    "DiscoveryPage",
    "DocumentDescriptor",
    "DocumentFormat",
    "ExtractedClaim",
    "ExtractionClass",
    "ExtractionResult",
    "Extractor",
    "FetchedContent",
    "ParsedDocument",
    "Parser",
    "ParserKind",
    "SourceObjectKind",
]
