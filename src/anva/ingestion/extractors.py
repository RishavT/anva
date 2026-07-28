"""Deterministic mechanical claim extraction from normalized parser output."""

from __future__ import annotations

from anva.ingestion.interfaces import (
    ExtractedClaim,
    ExtractionClass,
    ExtractionResult,
    JSONValue,
    ParsedDocument,
    ParserKind,
)

_SEMANTIC_PREDICATES = {
    "owner": "owned_by",
    "owners": "owned_by",
    "team": "owned_by",
    "maintainer": "maintained_by",
    "maintainers": "maintained_by",
    "depends_on": "depends_on",
    "dependencies": "depends_on",
    "service": "declares_service",
    "component": "declares_component",
}


class MechanicalExtractor:
    """Extract only explicit syntax-level claims; never infer intent."""

    implementation_name = "mechanical"
    implementation_version = "1"

    def supports(self, document: ParsedDocument) -> bool:
        return True

    def extract(self, document: ParsedDocument) -> ExtractionResult:
        if document.parser_kind == ParserKind.CODEOWNERS:
            claims = self._codeowners(document)
        elif document.parser_kind == ParserKind.MARKDOWN:
            claims = self._markdown(document)
        elif document.parser_kind == ParserKind.MIGRATION:
            claims = self._migrations(document)
        else:
            claims = self._structured(document)
        return ExtractionResult(
            extractor_name=self.implementation_name,
            extractor_version=self.implementation_version,
            claims=tuple(claims),
        )

    def _structured(self, document: ParsedDocument) -> list[ExtractedClaim]:
        root = document.normalized.get("data")
        if root is None:
            return []
        subject_key = self._subject_key(root)
        claims: list[ExtractedClaim] = []
        stack: list[tuple[str, JSONValue]] = [("", root)]
        while stack:
            pointer, value = stack.pop()
            if isinstance(value, dict):
                for key, child in reversed(tuple(value.items())):
                    escaped = key.replace("~", "~0").replace("/", "~1")
                    child_pointer = f"{pointer}/{escaped}"
                    predicate = _SEMANTIC_PREDICATES.get(key.lower())
                    if predicate is not None and not isinstance(child, dict):
                        claims.append(
                            self._claim(
                                subject_key=subject_key,
                                predicate=predicate,
                                value=child,
                                pointer=child_pointer,
                                method=f"key:{key.lower()}",
                            )
                        )
                    stack.append((child_pointer, child))
            elif isinstance(value, list):
                for index in range(len(value) - 1, -1, -1):
                    stack.append((f"{pointer}/{index}", value[index]))
        return claims

    def _subject_key(self, value: JSONValue) -> str:
        if isinstance(value, dict):
            for key in ("service", "component", "name", "id"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate:
                    prefix = key if key in {"service", "component"} else "source"
                    return f"{prefix}:{candidate}"
        return "source:document"

    def _codeowners(self, document: ParsedDocument) -> list[ExtractedClaim]:
        rules = document.normalized.get("rules")
        if not isinstance(rules, list):
            return []
        claims: list[ExtractedClaim] = []
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            pattern = rule.get("pattern")
            owners = rule.get("owners")
            if isinstance(pattern, str) and isinstance(owners, list):
                claims.append(
                    self._claim(
                        subject_key=f"path:{pattern}",
                        predicate="owned_by",
                        value=owners,
                        pointer=f"/rules/{index}",
                        method="codeowners-rule",
                    )
                )
        return claims

    def _markdown(self, document: ParsedDocument) -> list[ExtractedClaim]:
        headings = document.normalized.get("headings")
        if not isinstance(headings, list):
            return []
        claims: list[ExtractedClaim] = []
        for index, heading in enumerate(headings):
            if isinstance(heading, dict) and isinstance(heading.get("text"), str):
                claims.append(
                    self._claim(
                        subject_key="source:document",
                        predicate="documents_heading",
                        value=heading["text"],
                        pointer=f"/headings/{index}",
                        method="markdown-heading",
                    )
                )
        return claims

    def _migrations(self, document: ParsedDocument) -> list[ExtractedClaim]:
        operations = document.normalized.get("operations")
        if not isinstance(operations, list):
            return []
        claims: list[ExtractedClaim] = []
        for index, operation in enumerate(operations):
            if isinstance(operation, dict) and isinstance(operation.get("operation"), str):
                claims.append(
                    self._claim(
                        subject_key="source:document",
                        predicate="performs_migration_operation",
                        value=operation["operation"],
                        pointer=f"/operations/{index}",
                        method="migration-token",
                    )
                )
        return claims

    def _claim(
        self,
        *,
        subject_key: str,
        predicate: str,
        value: JSONValue,
        pointer: str,
        method: str,
    ) -> ExtractedClaim:
        return ExtractedClaim(
            subject_key=subject_key,
            predicate=predicate,
            value=value,
            location_pointer=pointer,
            extraction_class=ExtractionClass.MECHANICAL,
            extraction_method=method,
            confidence=1.0,
            is_inferred=False,
        )


def default_extractors() -> tuple[MechanicalExtractor, ...]:
    """Return conservative extractors enabled for automatic ingestion."""
    return (MechanicalExtractor(),)
