"""Secret-safe ingestion failures."""

from __future__ import annotations


class IngestionError(ValueError):
    """An expected item-level ingestion failure safe to persist and expose."""

    def __init__(self, code: str, safe_message: str, *, is_transient: bool = False) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message
        self.is_transient = is_transient


class UnsafeSourceError(IngestionError):
    """A source object violated a read-only or parser safety boundary."""
