"""Deterministic, versioned indexing for immutable source chunks."""

from __future__ import annotations

import hashlib
import math
import re

from django.contrib.postgres.search import SearchVector
from django.db.models import Value

from anva.core.models import SourceChunk, SourceChunkSearchIndex

INDEX_VERSION = "fts-vector-v1"
EMBEDDING_PROVIDER = "anva-deterministic-local"
EMBEDDING_VERSION = "hash-32-v1"
EMBEDDING_DIMENSIONS = 32
_TOKEN_PATTERN = re.compile(r"[\w./:-]+", re.UNICODE)


def deterministic_embedding(text: str) -> list[float]:
    """Produce a stable, dependency-free embedding suitable for local retrieval."""
    vector = [0.0] * EMBEDDING_DIMENSIONS
    tokens = _TOKEN_PATTERN.findall(text.casefold())
    if not tokens:
        tokens = [text.casefold() or "<empty>"]
    for token in tokens:
        digest = hashlib.sha256(token.encode()).digest()
        first = int.from_bytes(digest[:8], "big")
        second = int.from_bytes(digest[8:16], "big")
        vector[first % EMBEDDING_DIMENSIONS] += 1.0 if first & 1 else -1.0
        vector[second % EMBEDDING_DIMENSIONS] += 0.5 if second & 1 else -0.5
    norm = math.sqrt(sum(component * component for component in vector))
    if norm == 0:
        return vector
    return [round(component / norm, 12) for component in vector]


def index_source_chunk(chunk: SourceChunk) -> tuple[SourceChunkSearchIndex, bool]:
    """Create the immutable current-version index row for a source chunk."""
    return SourceChunkSearchIndex.objects.get_or_create(
        organization_id=chunk.organization_id,
        source_chunk=chunk,
        index_version=INDEX_VERSION,
        embedding_version=EMBEDDING_VERSION,
        defaults={
            "embedding_provider": EMBEDDING_PROVIDER,
            "indexed_text_hash": chunk.content_hash,
            # The database trigger recomputes this from the tenant-aligned chunk.
            "search_vector": SearchVector(Value(chunk.text), config="simple"),
            "embedding": deterministic_embedding(chunk.text),
        },
    )
