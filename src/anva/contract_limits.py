"""Dependency-safe bounds and wire semantics for public contract inputs."""

from typing import Final

ACCEPTANCE_CASE_MEDIA_TYPE: Final = "application/json"
ACCEPTANCE_CASE_ENCODING: Final = "utf-8"
ACCEPTANCE_CASE_SERIALIZATION: Final = "json-text"
ACCEPTANCE_CASE_BYTE_LIMIT_SCOPE: Final = "entire-encoded-document"
MAX_ACCEPTANCE_CASE_BYTES: Final = 1_000_000
MAX_ACCEPTANCE_UNIFIED_DIFF_CHARACTERS: Final = 150_000

# Canvas query limits are public contract and resource-safety boundaries. Keep
# them dependency-free so acceptance schemas, generated OpenAPI, and the live
# domain service cannot drift.
MAX_CANVAS_QUERY_DEPTH: Final = 4
MAX_CANVAS_QUERY_NODES: Final = 300
MAX_CANVAS_QUERY_EDGES: Final = 600
