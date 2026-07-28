"""Central resource limits for untrusted source ingestion."""

from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class IngestionLimits:
    """Fail-closed limits shared across connector and parser stages."""

    max_file_bytes: int = 2 * 1024 * 1024
    max_discovered_entries: int = 100_000
    max_discovery_page: int = 1_000
    max_directory_depth: int = 32
    max_relative_path_bytes: int = 2_000
    max_parse_nodes: int = 20_000
    max_parse_depth: int = 64
    max_scalar_bytes: int = 256 * 1024
    max_text_lines: int = 100_000
    max_yaml_tokens: int = 50_000

    def __post_init__(self) -> None:
        for field in fields(self):
            name = field.name
            value = getattr(self, name)
            if value < 1:
                raise ValueError(f"{name} must be positive")
