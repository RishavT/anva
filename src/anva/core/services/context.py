"""Explicit authorization and correlation context for mutations."""

from __future__ import annotations

import uuid
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActorContext:
    """The already-authenticated actor data required by domain operations."""

    organization_id: uuid.UUID
    actor_type: str
    actor_id: str
    authorization_path: str
    request_id: uuid.UUID
    source_ip_hash: str = ""

    def __post_init__(self) -> None:
        if not self.actor_type.strip():
            raise ValueError("actor_type is required")
        if not self.actor_id.strip():
            raise ValueError("actor_id is required")
        if not self.authorization_path.strip():
            raise ValueError("authorization_path is required")
