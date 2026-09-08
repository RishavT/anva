"""Integrity helpers for bootstrap credential-set attestations."""

from __future__ import annotations

import uuid
from datetime import datetime


def bootstrap_credential_set_id(
    *,
    request_sha256: str,
    generation: int,
    primary_token_id: str,
    primary_issued_at: datetime,
    reviewer_token_id: str | None,
    reviewer_issued_at: datetime | None,
) -> uuid.UUID:
    """Derive the stable identifier for one exact committed issuance snapshot."""
    return uuid.uuid5(
        uuid.NAMESPACE_URL,
        "\n".join(
            (
                "anva-bootstrap-credential-set-v1",
                request_sha256,
                str(generation),
                primary_token_id,
                primary_issued_at.isoformat(),
                reviewer_token_id or "none",
                reviewer_issued_at.isoformat() if reviewer_issued_at is not None else "none",
            )
        ),
    )
