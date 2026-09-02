#!/usr/bin/env python3
"""Validate and canonically bind GitHub release-environment approvals."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any


def _canonical_sha256(record: dict[str, Any]) -> str:
    canonical = json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def approved_release_hashes(payload: object) -> list[str]:
    if not isinstance(payload, list):
        raise ValueError("approval response must be a JSON array")

    approved: list[dict[str, Any]] = []
    for record in payload:
        if not isinstance(record, dict):
            raise ValueError("every approval record must be a JSON object")
        if record.get("state") == "approved":
            approved.append(record)

    if not approved:
        raise ValueError("at least one approved release-environment record is required")

    hashes: list[str] = []
    for record in approved:
        user = record.get("user")
        environments = record.get("environments")
        if not isinstance(user, dict) or user.get("login") != "RishavT":
            raise ValueError("every approved record must be approved by exact reviewer RishavT")
        if (
            not isinstance(environments, list)
            or len(environments) != 1
            or not isinstance(environments[0], dict)
            or environments[0].get("name") != "release"
        ):
            raise ValueError("every approved record must bind only the release environment")
        hashes.append(_canonical_sha256(record))
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-single", action="store_true")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()

    try:
        hashes = approved_release_hashes(json.load(sys.stdin))
        if args.require_single and len(hashes) != 1:
            raise ValueError("the initial release decision requires exactly one approved record")
        if args.expected_sha256 is not None and hashes.count(args.expected_sha256) != 1:
            raise ValueError(
                "the decision approval hash must match exactly one approved release record"
            )
    except (json.JSONDecodeError, ValueError) as error:
        print(f"invalid release approval history: {error}", file=sys.stderr)
        return 1

    if args.require_single:
        print(hashes[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
