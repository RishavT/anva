from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

VALIDATOR = Path(__file__).parents[2] / "scripts" / "validate_release_approvals.py"


def _record(record_id: int, reviewer: str = "RishavT") -> dict[str, object]:
    return {
        "comment": "approved exact candidate",
        "environments": [{"id": 42, "name": "release"}],
        "id": record_id,
        "state": "approved",
        "user": {"id": 7, "login": reviewer},
    }


def _sha(record: dict[str, object]) -> str:
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _validate(
    records: list[dict[str, object]], *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - executes the repository-owned validator.
        [sys.executable, str(VALIDATOR), *arguments],
        input=json.dumps(records),
        text=True,
        capture_output=True,
        check=False,
    )


def test_publish_accepts_multiple_rishavt_approvals_when_original_hash_matches() -> None:
    original = _record(1)
    result = _validate([original, _record(2)], "--expected-sha256", _sha(original))
    assert result.returncode == 0, result.stderr


def test_publish_rejects_wrong_or_missing_original_approval_hash() -> None:
    original = _record(1)
    records = [original, _record(2)]
    assert _validate(records, "--expected-sha256", "0" * 64).returncode == 1
    assert _validate([records[1]], "--expected-sha256", _sha(original)).returncode == 1


def test_publish_rejects_duplicate_original_approval_hash() -> None:
    original = _record(1)
    assert (
        _validate(
            [original, copy.deepcopy(original)], "--expected-sha256", _sha(original)
        ).returncode
        == 1
    )


def test_publish_rejects_any_foreign_approved_reviewer() -> None:
    original = _record(1)
    assert (
        _validate(
            [original, _record(2, "another-user")], "--expected-sha256", _sha(original)
        ).returncode
        == 1
    )


def test_validator_rejects_approved_environment_ambiguity() -> None:
    original = _record(1)
    original["environments"] = [{"name": "release"}, {"name": "production"}]
    assert _validate([original], "--expected-sha256", _sha(original)).returncode == 1


def test_initial_build_binding_still_requires_exactly_one_approval() -> None:
    original = _record(1)
    result = _validate([original], "--require-single")
    assert result.returncode == 0
    assert result.stdout.strip() == _sha(original)
    assert _validate([original, _record(2)], "--require-single").returncode == 1
