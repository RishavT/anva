#!/usr/bin/env python3
"""Validate and prepare the closed v0.1.0 public metadata correction."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

PRODUCT_SOURCE = "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac"
IMAGE_DIGEST = "sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d"
IMAGE_REFERENCE = f"ghcr.io/rishavt/anva@{IMAGE_DIGEST}"
RELEASE_TAG = "v0.1.0"
RELEASE_RUN = "33596661334"
CORRECTION_REASON = "Correct stale unpublished-candidate claims after verified publication"


@dataclass(frozen=True)
class ExpectedAsset:
    size: int
    sha256: str


EXPECTED_RELEASE_ASSETS = {
    "RELEASE_NOTES.md": ExpectedAsset(
        9686, "fff7157fe7a45dc2c2afc62f294891e96f569352733ebe8fa2c2123daa1932c0"
    ),
    "SHA256SUMS": ExpectedAsset(
        1118, "d120ddffd61cb5f1ff973f57c906e7ba73dc778e260d5d97415f529a87d9fadb"
    ),
    "anva-0.1.0-py3-none-any.whl": ExpectedAsset(
        832758, "a6d7eb8570da42d82b4f72a13b17afe4f8b9cab20a99bade6948162a86522c20"
    ),
    "anva-claude-skills-1.0.0.tar.gz": ExpectedAsset(
        9870, "70e3ed4fc523f9737dca85818a9d9d0ed044b00835e31d2cc8e20b5bde32e66d"
    ),
    "anva-codex-skills-1.0.0.tar.gz": ExpectedAsset(
        10417, "54483706b8fdcd627789d6d0e2c8a11c53476e56867fba2ada3c31824f074648"
    ),
    "anva-image-vulnerabilities.json": ExpectedAsset(
        430517, "7e666c5246208fb30bc820b8a197ed7ba2216d0dcca9c3d41f5f99761be3f2bf"
    ),
    "anva-image.cyclonedx.json": ExpectedAsset(
        234959, "f16891ecf35d76ff8f6ea826a4077a73dc1ae11b2aa11f27812f809f93d2c988"
    ),
    "anva-image.spdx.json": ExpectedAsset(
        296501, "06e745ecc16614f3c66b25437784a76a980b513eb8d9916b869a15f89cb96370"
    ),
    "anva-install-0.1.0.tar.gz": ExpectedAsset(
        6893196, "44de1b75f6cf3d36990c9d7e2709a6061296a98053aa72abb8c360a78ada011e"
    ),
    "anva-source-security.json": ExpectedAsset(
        38199, "2454cb767bb899ed536d09ee4bca1ec8a628afdabf9bf0c0dd4aeb4f44492a2d"
    ),
    "release-manifest.json": ExpectedAsset(
        2575, "b824ee2cda791ba841f8bac11d8f316228398ef3618e5cb23e04538484db13db"
    ),
    "vulnerability-exceptions.json": ExpectedAsset(
        6010, "8f082f1be368349f5a16535eed9141ab56767d63810bb2e3c621c5ce4e280974"
    ),
    "vulnerability-risk-acceptance.json": ExpectedAsset(
        10291, "6390ad56e77ff683359838fe62b3a64cbc54d98be1fc714ccd697430ad2c3a2f"
    ),
}
REPLACED_ASSETS = frozenset({"RELEASE_NOTES.md", "release-manifest.json", "SHA256SUMS"})
UNCHANGED_ASSETS = frozenset(EXPECTED_RELEASE_ASSETS) - REPLACED_ASSETS


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def assert_exact_inventory(directory: Path) -> None:
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(EXPECTED_RELEASE_ASSETS):
        raise ValueError(f"unexpected release inventory: {sorted(actual)}")


def assert_current_assets(directory: Path) -> None:
    assert_exact_inventory(directory)
    for name, expected in EXPECTED_RELEASE_ASSETS.items():
        path = directory / name
        if (
            path.is_symlink()
            or path.stat().st_size != expected.size
            or digest(path) != expected.sha256
        ):
            raise ValueError(f"current release asset differs from audited public bytes: {name}")
    manifest = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("source_commit") != PRODUCT_SOURCE:
        raise ValueError("current manifest product source differs")
    if manifest.get("image", {}).get("reference") != IMAGE_REFERENCE:
        raise ValueError("current manifest image digest differs")


def assert_unchanged_assets(old: Path, downloaded: Path) -> None:
    for name in UNCHANGED_ASSETS:
        if digest(old / name) != digest(downloaded / name):
            raise ValueError(f"non-metadata asset changed: {name}")


def generate_replacement_closure(
    current: Path,
    notes: Path,
    output: Path,
    metadata_commit: str,
    repair_run: str,
) -> None:
    assert_current_assets(current)
    if len(metadata_commit) != 40 or any(
        character not in "0123456789abcdef" for character in metadata_commit
    ):
        raise ValueError("metadata commit must be a full lowercase Git commit")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(notes, output / "RELEASE_NOTES.md")
    old_manifest = json.loads((current / "release-manifest.json").read_text(encoding="utf-8"))
    records = []
    for record in old_manifest["artifacts"]:
        name = record["path"]
        if name == "RELEASE_NOTES.md":
            records.append(
                {
                    "path": name,
                    "sha256": digest(output / name),
                    "size": (output / name).stat().st_size,
                }
            )
        else:
            records.append(record)
    manifest = {
        **old_manifest,
        "schema_version": 3,
        "artifact_kind": "anva.published-release-manifest",
        "publication_status": "published_metadata_repaired",
        "artifacts": records,
        "limitations": [
            "Technical publication and lifecycle verification completed; "
            "human acceptance gates #43 and #44 remain open.",
            "This metadata-only correction did not rebuild the image, move the tag, "
            "or change the residual-risk decision.",
        ],
        "publication": {
            "tag": RELEASE_TAG,
            "workflow_run": RELEASE_RUN,
            "product_source_commit": PRODUCT_SOURCE,
            "image_digest": IMAGE_DIGEST,
        },
        "metadata_repair": {
            "metadata_commit": metadata_commit,
            "repair_run": repair_run,
            "correction_reason": CORRECTION_REASON,
            "replaced_assets": sorted(REPLACED_ASSETS),
        },
    }
    (output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_lines = []
    for record in records:
        checksum_lines.append(f"{record['sha256']}  {record['path']}\n")
    checksum_lines.append(f"{digest(output / 'release-manifest.json')}  release-manifest.json\n")
    (output / "SHA256SUMS").write_text("".join(checksum_lines), encoding="utf-8")
    verify_replacement_closure(current, output)


def verify_replacement_closure(current: Path, replacement: Path) -> None:
    if {path.name for path in replacement.iterdir()} != set(REPLACED_ASSETS):
        raise ValueError("replacement directory is not the exact three-file closure")
    manifest = json.loads((replacement / "release-manifest.json").read_text(encoding="utf-8"))
    records = manifest["artifacts"]
    expected_lines = []
    for record in records:
        name = record["path"]
        path = replacement / name if name == "RELEASE_NOTES.md" else current / name
        if path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            raise ValueError(f"replacement manifest mismatch: {name}")
        expected_lines.append(f"{record['sha256']}  {name}\n")
    expected_lines.append(
        f"{digest(replacement / 'release-manifest.json')}  release-manifest.json\n"
    )
    if (replacement / "SHA256SUMS").read_text(encoding="utf-8") != "".join(expected_lines):
        raise ValueError("replacement checksum closure differs")


def snapshot_release_body(payload: bytes, output: Path) -> None:
    response = json.loads(payload)
    if not isinstance(response, dict) or not isinstance(response.get("body"), str):
        raise ValueError("release API response must contain a string body")
    output.write_bytes(response["body"].encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-current")
    verify.add_argument("directory", type=Path)
    generate = subparsers.add_parser("generate")
    generate.add_argument("current", type=Path)
    generate.add_argument("notes", type=Path)
    generate.add_argument("output", type=Path)
    generate.add_argument("--metadata-commit", required=True)
    generate.add_argument("--repair-run", required=True)
    snapshot = subparsers.add_parser("snapshot-body")
    snapshot.add_argument("output", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "verify-current":
        assert_current_assets(arguments.directory)
    elif arguments.command == "generate":
        generate_replacement_closure(
            arguments.current,
            arguments.notes,
            arguments.output,
            arguments.metadata_commit,
            arguments.repair_run,
        )
    else:
        snapshot_release_body(sys.stdin.buffer.read(), arguments.output)


if __name__ == "__main__":
    main()
