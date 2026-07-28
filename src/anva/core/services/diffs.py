"""Bounded, nonexecuting unified-diff validation, classification, and chunking."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from anva.core.logging import redact_text
from anva.core.services.hostile_inputs import validate_relative_artifact_path

PARSER_VERSION = "unified-diff-v1"
MAX_DIFF_BYTES = 1_000_000
MAX_DIFF_LINES = 30_000
MAX_CHANGED_PATHS = 500
MAX_CHUNKS = 2_000
MAX_CHUNK_CHARS = 100_000

_FILE_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)\n$")
_HUNK_HEADER = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?: .*)?\n$"
)


@dataclass(frozen=True, slots=True)
class ParsedDiffChunk:
    position: int
    path: str
    classification: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    text: str

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {
            "position": self.position,
            "path": self.path,
            "classification": self.classification,
            "old_start": self.old_start,
            "old_count": self.old_count,
            "new_start": self.new_start,
            "new_count": self.new_count,
            "text": self.text,
            "content_hash": self.content_hash,
        }


@dataclass(frozen=True, slots=True)
class ParsedDiff:
    changed_paths: tuple[str, ...]
    chunks: tuple[ParsedDiffChunk, ...]
    classifications: dict[str, int]
    limitations: tuple[str, ...]


def classify_path(path: str) -> str:
    """Classify one normalized path using deterministic, ordered rules."""
    normalized = path.casefold()
    parts = PurePosixPath(normalized).parts
    name = parts[-1]
    if any(
        token in normalized
        for token in (
            "auth",
            "permission",
            "security",
            "credential",
            "secret",
            "payment",
            "billing",
            "crypto",
        )
    ):
        return "SECURITY_SENSITIVE"
    if "migration" in parts or "migrations" in parts or name.endswith((".sql", ".ddl")):
        return "MIGRATION"
    if (
        "test" in parts
        or "tests" in parts
        or name.startswith("test_")
        or name.endswith(("_test.py", ".spec.py", ".test.py"))
    ):
        return "TEST"
    if name in {
        "pyproject.toml",
        "uv.lock",
        "requirements.txt",
        "poetry.lock",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
    } or name.endswith(".lock"):
        return "DEPENDENCY"
    if ".github" in parts or name.startswith(("dockerfile", "compose.")):
        return "CI"
    if "docs" in parts or name.endswith((".md", ".rst", ".txt")):
        return "DOCUMENTATION"
    return "SOURCE"


def _validate_path(path: str) -> None:
    if path.startswith(('"', "'")) or path.endswith(('"', "'")):
        raise ValueError("Quoted diff paths are unsupported")
    validate_relative_artifact_path(path)
    if path.startswith("-") or "//" in path:
        raise ValueError("Diff path is ambiguous")


def _validate_file_path_headers(
    *,
    git_old_path: str,
    git_new_path: str,
    old_header: str,
    new_header: str,
) -> None:
    expected_old = f"a/{git_old_path}"
    expected_new = f"b/{git_new_path}"
    if old_header not in {expected_old, "/dev/null"}:
        raise ValueError("Old diff path header does not match its Git file header")
    if new_header not in {expected_new, "/dev/null"}:
        raise ValueError("New diff path header does not match its Git file header")
    if old_header == "/dev/null" and new_header == "/dev/null":
        raise ValueError("Diff path headers cannot both be /dev/null")


def _validate_hunk_counts(
    *,
    lines: list[str],
    old_count: int,
    new_count: int,
) -> None:
    actual_old = 0
    actual_new = 0
    for line in lines[1:]:
        if line.startswith("\\ No newline at end of file"):
            continue
        if not line or line[0] not in {" ", "+", "-"}:
            raise ValueError("Diff hunk contains an invalid line prefix")
        if line[0] in {" ", "-"}:
            actual_old += 1
        if line[0] in {" ", "+"}:
            actual_new += 1
    if actual_old != old_count or actual_new != new_count:
        raise ValueError("Diff hunk line counts do not match its header")


def parse_unified_diff(unified_diff: str) -> ParsedDiff:
    """Parse a strict Git unified diff without executing, fetching, or applying it."""
    if not isinstance(unified_diff, str):
        raise ValueError("unified_diff must be text")
    encoded = unified_diff.encode()
    if not encoded or len(encoded) > MAX_DIFF_BYTES:
        raise ValueError("unified_diff must contain between 1 byte and 1,000,000 bytes")
    if "\x00" in unified_diff or "\r" in unified_diff:
        raise ValueError("unified_diff contains unsupported control characters")
    if redact_text(unified_diff) != unified_diff:
        raise ValueError("unified_diff contains credential material")
    lines = unified_diff.splitlines(keepends=True)
    if len(lines) > MAX_DIFF_LINES or any(not line.endswith("\n") for line in lines):
        raise ValueError("unified_diff must be newline-terminated and within the line limit")
    if any(
        line.startswith(("GIT binary patch", "Binary files ", "diff --cc ", "diff --combined "))
        for line in lines
    ):
        raise ValueError("Binary and combined diffs are unsupported")

    paths: list[str] = []
    chunks: list[ParsedDiffChunk] = []
    current_path: str | None = None
    current_old_path: str | None = None
    current_new_path: str | None = None
    old_path_header: str | None = None
    new_path_header: str | None = None
    current_has_hunk = False
    index = 0
    while index < len(lines):
        line = lines[index]
        file_match = _FILE_HEADER.fullmatch(line)
        if file_match is not None:
            if current_path is not None and (
                old_path_header is None or new_path_header is None or not current_has_hunk
            ):
                raise ValueError("Every changed file must contain matching path headers and a hunk")
            old_path, new_path = file_match.groups()
            _validate_path(old_path)
            _validate_path(new_path)
            current_old_path = old_path
            current_new_path = new_path
            old_path_header = None
            new_path_header = None
            current_has_hunk = False
            current_path = new_path
            if old_path != new_path:
                # Renames are represented by their destination while preserving the exact raw diff.
                current_path = new_path
            if current_path not in paths:
                paths.append(current_path)
            if len(paths) > MAX_CHANGED_PATHS:
                raise ValueError("unified_diff exceeds the changed-path limit")
            index += 1
            continue
        if line.startswith("--- "):
            if current_path is None or current_old_path is None or old_path_header is not None:
                raise ValueError("Old diff path header is missing, duplicated, or misplaced")
            old_path_header = line.removeprefix("--- ").removesuffix("\n")
            index += 1
            continue
        if line.startswith("+++ "):
            if (
                current_path is None
                or current_old_path is None
                or current_new_path is None
                or old_path_header is None
                or new_path_header is not None
            ):
                raise ValueError("New diff path header is missing, duplicated, or misplaced")
            new_path_header = line.removeprefix("+++ ").removesuffix("\n")
            _validate_file_path_headers(
                git_old_path=current_old_path,
                git_new_path=current_new_path,
                old_header=old_path_header,
                new_header=new_path_header,
            )
            index += 1
            continue
        hunk_match = _HUNK_HEADER.fullmatch(line)
        if hunk_match is not None:
            if (
                current_path is None
                or current_old_path is None
                or current_new_path is None
                or old_path_header is None
                or new_path_header is None
            ):
                raise ValueError("Diff hunk appears before matching file path headers")
            hunk_lines = [line]
            index += 1
            while index < len(lines) and not lines[index].startswith(("@@ ", "diff --git ")):
                hunk_lines.append(lines[index])
                index += 1
            old_count = int(hunk_match.group("old_count") or "1")
            new_count = int(hunk_match.group("new_count") or "1")
            old_start = int(hunk_match.group("old_start"))
            new_start = int(hunk_match.group("new_start"))
            if old_path_header == "/dev/null" and (old_start != 0 or old_count != 0):
                raise ValueError("New-file diff hunks must have an empty old range")
            if new_path_header == "/dev/null" and (new_start != 0 or new_count != 0):
                raise ValueError("Deleted-file diff hunks must have an empty new range")
            _validate_hunk_counts(
                lines=hunk_lines,
                old_count=old_count,
                new_count=new_count,
            )
            text = "".join(hunk_lines)
            if len(text) > MAX_CHUNK_CHARS:
                raise ValueError("A diff hunk exceeds the evaluator chunk limit")
            chunks.append(
                ParsedDiffChunk(
                    position=len(chunks) + 1,
                    path=current_path,
                    classification=classify_path(current_path),
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    text=text,
                )
            )
            if len(chunks) > MAX_CHUNKS:
                raise ValueError("unified_diff exceeds the hunk limit")
            current_has_hunk = True
            continue
        if line.startswith("diff --"):
            raise ValueError("Only Git unified diffs are supported")
        index += 1

    if current_path is not None and (
        old_path_header is None or new_path_header is None or not current_has_hunk
    ):
        raise ValueError("Every changed file must contain matching path headers and a hunk")
    if not paths or not chunks:
        raise ValueError("unified_diff must contain at least one changed file and hunk")
    classifications: dict[str, int] = {}
    for chunk in chunks:
        classifications[chunk.classification] = classifications.get(chunk.classification, 0) + 1
    return ParsedDiff(
        changed_paths=tuple(sorted(paths)),
        chunks=tuple(chunks),
        classifications=dict(sorted(classifications.items())),
        limitations=(
            "Manual diff provenance was supplied by an authorized operator.",
            "The diff was parsed as data and no repository code was fetched or executed.",
        ),
    )


def citation_in_diff(
    *,
    chunks: tuple[ParsedDiffChunk, ...] | list[ParsedDiffChunk],
    path: str,
    side: str,
    line: int,
) -> bool:
    """Return whether a citation falls within an exact parsed hunk coordinate."""
    if side not in {"OLD", "NEW"} or line < 1:
        return False
    for chunk in chunks:
        if chunk.path != path:
            continue
        start = chunk.old_start if side == "OLD" else chunk.new_start
        count = chunk.old_count if side == "OLD" else chunk.new_count
        if count > 0 and start <= line < start + count:
            return True
    return False
