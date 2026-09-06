"""Bounded, nonexecuting unified-diff validation, classification, and chunking."""

from __future__ import annotations

import hashlib
import re
import unicodedata
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
    r"^@@ -(?P<old_start>[0-9]{1,10})(?:,(?P<old_count>[0-9]{1,10}))? "
    r"\+(?P<new_start>[0-9]{1,10})(?:,(?P<new_count>[0-9]{1,10}))? @@(?: .*)?\n$"
)
_WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_INDEX_METADATA = re.compile(r"^index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64}(?: [0-7]{6})?\n$")
_FILE_MODE_METADATA = re.compile(r"^(?:new file mode|deleted file mode) [0-7]{6}\n$")
_MODE_METADATA = re.compile(r"^(?:old mode|new mode) [0-7]{6}\n$")
_SIMILARITY_METADATA = re.compile(r"^(?:dis)?similarity index (?:100|[0-9]{1,2})%\n$")
_EOF_MARKER = "\\ No newline at end of file\n"


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
    if not path or path == ".":
        raise ValueError("Diff path must identify a file")
    if path.startswith(('"', "'")) or path.endswith(('"', "'")):
        raise ValueError("Quoted diff paths are unsupported")
    if _WINDOWS_DRIVE_PATH.match(path) or path.startswith(("//", "\\\\")):
        raise ValueError("Absolute and Windows drive-qualified diff paths are unsupported")
    validate_relative_artifact_path(path)
    if path.startswith("-") or "//" in path:
        raise ValueError("Diff path is ambiguous")


def _validated_header_path(header: str, *, prefix: str, side: str) -> str | None:
    if header == "/dev/null":
        return None
    if not header.startswith(prefix):
        raise ValueError(f"{side} diff path header has an invalid prefix")
    path = header.removeprefix(prefix)
    _validate_path(path)
    return path


def _validate_file_path_headers(
    *,
    git_old_path: str,
    git_new_path: str,
    old_header: str,
    new_header: str,
) -> tuple[str, str]:
    header_old_path = _validated_header_path(old_header, prefix="a/", side="Old")
    header_new_path = _validated_header_path(new_header, prefix="b/", side="New")
    if header_old_path is not None and header_old_path != git_old_path:
        raise ValueError("Old diff path header does not match its Git file header")
    if header_new_path is not None and header_new_path != git_new_path:
        raise ValueError("New diff path header does not match its Git file header")
    if header_old_path is None and header_new_path is None:
        raise ValueError("Diff path headers cannot both be /dev/null")
    if header_old_path is None:
        if git_old_path != git_new_path:
            raise ValueError("New-file diff Git paths must identify the same destination")
        return git_new_path, "ADD"
    if header_new_path is None:
        if git_old_path != git_new_path:
            raise ValueError("Deleted-file diff Git paths must identify the same source")
        return git_old_path, "DELETE"
    if git_old_path != git_new_path:
        return git_new_path, "RENAME"
    return git_new_path, "MODIFY"


def _validate_change_metadata(
    *,
    change_kind: str,
    git_old_path: str,
    git_new_path: str,
    declared_file_kind: str | None,
    rename_from: str | None,
    rename_to: str | None,
) -> None:
    if declared_file_kind is not None and declared_file_kind != change_kind:
        raise ValueError("Diff file-mode metadata conflicts with its path headers")
    if (rename_from is None) != (rename_to is None):
        raise ValueError("Rename metadata must contain both source and destination")
    if rename_from is None or rename_to is None:
        return
    if change_kind != "RENAME" or rename_from != git_old_path or rename_to != git_new_path:
        raise ValueError("Rename metadata does not match the Git file header")


def _validate_hunk_counts(
    *,
    lines: list[str],
    old_count: int,
    new_count: int,
) -> None:
    actual_old = 0
    actual_new = 0
    has_effective_change = False
    previous_was_content = False
    for line in lines[1:]:
        if line == _EOF_MARKER:
            if not previous_was_content:
                raise ValueError("Diff EOF marker is misplaced or duplicated")
            previous_was_content = False
            continue
        if not line or line[0] not in {" ", "+", "-"}:
            raise ValueError("Diff hunk contains an invalid line prefix")
        previous_was_content = True
        if line[0] in {" ", "-"}:
            actual_old += 1
        if line[0] in {" ", "+"}:
            actual_new += 1
        if line[0] in {"+", "-"}:
            has_effective_change = True
    if actual_old != old_count or actual_new != new_count:
        raise ValueError("Diff hunk line counts do not match its header")
    if not has_effective_change:
        raise ValueError("Diff hunk must contain an effective change")


def parse_unified_diff(unified_diff: str) -> ParsedDiff:
    """Parse a strict Git unified diff without executing, fetching, or applying it."""
    if not isinstance(unified_diff, str):
        raise ValueError("unified_diff must be text")
    try:
        encoded = unified_diff.encode()
    except UnicodeEncodeError as error:
        raise ValueError("unified_diff must be valid UTF-8 text") from error
    if not encoded or len(encoded) > MAX_DIFF_BYTES:
        raise ValueError("unified_diff must contain between 1 byte and 1,000,000 bytes")
    if (
        any(
            character not in {"\n", "\t"} and unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            for character in unified_diff
        )
        or "\r" in unified_diff
    ):
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
    declared_file_kind: str | None = None
    rename_from: str | None = None
    rename_to: str | None = None
    current_has_hunk = False
    seen_file_headers: set[tuple[str, str]] = set()
    seen_metadata: set[str] = set()
    index = 0
    while index < len(lines):
        line = lines[index]
        file_match = _FILE_HEADER.fullmatch(line)
        if file_match is not None:
            if current_old_path is not None and (
                old_path_header is None or new_path_header is None or not current_has_hunk
            ):
                raise ValueError("Every changed file must contain matching path headers and a hunk")
            old_path, new_path = file_match.groups()
            _validate_path(old_path)
            _validate_path(new_path)
            file_identity = (old_path, new_path)
            if file_identity in seen_file_headers:
                raise ValueError("Diff Git file header is duplicated")
            seen_file_headers.add(file_identity)
            current_old_path = old_path
            current_new_path = new_path
            old_path_header = None
            new_path_header = None
            declared_file_kind = None
            rename_from = None
            rename_to = None
            current_has_hunk = False
            current_path = None
            seen_metadata = set()
            index += 1
            continue
        if line.startswith(("new file mode ", "deleted file mode ")):
            if (
                current_old_path is None
                or old_path_header is not None
                or declared_file_kind is not None
            ):
                raise ValueError("Diff file-mode metadata is duplicated or misplaced")
            if _FILE_MODE_METADATA.fullmatch(line) is None:
                raise ValueError("Diff file-mode metadata is invalid")
            declared_file_kind = "ADD" if line.startswith("new file mode ") else "DELETE"
            index += 1
            continue
        if (
            _INDEX_METADATA.fullmatch(line)
            or _MODE_METADATA.fullmatch(line)
            or _SIMILARITY_METADATA.fullmatch(line)
        ):
            if current_old_path is None or old_path_header is not None:
                raise ValueError("Diff metadata is misplaced")
            metadata_kind = line.split(" ", 1)[0]
            if line.startswith(("old mode ", "new mode ", "similarity ", "dissimilarity ")):
                metadata_kind = line.rsplit(" ", 1)[0]
            if metadata_kind in seen_metadata:
                raise ValueError("Diff metadata is duplicated")
            seen_metadata.add(metadata_kind)
            index += 1
            continue
        if line.startswith(("rename from ", "rename to ")):
            if current_old_path is None or old_path_header is not None:
                raise ValueError("Rename metadata is misplaced")
            if line.startswith("rename from "):
                if rename_from is not None:
                    raise ValueError("Rename source metadata is duplicated")
                rename_from = line.removeprefix("rename from ").removesuffix("\n")
                _validate_path(rename_from)
            else:
                if rename_to is not None:
                    raise ValueError("Rename destination metadata is duplicated")
                rename_to = line.removeprefix("rename to ").removesuffix("\n")
                _validate_path(rename_to)
            index += 1
            continue
        if line.startswith("--- "):
            if current_old_path is None or old_path_header is not None:
                raise ValueError("Old diff path header is missing, duplicated, or misplaced")
            if ("old mode" in seen_metadata) != ("new mode" in seen_metadata):
                raise ValueError("Diff mode metadata must contain both old and new modes")
            old_path_header = line.removeprefix("--- ").removesuffix("\n")
            index += 1
            continue
        if line.startswith("+++ "):
            if (
                current_old_path is None
                or current_new_path is None
                or old_path_header is None
                or new_path_header is not None
            ):
                raise ValueError("New diff path header is missing, duplicated, or misplaced")
            new_path_header = line.removeprefix("+++ ").removesuffix("\n")
            current_path, change_kind = _validate_file_path_headers(
                git_old_path=current_old_path,
                git_new_path=current_new_path,
                old_header=old_path_header,
                new_header=new_path_header,
            )
            _validate_change_metadata(
                change_kind=change_kind,
                git_old_path=current_old_path,
                git_new_path=current_new_path,
                declared_file_kind=declared_file_kind,
                rename_from=rename_from,
                rename_to=rename_to,
            )
            if current_path in paths:
                raise ValueError("Diff changed path is duplicated")
            paths.append(current_path)
            if len(paths) > MAX_CHANGED_PATHS:
                raise ValueError("unified_diff exceeds the changed-path limit")
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
            if (old_count > 0 and old_start < 1) or (new_count > 0 and new_start < 1):
                raise ValueError("Diff hunk range start is invalid")
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
        raise ValueError("Diff contains unsupported or misplaced metadata")

    if current_old_path is not None and (
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
