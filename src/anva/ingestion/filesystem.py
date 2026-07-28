"""Read-only filesystem connector hardened for hostile mounted corpora."""

from __future__ import annotations

import heapq
import os
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path, PurePosixPath

from anva.ingestion.errors import IngestionError, UnsafeSourceError
from anva.ingestion.interfaces import (
    ConnectorKind,
    ContainerDescriptor,
    DiscoveryFailure,
    DiscoveryPage,
    DocumentDescriptor,
    DocumentFormat,
    FetchedContent,
    JSONValue,
    SourceObjectKind,
)
from anva.ingestion.limits import IngestionLimits

_IGNORED_DIRECTORIES = frozenset({".git", ".hg", ".svn", "__pycache__", ".venv", "node_modules"})
_MANIFEST_NAMES = frozenset(
    {
        "dockerfile",
        "go.mod",
        "go.sum",
        "makefile",
        "package.json",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
    }
)


def classify_document(relative_path: PurePosixPath) -> tuple[DocumentFormat, str]:
    """Classify by path and filename without inspecting or executing content."""
    lower_name = relative_path.name.lower()
    suffix = relative_path.suffix.lower()
    parts = tuple(part.lower() for part in relative_path.parts)
    if lower_name == "codeowners":
        return DocumentFormat.CODEOWNERS, "text/plain"
    if len(parts) >= 3 and parts[-3:-1] == (".github", "workflows") and suffix in {".yaml", ".yml"}:
        return DocumentFormat.WORKFLOW, "application/yaml"
    if lower_name in {
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
    }:
        media_type = "application/json" if suffix == ".json" else "application/yaml"
        return DocumentFormat.OPENAPI, media_type
    if "migrations" in parts[:-1] and suffix in {".py", ".sql"}:
        return DocumentFormat.MIGRATION, "text/plain"
    if (
        lower_name in _MANIFEST_NAMES
        or lower_name.startswith("requirements")
        or lower_name.startswith("compose.")
        or lower_name.startswith("docker-compose.")
    ):
        return DocumentFormat.MANIFEST, "text/plain"
    if suffix in {".md", ".markdown"}:
        return DocumentFormat.MARKDOWN, "text/markdown"
    if suffix in {".yaml", ".yml"}:
        return DocumentFormat.YAML, "application/yaml"
    if suffix == ".json":
        return DocumentFormat.JSON, "application/json"
    return DocumentFormat.TEXT, "text/plain"


class FilesystemConnector:
    """Discover and fetch regular files beneath one immutable root boundary."""

    kind = ConnectorKind.FILESYSTEM
    implementation_name = "filesystem"
    implementation_version = "1"

    def __init__(self, root: Path, *, limits: IngestionLimits | None = None) -> None:
        self.limits = limits or IngestionLimits()
        if root.is_symlink():
            raise UnsafeSourceError("unsafe_root", "Filesystem source root cannot be a symlink")
        try:
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise IngestionError(
                "source_unavailable",
                "Filesystem source root is unavailable",
            ) from error
        if not resolved.is_dir():
            raise UnsafeSourceError(
                "unsafe_root",
                "Filesystem source root must be a directory",
            )
        self.root = resolved

    @property
    def container(self) -> ContainerDescriptor:
        """Return the stable root container."""
        return ContainerDescriptor(
            external_id="root",
            name=self.root.name,
            canonical_url=self.root.as_uri(),
        )

    def _iter_discovery_items(
        self,
    ) -> Iterator[tuple[str, DocumentDescriptor | DiscoveryFailure]]:
        pending: list[tuple[str, Path, int]] = []
        observed_entries = 0

        def add_directory(
            directory: Path,
            depth: int,
            *,
            root: bool = False,
        ) -> DiscoveryFailure | None:
            nonlocal observed_entries
            try:
                entries = os.scandir(directory)
            except OSError as error:
                if not root:
                    relative = directory.relative_to(self.root).as_posix()
                    return DiscoveryFailure(
                        item_key=relative[:1_000],
                        error_code="source_unavailable",
                        safe_message="A source directory could not be read",
                        is_transient=True,
                    )
                raise IngestionError(
                    "source_unavailable",
                    "A source directory could not be read",
                    is_transient=True,
                ) from error
            with entries:
                for entry in entries:
                    observed_entries += 1
                    if observed_entries > self.limits.max_discovered_entries:
                        raise IngestionError(
                            "discovery_limit_exceeded",
                            "Filesystem discovery entry limit exceeded",
                        )
                    path = Path(entry.path)
                    relative = path.relative_to(self.root).as_posix()
                    heapq.heappush(pending, (relative, path, depth))
            return None

        root_failure = add_directory(self.root, 1, root=True)
        assert root_failure is None
        while pending:
            key, path, depth = heapq.heappop(pending)
            try:
                metadata = os.lstat(path)
            except OSError:
                yield (
                    key,
                    DiscoveryFailure(
                        item_key=key[:1_000],
                        error_code="source_unavailable",
                        safe_message="A source entry could not be read",
                        is_transient=True,
                    ),
                )
                continue
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if path.name in _IGNORED_DIRECTORIES:
                    continue
                if len(key.encode()) > self.limits.max_relative_path_bytes:
                    yield (
                        key,
                        DiscoveryFailure(
                            item_key=key[:1_000],
                            error_code="path_limit_exceeded",
                            safe_message="Filesystem relative path limit exceeded",
                        ),
                    )
                    continue
                if depth > self.limits.max_directory_depth:
                    yield (
                        key,
                        DiscoveryFailure(
                            item_key=key[:1_000],
                            error_code="directory_depth_exceeded",
                            safe_message="Filesystem directory depth limit exceeded",
                        ),
                    )
                    continue
                failure = add_directory(path, depth + 1)
                if failure is not None:
                    yield key, failure
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if len(key.encode()) > self.limits.max_relative_path_bytes:
                yield (
                    key,
                    DiscoveryFailure(
                        item_key=key[:1_000],
                        error_code="path_limit_exceeded",
                        safe_message="Filesystem relative path limit exceeded",
                    ),
                )
                continue
            relative = PurePosixPath(key)
            yield key, self._descriptor(relative)

    def discover(
        self,
        *,
        cursor: Mapping[str, JSONValue] | None,
        limit: int,
    ) -> DiscoveryPage:
        """Return a deterministic page while treating the cursor as opaque input."""
        if limit < 1 or limit > self.limits.max_discovery_page:
            raise IngestionError(
                "invalid_discovery_limit",
                "Filesystem discovery page limit is invalid",
            )
        after = ""
        if cursor is not None:
            value = cursor.get("after")
            if not isinstance(value, str) or not value:
                raise IngestionError("invalid_cursor", "Filesystem cursor is invalid")
            after = value
        selected: list[DocumentDescriptor | DiscoveryFailure] = []
        has_more = False
        last_key = ""
        for key, item in self._iter_discovery_items():
            if key <= after:
                continue
            if len(selected) == limit:
                has_more = True
                break
            selected.append(item)
            last_key = key
        documents = tuple(item for item in selected if isinstance(item, DocumentDescriptor))
        failures = tuple(item for item in selected if isinstance(item, DiscoveryFailure))
        next_cursor: Mapping[str, JSONValue] | None = None
        if has_more and selected:
            next_cursor = {"after": last_key}
        return DiscoveryPage(
            containers=(self.container,),
            documents=documents,
            next_cursor=next_cursor,
            failures=failures,
        )

    def _descriptor(self, relative: PurePosixPath) -> DocumentDescriptor:
        document_format, media_type = classify_document(relative)
        return DocumentDescriptor(
            external_id=relative.as_posix(),
            relative_path=relative,
            canonical_url=f"{self.root.as_uri()}/{relative.as_posix()}",
            source_object_kind=SourceObjectKind.FILE,
            document_format=document_format,
            media_type=media_type,
        )

    def fetch(self, document: DocumentDescriptor, *, max_bytes: int) -> FetchedContent:
        """Read one regular file with ``openat`` and ``O_NOFOLLOW`` at every path segment."""
        allowed_bytes = min(max_bytes, self.limits.max_file_bytes)
        if allowed_bytes < 1:
            raise IngestionError("invalid_fetch_limit", "Filesystem fetch limit is invalid")
        relative = document.relative_path
        key = relative.as_posix()
        if (
            document.external_id != key
            or relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} or "\x00" in part for part in relative.parts)
        ):
            raise UnsafeSourceError("unsafe_path", "Filesystem document path is unsafe")

        fd = self._open_beneath(relative)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafeSourceError(
                    "unsupported_file_type",
                    "Filesystem document is not a regular file",
                )
            if metadata.st_size > allowed_bytes:
                raise IngestionError("file_too_large", "Filesystem document exceeds byte limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(64 * 1024, allowed_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > allowed_bytes:
                    raise IngestionError(
                        "file_too_large",
                        "Filesystem document exceeds byte limit",
                    )
            return FetchedContent(descriptor=document, content=b"".join(chunks))
        finally:
            os.close(fd)

    def _open_beneath(self, relative: PurePosixPath) -> int:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        current_fd = os.open(self.root, directory_flags)
        try:
            for part in relative.parts[:-1]:
                next_fd = os.open(part, directory_flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            try:
                return os.open(relative.parts[-1], file_flags, dir_fd=current_fd)
            except OSError as error:
                raise UnsafeSourceError(
                    "unsafe_or_unavailable_path",
                    "Filesystem document cannot be safely opened",
                ) from error
        finally:
            os.close(current_fd)
