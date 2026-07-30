"""Safely install rendered skills into an explicit host scope."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
from pathlib import Path
from urllib.parse import urlsplit

from anva.skills.contracts import load_distribution


class InstallError(ValueError):
    """Installation cannot continue without overwriting or escaping scope."""


_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_INSTALL_STAGE_PREFIX = ".anva-skills-stage-"
_MCP_STAGE_PREFIX = "..mcp.json.anva-tmp"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW
_MAX_CONFIG_BYTES = 64 * 1024
_RENAME_NOREPLACE = 1


def _destination_path(destination: Path) -> Path:
    if ".." in destination.parts:
        raise InstallError("Explicit destination must not contain path traversal")
    # This must remain lexical: resolve() would follow the symlinks this boundary rejects.
    return Path(os.path.abspath(os.fspath(destination)))  # noqa: PTH100


def _open_directory_chain(path: Path, *, create: bool) -> int:
    """Open a lexical absolute path without following a component symlink."""
    absolute = _destination_path(path)
    current = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise InstallError(f"Required directory is missing: {absolute}") from None
                try:
                    os.mkdir(component, mode=0o755, dir_fd=current)
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
                except OSError:
                    raise InstallError(
                        "Destination ancestry contains a symlink or non-directory"
                    ) from None
            except OSError:
                raise InstallError(
                    "Destination ancestry contains a symlink or non-directory"
                ) from None
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def _open_child_directory(parent_fd: int, name: str, *, create: bool) -> int:
    if not name or name in {".", ".."} or "/" in name:
        raise InstallError("Unsafe derived destination component")
    try:
        return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode=0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            return os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError:
            raise InstallError("Derived destination contains a symlink or non-directory") from None
    except OSError:
        raise InstallError("Derived destination contains a symlink or non-directory") from None


def _open_derived_chain(parent_fd: int, components: tuple[str, ...]) -> int:
    current = os.dup(parent_fd)
    try:
        for component in components:
            child = _open_child_directory(current, component, create=True)
            os.close(current)
            current = child
        return current
    except Exception:
        os.close(current)
        raise


def _entries(fd: int) -> list[os.DirEntry[str]]:
    with os.scandir(fd) as iterator:
        return sorted(iterator, key=lambda entry: entry.name)


def _reject_partial_state(fd: int, prefix: str) -> None:
    if any(entry.name.startswith(prefix) for entry in _entries(fd)):
        raise InstallError(f"Refusing unknown partial stage matching {prefix}")


def _digest_directory(fd: int, *, relative: str = "") -> str:
    digest = hashlib.sha256()

    def visit(directory_fd: int, parent: str) -> None:
        for entry in _entries(directory_fd):
            item_path = f"{parent}/{entry.name}" if parent else entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                raise InstallError(f"Unable to inspect skill tree entry: {item_path}") from None
            encoded = item_path.encode("utf-8")
            if stat.S_ISDIR(metadata.st_mode):
                digest.update(b"D\0")
                digest.update(encoded)
                child = _open_child_directory(directory_fd, entry.name, create=False)
                try:
                    visit(child, item_path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                digest.update(b"F\0")
                digest.update(encoded)
                try:
                    source = os.open(entry.name, _FILE_READ_FLAGS, dir_fd=directory_fd)
                except OSError:
                    raise InstallError(f"Unsafe skill file: {item_path}") from None
                try:
                    opened = os.fstat(source)
                    if not stat.S_ISREG(opened.st_mode):
                        raise InstallError(f"Unsafe skill file: {item_path}")
                    while chunk := os.read(source, 64 * 1024):
                        digest.update(chunk)
                finally:
                    os.close(source)
            else:
                raise InstallError(f"Refusing symlink or special file in skill tree: {item_path}")

    visit(fd, relative)
    return digest.hexdigest()


def _copy_directory(source_fd: int, destination_fd: int) -> None:
    for entry in _entries(source_fd):
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            source_child = _open_child_directory(source_fd, entry.name, create=False)
            try:
                os.mkdir(entry.name, mode=0o755, dir_fd=destination_fd)
                destination_child = _open_child_directory(destination_fd, entry.name, create=False)
                try:
                    _copy_directory(source_child, destination_child)
                    os.fsync(destination_child)
                finally:
                    os.close(destination_child)
            finally:
                os.close(source_child)
        elif stat.S_ISREG(metadata.st_mode):
            source_file = os.open(entry.name, _FILE_READ_FLAGS, dir_fd=source_fd)
            try:
                if not stat.S_ISREG(os.fstat(source_file).st_mode):
                    raise InstallError(f"Unsafe source skill file: {entry.name}")
                destination_file = os.open(
                    entry.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o644,
                    dir_fd=destination_fd,
                )
                try:
                    while chunk := os.read(source_file, 64 * 1024):
                        view = memoryview(chunk)
                        while view:
                            written = os.write(destination_file, view)
                            view = view[written:]
                    os.fsync(destination_file)
                finally:
                    os.close(destination_file)
            finally:
                os.close(source_file)
        else:
            raise InstallError(f"Refusing symlink or special file in skill tree: {entry.name}")


def _remove_tree_at(parent_fd: int, name: str) -> None:
    """Remove one anchored tree without following any link it contains."""
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(metadata.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    child_fd = _open_child_directory(parent_fd, name, create=False)
    try:
        for entry in _entries(child_fd):
            entry_metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_metadata.st_mode):
                _remove_tree_at(child_fd, entry.name)
            else:
                os.unlink(entry.name, dir_fd=child_fd)
    finally:
        os.close(child_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _rename_no_replace(
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
) -> None:
    """Use Linux renameat2 for an atomic handoff that cannot replace a race winner."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise InstallError("Atomic no-clobber installation is unsupported on this host")
    result = renameat2(
        source_fd,
        os.fsencode(source_name),
        destination_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise InstallError(f"Existing {destination_name} appeared; refusing to overwrite")
    raise OSError(error, os.strerror(error))


def _existing_directory_digest(parent_fd: int, name: str) -> str | None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        raise InstallError(f"Existing {name} is unsafe and differs")
    child = _open_child_directory(parent_fd, name, create=False)
    try:
        return _digest_directory(child)
    finally:
        os.close(child)


def install_skills(
    *,
    package_root: Path,
    destination: Path,
    host: str,
    scope: str,
) -> dict[str, object]:
    """Install all skills without following links or replacing existing content."""
    if host not in {"codex", "claude"}:
        raise InstallError("host must be codex or claude")
    if scope not in {"project", "user"}:
        raise InstallError("scope must be project or user")
    destination_path = _destination_path(destination)
    distribution = load_distribution(package_root)
    source_path = _destination_path(package_root) / "generated" / f"{host}-plugin" / "skills"
    source_fd = _open_directory_chain(source_path, create=False)
    destination_fd = _open_directory_chain(destination_path, create=True)
    target_fd: int | None = None
    stage_name: str | None = None
    created: list[str] = []
    try:
        _reject_partial_state(destination_fd, _INSTALL_STAGE_PREFIX)
        relative = (".agents", "skills") if host == "codex" else (".claude", "skills")
        target_fd = _open_derived_chain(destination_fd, relative)
        _reject_partial_state(target_fd, _INSTALL_STAGE_PREFIX)

        changed: list[str] = []
        unchanged: list[str] = []
        source_digests: dict[str, str] = {}
        for name in distribution.workflows:
            source_skill_fd = _open_child_directory(source_fd, name, create=False)
            try:
                source_digest = _digest_directory(source_skill_fd)
            finally:
                os.close(source_skill_fd)
            source_digests[name] = source_digest
            installed_digest = _existing_directory_digest(target_fd, name)
            if installed_digest is None:
                changed.append(name)
            elif installed_digest != source_digest:
                raise InstallError(f"Existing {name} differs; refusing to overwrite")
            else:
                unchanged.append(name)

        if changed:
            for _ in range(16):
                candidate = f"{_INSTALL_STAGE_PREFIX}{secrets.token_hex(16)}"
                try:
                    os.mkdir(candidate, mode=0o700, dir_fd=target_fd)
                except FileExistsError:
                    continue
                stage_name = candidate
                break
            if stage_name is None:
                raise InstallError("Unable to create a unique secure installation stage")
            stage_fd = _open_child_directory(target_fd, stage_name, create=False)
            try:
                for name in changed:
                    source_skill_fd = _open_child_directory(source_fd, name, create=False)
                    try:
                        os.mkdir(name, mode=0o755, dir_fd=stage_fd)
                        staged_skill_fd = _open_child_directory(stage_fd, name, create=False)
                        try:
                            _copy_directory(source_skill_fd, staged_skill_fd)
                            if _digest_directory(staged_skill_fd) != source_digests[name]:
                                raise InstallError(f"Staged {name} failed integrity validation")
                            os.fsync(staged_skill_fd)
                        finally:
                            os.close(staged_skill_fd)
                    finally:
                        os.close(source_skill_fd)
                os.fsync(stage_fd)
                for name in changed:
                    _rename_no_replace(stage_fd, name, target_fd, name)
                    created.append(name)
                os.fsync(target_fd)
            except Exception:
                for name in reversed(created):
                    _remove_tree_at(target_fd, name)
                raise
            finally:
                os.close(stage_fd)
                _remove_tree_at(target_fd, stage_name)
                stage_name = None

        return {
            "status": "installed" if changed else "unchanged",
            "host": host,
            "scope": scope,
            "skill_version": distribution.skill_version,
            "destination": str(destination_path.joinpath(*relative)),
            "installed": changed,
            "unchanged": unchanged,
            "mcp_configuration": "required-separately",
        }
    finally:
        if target_fd is not None:
            if stage_name is not None:
                _remove_tree_at(target_fd, stage_name)
            os.close(target_fd)
        os.close(destination_fd)
        os.close(source_fd)


def _read_json_object(fd: int, name: str) -> dict[str, object] | None:
    try:
        metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CONFIG_BYTES:
        raise InstallError("Existing Claude MCP configuration is unsafe")
    try:
        config_fd = os.open(name, _FILE_READ_FLAGS, dir_fd=fd)
    except OSError:
        raise InstallError("Existing Claude MCP configuration is unsafe") from None
    try:
        opened = os.fstat(config_fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_CONFIG_BYTES:
            raise InstallError("Existing Claude MCP configuration is unsafe")
        raw = b""
        while chunk := os.read(config_fd, _MAX_CONFIG_BYTES + 1 - len(raw)):
            raw += chunk
            if len(raw) > _MAX_CONFIG_BYTES:
                raise InstallError("Existing Claude MCP configuration is too large")
    finally:
        os.close(config_fd)
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise InstallError("Existing Claude MCP configuration is invalid") from None
    if not isinstance(payload, dict):
        raise InstallError("Existing Claude MCP configuration must be an object")
    return payload


def _write_new_config(fd: int, payload: dict[str, object]) -> None:
    temporary: str | None = None
    try:
        for _ in range(16):
            candidate = f"{_MCP_STAGE_PREFIX}-{secrets.token_hex(16)}"
            try:
                config_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=fd,
                )
            except FileExistsError:
                continue
            temporary = candidate
            break
        else:
            raise InstallError("Unable to create a unique secure configuration stage")
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(config_fd, view)
                view = view[written:]
            os.fsync(config_fd)
        finally:
            os.close(config_fd)
        try:
            os.link(
                temporary,
                ".mcp.json",
                src_dir_fd=fd,
                dst_dir_fd=fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise InstallError("Claude MCP configuration appeared; refusing to overwrite") from None
        os.fsync(fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError:
                pass


def configure_mcp(
    *,
    host: str,
    destination: Path,
    token_env: str,
    mcp_url: str | None = None,
    mcp_url_env: str = "ANVA_MCP_URL",
) -> dict[str, object]:
    """Create a secret-free host handoff without executing or trusting a plugin hook."""
    if host not in {"codex", "claude"}:
        raise InstallError("host must be codex or claude")
    if not _ENVIRONMENT_NAME.fullmatch(token_env):
        raise InstallError("token environment name is invalid")
    if not _ENVIRONMENT_NAME.fullmatch(mcp_url_env):
        raise InstallError("MCP URL environment name is invalid")
    if host == "codex":
        if mcp_url is None:
            raise InstallError("Codex MCP handoff requires an explicit MCP URL")
        parsed = urlsplit(mcp_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise InstallError("MCP URL must be absolute HTTP(S)")
    destination_path = _destination_path(destination)
    destination_fd = _open_directory_chain(destination_path, create=True)
    try:
        if host == "codex":
            assert mcp_url is not None
            return {
                "status": "configuration_required",
                "host": host,
                "command": [
                    "codex",
                    "mcp",
                    "add",
                    "anva",
                    "--url",
                    mcp_url,
                    "--bearer-token-env-var",
                    token_env,
                ],
                "token": {"environment": token_env, "present": bool(os.getenv(token_env))},
                "executed": False,
            }

        _reject_partial_state(destination_fd, _MCP_STAGE_PREFIX)
        configuration = {
            "type": "http",
            "url": f"${{{mcp_url_env}}}",
            "headers": {"Authorization": f"Bearer ${{{token_env}}}"},
        }
        payload = _read_json_object(destination_fd, ".mcp.json")
        if payload is not None:
            servers = payload.get("mcpServers")
            if not isinstance(servers, dict):
                raise InstallError("Existing mcpServers must be an object")
            existing = servers.get("anva")
            if existing != configuration:
                raise InstallError(
                    "Existing Claude MCP configuration differs; refusing to overwrite"
                )
            status_value = "unchanged"
        else:
            payload = {"mcpServers": {"anva": configuration}}
            _write_new_config(destination_fd, payload)
            status_value = "configured"
        return {
            "status": status_value,
            "host": host,
            "configuration": str(destination_path / ".mcp.json"),
            "url_environment": mcp_url_env,
            "token": {"environment": token_env, "present": bool(os.getenv(token_env))},
        }
    finally:
        os.close(destination_fd)
