"""Safely install rendered skills into an explicit host scope."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from anva.skills.contracts import load_distribution


class InstallError(ValueError):
    """Installation cannot continue without overwriting or escaping scope."""


_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise InstallError(f"Refusing symlink in skill tree: {item}")
        if item.is_file():
            digest.update(item.relative_to(path).as_posix().encode())
            digest.update(item.read_bytes())
    return digest.hexdigest()


def _validate_destination(destination: Path) -> Path:
    if ".." in destination.parts:
        raise InstallError("Explicit destination must not contain path traversal")
    if destination.is_symlink():
        raise InstallError("Explicit destination must not be a symlink")
    current = destination
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise InstallError("Explicit destination parent must not be a symlink")
        current = current.parent
    return destination.resolve()


def install_skills(
    *,
    package_root: Path,
    destination: Path,
    host: str,
    scope: str,
) -> dict[str, object]:
    """Install all skills without replacing unknown existing content."""
    if host not in {"codex", "claude"}:
        raise InstallError("host must be codex or claude")
    if scope not in {"project", "user"}:
        raise InstallError("scope must be project or user")
    target_base = _validate_destination(destination)
    source = package_root.resolve() / "generated" / f"{host}-plugin" / "skills"
    if not source.is_dir():
        raise InstallError("Generated skill package is missing; render it first")
    distribution = load_distribution(package_root)
    relative = Path(".agents/skills") if host == "codex" else Path(".claude/skills")
    target = target_base / relative

    changed: list[str] = []
    unchanged: list[str] = []
    for name in distribution.workflows:
        source_skill = source / name
        target_skill = target / name
        if target_skill.exists():
            if target_skill.is_symlink() or not target_skill.is_dir():
                raise InstallError(f"Existing {name} is unsafe and differs")
            if _tree_digest(source_skill) != _tree_digest(target_skill):
                raise InstallError(f"Existing {name} differs; refusing to overwrite")
            unchanged.append(name)
        else:
            changed.append(name)

    target.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        with tempfile.TemporaryDirectory(
            prefix=".anva-skills-stage-",
            dir=target_base,
        ) as temporary:
            stage = Path(temporary)
            for name in changed:
                staged = stage / name
                shutil.copytree(source / name, staged, symlinks=False)
                _tree_digest(staged)
            for name in changed:
                installed = target / name
                (stage / name).replace(installed)
                created.append(installed)
    except Exception:
        for path in reversed(created):
            shutil.rmtree(path)
        raise

    return {
        "status": "installed" if changed else "unchanged",
        "host": host,
        "scope": scope,
        "skill_version": distribution.skill_version,
        "destination": str(target),
        "installed": changed,
        "unchanged": unchanged,
        "mcp_configuration": "required-separately",
    }


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
    target = _validate_destination(destination)
    if host == "codex":
        if mcp_url is None:
            raise InstallError("Codex MCP handoff requires an explicit MCP URL")
        parsed = urlsplit(mcp_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise InstallError("MCP URL must be absolute HTTP(S)")
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

    config_path = target / ".mcp.json"
    if config_path.is_symlink():
        raise InstallError("Claude MCP configuration must not be a symlink")
    if config_path.exists():
        try:
            payload = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raise InstallError("Existing Claude MCP configuration is invalid") from None
        if not isinstance(payload, dict):
            raise InstallError("Existing Claude MCP configuration must be an object")
    else:
        payload = {}
    servers = payload.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise InstallError("Existing mcpServers must be an object")
    configuration = {
        "type": "http",
        "url": f"${{{mcp_url_env}}}",
        "headers": {"Authorization": f"Bearer ${{{token_env}}}"},
    }
    existing = servers.get("anva")
    if existing is not None and existing != configuration:
        raise InstallError("Existing Anva MCP configuration differs; refusing to overwrite")
    servers["anva"] = configuration
    target.mkdir(parents=True, exist_ok=True)
    temporary = config_path.with_name(f".{config_path.name}.anva-tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(config_path)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "status": "configured" if existing is None else "unchanged",
        "host": host,
        "configuration": str(config_path),
        "url_environment": mcp_url_env,
        "token": {"environment": token_env, "present": bool(os.getenv(token_env))},
    }
