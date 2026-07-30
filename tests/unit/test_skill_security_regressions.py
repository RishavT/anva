"""Regression coverage for skill installation path and handoff safety."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from anva.skills.installer import InstallError, configure_mcp, install_skills

PACKAGE_ROOT = Path(__file__).parents[2] / "packages" / "anva-skills"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("host", "derived"),
    [
        ("codex", Path(".agents")),
        ("claude", Path(".claude/skills")),
    ],
)
def test_install_rejects_symlink_in_derived_destination_ancestry(
    tmp_path: Path,
    host: str,
    derived: Path,
) -> None:
    destination = tmp_path / "project"
    outside = tmp_path / "outside"
    destination.mkdir()
    outside.mkdir()
    canary = outside / "CANARY.txt"
    canary.write_text("OUTSIDE-CANARY", encoding="utf-8")
    link = destination / derived
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(InstallError, match="symlink|directory|unsafe"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=destination,
            host=host,
            scope="project",
        )

    assert canary.read_text(encoding="utf-8") == "OUTSIDE-CANARY"
    assert sorted(path.name for path in outside.iterdir()) == ["CANARY.txt"]


@pytest.mark.unit
@pytest.mark.parametrize("host", ["codex", "claude"])
def test_install_rejects_non_directory_derived_ancestor(
    tmp_path: Path,
    host: str,
) -> None:
    destination = tmp_path / "project"
    destination.mkdir()
    derived = destination / (".agents" if host == "codex" else ".claude")
    derived.write_text("not a directory", encoding="utf-8")

    with pytest.raises(InstallError, match="directory|unsafe"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=destination,
            host=host,
            scope="project",
        )

    assert derived.read_text(encoding="utf-8") == "not a directory"


@pytest.mark.unit
def test_install_refuses_unknown_partial_stage_without_touching_it(tmp_path: Path) -> None:
    destination = tmp_path / "project"
    destination.mkdir()
    partial = destination / ".anva-skills-stage-untrusted"
    partial.mkdir()
    canary = partial / "CANARY.txt"
    canary.write_text("PARTIAL-CANARY", encoding="utf-8")

    with pytest.raises(InstallError, match="partial|stage"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=destination,
            host="codex",
            scope="project",
        )

    assert canary.read_text(encoding="utf-8") == "PARTIAL-CANARY"
    assert not (destination / ".agents").exists()


@pytest.mark.unit
def test_claude_config_refuses_preexisting_temp_symlink_and_preserves_canary(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "project"
    destination.mkdir()
    outside = tmp_path / "outside-canary"
    outside.write_text("OUTSIDE-CONFIG-CANARY", encoding="utf-8")
    temporary = destination / "..mcp.json.anva-tmp"
    temporary.symlink_to(outside)

    with pytest.raises(InstallError, match="partial|temporary|symlink|unsafe"):
        configure_mcp(
            host="claude",
            destination=destination,
            token_env="ANVA_TOKEN",
        )

    assert outside.read_text(encoding="utf-8") == "OUTSIDE-CONFIG-CANARY"
    assert temporary.is_symlink()
    assert not (destination / ".mcp.json").exists()


@pytest.mark.unit
@pytest.mark.parametrize("host", ["codex", "claude"])
def test_configure_rejects_symlink_destination_ancestor(
    tmp_path: Path,
    host: str,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    canary = outside / "CANARY.txt"
    canary.write_text("CONFIG-CANARY", encoding="utf-8")
    destination = tmp_path / "linked"
    destination.symlink_to(outside, target_is_directory=True)

    kwargs: dict[str, object] = {}
    if host == "codex":
        kwargs["mcp_url"] = "https://mcp.example.test/mcp"
    with pytest.raises(InstallError, match="symlink|directory|unsafe"):
        configure_mcp(
            host=host,
            destination=destination,
            token_env="ANVA_TOKEN",
            **kwargs,  # type: ignore[arg-type]
        )

    assert canary.read_text(encoding="utf-8") == "CONFIG-CANARY"
    assert not (outside / ".mcp.json").exists()


@pytest.mark.unit
@pytest.mark.parametrize("host", ["codex", "claude"])
def test_configure_rejects_non_directory_destination_ancestor(
    tmp_path: Path,
    host: str,
) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("NON-DIRECTORY-CANARY", encoding="utf-8")
    kwargs: dict[str, object] = {}
    if host == "codex":
        kwargs["mcp_url"] = "https://mcp.example.test/mcp"

    with pytest.raises(InstallError, match="symlink|directory|unsafe"):
        configure_mcp(
            host=host,
            destination=blocked / "project",
            token_env="ANVA_TOKEN",
            **kwargs,  # type: ignore[arg-type]
        )

    assert blocked.read_text(encoding="utf-8") == "NON-DIRECTORY-CANARY"


@pytest.mark.unit
def test_invalid_codex_handoff_does_not_create_destination(tmp_path: Path) -> None:
    destination = tmp_path / "must-not-be-created"

    with pytest.raises(InstallError, match="absolute HTTP"):
        configure_mcp(
            host="codex",
            destination=destination,
            token_env="ANVA_TOKEN",
            mcp_url="not-a-url",
        )

    assert not destination.exists()


@pytest.mark.unit
def test_install_refuses_final_skill_symlink_without_touching_outside(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "project"
    skill_root = destination / ".agents/skills"
    outside = tmp_path / "outside"
    skill_root.mkdir(parents=True)
    outside.mkdir()
    canary = outside / "CANARY.txt"
    canary.write_text("FINAL-SYMLINK-CANARY", encoding="utf-8")
    (skill_root / "anva-prepare").symlink_to(outside, target_is_directory=True)

    with pytest.raises(InstallError, match="unsafe|differs"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=destination,
            host="codex",
            scope="project",
        )

    assert canary.read_text(encoding="utf-8") == "FINAL-SYMLINK-CANARY"
    assert sorted(path.name for path in outside.iterdir()) == ["CANARY.txt"]


@pytest.mark.unit
def test_atomic_install_handoff_never_clobbers_a_race_winner(tmp_path: Path) -> None:
    from anva.skills.installer import _rename_no_replace

    destination = tmp_path / "project"
    raced = False

    def race_then_handoff(
        source_fd: int,
        source_name: str,
        destination_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal raced
        if not raced:
            raced = True
            os.mkdir(destination_name, mode=0o700, dir_fd=destination_fd)
            winner_fd = os.open(
                destination_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=destination_fd,
            )
            try:
                canary_fd = os.open(
                    "RACE-WINNER.txt",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=winner_fd,
                )
                try:
                    os.write(canary_fd, b"RACE-WINNER-CANARY")
                finally:
                    os.close(canary_fd)
            finally:
                os.close(winner_fd)
        _rename_no_replace(source_fd, source_name, destination_fd, destination_name)

    with patch(
        "anva.skills.installer._rename_no_replace",
        side_effect=race_then_handoff,
    ):
        with pytest.raises(InstallError, match="refusing to overwrite"):
            install_skills(
                package_root=PACKAGE_ROOT,
                destination=destination,
                host="codex",
                scope="project",
            )

    winner = destination / ".agents/skills/anva-prepare/RACE-WINNER.txt"
    assert winner.read_text(encoding="utf-8") == "RACE-WINNER-CANARY"
    assert not tuple(destination.rglob(".anva-skills-stage-*"))


@pytest.mark.unit
def test_atomic_claude_config_handoff_never_clobbers_a_race_winner(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "project"
    destination.mkdir()
    real_link = os.link

    def race_then_link(
        source: str,
        destination_name: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool,
    ) -> None:
        winner_fd = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=dst_dir_fd,
        )
        try:
            os.write(winner_fd, b"RACE-WINNER-CONFIG")
        finally:
            os.close(winner_fd)
        real_link(
            source,
            destination_name,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    with patch("anva.skills.installer.os.link", side_effect=race_then_link):
        with pytest.raises(InstallError, match="refusing to overwrite"):
            configure_mcp(
                host="claude",
                destination=destination,
                token_env="ANVA_TOKEN",
            )

    assert (destination / ".mcp.json").read_text(encoding="utf-8") == ("RACE-WINNER-CONFIG")
    assert not tuple(destination.glob("..mcp.json.anva-tmp*"))
