"""Unit coverage for safe, host-neutral skill installation and diagnostics."""

from __future__ import annotations

import json
import os
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

import pytest

from anva.skills.diagnostics import diagnose_skills
from anva.skills.installer import InstallError, configure_mcp, install_skills

PACKAGE_ROOT = Path(__file__).parents[2] / "packages" / "anva-skills"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("host", "skill_root"),
    [
        ("codex", Path(".agents/skills")),
        ("claude", Path(".claude/skills")),
    ],
)
def test_fresh_project_install_and_exact_replay_are_safe_noops(
    tmp_path: Path,
    host: str,
    skill_root: Path,
) -> None:
    first = install_skills(
        package_root=PACKAGE_ROOT,
        destination=tmp_path,
        host=host,
        scope="project",
    )
    second = install_skills(
        package_root=PACKAGE_ROOT,
        destination=tmp_path,
        host=host,
        scope="project",
    )

    assert first["status"] == "installed"
    assert second["status"] == "unchanged"
    for name in ("anva-prepare", "anva-build", "anva-preflight", "anva-learn"):
        assert (tmp_path / skill_root / name / "SKILL.md").is_file()
    assert not tuple(tmp_path.rglob("*.tmp"))


@pytest.mark.unit
def test_install_refuses_tamper_symlink_and_path_escape(tmp_path: Path) -> None:
    install_skills(
        package_root=PACKAGE_ROOT,
        destination=tmp_path,
        host="codex",
        scope="project",
    )
    skill = tmp_path / ".agents/skills/anva-build/SKILL.md"
    skill.write_text("tampered", encoding="utf-8")

    with pytest.raises(InstallError, match="differs"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=tmp_path,
            host="codex",
            scope="project",
        )

    outside = tmp_path.parent / "outside-skill-target"
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(InstallError, match="symlink"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=linked,
            host="claude",
            scope="project",
        )

    with pytest.raises(InstallError, match="destination"):
        install_skills(
            package_root=PACKAGE_ROOT,
            destination=tmp_path / "..",
            host="claude",
            scope="project",
        )


@pytest.mark.unit
def test_interrupted_install_rolls_back_all_created_skills(tmp_path: Path) -> None:
    from anva.skills.installer import _rename_no_replace

    calls = 0

    def interrupted(
        source_fd: int,
        source_name: str,
        destination_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic interruption")
        _rename_no_replace(source_fd, source_name, destination_fd, destination_name)

    with patch("anva.skills.installer._rename_no_replace", side_effect=interrupted):
        with pytest.raises(OSError, match="synthetic interruption"):
            install_skills(
                package_root=PACKAGE_ROOT,
                destination=tmp_path,
                host="codex",
                scope="project",
            )

    skill_root = tmp_path / ".agents/skills"
    assert not any(skill_root.iterdir())
    assert not tuple(tmp_path.rglob(".anva-skills-stage-*"))


@pytest.mark.unit
def test_mcp_handoffs_reference_environment_names_never_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-MCP-CONFIG-TOKEN")
    codex = configure_mcp(
        host="codex",
        destination=tmp_path,
        token_env="ANVA_TOKEN",
        mcp_url="https://mcp.example.test/mcp",
    )
    assert codex["executed"] is False
    assert codex["command"] == [
        "codex",
        "mcp",
        "add",
        "anva",
        "--url",
        "https://mcp.example.test/mcp",
        "--bearer-token-env-var",
        "ANVA_TOKEN",
    ]

    first = configure_mcp(
        host="claude",
        destination=tmp_path,
        token_env="ANVA_TOKEN",
        mcp_url_env="ANVA_MCP_URL",
    )
    second = configure_mcp(
        host="claude",
        destination=tmp_path,
        token_env="ANVA_TOKEN",
        mcp_url_env="ANVA_MCP_URL",
    )
    config = (tmp_path / ".mcp.json").read_text(encoding="utf-8")
    assert first["status"] == "configured"
    assert second["status"] == "unchanged"
    assert "${ANVA_MCP_URL}" in config
    assert "Bearer ${ANVA_TOKEN}" in config
    assert "CANARY-MCP-CONFIG-TOKEN" not in config
    assert "CANARY-MCP-CONFIG-TOKEN" not in json.dumps(first)


@pytest.mark.unit
def test_diagnostics_checks_real_endpoint_without_leaking_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ANVA_TOKEN", "CANARY-SKILL-DIAGNOSTIC-TOKEN")
    payload = {
        "status": "available",
        "service": "anva-mcp",
        "transport": "streamable-http",
        "endpoint": "https://mcp.example.test/mcp",
        "contract_version": "1",
        "supported_contract_versions": ["1"],
        "supported_protocol_versions": ["2025-11-25"],
        "read_only": True,
        "authentication": {
            "type": "bearer",
            "scope": "organization-and-exact-repository",
            "rotation": True,
            "revocation": True,
        },
        "limits": {
            "page_size": 50,
            "input_bytes": 65536,
            "output_bytes": 65536,
            "source_excerpt_characters": 4000,
        },
    }
    response_headers = Message()
    response_headers["Content-Type"] = "application/json"
    with patch("anva.skills.diagnostics.urlopen") as open_url:
        response = open_url.return_value.__enter__.return_value
        response.read.return_value = json.dumps(payload).encode()
        response.headers = response_headers
        result = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="0.145.0",
            token_env="ANVA_TOKEN",
            expected_read_only=True,
        )

    assert result["status"] == "compatible"
    token = result["token"]
    assert isinstance(token, dict)
    assert token["environment"] == "ANVA_TOKEN"
    assert token["present"] is True
    request = open_url.call_args.args[0]
    assert request.full_url == "https://mcp.example.test/diagnostics"
    assert "CANARY-SKILL-DIAGNOSTIC-TOKEN" not in json.dumps(result)
    assert "CANARY-SKILL-DIAGNOSTIC-TOKEN" not in capsys.readouterr().out


@pytest.mark.unit
def test_diagnostics_fail_safely_for_unavailable_and_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANVA_TOKEN", raising=False)
    with patch("anva.skills.diagnostics.urlopen", side_effect=URLError("CANARY-DETAIL")):
        unavailable = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="claude",
            host_version="2.1.220",
            token_env="ANVA_TOKEN",
        )
    assert unavailable["status"] == "unavailable"
    assert "CANARY-DETAIL" not in json.dumps(unavailable)

    with patch("anva.skills.diagnostics.urlopen") as open_url:
        response_headers = Message()
        response_headers["Content-Type"] = "application/json"
        response = open_url.return_value.__enter__.return_value
        response.headers = response_headers
        response.read.return_value = json.dumps(
            {
                "status": "available",
                "service": "anva-mcp",
                "transport": "streamable-http",
                "endpoint": "https://mcp.example.test/mcp",
                "contract_version": "99",
                "supported_contract_versions": ["99"],
                "supported_protocol_versions": ["2025-11-25"],
                "read_only": False,
                "authentication": {
                    "type": "bearer",
                    "scope": "organization-and-exact-repository",
                    "rotation": True,
                    "revocation": True,
                },
                "limits": {
                    "page_size": 50,
                    "input_bytes": 65536,
                    "output_bytes": 65536,
                    "source_excerpt_characters": 4000,
                },
            }
        ).encode()
        unsupported = diagnose_skills(
            mcp_url="https://mcp.example.test/mcp",
            host="codex",
            host_version="unknown",
            token_env="ANVA_TOKEN",
        )
    assert unsupported["status"] == "unsupported"
    assert unsupported["limitations"]
    assert "/capabilities" not in json.dumps(unsupported)
    assert os.getenv("ANVA_TOKEN") is None
