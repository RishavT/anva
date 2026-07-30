"""Contract coverage for canonical workflows and generated host packages."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from anva.mcp.contracts import PROPOSAL_TOOL_NAMES, READ_TOOL_NAMES
from anva.skills.contracts import load_distribution
from anva.skills.packages import build_distributions
from anva.skills.render import check_rendered, normalize_rendered_skill

ROOT = Path(__file__).parents[2]
PACKAGE_ROOT = ROOT / "packages" / "anva-skills"
SKILL_NAMES = ("anva-prepare", "anva-build", "anva-preflight", "anva-learn")


@pytest.mark.contract
def test_canonical_contract_uses_only_the_mcp_facade_and_shared_schemas() -> None:
    distribution = load_distribution(PACKAGE_ROOT)

    assert distribution.skill_version == "1.0.0"
    assert distribution.mcp_contract_versions == ("1",)
    assert set(distribution.workflows) == set(SKILL_NAMES)
    for workflow in distribution.workflows.values():
        assert set(workflow.read_tools) <= READ_TOOL_NAMES
        assert set(workflow.proposal_tools) <= PROPOSAL_TOOL_NAMES
        assert not any("/api/" in step or "objects." in step for step in workflow.steps)
        schema_path = PACKAGE_ROOT / workflow.output_schema
        Draft202012Validator.check_schema(json.loads(schema_path.read_text()))


@pytest.mark.contract
def test_generated_adapters_normalize_to_one_canonical_contract() -> None:
    assert check_rendered(PACKAGE_ROOT) == []

    for name in SKILL_NAMES:
        codex = ROOT / ".agents" / "skills" / name / "SKILL.md"
        claude = ROOT / ".claude" / "skills" / name / "SKILL.md"
        assert normalize_rendered_skill(codex) == normalize_rendered_skill(claude)

        codex_frontmatter = yaml.safe_load(codex.read_text().split("---", 2)[1])
        claude_frontmatter = yaml.safe_load(claude.read_text().split("---", 2)[1])
        assert set(codex_frontmatter) == {"name", "description"}
        assert set(claude_frontmatter) <= {
            "name",
            "description",
            "disable-model-invocation",
        }
        if name == "anva-learn":
            assert claude_frontmatter["disable-model-invocation"] is True


@pytest.mark.contract
def test_plugin_manifests_mcp_handoff_and_package_hygiene() -> None:
    codex = PACKAGE_ROOT / "generated" / "codex-plugin"
    claude = PACKAGE_ROOT / "generated" / "claude-plugin"
    codex_manifest = json.loads((codex / ".codex-plugin/plugin.json").read_text())
    claude_manifest = json.loads((claude / ".claude-plugin/plugin.json").read_text())

    assert codex_manifest["skills"] == "./skills/"
    assert "mcpServers" not in codex_manifest
    assert claude_manifest["skills"] == "./skills/"
    assert not (codex / ".mcp.json").exists()
    assert not (claude / ".mcp.json").exists()

    forbidden_names = {
        ".env",
        "package.json",
        "package-lock.json",
        "node_modules",
        "hooks",
        "bin",
        "scripts",
    }
    secret_pattern = re.compile(
        r"(?i)(authorization\s*:\s*bearer\s+[A-Za-z0-9]|api[_-]?key\s*[:=]\s*\\S+)"
    )
    for package in (codex, claude):
        for path in package.rglob("*"):
            assert not (set(path.parts) & forbidden_names)
            if path.is_file():
                assert not secret_pattern.search(path.read_text(errors="ignore"))


@pytest.mark.contract
def test_archives_are_reproducible_checksummed_and_safe(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_result = build_distributions(PACKAGE_ROOT, first)
    second_result = build_distributions(PACKAGE_ROOT, second)

    assert first_result == second_result
    for name, digest in first_result.items():
        first_archive = first / name
        second_archive = second / name
        assert first_archive.read_bytes() == second_archive.read_bytes()
        assert hashlib.sha256(first_archive.read_bytes()).hexdigest() == digest
        with tarfile.open(first_archive, "r:gz") as archive:
            for member in archive.getmembers():
                assert not member.name.startswith("/")
                assert ".." not in Path(member.name).parts
                assert not member.issym()
                assert not member.islnk()
