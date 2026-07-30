"""Load and validate the canonical host-neutral skill contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml
from jsonschema import Draft202012Validator


class SkillContractError(ValueError):
    """A portable workflow contract is invalid."""


@dataclass(frozen=True)
class Workflow:
    """One host-neutral workflow definition."""

    name: str
    description: str
    phase: str
    implicit: bool
    read_tools: tuple[str, ...]
    proposal_tools: tuple[str, ...]
    steps: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    degraded_behavior: tuple[str, ...]
    output_schema: str
    output_sections: tuple[str, ...]


@dataclass(frozen=True)
class Distribution:
    """Versioned portable skill family."""

    skill_version: str
    mcp_contract_versions: tuple[str, ...]
    context_packet_schema_versions: tuple[int, ...]
    tested_hosts: dict[str, str]
    workflows: dict[str, Workflow]


def default_package_root() -> Path:
    """Find packaged sources without relying on the current directory alone."""
    candidates = (
        Path.cwd() / "packages" / "anva-skills",
        Path(__file__).resolve().parents[3] / "packages" / "anva-skills",
        Path(__file__).resolve().parent,
    )
    for candidate in candidates:
        if (candidate / "manifest.yaml").is_file():
            return candidate
    raise SkillContractError("Unable to locate the Anva skill package root")


def _mapping(path: Path) -> dict[str, object]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SkillContractError(f"{path} must contain a mapping")
    return cast(dict[str, object], payload)


def _strings(payload: dict[str, object], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SkillContractError(f"{key} must be a list of strings")
    return tuple(value)


def load_distribution(package_root: Path | None = None) -> Distribution:
    """Load a validated canonical distribution."""
    root = (package_root or default_package_root()).resolve()
    manifest = _mapping(root / "manifest.yaml")
    workflow_names = manifest.get("workflows")
    if not isinstance(workflow_names, list) or not all(
        isinstance(name, str) for name in workflow_names
    ):
        raise SkillContractError("manifest workflows must be a list of names")
    schema = json.loads((root / "workflow-contract.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    workflows: dict[str, Workflow] = {}
    for name in workflow_names:
        payload = _mapping(root / "workflows" / f"{name}.yaml")
        errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
        if errors:
            first = errors[0]
            location = ".".join(str(part) for part in first.absolute_path) or "$"
            raise SkillContractError(f"{name} {location}: {first.message}")
        if payload["name"] != name:
            raise SkillContractError(f"{name} does not match its declared name")
        workflow = Workflow(
            name=name,
            description=cast(str, payload["description"]),
            phase=cast(str, payload["phase"]),
            implicit=bool(payload.get("implicit", True)),
            read_tools=_strings(payload, "read_tools"),
            proposal_tools=_strings(payload, "proposal_tools"),
            steps=_strings(payload, "steps"),
            stop_conditions=_strings(payload, "stop_conditions"),
            degraded_behavior=_strings(payload, "degraded_behavior"),
            output_schema=cast(str, payload["output_schema"]),
            output_sections=_strings(payload, "output_sections"),
        )
        output_path = (root / workflow.output_schema).resolve()
        if not output_path.is_relative_to(root) or not output_path.is_file():
            raise SkillContractError(f"{name} output schema is outside the package")
        Draft202012Validator.check_schema(json.loads(output_path.read_text(encoding="utf-8")))
        workflows[name] = workflow

    versions = manifest.get("mcp_contract_versions")
    packet_versions = manifest.get("context_packet_schema_versions")
    tested_hosts = manifest.get("tested_hosts")
    if not isinstance(versions, list) or not all(isinstance(item, str) for item in versions):
        raise SkillContractError("mcp_contract_versions must be strings")
    if not isinstance(packet_versions, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in packet_versions
    ):
        raise SkillContractError("context_packet_schema_versions must be integers")
    if not isinstance(tested_hosts, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in tested_hosts.items()
    ):
        raise SkillContractError("tested_hosts must map hosts to versions")
    skill_version = manifest.get("skill_version")
    if not isinstance(skill_version, str):
        raise SkillContractError("skill_version must be a string")
    return Distribution(
        skill_version=skill_version,
        mcp_contract_versions=tuple(versions),
        context_packet_schema_versions=tuple(packet_versions),
        tested_hosts=cast(dict[str, str], tested_hosts),
        workflows=workflows,
    )
