"""Load and validate the canonical host-neutral skill contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


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


def _schema_documents(root: Path) -> dict[str, dict[str, object]]:
    schema_root = root / "shared" / "output-schemas"
    documents: dict[str, dict[str, object]] = {}
    for path in sorted(schema_root.glob("*.schema.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("$id"), str):
            raise SkillContractError(f"{path} must be an identified JSON Schema object")
        Draft202012Validator.check_schema(payload)
        identifier = cast(str, payload["$id"])
        if identifier in documents:
            raise SkillContractError(f"Duplicate output schema identifier: {identifier}")
        documents[identifier] = cast(dict[str, object], payload)
    if "https://schemas.anva.dev/skills/v1/common.schema.json" not in documents:
        raise SkillContractError("Common output schema is missing")
    return documents


def _schema_registry(
    documents: dict[str, dict[str, object]],
) -> Registry[dict[str, object]]:
    registry: Registry[dict[str, object]] = Registry()
    for identifier, payload in documents.items():
        registry = registry.with_resource(identifier, Resource.from_contents(payload))
    return registry


def _output_validator(
    root: Path,
    workflow: Workflow,
) -> Draft202012Validator:
    documents = _schema_documents(root)
    output_path = (root / workflow.output_schema).resolve()
    schema = json.loads(output_path.read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        registry=_schema_registry(documents),
        format_checker=FormatChecker(),
    )


def _collect_source_refs(value: object) -> set[str]:
    references: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"source_refs", "source_references"} and isinstance(child, list):
                references.update(item for item in child if isinstance(item, str))
            else:
                references.update(_collect_source_refs(child))
    elif isinstance(value, list):
        for child in value:
            references.update(_collect_source_refs(child))
    return references


def source_reference_errors(payload: dict[str, object], workflow_name: str) -> tuple[str, ...]:
    """Return redacted host-neutral source-closure and proposal invariants."""
    source_values = payload.get("anva_sources", payload.get("normalized_sources", []))
    if not isinstance(source_values, list):
        return ("normalized sources are not an array",)
    source_refs = [
        source.get("source_ref")
        for source in source_values
        if isinstance(source, dict) and isinstance(source.get("source_ref"), str)
    ]
    errors: list[str] = []
    if len(source_refs) != len(set(source_refs)):
        errors.append("normalized source references must be unique")
    retained_refs = _collect_source_refs(payload)
    available_refs = set(source_refs)
    if retained_refs - available_refs:
        errors.append("source references lack normalized provenance")
    if available_refs - retained_refs:
        errors.append("normalized sources are not referenced by retained material")
    if workflow_name == "anva-learn":
        preview = payload.get("preview")
        compared = (
            ("proposal_type", "proposal_type"),
            ("target", "target"),
            ("proposed_content", "proposed_content"),
            ("rationale", "rationale"),
            ("source_references", "source_references"),
        )
        if not isinstance(preview, dict) or any(
            payload.get(root_key) != preview.get(preview_key) for root_key, preview_key in compared
        ):
            errors.append("proposal preview must exactly match submitted content")
    return tuple(errors)


def validate_skill_output(
    workflow_name: str,
    payload: object,
    *,
    package_root: Path | None = None,
) -> None:
    """Validate one real host result against schema and cross-reference invariants."""
    root = (package_root or default_package_root()).resolve()
    distribution = load_distribution(root)
    workflow = distribution.workflows.get(workflow_name)
    if workflow is None:
        raise SkillContractError(f"Unknown workflow: {workflow_name}")
    errors = sorted(
        _output_validator(root, workflow).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise SkillContractError(f"{workflow_name} output {location}: {first.message}")
    if not isinstance(payload, dict):
        raise SkillContractError(f"{workflow_name} output must be an object")
    semantic_errors = source_reference_errors(payload, workflow_name)
    if semantic_errors:
        raise SkillContractError(f"{workflow_name} {semantic_errors[0]}")


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
    documents = _schema_documents(root)
    registry = _schema_registry(documents)
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
        output_schema = json.loads(output_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(output_schema)
        Draft202012Validator(
            output_schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
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
