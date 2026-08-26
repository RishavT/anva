import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
ACTION_USE = re.compile(r"^\s*-?\s*uses:\s*[^#\s]+@([^\s#]+)", re.MULTILINE)
IMMUTABLE_SHA = re.compile(r"^[0-9a-f]{40}$")
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def test_required_public_repository_policies_are_present() -> None:
    required = {
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "SUPPORT.md",
        "docs/security/public-repository-policy.md",
        "docs/security/github-actions-trust-boundary.md",
        "docs/security/history-rewrite-plan.json",
    }
    assert not [path for path in sorted(required) if not (ROOT / path).is_file()]
    assert "All rights reserved" in (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "open source" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_all_github_actions_are_pinned_to_immutable_shas() -> None:
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows
    uses = [
        (workflow, reference)
        for workflow in workflows
        for reference in ACTION_USE.findall(workflow.read_text(encoding="utf-8"))
    ]
    assert uses
    assert not [(path.name, ref) for path, ref in uses if not IMMUTABLE_SHA.fullmatch(ref)]


def test_history_decision_and_remote_ref_proposal_are_complete() -> None:
    plan = json.loads(
        (ROOT / "docs/security/history-rewrite-plan.json").read_text(encoding="utf-8")
    )
    assert plan["status"] == "OWNER_ACCEPTED_HISTORY_WITHOUT_REWRITE"
    assert plan["decision"]["rewrite_history"] is False
    assert plan["decision"]["rewrite_authorship"] is False
    assert plan["decision"]["credential_rotation_required"] is False
    assert plan["decision"]["potentially_real_credentials_found"] == 0
    assert plan["owner"]["organization"] == "AI Soft Work"
    inventory = plan["remote_inventory"]
    assert inventory["repository_visibility_at_inventory"] == "PRIVATE"
    assert inventory["tags"] == []
    assert len(inventory["refs"]) == 14
    assert plan["proposed_ref_actions"]["keep"] == ["refs/heads/main"]
    assert len(plan["proposed_ref_actions"]["delete_before_public"]) == 13
    assert plan["proposed_ref_actions"]["archive"] == []
    assert plan["mutation_performed_by_this_inventory"] is False
    assert plan["pre_visibility_requirements"]


def test_generated_private_artifacts_are_ignored() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".worktrees/" in ignore
    assert "evidence/" in ignore
    for prohibited in ("raw-host-stdout.bin", "raw-host-stderr.bin", "run-record.json"):
        assert not list((ROOT / "docs" / "evidence").rglob(prohibited))


def test_local_markdown_links_resolve() -> None:
    missing: list[str] = []
    for document in sorted(ROOT.rglob("*.md")):
        relative_parts = document.relative_to(ROOT).parts
        if any(part.startswith(".") for part in relative_parts) or relative_parts[0] in {
            "backups",
            "build",
            "dist",
            "evidence",
            "release",
        }:
            continue
        for raw_target in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip("<>").split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = (
                ROOT / target.lstrip("/") if target.startswith("/") else document.parent / target
            )
            try:
                repository_target = resolved.resolve().relative_to(ROOT.resolve())
            except ValueError:
                missing.append(f"{document.relative_to(ROOT)} -> {raw_target}")
                continue
            if (
                not repository_target.parts
                or repository_target.parts[0] == "evidence"
                or not resolved.resolve().exists()
            ):
                missing.append(f"{document.relative_to(ROOT)} -> {raw_target}")
    assert not missing
