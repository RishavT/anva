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


def test_history_plan_is_explicitly_non_executed_and_complete() -> None:
    plan = json.loads(
        (ROOT / "docs/security/history-rewrite-plan.json").read_text(encoding="utf-8")
    )
    assert plan["status"] == "PLAN_ONLY_NOT_EXECUTED"
    assert plan["credential_rotation_required"] is False
    assert plan["secret_scan"]["findings"] == 31
    assert plan["secret_scan"]["classification"]["potentially_real_credential"] == 0
    assert plan["owner"]["organization"] == "AI Soft Work"
    assert plan["path_rewrites"]
    assert plan["execution_requires_explicit_approval"]


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
            resolved = ROOT / target.lstrip("/") if target.startswith("/") else document.parent / target
            if not resolved.resolve().exists():
                missing.append(f"{document.relative_to(ROOT)} -> {raw_target}")
    assert not missing
