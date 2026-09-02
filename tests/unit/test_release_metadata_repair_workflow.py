"""Fail-closed contracts for the one-time v0.1.0 metadata correction."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
import yaml

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-metadata-repair.yml"
SCRIPT = ROOT / "scripts" / "release_metadata_repair.py"


def _load_repair_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("release_metadata_repair_test", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _workflow() -> tuple[str, dict[object, object]]:
    text = WORKFLOW.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert isinstance(parsed, dict)
    return text, parsed


def test_repair_is_manual_protected_serialized_and_least_privilege() -> None:
    text, workflow = _workflow()
    triggers = workflow.get("on", workflow.get(True))
    assert set(cast(dict[object, object], triggers)) == {"workflow_dispatch"}
    assert "pull_request" not in text
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "release-v0.1.0",
        "cancel-in-progress": False,
    }
    job = cast(dict[str, object], cast(dict[str, object], workflow["jobs"])["repair"])
    assert job["environment"] == "release"
    assert job["permissions"] == {
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
        "issues": "read",
    }
    assert "secrets." not in text
    assert "github.token" in text
    assert "@v" not in "\n".join(line for line in text.splitlines() if "uses:" in line)


def test_repair_pins_existing_product_and_never_rebuilds_or_pushes_it() -> None:
    text, workflow = _workflow()
    environment = cast(dict[str, str], workflow["env"])
    assert environment["ANVA_RELEASE_TAG"] == "v0.1.0"
    assert environment["ANVA_PRODUCT_SOURCE"] == ("d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac")
    assert environment["ANVA_IMAGE_DIGEST"] == (
        "sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d"
    )
    forbidden = ("docker build", "docker push", "gh release create", "git tag", "v0.1.1")
    assert not any(command in text for command in forbidden)
    assert 'test "$tag_commit" = "$ANVA_PRODUCT_SOURCE"' in text
    assert 'test "$manifest_image" = "${ANVA_IMAGE_REPOSITORY}@${ANVA_IMAGE_DIGEST}"' in text
    assert "gh issue view 43" in text
    assert "gh issue view 44" in text


def test_repair_asserts_exact_inventory_and_three_file_closure() -> None:
    text, _ = _workflow()
    script = SCRIPT.read_text(encoding="utf-8")
    assert "EXPECTED_RELEASE_ASSETS" in script
    assert len([line for line in script.splitlines() if "ExpectedAsset(" in line]) == 13
    assert "REPLACED_ASSETS" in script
    for name in ("RELEASE_NOTES.md", "release-manifest.json", "SHA256SUMS"):
        assert name in script
    assert "assert_unchanged_assets" in script
    assert "generate_replacement_closure" in script
    assert "verify_replacement_closure" in script
    assert "download_url" in text
    assert "--clobber" in text


def test_post_repair_inventory_rejects_an_unexpected_fourteenth_asset(tmp_path: Path) -> None:
    release_metadata_repair = _load_repair_module()
    for name in release_metadata_repair.EXPECTED_RELEASE_ASSETS:
        (tmp_path / name).touch()
    release_metadata_repair.assert_exact_inventory(tmp_path)

    (tmp_path / "unexpected-fourteenth-asset.txt").touch()
    with pytest.raises(ValueError, match="unexpected release inventory"):
        release_metadata_repair.assert_exact_inventory(tmp_path)


def test_attestations_precede_upload_and_bind_product_and_metadata_sources() -> None:
    text, _ = _workflow()
    standard = text.index("name: Attest the replacement metadata files")
    custom = text.index("name: Attest the metadata correction record")
    verify = text.index("name: Verify replacement attestations before upload")
    mutate = text.index("name: Replace only the metadata closure and verify or roll back")
    assert standard < custom < verify < mutate
    assert "actions/attest-build-provenance@96b4a1ef7235a096b17240c259729fdd70c83d45" in text
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in text
    assert "subject-path: replacement/RELEASE_NOTES.md" in text
    assert "subject-path: replacement/release-manifest.json" in text
    assert "subject-path: replacement/SHA256SUMS" in text
    assert '"productSourceCommit": os.environ["ANVA_PRODUCT_SOURCE"]' in text
    assert '"metadataCommit": os.environ["METADATA_COMMIT"]' in text
    assert '"correctionReason": os.environ["ANVA_CORRECTION_REASON"]' in text
    assert '"repairRun": os.environ["REPAIR_RUN"]' in text
    pre_upload = text[verify:mutate]
    assert "gh attestation verify" in pre_upload
    assert "productSourceCommit == $product" in pre_upload
    assert "metadataCommit == $metadata" in pre_upload
    assert "correctionReason == $reason" in pre_upload
    assert "repairRun == $run" in pre_upload


def test_apply_mode_has_verified_rollback_and_anonymous_post_checks() -> None:
    text, _ = _workflow()
    mutation = text[text.index("name: Replace only the metadata closure and verify or roll back") :]
    assert "rollback()" in mutation
    assert "old-release-body.md" in mutation
    assert "old/RELEASE_NOTES.md old/release-manifest.json old/SHA256SUMS" in mutation
    assert 'gh release edit "$ANVA_RELEASE_TAG" --notes-file old-release-body.md' in mutation
    assert "verify_old_snapshot" in mutation
    assert "trap rollback EXIT" in mutation
    assert "trap 'exit 143' TERM" in mutation
    assert 'assert_exact_inventory(Path("anonymous"))' in mutation
    assert "env -u GH_TOKEN -u GITHUB_TOKEN" in mutation
    assert "sha256sum --check SHA256SUMS" in mutation
    assert "gh attestation verify" in mutation
    assert "up --no-build --wait" in mutation
    assert "github.event.inputs.mode == 'apply'" in text
