"""Fail-closed contracts for the one-time v0.1.0 metadata correction."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
import yaml

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-metadata-repair.yml"
SCRIPT = ROOT / "scripts" / "release_metadata_repair.py"
RELEASE_GUIDE = ROOT / "docs" / "releases" / "github-native-release.md"
INSTALL_GUIDE = ROOT / "docs" / "runbooks" / "install-upgrade-uninstall.md"


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


def _mutation_script() -> str:
    _, workflow = _workflow()
    jobs = cast(dict[str, object], workflow["jobs"])
    repair = cast(dict[str, object], jobs["repair"])
    steps = cast(list[dict[str, object]], repair["steps"])
    step = next(
        item
        for item in steps
        if item.get("name") == "Replace only the metadata closure and verify or roll back"
    )
    return cast(str, step["run"])


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
    assert "snapshot-body old-release-body.md" in text
    assert "--json body --jq .body > old-release-body.md" not in text
    assert "old/RELEASE_NOTES.md old/release-manifest.json old/SHA256SUMS" in mutation
    assert 'gh release edit "$ANVA_RELEASE_TAG" --notes-file old-release-body.md' in mutation
    assert "verify_old_snapshot" in mutation
    assert "trap rollback EXIT" in mutation
    assert "trap 'exit 143' TERM" in mutation
    assert 'assert_exact_inventory(Path("anonymous"))' in mutation
    assert "env -u GH_TOKEN -u GITHUB_TOKEN curl" in mutation
    assert "env -u GH_TOKEN -u GITHUB_TOKEN gh attestation verify" not in mutation
    assert "sha256sum --check SHA256SUMS" in mutation
    assert "gh attestation verify" in mutation
    assert "up --no-build --wait" in mutation
    assert "github.event.inputs.mode == 'apply'" in text


@pytest.mark.parametrize(
    "body", [b"body without newline", b"body with one newline\n", b"body with two newlines\n\n"]
)
def test_release_body_snapshot_decodes_json_without_changing_bytes(
    tmp_path: Path, body: bytes
) -> None:
    snapshot = tmp_path / "snapshot.md"
    payload = ('{"body":' + __import__("json").dumps(body.decode()) + "}").encode()
    result = subprocess.run(  # noqa: S603 - executes the trusted repository script.
        [sys.executable, str(SCRIPT), "snapshot-body", str(snapshot)],
        input=payload,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode()
    assert snapshot.read_bytes() == body


def test_post_upload_attestation_verification_keeps_the_job_token(tmp_path: Path) -> None:
    mutation = _mutation_script()
    loop_start = (
        "for artifact in anonymous/RELEASE_NOTES.md "
        "anonymous/release-manifest.json anonymous/SHA256SUMS; do"
    )
    start = mutation.index(loop_start)
    end = mutation.index('install_root="$(mktemp -d)"')
    verification_script = mutation[start:end]
    fake_bin = tmp_path / "bin"
    anonymous = tmp_path / "anonymous"
    fake_bin.mkdir()
    anonymous.mkdir()
    for name in ("RELEASE_NOTES.md", "release-manifest.json", "SHA256SUMS"):
        (anonymous / name).touch()

    gh = fake_bin / "gh"
    gh.write_text(
        """#!/bin/sh
set -eu
test -n "${GH_TOKEN:-}"
case " $* " in
  *" --format json "*)
    printf '%s\n' '[{}]'
    ;;
esac
""",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    jq = fake_bin / "jq"
    jq.write_text(
        """#!/bin/sh
set -eu
payload="$(cat)"
test -n "$payload"
""",
        encoding="utf-8",
    )
    jq.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "GH_TOKEN": "least-privilege-workflow-token",
        "GITHUB_TOKEN": "least-privilege-workflow-token",
        "GITHUB_REPOSITORY": "RishavT/anva",
        "ANVA_PRODUCT_SOURCE": "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac",
        "ANVA_REPAIR_PREDICATE_TYPE": (
            "https://github.com/RishavT/anva/attestations/release-metadata-repair/v1"
        ),
        "METADATA_COMMIT": "146f4ec44d5caaba8dfea893a9b087bd3b5f8083",
        "ANVA_CORRECTION_REASON": "reason",
        "REPAIR_RUN": "run",
    }
    result = subprocess.run(  # noqa: S603 - executes the trusted workflow contract.
        ["/bin/bash", "-c", verification_script],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


def test_public_verification_docs_distinguish_anonymous_assets_from_attestation_auth() -> None:
    for guide in (RELEASE_GUIDE, INSTALL_GUIDE):
        normalized = " ".join(guide.read_text(encoding="utf-8").split())
        assert "Public release asset download and checksum" in normalized
        assert "do not require GitHub authentication" in normalized
        assert "GitHub attestation lookup does" in normalized
        assert "gh auth login" in normalized
        assert "scoped `GH_TOKEN`" in normalized


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [("normal", 41), ("HUP", 129), ("TERM", 143), ("INT", 130)],
)
@pytest.mark.parametrize(
    "body", [b"old release body", b"old release body\n", b"old release body\n\n"]
)
def test_lifecycle_failure_restores_snapshot_from_workspace(
    tmp_path: Path, failure: str, expected_status: int, body: bytes
) -> None:
    mutation = _mutation_script()
    lifecycle = mutation[mutation.index('install_root="$(mktemp -d)"') :]
    assert '(\n  cd "$install_root/anva-0.1.0"' in lifecycle
    assert lifecycle.index("(") < lifecycle.index('cd "$install_root/anva-0.1.0"')
    assert lifecycle.index('cd "$install_root/anva-0.1.0"') < lifecycle.index(")\nsucceeded=true")

    rollback_prefix = mutation[
        : mutation.index("python scripts/release_metadata_repair.py verify-current current")
    ]
    old = tmp_path / "old"
    public = tmp_path / "public"
    fake_bin = tmp_path / "bin"
    install = tmp_path / "install"
    for directory in (old, public, fake_bin, install):
        directory.mkdir()
    assets = ("RELEASE_NOTES.md", "release-manifest.json", "SHA256SUMS")
    for name in assets:
        (old / name).write_text(f"old {name}\n", encoding="utf-8")
        (public / name).write_text(f"partial new {name}\n", encoding="utf-8")
    (tmp_path / "old-release-body.md").write_bytes(body)
    (tmp_path / "public-body.md").write_text("partial new body\n", encoding="utf-8")

    gh = fake_bin / "gh"
    gh.write_text(
        """#!/bin/sh
set -eu
command="$1 $2"
shift 2
case "$command" in
  "release upload")
    shift
    while [ "$#" -gt 0 ] && [ "$1" != "--clobber" ]; do
      cp "$1" "$FAKE_PUBLIC/$(basename "$1")"
      shift
    done
    ;;
  "release edit")
    shift
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--notes-file" ]; then
        cp "$2" "$FAKE_PUBLIC_BODY"
        exit 0
      fi
      shift
    done
    exit 2
    ;;
  "release download")
    shift
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--dir" ]; then
        mkdir -p "$2"
        cp "$FAKE_PUBLIC"/* "$2"/
        exit 0
      fi
      shift
    done
    exit 2
    ;;
  "release view")
    cat "$FAKE_PUBLIC_BODY"
    ;;
  api?*)
    "$REAL_PYTHON" -c 'import json,os; p=os.environ["FAKE_PUBLIC_BODY"];'\
'print(json.dumps({"body":open(p,encoding="utf-8").read()}))'
    ;;
  *) exit 2 ;;
esac
""",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    python = fake_bin / "python"
    python.write_text(
        """#!/bin/sh
set -eu
test "$PWD" = "$EXPECTED_WORKSPACE"
test "$1" = "scripts/release_metadata_repair.py"
if [ "$2" = "snapshot-body" ]; then
  exec "$REAL_PYTHON" "$REAL_SCRIPT" "$2" "$3"
fi
test "$2" = "verify-current"
test "$3" = "rollback-check"
for name in RELEASE_NOTES.md release-manifest.json SHA256SUMS; do
  cmp "$OLD_SNAPSHOT/$name" "rollback-check/$name"
done
touch "$VERIFICATION_MARKER"
""",
        encoding="utf-8",
    )
    python.chmod(0o755)

    if failure == "normal":
        trigger = "(cd install; exit 41)"
    else:
        trigger = f'(cd install; kill -{failure} "$parent_pid"; sleep 1)'
    harness = (
        rollback_prefix
        + "\nmutated=true\n"
        + "parent_pid=$$\n"
        + trigger
        + "\necho lifecycle unexpectedly continued >&2\nexit 99\n"
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "ANVA_RELEASE_TAG": "v0.1.0",
        "GITHUB_REPOSITORY": "RishavT/anva",
        "FAKE_PUBLIC": str(public),
        "FAKE_PUBLIC_BODY": str(tmp_path / "public-body.md"),
        "EXPECTED_WORKSPACE": str(tmp_path),
        "OLD_SNAPSHOT": str(old),
        "VERIFICATION_MARKER": str(tmp_path / "verified"),
        "REAL_PYTHON": sys.executable,
        "REAL_SCRIPT": str(SCRIPT),
    }
    result = subprocess.run(  # noqa: S603 - controlled regression harness
        ["/bin/bash", "-c", harness], cwd=tmp_path, env=environment, check=False, timeout=10
    )

    assert result.returncode == expected_status
    assert {path.name for path in public.iterdir()} == set(assets)
    for name in assets:
        assert (public / name).read_bytes() == (old / name).read_bytes()
    assert (tmp_path / "public-body.md").read_bytes() == (
        tmp_path / "old-release-body.md"
    ).read_bytes()
    assert (tmp_path / "verified").is_file()
