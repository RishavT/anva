from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "release.yml"


def _workflow() -> tuple[str, dict[object, object]]:
    text = WORKFLOW.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert isinstance(parsed, dict)
    return text, parsed


def test_release_workflow_has_no_untrusted_trigger_or_long_lived_secret() -> None:
    text, workflow = _workflow()
    # PyYAML implements YAML 1.1 and therefore decodes the YAML 1.2 key `on`
    # as True. GitHub Actions correctly treats it as the `on` trigger key.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert "pull_request" not in text
    assert "secrets." not in text
    assert "github.token" in text
    assert "environment: release" in text


def test_release_workflow_pins_actions_and_uses_minimal_permissions() -> None:
    text, workflow = _workflow()
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in text
    assert (
        text.count("actions/attest-build-provenance@96b4a1ef7235a096b17240c259729fdd70c83d45") == 2
    )
    assert "@v" not in "\n".join(line for line in text.splitlines() if "uses:" in line)
    assert workflow["permissions"] == {"contents": "read"}
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    for job_name in ("build", "publish", "verify"):
        assert isinstance(jobs[job_name], dict)
    assert jobs["build"]["permissions"] == {
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
        "packages": "write",
    }
    assert jobs["publish"]["permissions"] == {"contents": "write"}
    assert jobs["verify"]["permissions"] == {
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }


def test_release_order_is_fail_closed() -> None:
    text, _ = _workflow()
    identity = text.index("Verify tag, version, commit, and clean source")
    artifacts = text.index("Build and fail-closed verify release artifacts")
    push = text.index("Push the exact image and resolve its registry digest")
    image_attest = text.index("Attest the GHCR image")
    file_attest = text.index("Attest every downloadable release artifact")
    release = text.index("Create the GitHub Release after attestations")
    published_verify = text.index("Verify published digest, attestations, and install lifecycle")
    assert identity < artifacts < push < image_attest < file_attest < release < published_verify
    assert "(cd release && sha256sum --check SHA256SUMS)" in text
    assert '[[ "$EVENT_REF" == "refs/heads/main" ]]' in text
    assert "gh attestation verify" in text
    assert 'docker pull "$image"' in text
    assert 'archive.extractall(os.environ["INSTALL_ROOT"], filter="data")' in text
    assert "up --no-build --wait" in text


def test_dispatch_uses_main_workflow_but_binds_products_to_the_tag_commit() -> None:
    text, workflow = _workflow()
    build = workflow["jobs"]["build"]

    assert workflow["env"]["ANVA_RELEASE_COMMIT"] == (
        "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac"
    )
    assert build["outputs"]["source_commit"] == "${{ steps.source.outputs.commit }}"
    assert "git ls-remote --exit-code origin" in text
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in text
    assert 'test "$source_commit" = "$ANVA_RELEASE_COMMIT"' in text
    assert 'echo "commit=$source_commit" >> "$GITHUB_OUTPUT"' in text
    assert '--source-commit "$ANVA_REVISION"' in text
    assert 'needs.build.outputs.source_commit' in text
    assert '--target "$SOURCE_COMMIT"' in text
    assert "$GITHUB_SHA" not in text


def test_recovery_prepares_only_its_labeled_cache_before_tag_checkout() -> None:
    text, workflow = _workflow()

    assert workflow["env"]["ANVA_TRIVY_IMAGE"] == (
        "aquasec/trivy:0.64.1@sha256:"
        "a8ca29078522f30393bdb34225e4c0994d38f37083be81a42da3a2a7e1488e9e"
    )
    prepare = text.index("name: Prepare the run-owned scanner cache")
    checkout = text.index("name: Check out the exact tag")
    verify = text.index("name: Verify tag, version, commit, and clean source")
    assert prepare < checkout < verify

    preparation = text[prepare:checkout]
    assert 'cache_volume="${COMPOSE_PROJECT}_release-trivy-cache"' in preparation
    assert 'docker volume inspect "$cache_volume"' in preparation
    assert 'docker volume create \\' in preparation
    assert '--label "com.docker.compose.project=$COMPOSE_PROJECT"' in preparation
    assert '--label "com.docker.compose.volume=release-trivy-cache"' in preparation
    assert '--user "$runner_uid:$runner_gid"' in preparation
    assert "--read-only" in preparation
    assert "--cap-drop ALL" in preparation
    assert "--security-opt no-new-privileges" in preparation
    assert "--network none" in preparation
    assert 'src=${cache_volume},dst=/tmp' in preparation
    assert "/var/run/docker.sock" not in preparation
    assert 'mkdir /tmp/fanal' in preparation

    cleanup = text[text.index("name: Remove only build-owned resources") :]
    assert 'docker volume inspect "$cache_volume"' in cleanup
    assert 'docker volume rm "$cache_volume"' in cleanup
    assert 'test "$project_label" = "$COMPOSE_PROJECT"' in cleanup
    assert 'test "$volume_label" = "release-trivy-cache"' in cleanup


def test_publish_rechecks_remote_tag_before_any_release_side_effect() -> None:
    _, workflow = _workflow()
    publish = workflow["jobs"]["publish"]
    steps = publish["steps"]
    checkout = steps[0]
    identity = steps[1]

    assert checkout["name"] == "Check out the verified source commit without credentials"
    assert checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ needs.build.outputs.source_commit }}",
    }
    assert identity["name"] == "Recheck immutable release identity"
    assert identity["env"] == {
        "RELEASE_TAG": "${{ needs.build.outputs.tag }}",
        "SOURCE_COMMIT": "${{ needs.build.outputs.source_commit }}",
    }
    identity_script = identity["run"]
    assert "git ls-remote --exit-code origin" in identity_script
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in identity_script
    assert 'test "$remote_commit" = "$SOURCE_COMMIT"' in identity_script
    assert 'test "$SOURCE_COMMIT" = "$ANVA_RELEASE_COMMIT"' in identity_script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in identity_script
    names = [step["name"] for step in steps]
    assert names.index("Recheck immutable release identity") < names.index(
        "Download attested release assets"
    )
    assert names.index("Recheck immutable release identity") < names.index(
        "Create the GitHub Release after attestations"
    )


def test_verify_rechecks_remote_tag_before_authentication_or_download() -> None:
    _, workflow = _workflow()
    verify = workflow["jobs"]["verify"]
    steps = verify["steps"]
    checkout = steps[0]
    identity = steps[1]

    assert checkout["name"] == "Check out the verified source commit without credentials"
    assert checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ needs.build.outputs.source_commit }}",
    }
    assert identity["name"] == "Recheck immutable release identity"
    assert identity["env"] == {
        "RELEASE_TAG": "${{ needs.build.outputs.tag }}",
        "SOURCE_COMMIT": "${{ needs.build.outputs.source_commit }}",
    }
    identity_script = identity["run"]
    assert "git ls-remote --exit-code origin" in identity_script
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in identity_script
    assert 'test "$remote_commit" = "$SOURCE_COMMIT"' in identity_script
    assert 'test "$SOURCE_COMMIT" = "$ANVA_RELEASE_COMMIT"' in identity_script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in identity_script
    names = [step["name"] for step in steps]
    assert names.index("Recheck immutable release identity") < names.index(
        "Authenticate to GHCR with the job token"
    )
    assert names.index("Recheck immutable release identity") < names.index(
        "Verify published digest, attestations, and install lifecycle"
    )
