from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "release.yml"


def _workflow() -> tuple[str, dict[object, object]]:
    text = WORKFLOW.read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert isinstance(parsed, dict)
    return text, parsed


def _jobs(workflow: dict[object, object]) -> dict[str, dict[str, object]]:
    return cast(dict[str, dict[str, object]], workflow["jobs"])


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
    assert text.count("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6") == 2
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
    assert jobs["publish"]["permissions"] == {
        "attestations": "read",
        "contents": "write",
        "packages": "read",
    }
    assert jobs["verify"]["permissions"] == {
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }


def test_release_order_is_fail_closed() -> None:
    text, _ = _workflow()
    identity = text.index("Verify tag, version, commit, and clean source")
    artifacts = text.index("Build and fail-closed verify release artifacts")
    source_binding = text.index("Create the immutable product source binding")
    local_registry = text.index("Prepare the run-owned local digest registry")
    digest = text.index("Resolve the exact image digest without remote publication")
    risk = text.index("Bind approved residual risk to the immutable image")
    publish_image = text.index("Publish the exact version image after local release gates")
    image_attest = text.index("Attest the GHCR image")
    file_attest = text.index("Attest every downloadable release artifact")
    source_attest = text.index("Attest artifact digests to the immutable product source")
    release = text.index("Create the GitHub Release after attestations")
    published_verify = text.index("Verify published digest, attestations, and install lifecycle")
    assert (
        identity
        < artifacts
        < source_binding
        < local_registry
        < digest
        < risk
        < publish_image
        < image_attest
        < file_attest
        < source_attest
        < release
        < published_verify
    )
    assert "(cd release && sha256sum --check SHA256SUMS)" in text
    assert '[[ "$EVENT_REF" == "refs/heads/main" ]]' in text
    assert "gh attestation verify" in text
    assert 'docker pull "$image"' in text
    assert 'archive.extractall(os.environ["INSTALL_ROOT"], filter="data")' in text
    assert "up --no-build --wait" in text


def test_dispatch_uses_main_workflow_but_binds_products_to_the_tag_commit() -> None:
    text, workflow = _workflow()
    build = _jobs(workflow)["build"]
    environment = cast(dict[str, str], workflow["env"])
    outputs = cast(dict[str, str], build["outputs"])

    assert environment["ANVA_RELEASE_COMMIT"] == ("d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac")
    assert outputs["source_commit"] == "${{ steps.source.outputs.commit }}"
    assert "git ls-remote --exit-code origin" in text
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in text
    assert 'test "$source_commit" = "$ANVA_RELEASE_COMMIT"' in text
    assert 'echo "commit=$source_commit" >> "$GITHUB_OUTPUT"' in text
    assert '--source-commit "$ANVA_REVISION"' in text
    assert "needs.build.outputs.source_commit" in text
    assert '--target "$SOURCE_COMMIT"' in text
    assert "$GITHUB_SHA" not in text


def test_supplemental_attestation_binds_subjects_to_immutable_product_source() -> None:
    text, workflow = _workflow()
    environment = cast(dict[str, str], workflow["env"])

    predicate_type = environment["ANVA_SOURCE_PREDICATE_TYPE"]
    assert predicate_type == "https://github.com/RishavT/anva/attestations/source/v1"
    assert not predicate_type.startswith("https://slsa.dev/")
    assert '"sourceCommit": os.environ["SOURCE_COMMIT"]' in text
    assert '"sourceRef": f"refs/tags/{os.environ[\'RELEASE_TAG\']}"' in text
    assert '"sourceTag": os.environ["RELEASE_TAG"]' in text
    assert '"sourceRepository": f"https://github.com/{os.environ[\'GITHUB_REPOSITORY\']}"' in text
    assert "predicate-type: ${{ env.ANVA_SOURCE_PREDICATE_TYPE }}" in text
    assert "predicate-path: ${{ steps.source-binding.outputs.predicate }}" in text
    assert "subject-digest: ${{ steps.image.outputs.digest }}" in text
    assert "subject-path: release/*" in text
    assert "push-to-registry: true" in text


def test_publish_and_verify_cryptographically_inspect_product_source_binding() -> None:
    text, workflow = _workflow()

    for job_name in ("publish", "verify"):
        job = _jobs(workflow)[job_name]
        steps = cast(list[dict[str, object]], job["steps"])
        binding_step = next(
            step for step in steps if step["name"] == "Verify immutable product source bindings"
        )
        script = cast(str, binding_step["run"])
        environment = cast(dict[str, str], binding_step["env"])

        assert environment["SOURCE_COMMIT"] == "${{ needs.build.outputs.source_commit }}"
        assert environment["RELEASE_TAG"] == "${{ needs.build.outputs.tag }}"
        assert environment["IMAGE_DIGEST"] == "${{ needs.build.outputs.digest }}"
        assert 'gh attestation verify "$subject"' in script
        assert '--predicate-type "$ANVA_SOURCE_PREDICATE_TYPE"' in script
        assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"' in script
        assert "--format json" in script
        assert '--arg version "$ANVA_VERSION"' in script
        assert '.verificationResult.statement.predicate["sourceCommit"] == $commit' in script
        assert '.verificationResult.statement.predicate["sourceRef"] == $ref' in script
        assert '.verificationResult.statement.predicate["sourceTag"] == $tag' in script
        assert '.verificationResult.statement.predicate["version"] == $version' in script
        assert (
            '.verificationResult.statement.predicate["sourceRepository"] == $repository' in script
        )
        assert 'for artifact in "$published"/*; do' in script
        assert 'verify_source_binding "$artifact"' in script
        assert 'verify_source_binding "oci://${ANVA_IMAGE_REPOSITORY}@${IMAGE_DIGEST}"' in script

    publish_text = text[text.index("publish:") : text.index("verify:")]
    assert publish_text.index("Verify immutable product source bindings") < publish_text.index(
        "Create the GitHub Release after attestations"
    )


def test_recovery_prepares_only_its_labeled_cache_before_tag_checkout() -> None:
    text, workflow = _workflow()
    environment = cast(dict[str, str], workflow["env"])

    assert environment["ANVA_TRIVY_IMAGE"] == (
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
    assert "docker volume create \\" in preparation
    assert '--label "com.docker.compose.project=$COMPOSE_PROJECT"' in preparation
    assert '--label "com.docker.compose.volume=release-trivy-cache"' in preparation
    assert '--user "$runner_uid:$runner_gid"' in preparation
    assert "--read-only" in preparation
    assert "--cap-drop ALL" in preparation
    assert "--security-opt no-new-privileges" in preparation
    assert "--network none" in preparation
    assert "src=${cache_volume},dst=/tmp" in preparation
    assert "/var/run/docker.sock" not in preparation
    assert "mkdir /tmp/fanal" in preparation

    cleanup = text[text.index("name: Remove only build-owned resources") :]
    assert 'docker volume inspect "$cache_volume"' in cleanup
    assert 'docker volume rm "$cache_volume"' in cleanup
    assert 'test "$project_label" = "$COMPOSE_PROJECT"' in cleanup
    assert 'test "$volume_label" = "release-trivy-cache"' in cleanup


def test_release_compose_receives_a_validated_docker_gid_across_step_boundaries() -> None:
    _, workflow = _workflow()
    build = _jobs(workflow)["build"]
    steps = cast(list[dict[str, object]], build["steps"])
    named_steps = {cast(str, step["name"]): step for step in steps}

    source = named_steps["Verify tag, version, commit, and clean source"]
    source_script = cast(str, source["run"])
    assert "docker_gid=\"$(stat -c '%g' /var/run/docker.sock)\"" in source_script
    assert '[[ "$docker_gid" =~ ^[0-9]+$ ]]' in source_script
    assert 'echo "ANVA_DOCKER_GID=$docker_gid"' in source_script
    assert '} >> "$GITHUB_ENV"' in source_script

    release_compose_steps = [
        cast(str, step["name"])
        for step in steps
        if "run" in step
        and (
            "compose.release.yaml" in cast(str, step["run"])
            or "make release-artifacts" in cast(str, step["run"])
            or "make release-manifest" in cast(str, step["run"])
        )
    ]
    assert release_compose_steps == [
        "Build and fail-closed verify release artifacts",
        "Bind approved residual risk to the immutable image",
        "Remove only build-owned resources",
    ]

    source_index = steps.index(source)
    for name in release_compose_steps[:-1]:
        assert source_index < steps.index(named_steps[name])

    cleanup_script = cast(str, named_steps[release_compose_steps[-1]]["run"])
    assert "docker_gid=\"$(stat -c '%g' /var/run/docker.sock)\"" in cleanup_script
    assert '[[ "$docker_gid" =~ ^[0-9]+$ ]]' in cleanup_script
    assert 'export ANVA_DOCKER_GID="$docker_gid"' in cleanup_script


def test_release_resolves_digest_locally_and_withholds_remote_push_until_gates() -> None:
    text, workflow = _workflow()
    build = _jobs(workflow)["build"]
    steps = cast(list[dict[str, object]], build["steps"])
    names = [cast(str, step["name"]) for step in steps]

    registry_name = "Prepare the run-owned local digest registry"
    digest_name = "Resolve the exact image digest without remote publication"
    risk_name = "Bind approved residual risk to the immutable image"
    source_binding_name = "Create the immutable product source binding"
    publish_name = "Publish the exact version image after local release gates"
    attest_name = "Attest the GHCR image"
    assert names.index(source_binding_name) < names.index(registry_name)
    assert names.index(registry_name) < names.index(digest_name)
    assert names.index(digest_name) < names.index(risk_name)
    assert names.index(risk_name) < names.index(publish_name)
    assert names.index(publish_name) < names.index(attest_name)

    environment = cast(dict[str, str], workflow["env"])
    assert environment["ANVA_REGISTRY_IMAGE"] == (
        "registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
    )
    registry = cast(str, steps[names.index(registry_name)]["run"])
    assert "--publish 127.0.0.1::5000" in registry
    assert "--read-only" in registry
    assert "--cap-drop ALL" in registry
    assert "--security-opt no-new-privileges" in registry
    assert "--tmpfs /var/lib/registry:rw,nosuid,nodev,noexec,size=1g" in registry

    digest = cast(str, steps[names.index(digest_name)]["run"])
    assert '[[ "$LOCAL_REGISTRY" =~ ^127\\.0\\.0\\.1:[0-9]+$ ]]' in digest
    assert 'local_image="${LOCAL_REGISTRY}/anva:${ANVA_VERSION}"' in digest
    assert 'docker push "$local_image"' in digest
    assert "ANVA_IMAGE_REPOSITORY}:release-candidate" not in digest
    assert 'docker push "$image"' not in digest

    publish = cast(str, steps[names.index(publish_name)]["run"])
    assert 'image="${ANVA_IMAGE_REPOSITORY}:${ANVA_VERSION}"' in publish
    assert 'docker push "$image"' in publish
    assert 'test "$published_digest" = "$IMAGE_DIGEST"' in publish
    assert "docker build" not in publish
    assert "make release" not in publish
    assert text.count("name: Publish the exact version image after local release gates") == 1

    cleanup = cast(str, steps[names.index("Remove only build-owned resources")]["run"])
    assert 'registry_container="${COMPOSE_PROJECT}-digest-registry"' in cleanup
    assert 'test "$(docker inspect --format' in cleanup
    assert 'docker rm --force "$registry_container"' in cleanup


def test_publish_rechecks_remote_tag_before_any_release_side_effect() -> None:
    _, workflow = _workflow()
    publish = _jobs(workflow)["publish"]
    steps = cast(list[dict[str, object]], publish["steps"])
    checkout = steps[0]
    identity = steps[1]

    assert checkout["name"] == "Check out the verified source commit without credentials"
    assert cast(dict[str, object], checkout["with"]) == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ needs.build.outputs.source_commit }}",
    }
    assert identity["name"] == "Recheck immutable release identity"
    assert cast(dict[str, str], identity["env"]) == {
        "RELEASE_TAG": "${{ needs.build.outputs.tag }}",
        "SOURCE_COMMIT": "${{ needs.build.outputs.source_commit }}",
    }
    identity_script = cast(str, identity["run"])
    assert "git ls-remote --exit-code origin" in identity_script
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in identity_script
    assert 'test "$remote_commit" = "$SOURCE_COMMIT"' in identity_script
    assert 'test "$SOURCE_COMMIT" = "$ANVA_RELEASE_COMMIT"' in identity_script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in identity_script
    names = [cast(str, step["name"]) for step in steps]
    assert names.index("Recheck immutable release identity") < names.index(
        "Download attested release assets"
    )
    assert names.index("Recheck immutable release identity") < names.index(
        "Create the GitHub Release after attestations"
    )


def test_verify_rechecks_remote_tag_before_authentication_or_download() -> None:
    _, workflow = _workflow()
    verify = _jobs(workflow)["verify"]
    steps = cast(list[dict[str, object]], verify["steps"])
    checkout = steps[0]
    identity = steps[1]

    assert checkout["name"] == "Check out the verified source commit without credentials"
    assert cast(dict[str, object], checkout["with"]) == {
        "fetch-depth": 0,
        "persist-credentials": False,
        "ref": "${{ needs.build.outputs.source_commit }}",
    }
    assert identity["name"] == "Recheck immutable release identity"
    assert cast(dict[str, str], identity["env"]) == {
        "RELEASE_TAG": "${{ needs.build.outputs.tag }}",
        "SOURCE_COMMIT": "${{ needs.build.outputs.source_commit }}",
    }
    identity_script = cast(str, identity["run"])
    assert "git ls-remote --exit-code origin" in identity_script
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in identity_script
    assert 'test "$remote_commit" = "$SOURCE_COMMIT"' in identity_script
    assert 'test "$SOURCE_COMMIT" = "$ANVA_RELEASE_COMMIT"' in identity_script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in identity_script
    names = [cast(str, step["name"]) for step in steps]
    assert names.index("Recheck immutable release identity") < names.index(
        "Authenticate to GHCR with the job token"
    )
    assert names.index("Recheck immutable release identity") < names.index(
        "Verify published digest, attestations, and install lifecycle"
    )
