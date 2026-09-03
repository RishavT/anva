from __future__ import annotations

import os
import subprocess
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
    assert set(triggers) == {"workflow_dispatch"}
    assert "pull_request" not in text
    assert "secrets." not in text
    assert "github.token" in text
    assert "environment: release" in text


def test_release_workflow_pins_actions_and_uses_minimal_permissions() -> None:
    text, workflow = _workflow()
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in text
    assert (
        text.count("actions/attest-build-provenance@96b4a1ef7235a096b17240c259729fdd70c83d45") == 4
    )
    assert text.count("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6") == 2
    assert "@v" not in "\n".join(line for line in text.splitlines() if "uses:" in line)
    assert workflow["permissions"] == {"contents": "read"}
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    for job_name in ("build", "publish", "verify"):
        assert isinstance(jobs[job_name], dict)
        assert jobs[job_name]["environment"] == "release"
    assert jobs["build"]["permissions"] == {
        "actions": "read",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
        "packages": "write",
    }
    assert jobs["publish"]["permissions"] == {
        "actions": "read",
        "attestations": "read",
        "contents": "write",
        "packages": "read",
    }
    assert jobs["verify"]["permissions"] == {
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }


def test_release_jobs_never_execute_repository_helpers_from_candidate_worktree() -> None:
    _, workflow = _workflow()
    for job in _jobs(workflow).values():
        for step in cast(list[dict[str, object]], job["steps"]):
            script = step.get("run")
            if isinstance(script, str):
                assert "python3 scripts/" not in script
                assert "python scripts/" not in script


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


def test_risk_decision_requires_exact_proposal_and_actual_environment_approval() -> None:
    text, workflow = _workflow()
    jobs = _jobs(workflow)
    candidate = jobs["candidate"]
    build = jobs["build"]
    assert "environment" not in candidate
    assert build["needs"] == "candidate"
    assert build["environment"] == "release"
    assert cast(dict[str, str], build["permissions"])["actions"] == "read"

    steps = cast(list[dict[str, object]], build["steps"])
    named = {cast(str, step["name"]): step for step in steps}
    materialize = cast(
        str, named["Materialize approval validator from reviewed workflow source"]["run"]
    )
    approval = cast(
        str, named["Verify exact RishavT environment approval and proposal provenance"]["run"]
    )
    assert "contents/scripts/validate_release_approvals.py" in materialize
    assert '-f "ref=${GITHUB_SHA}"' in materialize
    assert 'reviewed_dir="$RUNNER_TEMP/reviewed-workflow"' in materialize
    assert 'git hash-object "$validator"' in materialize
    assert "REVIEWED_APPROVAL_VALIDATOR=$validator" in materialize
    assert "actions/runs/${GITHUB_RUN_ID}/approvals" in approval
    assert 'python3 "$REVIEWED_APPROVAL_VALIDATOR"' in approval
    assert "python3 scripts/" not in approval
    assert "--require-single" in approval
    assert "gh attestation verify" in approval
    assert 'test "$actual_proposal_sha256" = "$EXPECTED_PROPOSAL_SHA256"' in approval

    decision = cast(str, named["Bind approved residual risk to the immutable image"]["run"])
    for exact_binding in (
        '"source_commit": os.environ["ANVA_REVISION"]',
        '"image_digest": os.environ["IMAGE_DIGEST"]',
        '"runtime_controls_sha256": controls',
        '"high_critical_tuples": tuples',
        '"proposal_sha256": proposal_sha',
        '"proposal_source_security_report_sha256"',
        '"proposal_source_scan_diagnostic_sha256"',
        '"environment_approval_record_sha256"',
        '"approved_by": "RishavT"',
        "if expiry < today or (expiry - today).days > 30",
    ):
        assert exact_binding in decision
    assert "docs/security/vulnerability-exceptions.json" not in text

    names = [cast(str, step["name"]) for step in steps]
    assert names.index(
        "Materialize approval validator from reviewed workflow source"
    ) < names.index("Verify exact RishavT environment approval and proposal provenance")
    assert names.index(
        "Materialize approval validator from reviewed workflow source"
    ) < names.index("Check out the exact tag")
    assert names.index("Verify exact RishavT environment approval and proposal provenance") < (
        names.index("Build and fail-closed verify release artifacts")
    )
    assert names.index("Verify the human decision attestation before publication") < names.index(
        "Publish the exact version image after local release gates"
    )


def test_candidate_retains_and_attests_original_scan_and_database_metadata() -> None:
    _, workflow = _workflow()
    environment = cast(dict[str, str], workflow["env"])
    assert environment["BUILDKIT_PROGRESS"] == "plain"
    candidate = _jobs(workflow)["candidate"]
    steps = cast(list[dict[str, object]], candidate["steps"])
    named = {cast(str, step["name"]): step for step in steps}
    build = cast(
        str,
        named["Build release assets without applying a risk decision"]["run"],
    )
    source_scan = cast(str, named["Run and explicitly validate every candidate scan stage"]["run"])
    diagnostics = named["Retain all completed scan diagnostics before cleanup"]
    proposal = cast(str, named["Create canonical exact-candidate risk proposal"]["run"])
    attestation = cast(dict[str, str], named["Attest exact-candidate risk proposal"]["with"])[
        "subject-path"
    ]
    upload = cast(dict[str, object], named["Upload proposal for personal review"]["with"])
    assert "make release-build" in build
    assert 'metadata="$TRIVY_CACHE_DIR/db/metadata.json"' in source_scan
    assert '--env "TRIVY_CACHE_DIR=$ANVA_TRIVY_CACHE_DIR"' in source_scan
    assert "dst=${ANVA_TRIVY_CACHE_DIR},readonly" in source_scan
    assert '"report_sha256"' in proposal
    assert '"database_metadata_sha256"' in proposal
    assert '"source_security_report_sha256"' in proposal
    assert '"source_scan_diagnostic_sha256"' in proposal
    assert 'source_diagnostic.get("classification") != "passed"' in proposal
    assert 'source_diagnostic.get("engine_exit_code") != 0' in proposal
    assert 'source_diagnostic.get("blocking_findings") != []' in proposal
    assert 'source_report.get("SchemaVersion") != 2' in proposal
    assert "source security report does not match its diagnostic" in proposal
    assert "source scan database metadata does not match" in proposal
    for evidence in (
        "release-risk-proposal.json",
        "release-risk-report.json",
        "release-risk-db-metadata.json",
        "release-risk-source-security.json",
        "release-risk-source-scan-diagnostic.json",
    ):
        assert evidence in attestation
        assert evidence in cast(str, upload["path"])
    assert "--exit-code 0" in source_scan
    assert "scripts/classify_release_source_scan.py" in source_scan
    assert 'git show "${GITHUB_SHA}:scripts/classify_release_source_scan.py"' in source_scan
    assert "run-release-scan-stage.py" in source_scan
    assert "local rc=$?" in source_scan
    assert "--report-kind" in source_scan
    assert "trap 'rm -f \"$source_raw\"' EXIT" in source_scan
    assert source_scan.count("--skip-dir ") == 10
    assert source_scan.count("--skip-dirs ") == 10
    assert source_scan.count("--skip-file /workspace/.env") == 1
    assert source_scan.count("--skip-files /workspace/.env") == 1
    assert "image --scanners vuln --format spdx-json" in source_scan
    assert "image --scanners vuln --format cyclonedx" in source_scan
    assert diagnostics["if"] == "always()"
    assert diagnostics["uses"] == (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    )
    diagnostics_with = cast(dict[str, object], diagnostics["with"])
    assert diagnostics_with["if-no-files-found"] == "warn"
    assert "${{ github.run_attempt }}" in cast(str, diagnostics_with["name"])

    names = [cast(str, step["name"]) for step in steps]
    assert names.index("Run and explicitly validate every candidate scan stage") < names.index(
        "Retain all completed scan diagnostics before cleanup"
    )
    assert names.index("Retain all completed scan diagnostics before cleanup") < names.index(
        "Resolve candidate registry digest locally"
    )
    assert names.index("Resolve candidate registry digest locally") < names.index(
        "Create canonical exact-candidate risk proposal"
    )
    assert names.index("Retain all completed scan diagnostics before cleanup") < names.index(
        "Remove only candidate-owned resources"
    )


def test_release_cache_contract_has_one_root_from_compose_through_evidence() -> None:
    text, workflow = _workflow()
    environment = cast(dict[str, str], workflow["env"])
    cache_root = environment["ANVA_TRIVY_CACHE_DIR"]
    compose_text = (WORKFLOW.parents[2] / "compose.release.yaml").read_text(encoding="utf-8")
    override_text = (WORKFLOW.parents[2] / "compose.release.cache.yaml").read_text(encoding="utf-8")

    assert cache_root == "/tmp"  # noqa: S108 - isolated container cache contract
    assert "TRIVY_CACHE_DIR: ${ANVA_TRIVY_CACHE_DIR:-/tmp}" in compose_text
    assert "release-trivy-cache:${ANVA_TRIVY_CACHE_DIR:-/tmp}" in compose_text
    assert "TRIVY_CACHE_DIR: ${ANVA_TRIVY_CACHE_DIR:?set canonical Trivy cache directory}" in (
        override_text
    )
    assert "dst=${ANVA_TRIVY_CACHE_DIR}" in text
    assert 'metadata="$TRIVY_CACHE_DIR/db/metadata.json"' in text
    assert "/cache/trivy-cache" not in text + compose_text
    assert text.count('git show "${GITHUB_SHA}:compose.release.cache.yaml"') == 2
    assert '-f "$cache_override"' in text
    assert "-f $RUNNER_TEMP/release-cache.override.yaml" in text


def test_source_scan_failure_cannot_reach_protected_or_proposal_jobs() -> None:
    _, workflow = _workflow()
    jobs = _jobs(workflow)
    candidate = jobs["candidate"]
    steps = cast(list[dict[str, object]], candidate["steps"])
    named = {cast(str, step["name"]): step for step in steps}
    scan = named["Run and explicitly validate every candidate scan stage"]
    proposal = named["Create canonical exact-candidate risk proposal"]

    assert "continue-on-error" not in scan
    assert "if" not in proposal
    assert jobs["build"]["needs"] == "candidate"
    assert jobs["build"]["environment"] == "release"
    assert jobs["publish"]["needs"] == ["candidate", "build"]
    assert jobs["verify"]["needs"] == ["build", "publish"]


def test_validated_source_scan_evidence_remains_bound_through_publication() -> None:
    _, workflow = _workflow()
    jobs = _jobs(workflow)
    build_steps = cast(list[dict[str, object]], jobs["build"]["steps"])
    build_named = {cast(str, step["name"]): step for step in build_steps}
    approval = cast(
        str,
        build_named["Verify exact RishavT environment approval and proposal provenance"]["run"],
    )
    for evidence in (
        "release-risk-source-security.json",
        "release-risk-source-scan-diagnostic.json",
        ".source_security_report_sha256",
        ".source_scan_diagnostic_sha256",
        ".classification",
    ):
        assert evidence in approval

    publish_steps = cast(list[dict[str, object]], jobs["publish"]["steps"])
    publish = cast(
        str,
        next(
            step
            for step in publish_steps
            if step["name"] == "Create the GitHub Release after attestations"
        )["run"],
    )
    for binding in (
        "release-risk-source-security.json",
        "release-risk-source-scan-diagnostic.json",
        '"proposal_source_security_report_sha256"',
        '"proposal_source_scan_diagnostic_sha256"',
        'get("classification") != "passed"',
    ):
        assert binding in publish


def test_remote_tag_is_rechecked_immediately_before_first_ghcr_push() -> None:
    _, workflow = _workflow()
    build = _jobs(workflow)["build"]
    steps = cast(list[dict[str, object]], build["steps"])
    publish = next(
        step
        for step in steps
        if step["name"] == "Publish the exact version image after local release gates"
    )
    script = cast(str, publish["run"])
    push = script.index('docker push "$image"')
    assert script.rfind('test "$remote_commit" = "$SOURCE_COMMIT"', 0, push) >= 0
    assert script.rfind('test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"', 0, push) >= 0
    assert script.rfind('"refs/tags/${RELEASE_TAG}"', 0, push) >= 0


def test_dispatch_uses_main_workflow_but_binds_products_to_the_tag_commit() -> None:
    text, workflow = _workflow()
    build = _jobs(workflow)["build"]
    environment = cast(dict[str, str], workflow["env"])
    outputs = cast(dict[str, str], build["outputs"])

    assert environment["ANVA_VERSION"] == "0.1.2"
    triggers = cast(dict[str, object], workflow.get("on", workflow.get(True)))
    dispatch = cast(dict[str, object], triggers["workflow_dispatch"])
    inputs = cast(dict[str, dict[str, object]], dispatch["inputs"])
    assert inputs["tag"]["default"] == "v0.1.2"
    assert inputs["source_commit"]["required"] is True
    assert outputs["source_commit"] == "${{ steps.source.outputs.commit }}"
    assert "git ls-remote --exit-code origin" in text
    assert '"refs/tags/${RELEASE_TAG}" "refs/tags/${RELEASE_TAG}^{}"' in text
    assert '[[ "$EXPECTED_SOURCE_COMMIT" =~ ^[a-f0-9]{40}$ ]]' in text
    assert 'test "$source_commit" = "$EXPECTED_SOURCE_COMMIT"' in text
    assert 'echo "commit=$source_commit" >> "$GITHUB_OUTPUT"' in text
    assert '"source_commit": os.environ["ANVA_REVISION"]' in text
    assert "needs.build.outputs.source_commit" in text
    assert "target: product-source" not in text
    assert "--verify-tag" in text
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
    assert "ANVA_TRIVY_CACHE_DIR: /tmp" in text
    assert "src=${cache_volume},dst=${ANVA_TRIVY_CACHE_DIR}" in preparation
    assert "/var/run/docker.sock" not in preparation
    assert 'mkdir "$TRIVY_CACHE_DIR/fanal"' in preparation

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
            or "make release-build" in cast(str, step["run"])
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
    named = {cast(str, step["name"]): step for step in steps}
    checkout = named["Check out the verified source commit without credentials"]
    identity = named["Recheck immutable release identity"]

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
    assert "ANVA_RELEASE_COMMIT" not in identity_script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in identity_script
    names = [cast(str, step["name"]) for step in steps]
    assert names.index("Recheck immutable release identity") < names.index(
        "Download attested release assets"
    )
    assert names.index("Recheck immutable release identity") < names.index(
        "Create the GitHub Release after attestations"
    )


def test_release_creation_uses_existing_verified_tag_without_target_and_rechecks_it() -> None:
    _, workflow = _workflow()
    publish = _jobs(workflow)["publish"]
    steps = cast(list[dict[str, object]], publish["steps"])
    release_step = next(
        step for step in steps if step["name"] == "Create the GitHub Release after attestations"
    )
    script = cast(str, release_step["run"])

    named = {cast(str, step["name"]): step for step in steps}
    materialize = cast(
        str, named["Materialize approval validator from reviewed workflow source"]["run"]
    )
    names = [cast(str, step["name"]) for step in steps]
    assert names.index(
        "Materialize approval validator from reviewed workflow source"
    ) < names.index("Check out the verified source commit without credentials")
    assert "contents/scripts/validate_release_approvals.py" in materialize
    assert '-f "ref=${GITHUB_SHA}"' in materialize
    assert 'git hash-object "$validator"' in materialize

    assert 'gh attestation verify "$decision"' in script
    assert "actions/runs/${GITHUB_RUN_ID}/approvals" in script
    assert 'python3 "$REVIEWED_APPROVAL_VALIDATOR"' in script
    assert "python3 scripts/" not in script
    assert '--expected-sha256 "$APPROVAL_RECORD_SHA256"' in script
    assert "][0]" not in script
    for binding in (
        '"approved_by": "RishavT"',
        '"environment_approval_record_sha256"',
        '"proposal_sha256"',
        '"proposal_report_sha256"',
        '"proposal_database_metadata_sha256"',
        '"proposal_source_security_report_sha256"',
        '"proposal_source_scan_diagnostic_sha256"',
        '"verification_report_sha256"',
        '"source_commit": os.environ["SOURCE_COMMIT"]',
        '"image_digest": os.environ["IMAGE_DIGEST"]',
        '"runtime_controls_sha256": controls',
        '"high_critical_tuples": proposal["high_critical_tuples"]',
        "if expiry < today or (expiry - today).days > 30",
    ):
        assert binding in script
    assert "--target" not in script
    assert "--verify-tag" in script
    assert "resolve_remote_tag() {" in script
    assert '"refs/tags/${tag}" "refs/tags/${tag}^{}")" || return 1' in script
    assert 'test "$direct_count" -eq 1 || return 1' in script
    assert 'test "$peeled_count" -le 1 || return 1' in script
    assert '[[ "$remote_commit" =~ ^[a-f0-9]{40}$ ]] || return 1' in script
    assert 'remote_commit="$(resolve_remote_tag "$RELEASE_TAG")"' in script
    assert "ANVA_RELEASE_COMMIT" not in script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in script
    assert 'test "$remote_commit" = "$SOURCE_COMMIT"' in script
    assert 'gh release create "$RELEASE_TAG" release/*' in script
    assert script.index('test "$remote_commit" = "$SOURCE_COMMIT"') < script.index(
        'gh release create "$RELEASE_TAG" release/*'
    )
    assert script.index('gh attestation verify "$decision"') < script.index(
        'gh release create "$RELEASE_TAG" release/*'
    )
    assert "gh release upload" not in script
    assert "--clobber" not in script
    assert "Refusing to overwrite an existing immutable release" in script

    assert '"repos/${GITHUB_REPOSITORY}/releases/tags/${RELEASE_TAG}"' in script
    assert "--jq .tag_name" in script
    assert 'test "$published_release_tag" = "$RELEASE_TAG"' in script
    assert 'release_commit="$(resolve_remote_tag "$published_release_tag")"' in script
    assert 'test "$release_commit" = "$SOURCE_COMMIT"' in script
    assert script.index('gh release create "$RELEASE_TAG" release/*') < script.index(
        'test "$release_commit" = "$SOURCE_COMMIT"'
    )


def test_release_tag_resolution_failures_exit_before_release_side_effect(tmp_path: Path) -> None:
    _, workflow = _workflow()
    publish = _jobs(workflow)["publish"]
    steps = cast(list[dict[str, object]], publish["steps"])
    release_step = next(
        step for step in steps if step["name"] == "Create the GitHub Release after attestations"
    )
    script = cast(str, release_step["run"])
    script = "set -euo pipefail\n" + script[script.index("resolve_remote_tag() {") :]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    side_effect_log = tmp_path / "release-side-effects"
    source_commit = "d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac"

    git = bin_dir / "git"
    git.write_text(
        """#!/bin/sh
set -eu
if [ "$1" = ls-remote ]; then
  case "$TAG_RESPONSE" in
    nonzero_partial)
      printf '%s\\trefs/tags/v0.1.2\\n' "$SOURCE_COMMIT"
      exit 2
      ;;
    missing) exit 2 ;;
    malformed) printf '%s\\trefs/tags/v0.1.2\\n' not-a-commit ;;
    duplicate_direct)
      printf '%s\\trefs/tags/v0.1.2\\n' "$SOURCE_COMMIT"
      printf '%s\\trefs/tags/v0.1.2\\n' "$SOURCE_COMMIT"
      ;;
    duplicate_peeled)
      printf '%s\\trefs/tags/v0.1.2\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      printf '%s\\trefs/tags/v0.1.2^{}\\n' "$SOURCE_COMMIT"
      printf '%s\\trefs/tags/v0.1.2^{}\\n' "$SOURCE_COMMIT"
      ;;
    valid) printf '%s\\trefs/tags/v0.1.2\\n' "$SOURCE_COMMIT" ;;
  esac
elif [ "$1" = rev-parse ]; then
  printf '%s\\n' "$SOURCE_COMMIT"
else
  exit 64
fi
""",
        encoding="utf-8",
    )
    git.chmod(0o755)

    gh = bin_dir / "gh"
    gh.write_text(
        """#!/bin/sh
set -eu
if [ "$1" = release ] && [ "$2" = view ]; then
  exit 1
fi
if [ "$1" = release ] && { [ "$2" = create ] || [ "$2" = upload ]; }; then
  printf '%s\\n' "$2" >> "$SIDE_EFFECT_LOG"
  exit 0
fi
if [ "$1" = api ]; then
  printf '%s\\n' v0.1.2
  exit 0
fi
exit 64
""",
        encoding="utf-8",
    )
    gh.chmod(0o755)

    base_environment = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SOURCE_COMMIT": source_commit,
        "RELEASE_TAG": "v0.1.2",
        "ANVA_VERSION": "0.1.2",
        "GITHUB_REPOSITORY": "RishavT/anva",
        "SIDE_EFFECT_LOG": str(side_effect_log),
    }
    for response in (
        "nonzero_partial",
        "missing",
        "malformed",
        "duplicate_direct",
        "duplicate_peeled",
    ):
        side_effect_log.unlink(missing_ok=True)
        result = subprocess.run(  # noqa: S603 - executes the trusted workflow contract.
            ["/bin/bash", "-c", script],
            check=False,
            capture_output=True,
            env={**base_environment, "TAG_RESPONSE": response},
            text=True,
        )
        assert result.returncode != 0, (response, result.stdout, result.stderr)
        assert not side_effect_log.exists(), response

    result = subprocess.run(  # noqa: S603 - executes the trusted workflow contract.
        ["/bin/bash", "-c", script],
        check=False,
        capture_output=True,
        env={**base_environment, "TAG_RESPONSE": "valid"},
        text=True,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert side_effect_log.read_text(encoding="utf-8") == "create\n"


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
    assert "ANVA_RELEASE_COMMIT" not in identity_script
    assert 'test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"' in identity_script
    names = [cast(str, step["name"]) for step in steps]
    assert names.index("Recheck immutable release identity") < names.index(
        "Authenticate to GHCR with the job token"
    )
    assert names.index("Recheck immutable release identity") < names.index(
        "Verify published digest, attestations, and install lifecycle"
    )
