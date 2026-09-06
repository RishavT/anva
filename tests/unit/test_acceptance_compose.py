"""Static security contract for the acceptance Compose foundation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml


@pytest.mark.unit
def test_only_adapter_mounts_raw_acceptance_input() -> None:
    compose_text = Path("compose.acceptance.yaml").read_text(encoding="utf-8")
    document = cast(dict[str, object], yaml.safe_load(compose_text))
    services = cast(dict[str, dict[str, object]], document["services"])
    adapter = services["acceptance-adapter"]

    assert compose_text.count("target: /acceptance/raw") == 1
    assert adapter["network_mode"] == "none"
    # The runtime image seeds the named volume as the unprivileged ``anva``
    # user. Root with every capability dropped cannot write or chmod that
    # root-owned-by-anva mount and would turn the first write failure into an
    # unprovable-cleanup failure. Keep the adapter on the owning uid instead.
    assert adapter["user"] == "${ANVA_ACCEPTANCE_UID:-10001}:${ANVA_ACCEPTANCE_GID:-10001}"
    assert adapter["user"] != "0:0"
    assert adapter["read_only"] is True
    assert adapter["cap_drop"] == ["ALL"]
    assert adapter["security_opt"] == ["no-new-privileges:true"]
    assert adapter["mem_limit"] == "256m"
    assert adapter["memswap_limit"] == "256m"
    assert adapter["pids_limit"] == 64
    assert "acceptance" in cast(list[str], adapter["profiles"])
    command = cast(list[str], adapter["command"])
    assert command[:3] == ["anva", "acceptance", "canonicalize"]
    assert not {"sh", "bash", "/bin/sh", "/bin/bash"} & set(command)
    tmp_mount = f"{Path('/').joinpath('tmp')}:size=16m,mode=1777"
    assert adapter["tmpfs"] == [
        tmp_mount,
        "/app/run:size=4m,mode=0700,uid=${ANVA_ACCEPTANCE_UID:-10001},gid=${ANVA_ACCEPTANCE_GID:-10001}",
    ]
    mounts = cast(list[dict[str, object]], adapter["volumes"])
    assert len(mounts) == 2
    raw_mount = next(mount for mount in mounts if mount["target"] == "/acceptance/raw")
    assert raw_mount == {
        "type": "bind",
        "source": "${ANVA_ACCEPTANCE_INPUT_DIR:-/nonexistent-anva-public-input}",
        "target": "/acceptance/raw",
        "read_only": True,
        "bind": {"create_host_path": False},
    }
    canonical_mount = next(
        mount for mount in mounts if mount["target"] == "/app/acceptance/canonical"
    )
    assert canonical_mount == {
        "type": "volume",
        "source": "acceptance-canonical",
        "target": "/app/acceptance/canonical",
    }


@pytest.mark.unit
def test_product_and_runner_receive_only_read_only_canonical_volume() -> None:
    document = cast(
        dict[str, object],
        yaml.safe_load(Path("compose.acceptance.yaml").read_text(encoding="utf-8")),
    )
    services = cast(dict[str, dict[str, object]], document["services"])

    api = services["api"]
    assert api["user"] == "${ANVA_ACCEPTANCE_UID:-10001}:${ANVA_ACCEPTANCE_GID:-10001}"
    assert api["tmpfs"] == [
        "/tmp:size=64m,mode=1777",  # noqa: S108
        "/app/run:size=16m,mode=0700,"
        "uid=${ANVA_ACCEPTANCE_UID:-10001},gid=${ANVA_ACCEPTANCE_GID:-10001}",
    ]

    for service_name in ("api", "worker", "mcp", "cli"):
        service = services[service_name]
        assert service["volumes"] == ["acceptance-canonical:/app/acceptance/canonical:ro"]
        environment = cast(dict[str, str], service["environment"])
        assert environment["ANVA_FILESYSTEM_ALLOWED_ROOTS"] == ("/app/acceptance/canonical/payload")
        assert "/acceptance/raw" not in str(service)

    runner = services["acceptance-runner"]
    assert runner["volumes"] == ["acceptance-canonical:/app/acceptance/canonical:ro"]
    assert runner["read_only"] is True
    assert runner["cap_drop"] == ["ALL"]
    assert runner["user"] == "10001:10001"
    assert runner["network_mode"] == "none"
    assert "/acceptance/raw" not in str(runner)
    command = cast(list[str], runner["command"])
    assert command == [
        "anva",
        "acceptance",
        "verify",
        "--canonical-root",
        "/app/acceptance/canonical",
        "--manifest-sha256",
        "${ANVA_ACCEPTANCE_MANIFEST_SHA256:-invalid-unpinned-manifest}",
        "--source-fingerprint",
        "${ANVA_ACCEPTANCE_SOURCE_FINGERPRINT:-invalid-unpinned-fingerprint}",
        "--canonical-manifest-sha256",
        "${ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256:-invalid-unpinned-canonical-manifest}",
    ]


@pytest.mark.unit
def test_acceptance_make_targets_are_scoped_and_cleanup_ephemeral_volume() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    assert "ACCEPTANCE_PROJECT ?= anva-acceptance" in makefile
    assert "-f compose.yaml -f compose.acceptance.yaml" in makefile
    cleanup = makefile.split("\nacceptance-down:\n", 1)[1].split("\ncontract:\n", 1)[0]
    assert "$(ACCEPTANCE_COMPOSE) --profile acceptance down --volumes --remove-orphans" in cleanup
    assert "prune" not in cleanup
    verify = makefile.split("\nacceptance-verify:", 1)[1].split("\nacceptance-down:", 1)[0]
    for pin in (
        "ANVA_ACCEPTANCE_MANIFEST_SHA256",
        "ANVA_ACCEPTANCE_SOURCE_FINGERPRINT",
        "ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256",
    ):
        assert f'@test -n "$({pin})"' in verify
    assert "acceptance-runner" in verify


@pytest.mark.unit
def test_runtime_image_owns_fresh_canonical_volume_seed_path() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    compose = cast(
        dict[str, object],
        yaml.safe_load(Path("compose.acceptance.yaml").read_text(encoding="utf-8")),
    )
    services = cast(dict[str, dict[str, object]], compose["services"])

    assert "groupadd --gid 10001 anva" in dockerfile
    assert "useradd --uid 10001 --gid anva" in dockerfile
    assert "mkdir -p /app/acceptance/canonical" in dockerfile
    assert "chmod 01777 /app/acceptance/canonical" in dockerfile
    assert "chown -R anva:anva /app" in dockerfile
    assert dockerfile.count("USER 10001:10001") == 3
    assert services["acceptance-adapter"]["user"] == (
        "${ANVA_ACCEPTANCE_UID:-10001}:${ANVA_ACCEPTANCE_GID:-10001}"
    )


@pytest.mark.unit
def test_product_acceptance_phases_have_disjoint_hardened_mounts() -> None:
    text = Path("compose.acceptance.yaml").read_text(encoding="utf-8")
    document = cast(dict[str, object], yaml.safe_load(text))
    services = cast(dict[str, dict[str, object]], document["services"])
    phase_names = (
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    )
    targets: dict[str, set[str]] = {}
    for name in phase_names:
        service = services[name]
        assert service["read_only"] is True
        assert service["privileged"] is False
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["mem_limit"] == "512m"
        assert service["memswap_limit"] == "512m"
        assert service["pids_limit"] == 96
        assert service["user"] == ("${ANVA_ACCEPTANCE_UID:-10001}:${ANVA_ACCEPTANCE_GID:-10001}")
        assert service["tmpfs"] == [
            "/tmp:size=32m,mode=1777,noexec,nosuid,nodev",  # noqa: S108
            "/app/run:size=8m,mode=0700,"
            "uid=${ANVA_ACCEPTANCE_UID:-10001},"
            "gid=${ANVA_ACCEPTANCE_GID:-10001},noexec,nosuid,nodev",
        ]
        assert service["networks"] == ["acceptance-edge"]
        rendered = str(service).casefold()
        assert "/acceptance/raw" not in rendered
        assert "docker.sock" not in rendered
        assert "private-oracle" not in rendered
        assert "private-grader" not in rendered
        volumes = cast(list[object], service["volumes"])
        targets[name] = {
            cast(str, volume["target"]) for volume in volumes if isinstance(volume, dict)
        }
        assert "acceptance-canonical:/app/acceptance/canonical:ro" in volumes
        command = cast(list[str], service["command"])
        assert command[:2] == ["anva", "acceptance"]
        assert not {"sh", "bash", "/bin/sh", "/bin/bash"} & set(command)

    assert targets["acceptance-product-start"] == {
        "/acceptance/state",
        "/acceptance/credentials",
        "/acceptance/launch/manifest.json",
    }
    assert targets["acceptance-review-request"] == {
        "/acceptance/state",
        "/acceptance/handoff",
        "/acceptance/launch/manifest.json",
    }
    assert targets["acceptance-review-submit"] == {
        "/acceptance/state",
        "/acceptance/handoff",
        "/acceptance/reviewer",
        "/acceptance/launch/manifest.json",
    }
    assert targets["acceptance-product-finalize"] == {
        "/acceptance/state",
        "/acceptance/results",
        "/acceptance/launch/manifest.json",
    }
    assert text.count("target: /acceptance/credentials") == 1
    assert text.count("target: /acceptance/results") == 1
    assert "grader" not in " ".join(phase_names)


@pytest.mark.unit
def test_optional_acceptance_case_overlay_is_read_only_and_consistent() -> None:
    base = cast(
        dict[str, object],
        yaml.safe_load(Path("compose.acceptance.yaml").read_text(encoding="utf-8")),
    )
    base_services = cast(dict[str, dict[str, object]], base["services"])
    overlay = cast(
        dict[str, object],
        yaml.safe_load(Path("compose.acceptance.case.yaml").read_text(encoding="utf-8")),
    )
    services = cast(dict[str, dict[str, object]], overlay["services"])
    phase_names = (
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    )
    expected_mount = {
        "type": "bind",
        "source": "${ANVA_ACCEPTANCE_CASE_FILE:?ANVA_ACCEPTANCE_CASE_FILE is required}",
        "target": "/acceptance/case/case.json",
        "read_only": True,
        "bind": {"create_host_path": False},
    }

    for name in phase_names:
        service = services[name]
        command = cast(list[str], service["command"])
        assert command.count("--case") == 1
        case_index = command.index("--case")
        assert command[case_index + 1] == "/acceptance/case/case.json"
        assert command[:case_index] + command[case_index + 2 :] == base_services[name]["command"]
        assert "--case" not in cast(list[str], base_services[name]["command"])
        assert service["volumes"] == [expected_mount]


@pytest.mark.unit
def test_acceptance_case_overlay_is_conditional_and_resolves_for_all_phases() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    assert (
        "ACCEPTANCE_CASE_COMPOSE = $(if $(strip $(ANVA_ACCEPTANCE_CASE_FILE)),"
        "-f compose.acceptance.case.yaml,)" in makefile
    )
    assert "$(ACCEPTANCE_CASE_COMPOSE)" in makefile

    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable for resolved Compose validation")
    environment = os.environ.copy()
    environment["ANVA_ACCEPTANCE_CASE_FILE"] = str(Path("pyproject.toml").resolve())
    completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [
            docker,
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.acceptance.yaml",
            "-f",
            "compose.acceptance.case.yaml",
            "--profile",
            "acceptance",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    services = cast(dict[str, dict[str, object]], json.loads(completed.stdout)["services"])
    for name in (
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    ):
        service = services[name]
        command = cast(list[str], service["command"])
        assert command[command.index("--case") + 1] == "/acceptance/case/case.json"
        case_mount = next(
            mount
            for mount in cast(list[dict[str, object]], service["volumes"])
            if mount["target"] == "/acceptance/case/case.json"
        )
        assert case_mount["source"] == str(Path("pyproject.toml").resolve())
        assert case_mount["read_only"] is True
        assert cast(dict[str, object], case_mount["bind"])["create_host_path"] is False


@pytest.mark.unit
def test_product_acceptance_make_targets_use_scoped_compose_services() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    for target, service in (
        ("acceptance-start", "acceptance-product-start"),
        ("acceptance-review-request", "acceptance-review-request"),
        ("acceptance-review-submit", "acceptance-review-submit"),
        ("acceptance-finalize", "acceptance-product-finalize"),
    ):
        assert f"{target}: acceptance-launch-manifest" in makefile
        body = makefile.split(f"\n{target}:", 1)[1].split("\n\n", 1)[0]
        assert f"run --rm --no-deps {service}" in body
        assert "prune" not in body
        assert 'test -n "$(ANVA_REVISION)"' in body
        assert 'test -n "$(ANVA_IMAGE_SHA256)"' in body
        assert 'test -n "$(ANVA_BUILD_INPUT_SHA256)"' in body
        assert 'test -n "$(ANVA_ACCEPTANCE_LAUNCH_MANIFEST)"' in body


@pytest.mark.unit
def test_acceptance_case_preflight_is_hardened_and_precedes_launch() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    body = makefile.split("\nacceptance-case-validate: acceptance-identity-preflight", 1)[1].split(
        "\n\nacceptance-canonicalize:", 1
    )[0]

    assert (
        "acceptance-launch-manifest: acceptance-identity-preflight acceptance-case-validate"
        in makefile
    )
    assert "ANVA_ACCEPTANCE_CASE_FILE must be an absolute path" in body
    assert "regular non-symlink file" in body
    for option in (
        "--rm",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pids-limit 64",
        "--memory 256m",
        "readonly",
    ):
        assert option in body
    assert "anva acceptance case-validate --case /acceptance-case.json" in body


@pytest.mark.unit
def test_acceptance_start_stops_before_compose_when_case_preflight_fails(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "docker-calls"
    docker = fake_bin / "docker"
    docker.write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$ANVA_TEST_DOCKER_CALLS"\nexit 2\n',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    malformed_case = tmp_path / "malformed-case.json"
    malformed_case.write_text("{}\n", encoding="utf-8")
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "ANVA_TEST_DOCKER_CALLS": str(calls),
    }

    make = shutil.which("make")
    assert make is not None
    result = subprocess.run(  # noqa: S603 - fixed local test command and arguments
        [
            make,
            "acceptance-start",
            f"ANVA_ACCEPTANCE_CASE_FILE={malformed_case}",
            "ANVA_REVISION=" + "a" * 40,
            "ANVA_IMAGE_SHA256=sha256:" + "b" * 64,
            "ANVA_BUILD_INPUT_SHA256=" + "c" * 64,
            f"ANVA_ACCEPTANCE_LAUNCH_MANIFEST={tmp_path / 'launch.json'}",
            f"ANVA_ACCEPTANCE_STATE_DIR={tmp_path}",
        ],
        cwd=Path.cwd(),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    recorded = calls.read_text(encoding="utf-8").splitlines()
    assert len(recorded) == 1
    assert recorded[0].startswith("run ")
    assert "acceptance case-validate" in recorded[0]
    assert all("compose" not in call for call in recorded)


@pytest.mark.unit
def test_public_launch_manifest_make_path_is_hardened_and_start_uses_it() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    body = makefile.split("\nacceptance-launch-manifest: acceptance-identity-preflight", 1)[
        1
    ].split("\n\nacceptance-start:", 1)[0]

    assert "acceptance-start: acceptance-launch-manifest" in makefile
    assert "ANVA_ACCEPTANCE_LAUNCH_MANIFEST is the required protected host output path" in body
    assert "Reusing existing immutable launch manifest after exact" in body
    assert "does not match the current resolved launch configuration" in body
    assert "acceptance launch-manifest" in body
    assert "--network none" in body
    assert "--read-only" in body
    assert "--cap-drop ALL" in body
    assert "--security-opt no-new-privileges" in body
    assert '--user "$$(id -u):$$(id -g)"' in body
    assert 'test "$$(id -u)" -ne 0' in body
    assert "readonly" in body
    assert "chmod 0444" in body
    assert "config --format json" in body
    assert "docker image inspect" in body
    assert "cmp --silent" in body
    assert 'mktemp "$$(dirname "$$manifest")/.$$(basename "$$manifest").tmp.XXXXXX"' in body
    assert 'ln "$$output_tmp" "$$manifest"' in body
    assert "trap cleanup EXIT" in body
    assert "trap 'trap - HUP INT TERM; exit 129' HUP" in body
    assert "trap 'trap - HUP INT TERM; exit 130' INT" in body
    assert "trap 'trap - HUP INT TERM; exit 143' TERM" in body
    assert 'if test -d "$$input_dir"' in body
    assert "trap cleanup EXIT HUP INT TERM" not in body
    assert body.index("config --format json") < body.index("cmp --silent")
    assert body.index("cmp --silent") < body.index("Reusing existing immutable launch manifest")
    assert "prune" not in body


@pytest.mark.unit
def test_launch_manifest_make_reuses_only_exact_current_candidate(tmp_path: Path) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable for launch manifest lifecycle validation")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        """#!/bin/sh
if test "$1" = "compose"; then
    printf '%s\n' '{"services":{}}'
elif test "$1" = "image"; then
    printf '%s\n' '[{}]'
elif test "$1" = "run"; then
    printf '%s\n' "$FAKE_MANIFEST_PAYLOAD"
else
    exit 64
fi
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    manifest = tmp_path / "launch-manifest.json"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    command = [
        make,
        "acceptance-launch-manifest",
        f"ANVA_REVISION={'a' * 40}",
        f"ANVA_IMAGE_SHA256={'b' * 64}",
        f"ANVA_BUILD_INPUT_SHA256={'c' * 64}",
        "ANVA_IMAGE_REPOSITORY=fake-anva",
        "ANVA_VERSION=test",
        f"ANVA_ACCEPTANCE_LAUNCH_MANIFEST={manifest}",
        f"ANVA_ACCEPTANCE_STATE_DIR={state_dir}",
    ]

    environment["FAKE_MANIFEST_PAYLOAD"] = '{"identity":"current"}'
    created = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        command, check=False, capture_output=True, text=True, env=environment
    )
    assert created.returncode == 0, created.stderr
    original = manifest.read_bytes()
    assert original == b'{"identity":"current"}\n'
    assert manifest.stat().st_mode & 0o777 == 0o444

    tmp_path.chmod(0o555)
    try:
        reused = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            command, check=False, capture_output=True, text=True, env=environment
        )
        assert reused.returncode == 0, reused.stderr
        assert "after exact current-configuration comparison" in reused.stdout
        assert manifest.read_bytes() == original

        environment["FAKE_MANIFEST_PAYLOAD"] = '{"identity":"drifted"}'
        rejected = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            command, check=False, capture_output=True, text=True, env=environment
        )
        assert rejected.returncode == 2
        assert "does not match the current resolved launch configuration" in rejected.stderr
        assert manifest.read_bytes() == original
    finally:
        tmp_path.chmod(0o700)


@pytest.mark.unit
@pytest.mark.parametrize("signal_name", ["HUP", "INT", "TERM"])
def test_launch_manifest_make_signal_fails_closed_and_cleans_once(
    tmp_path: Path, signal_name: str
) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable for launch manifest signal validation")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        """#!/bin/sh
if test "$1" = "compose"; then
    kill "-$FAKE_SIGNAL" "$PPID"
    printf '%s\n' '{"services":{}}'
    exit 0
fi
exit 64
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    manifest = tmp_path / "launch-manifest.json"
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["FAKE_SIGNAL"] = signal_name
    command = [
        make,
        "acceptance-launch-manifest",
        f"ANVA_REVISION={'a' * 40}",
        f"ANVA_IMAGE_SHA256={'b' * 64}",
        f"ANVA_BUILD_INPUT_SHA256={'c' * 64}",
        "ANVA_IMAGE_REPOSITORY=fake-anva",
        "ANVA_VERSION=test",
        f"ANVA_ACCEPTANCE_LAUNCH_MANIFEST={manifest}",
        f"ANVA_ACCEPTANCE_STATE_DIR={state_dir}",
    ]

    interrupted = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        command, check=False, capture_output=True, text=True, env=environment
    )

    assert interrupted.returncode != 0
    assert not manifest.exists()
    assert list(state_dir.iterdir()) == []
    assert "No such file or directory" not in interrupted.stderr


@pytest.mark.unit
def test_cli_launch_manifest_option_is_explicitly_optional_with_supported_default(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from anva.entrypoints.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit) as captured:
        parser.parse_args(["acceptance", "start", "--help"])
    assert captured.value.code == 0
    help_text = capsys.readouterr().out
    assert "Optional in-container manifest path" in help_text
    assert "/acceptance/launch/manifest.json" in help_text
    assert "ANVA_ACCEPTANCE_LAUNCH_MANIFEST" in help_text

    arguments = parser.parse_args(
        [
            "acceptance",
            "start",
            "--canonical-root",
            "/canonical",
            "--state",
            "/state/resume.json",
            "--output",
            "/output",
            "--manifest-sha256",
            "a" * 64,
            "--source-fingerprint",
            "b" * 64,
            "--canonical-manifest-sha256",
            "c" * 64,
            "--product-commit",
            "d" * 40,
            "--product-image-sha256",
            "e" * 64,
            "--product-image-reference",
            "anva:test",
            "--build-input-sha256",
            "f" * 64,
            "--launch-service",
            "acceptance-product-start",
            "--credential-output",
            "/credentials/credentials.json",
        ]
    )
    assert arguments.launch_manifest == Path("/acceptance/launch/manifest.json")


@pytest.mark.unit
def test_acceptance_identity_preflight_rejects_unpaired_or_unsafe_ids() -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable for acceptance preflight validation")

    base_environment = os.environ.copy()
    base_environment.pop("ANVA_ACCEPTANCE_UID", None)
    base_environment.pop("ANVA_ACCEPTANCE_GID", None)

    for overrides in (
        {"ANVA_ACCEPTANCE_UID": "1000"},
        {"ANVA_ACCEPTANCE_GID": "1000"},
        {"ANVA_ACCEPTANCE_UID": "0", "ANVA_ACCEPTANCE_GID": "1000"},
        {"ANVA_ACCEPTANCE_UID": "00", "ANVA_ACCEPTANCE_GID": "1000"},
        {"ANVA_ACCEPTANCE_UID": "1000:1000", "ANVA_ACCEPTANCE_GID": "1000"},
        {"ANVA_ACCEPTANCE_UID": "1000", "ANVA_ACCEPTANCE_GID": "not-a-gid"},
        {"ANVA_ACCEPTANCE_UID": "2147483648", "ANVA_ACCEPTANCE_GID": "1000"},
        {"ANVA_ACCEPTANCE_UID": "1000", "ANVA_ACCEPTANCE_GID": "2147483648"},
        {"ANVA_ACCEPTANCE_UID": "999999999999999999999", "ANVA_ACCEPTANCE_GID": "1000"},
    ):
        environment = base_environment | overrides
        completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [make, "acceptance-identity-preflight"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        assert completed.returncode == 2

    for overrides in ({}, {"ANVA_ACCEPTANCE_UID": "1000", "ANVA_ACCEPTANCE_GID": "1000"}):
        completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [make, "acceptance-identity-preflight"],
            check=False,
            capture_output=True,
            text=True,
            env=base_environment | overrides,
        )
        assert completed.returncode == 0, completed.stderr


@pytest.mark.unit
def test_resolved_acceptance_compose_enforces_edge_backend_separation() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable for resolved Compose validation")
    completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [
            docker,
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.acceptance.yaml",
            "--profile",
            "acceptance",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    services = cast(dict[str, dict[str, object]], json.loads(completed.stdout)["services"])
    phases = (
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    )
    for name in phases:
        assert services[name]["user"] == "10001:10001"
        assert set(cast(dict[str, object], services[name]["networks"])) == {"acceptance-edge"}
    for name in ("worker", "mcp", "migrate"):
        assert services[name]["user"] == "10001:10001"
    for name in ("postgres", "minio", "worker", "migrate"):
        assert set(cast(dict[str, object], services[name]["networks"])) == {"acceptance-backend"}
    for name in ("api", "mcp"):
        assert set(cast(dict[str, object], services[name]["networks"])) == {
            "acceptance-backend",
            "acceptance-edge",
        }


@pytest.mark.unit
@pytest.mark.parametrize(
    ("identity_environment", "expected_id"),
    [({}, "10001"), ({"ANVA_ACCEPTANCE_UID": "1000", "ANVA_ACCEPTANCE_GID": "1000"}, "1000")],
)
def test_resolved_acceptance_identity_is_consistent_across_protected_services(
    identity_environment: dict[str, str], expected_id: str
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is unavailable for resolved Compose validation")
    environment = os.environ.copy()
    environment.pop("ANVA_ACCEPTANCE_UID", None)
    environment.pop("ANVA_ACCEPTANCE_GID", None)
    environment.update(identity_environment)
    completed = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
        [
            docker,
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.acceptance.yaml",
            "--profile",
            "acceptance",
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    services = cast(dict[str, dict[str, object]], json.loads(completed.stdout)["services"])
    protected_services = (
        "acceptance-adapter",
        "api",
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    )
    for name in protected_services:
        service = services[name]
        assert service["user"] == f"{expected_id}:{expected_id}"
        run_tmpfs = next(
            entry for entry in cast(list[str], service["tmpfs"]) if entry.startswith("/app/run:")
        )
        assert f"uid={expected_id}" in run_tmpfs
        assert f"gid={expected_id}" in run_tmpfs
