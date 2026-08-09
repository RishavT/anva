"""Static security contract for the acceptance Compose foundation."""

from __future__ import annotations

import json
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
    assert adapter["user"] == "10001:10001"
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
        "/app/run:size=4m,mode=0700,uid=10001,gid=10001",
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
    verify = makefile.split("\nacceptance-verify:\n", 1)[1].split("\nacceptance-down:\n", 1)[0]
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
    assert "chown -R anva:anva /app" in dockerfile
    assert "USER anva" in dockerfile
    assert services["acceptance-adapter"]["user"] == "10001:10001"


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
        assert service["user"] == "10001:10001"
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
    }
    assert targets["acceptance-review-request"] == {
        "/acceptance/state",
        "/acceptance/handoff",
    }
    assert targets["acceptance-review-submit"] == {
        "/acceptance/state",
        "/acceptance/handoff",
        "/acceptance/reviewer",
    }
    assert targets["acceptance-product-finalize"] == {
        "/acceptance/state",
        "/acceptance/results",
    }
    assert text.count("target: /acceptance/credentials") == 1
    assert text.count("target: /acceptance/results") == 1
    assert "grader" not in " ".join(phase_names)


@pytest.mark.unit
def test_product_acceptance_make_targets_use_scoped_compose_services() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    for target, service in (
        ("acceptance-start", "acceptance-product-start"),
        ("acceptance-review-request", "acceptance-review-request"),
        ("acceptance-review-submit", "acceptance-review-submit"),
        ("acceptance-finalize", "acceptance-product-finalize"),
    ):
        body = makefile.split(f"\n{target}:\n", 1)[1].split("\n\n", 1)[0]
        assert f"run --rm --no-deps {service}" in body
        assert "prune" not in body
        assert 'test -n "$(ANVA_REVISION)"' in body
        assert 'test -n "$(ANVA_IMAGE_SHA256)"' in body


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
    for name in ("postgres", "minio", "worker", "migrate"):
        assert set(cast(dict[str, object], services[name]["networks"])) == {"acceptance-backend"}
    for name in ("api", "mcp"):
        assert set(cast(dict[str, object], services[name]["networks"])) == {
            "acceptance-backend",
            "acceptance-edge",
        }
