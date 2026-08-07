"""Static security contract for the acceptance Compose foundation."""

from __future__ import annotations

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
    assert adapter["user"] == "0:0"
    assert adapter["read_only"] is True
    assert adapter["cap_drop"] == ["ALL"]
    assert adapter["security_opt"] == ["no-new-privileges:true"]
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
    assert "/acceptance/raw" not in str(runner)


@pytest.mark.unit
def test_acceptance_make_targets_are_scoped_and_cleanup_ephemeral_volume() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    assert "ACCEPTANCE_PROJECT ?= anva-acceptance" in makefile
    assert "-f compose.yaml -f compose.acceptance.yaml" in makefile
    cleanup = makefile.split("\nacceptance-down:\n", 1)[1].split("\ncontract:\n", 1)[0]
    assert "$(ACCEPTANCE_COMPOSE) --profile acceptance down --volumes --remove-orphans" in cleanup
    assert "prune" not in cleanup


@pytest.mark.unit
def test_runtime_image_owns_fresh_canonical_volume_seed_path() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "mkdir -p /app/acceptance/canonical" in dockerfile
    assert "chown -R anva:anva /app" in dockerfile
