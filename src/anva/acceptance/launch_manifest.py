"""Deterministic public launch-manifest generation from Docker runtime inputs."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from anva.acceptance.provenance import (
    COMMIT_PATTERN,
    IMAGE_REFERENCE_PATTERN,
    REQUIRED_LAUNCH_SERVICES,
    SHA256_PATTERN,
    AcceptanceProvenanceError,
    attest_build_provenance,
)

LAUNCH_PHASES = frozenset(
    {
        "acceptance-product-start",
        "acceptance-review-request",
        "acceptance-review-submit",
        "acceptance-product-finalize",
    }
)
LAUNCH_MANIFEST_TARGET = "/acceptance/launch/manifest.json"
CANONICAL_ROOT_TARGET = "/app/acceptance/canonical"
CASE_TARGET = "/acceptance/case/case.json"
CORE_RUNTIME_KEYS = frozenset(
    {
        "build",
        "cap_drop",
        "command",
        "depends_on",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "logging",
        "networks",
        "read_only",
        "security_opt",
        "tmpfs",
        "volumes",
    }
)
CORE_SERVICE_RUNTIME_KEYS = {
    "api": CORE_RUNTIME_KEYS | {"secrets", "user"},
    "worker": CORE_RUNTIME_KEYS,
    "mcp": CORE_RUNTIME_KEYS,
}
PHASE_RUNTIME_KEYS = frozenset(
    {
        "build",
        "cap_drop",
        "command",
        "entrypoint",
        "environment",
        "image",
        "logging",
        "mem_limit",
        "memswap_limit",
        "networks",
        "pids_limit",
        "profiles",
        "read_only",
        "restart",
        "security_opt",
        "tmpfs",
        "user",
        "volumes",
    }
)
PHASE_MOUNT_RULES: dict[str, dict[str, tuple[str, bool]]] = {
    "acceptance-product-start": {
        CANONICAL_ROOT_TARGET: ("volume", True),
        "/acceptance/state": ("bind", False),
        "/acceptance/credentials": ("bind", False),
        LAUNCH_MANIFEST_TARGET: ("bind", True),
    },
    "acceptance-review-request": {
        CANONICAL_ROOT_TARGET: ("volume", True),
        "/acceptance/state": ("bind", False),
        "/acceptance/handoff": ("bind", False),
        LAUNCH_MANIFEST_TARGET: ("bind", True),
    },
    "acceptance-review-submit": {
        CANONICAL_ROOT_TARGET: ("volume", True),
        "/acceptance/state": ("bind", False),
        "/acceptance/handoff": ("bind", False),
        "/acceptance/reviewer": ("bind", True),
        LAUNCH_MANIFEST_TARGET: ("bind", True),
    },
    "acceptance-product-finalize": {
        CANONICAL_ROOT_TARGET: ("volume", True),
        "/acceptance/state": ("bind", False),
        "/acceptance/results": ("bind", False),
        LAUNCH_MANIFEST_TARGET: ("bind", True),
    },
}
SAFE_RUNTIME_KEYS = (
    "cap_drop",
    "command",
    "entrypoint",
    "healthcheck",
    "image",
    "logging",
    "mem_limit",
    "memswap_limit",
    "network_mode",
    "networks",
    "pids_limit",
    "ports",
    "profiles",
    "read_only",
    "restart",
    "security_opt",
    "tmpfs",
    "user",
)


def _reject(reason_code: str, message: str) -> AcceptanceProvenanceError:
    return AcceptanceProvenanceError(message, reason_code=reason_code)


def _read_json(path: Path, *, maximum: int, label: str) -> object:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise _reject("launch_input_unavailable", f"{label} input is unavailable or unsafe")
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _reject("launch_input_invalid", f"{label} input is invalid") from error


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _volume_identity(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _reject("launch_runtime_invalid", "Resolved Compose volume is invalid")
    volume = cast(dict[str, object], value)
    volume_type = volume.get("type")
    target = volume.get("target")
    if volume_type not in {"bind", "volume", "tmpfs"} or not isinstance(target, str):
        raise _reject("launch_runtime_invalid", "Resolved Compose volume is invalid")
    identity: dict[str, object] = {
        "type": volume_type,
        "target": target,
        "read_only": volume.get("read_only", False) is True,
    }
    if volume_type == "bind":
        bind = volume.get("bind")
        identity["source"] = "launch-manifest" if target == LAUNCH_MANIFEST_TARGET else "host-bind"
        identity["create_host_path"] = (
            isinstance(bind, dict) and bind.get("create_host_path") is True
        )
    elif volume_type == "volume":
        identity["source"] = str(volume.get("source", ""))
    return identity


def _runtime_identity(service: Mapping[str, object]) -> dict[str, object]:
    """Return the security-relevant model without secret values or host paths."""
    identity = {key: service[key] for key in SAFE_RUNTIME_KEYS if key in service}
    environment = service.get("environment")
    if environment is not None:
        if not isinstance(environment, dict):
            raise _reject("launch_runtime_invalid", "Resolved Compose environment is invalid")
        identity["environment_keys"] = sorted(str(key) for key in environment)
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise _reject("launch_runtime_invalid", "Resolved Compose volumes are invalid")
    identity["volumes"] = [_volume_identity(value) for value in volumes]
    return identity


def _service_dict(services: Mapping[str, object], name: str) -> dict[str, object]:
    value = services.get(name)
    if not isinstance(value, dict):
        raise _reject("launch_service_set_mismatch", f"Required launch service {name} is absent")
    return cast(dict[str, object], value)


def _validate_closed_runtime(name: str, service: Mapping[str, object]) -> None:
    allowed = PHASE_RUNTIME_KEYS if name in LAUNCH_PHASES else CORE_SERVICE_RUNTIME_KEYS[name]
    unknown = set(service) - allowed
    if unknown:
        raise _reject("launch_runtime_mismatch", f"Launch service {name} runtime fields differ")
    if (
        service.get("read_only") is not True
        or service.get("cap_drop") != ["ALL"]
        or service.get("security_opt") != ["no-new-privileges:true"]
    ):
        raise _reject("launch_runtime_mismatch", f"Launch service {name} security posture differs")
    tmpfs = service.get("tmpfs")
    if (
        not isinstance(tmpfs, list)
        or len(tmpfs) != 2
        or {str(item).split(":", 1)[0] for item in tmpfs} != {"/tmp", "/app/run"}  # noqa: S108
    ):
        raise _reject("launch_runtime_mismatch", f"Launch service {name} tmpfs inventory differs")


def _validate_mounts(
    name: str,
    service: Mapping[str, object],
    *,
    launch_manifest_source: Path,
) -> None:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        raise _reject("launch_bind_mismatch", f"Launch service {name} mounts are invalid")
    expected = dict(PHASE_MOUNT_RULES.get(name, {CANONICAL_ROOT_TARGET: ("volume", True)}))
    command = service.get("command")
    has_case_argument = (
        isinstance(command, list)
        and "--case" in command
        and command.index("--case") + 1 < len(command)
        and command[command.index("--case") + 1] == CASE_TARGET
    )
    if has_case_argument:
        expected[CASE_TARGET] = ("bind", True)
    observed: set[str] = set()
    for value in volumes:
        if not isinstance(value, dict):
            raise _reject("launch_bind_mismatch", f"Launch service {name} mount is invalid")
        volume = cast(dict[str, object], value)
        target = volume.get("target")
        if not isinstance(target, str) or target in observed or target not in expected:
            raise _reject("launch_bind_mismatch", f"Launch service {name} mount inventory differs")
        observed.add(target)
        expected_type, expected_read_only = expected[target]
        if (
            volume.get("type") != expected_type
            or (volume.get("read_only", False) is True) is not expected_read_only
        ):
            raise _reject("launch_bind_mismatch", f"Launch service {name} mount mode differs")
        source = volume.get("source")
        if expected_type == "volume":
            if (
                set(volume) != {"type", "source", "target", "read_only", "volume"}
                or source != "acceptance-canonical"
                or volume.get("volume") != {}
            ):
                raise _reject("launch_bind_mismatch", f"Launch service {name} volume differs")
            continue
        if set(volume) - {"type", "source", "target", "read_only", "bind"}:
            raise _reject("launch_bind_mismatch", f"Launch service {name} bind fields differ")
        bind = volume.get("bind")
        if (
            not isinstance(source, str)
            or not Path(source).is_absolute()
            or "docker.sock" in source
            or not isinstance(bind, dict)
            or bind != {"create_host_path": False}
        ):
            raise _reject("launch_bind_mismatch", f"Launch service {name} bind differs")
        if target == LAUNCH_MANIFEST_TARGET:
            try:
                source_path = Path(source).resolve(strict=False)
                expected_path = launch_manifest_source.resolve(strict=False)
            except OSError as error:
                raise _reject(
                    "launch_bind_mismatch", f"Launch service {name} manifest bind is invalid"
                ) from error
            if source_path != expected_path:
                raise _reject(
                    "launch_bind_mismatch", f"Launch service {name} manifest bind differs"
                )
    if observed != set(expected):
        raise _reject("launch_bind_mismatch", f"Launch service {name} mount inventory differs")


def _validate_networks(compose: Mapping[str, object], services: Mapping[str, object]) -> None:
    networks = compose.get("networks")
    if not isinstance(networks, dict):
        raise _reject("launch_runtime_mismatch", "Acceptance networks are absent")
    for name in ("acceptance-backend", "acceptance-edge"):
        network = networks.get(name)
        if not isinstance(network, dict) or network.get("internal") is not True:
            raise _reject("launch_runtime_mismatch", f"Acceptance network {name} is not internal")
    expected = {
        "api": {"acceptance-backend", "acceptance-edge"},
        "worker": {"acceptance-backend"},
        "mcp": {"acceptance-backend", "acceptance-edge"},
    }
    for name, expected_networks in expected.items():
        service_networks = _service_dict(services, name).get("networks")
        if not isinstance(service_networks, dict) or set(service_networks) != expected_networks:
            raise _reject("launch_runtime_mismatch", f"Launch service {name} networks differ")


def _validate_phase(
    name: str,
    service: Mapping[str, object],
    *,
    launch_manifest_source: Path,
) -> None:
    user = service.get("user")
    if not isinstance(user, str) or re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user) is None:
        raise _reject("launch_runtime_mismatch", f"Launch service {name} is not non-root")
    expected_scalars: dict[str, object] = {
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": "536870912",
        "memswap_limit": "536870912",
        "pids_limit": 96,
        "restart": "no",
    }
    for key, expected in expected_scalars.items():
        if service.get(key) != expected:
            raise _reject("launch_runtime_mismatch", f"Launch service {name} {key} differs")
    if service.get("privileged", False) is not False or service.get("ports"):
        raise _reject("launch_runtime_mismatch", f"Launch service {name} is externally exposed")
    if service.get("networks") != {"acceptance-edge": None}:
        raise _reject("launch_runtime_mismatch", f"Launch service {name} network differs")
    tmpfs = service.get("tmpfs")
    if not isinstance(tmpfs, list) or not all(
        isinstance(item, str) and all(flag in item for flag in ("noexec", "nosuid", "nodev"))
        for item in tmpfs
    ):
        raise _reject("launch_runtime_mismatch", f"Launch service {name} tmpfs differs")
    command = service.get("command")
    if not isinstance(command, list):
        raise _reject("launch_service_mismatch", f"Launch service {name} command is invalid")
    for flag, expected in (
        ("--launch-manifest", LAUNCH_MANIFEST_TARGET),
        ("--launch-service", name),
    ):
        try:
            index = command.index(flag)
        except ValueError as error:
            raise _reject(
                "launch_service_mismatch", f"Launch service {name} omits {flag}"
            ) from error
        if index + 1 >= len(command) or command[index + 1] != expected:
            raise _reject("launch_service_mismatch", f"Launch service {name} {flag} differs")
    _validate_mounts(name, service, launch_manifest_source=launch_manifest_source)


def generate_launch_manifest(
    resolved_compose_path: Path,
    image_inspect_path: Path,
    *,
    build_provenance_path: Path,
    product_commit: str,
    build_input_sha256: str,
    product_image_sha256: str,
    image_reference: str,
    launch_manifest_source: Path,
) -> dict[str, object]:
    """Validate exact runtime inputs and build the numeric-v1 public manifest."""
    if COMMIT_PATTERN.fullmatch(product_commit) is None:
        raise _reject("launch_product_commit_invalid", "Product commit is not exact lowercase hex")
    if (
        SHA256_PATTERN.fullmatch(build_input_sha256) is None
        or SHA256_PATTERN.fullmatch(product_image_sha256) is None
        or IMAGE_REFERENCE_PATTERN.fullmatch(image_reference) is None
    ):
        raise _reject("launch_identity_invalid", "Launch identity pins are invalid")
    provenance = attest_build_provenance(
        build_provenance_path,
        expected_commit=product_commit,
        expected_build_input_sha256=build_input_sha256,
    )
    inspect_value = _read_json(image_inspect_path, maximum=1_000_000, label="Docker image inspect")
    if not isinstance(inspect_value, list) or len(inspect_value) != 1:
        raise _reject("launch_image_mismatch", "Docker image inspect must contain one image")
    image = inspect_value[0]
    if not isinstance(image, dict):
        raise _reject("launch_image_mismatch", "Docker image inspect is invalid")
    image_values = cast(dict[str, object], image)
    image_id = f"sha256:{product_image_sha256}"
    config = image_values.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    image_user = str(config.get("User", "")) if isinstance(config, dict) else ""
    image_uid = image_user.split(":", 1)[0].lower()
    if (
        image_values.get("Id") != image_id
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != product_commit
        or image_uid in {"", "0", "root"}
    ):
        raise _reject("launch_image_mismatch", "Docker image does not match exact identity pins")

    compose_value = _read_json(
        resolved_compose_path,
        maximum=8_388_608,
        label="Resolved Compose",
    )
    if not isinstance(compose_value, dict):
        raise _reject("launch_runtime_invalid", "Resolved Compose input must be an object")
    compose = cast(dict[str, object], compose_value)
    services_value = compose.get("services")
    if not isinstance(services_value, dict):
        raise _reject("launch_service_set_mismatch", "Resolved Compose services are absent")
    services = cast(dict[str, object], services_value)
    if not REQUIRED_LAUNCH_SERVICES.issubset(services):
        raise _reject("launch_service_set_mismatch", "Resolved Compose lacks required services")
    _validate_networks(compose, services)

    runtime: dict[str, object] = {}
    manifest_services: dict[str, object] = {}
    for name in sorted(REQUIRED_LAUNCH_SERVICES):
        service = _service_dict(services, name)
        _validate_closed_runtime(name, service)
        if service.get("image") != image_reference:
            raise _reject("launch_image_reference_mismatch", f"Launch service {name} image differs")
        if name in LAUNCH_PHASES:
            _validate_phase(name, service, launch_manifest_source=launch_manifest_source)
        else:
            _validate_mounts(name, service, launch_manifest_source=launch_manifest_source)
            if name == "api":
                if service.get("secrets") != [
                    {
                        "source": "anva_bootstrap_secret",
                        "target": "/run/secrets/anva_bootstrap_secret",
                    }
                ]:
                    raise _reject("launch_runtime_mismatch", "Launch service api secret differs")
                user = service.get("user")
                if (
                    not isinstance(user, str)
                    or re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user) is None
                ):
                    raise _reject("launch_runtime_mismatch", "Launch service api is not non-root")
        identity = _runtime_identity(service)
        runtime[name] = identity
        manifest_services[name] = {
            "config_sha256": hashlib.sha256(_canonical_bytes(identity)).hexdigest(),
            "engine_image_id": image_id,
            "image_reference": image_reference,
        }
    resolved_identity = {
        "networks": {
            name: {"internal": True} for name in ("acceptance-backend", "acceptance-edge")
        },
        "services": runtime,
    }
    return {
        "schema_version": 1,
        "kind": "anva-docker-launch",
        "product_commit": product_commit,
        "build_input_sha256": build_input_sha256,
        "package_sha256": provenance["package_sha256"],
        "engine_image_id": image_id,
        "image_reference": image_reference,
        "resolved_compose_sha256": hashlib.sha256(_canonical_bytes(resolved_identity)).hexdigest(),
        "services": manifest_services,
    }


def launch_manifest_bytes(payload: object) -> bytes:
    """Serialize a launch manifest deterministically for immutable host storage."""
    return _canonical_bytes(payload)
