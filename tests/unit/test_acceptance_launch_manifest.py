"""Public launch-manifest contract, generator, and fail-closed diagnostics."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from anva.acceptance.launch_manifest import generate_launch_manifest, launch_manifest_bytes
from anva.acceptance.provenance import (
    REQUIRED_LAUNCH_SERVICES,
    AcceptanceProvenanceError,
    attest_launch_manifest,
    package_sha256,
)
from anva.acceptance.runner import AcceptanceRunner, AcceptanceRunnerError, RunnerConfig
from anva.contracts import validate_payload
from anva.contracts.catalog import EXAMPLES, SCHEMAS

COMMIT = "d" * 40
BUILD_INPUT = "b" * 64
IMAGE_SHA = "e" * 64
IMAGE_REFERENCE = "anva:0.1.6"
MANIFEST_PATH = Path("/protected/acceptance/launch-manifest.json")


def _phase(name: str, canary_value: str) -> dict[str, object]:
    return {
        "image": IMAGE_REFERENCE,
        "user": "10001:10001",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": "536870912",
        "memswap_limit": "536870912",
        "pids_limit": 96,
        "restart": "no",
        "networks": {"acceptance-edge": None},
        "environment": {
            "ANVA_ACCEPTANCE_TOKEN": canary_value,
            "ANVA_API_URL": "http://api:8000",
        },
        "tmpfs": ["/tmp:size=32m,mode=1777,noexec,nosuid,nodev"],  # noqa: S108
        "command": [
            "anva",
            "acceptance",
            "start",
            "--launch-manifest",
            "/acceptance/launch/manifest.json",
            "--launch-service",
            name,
        ],
        "volumes": [
            {
                "type": "volume",
                "source": "acceptance-canonical",
                "target": "/app/acceptance/canonical",
                "read_only": True,
                "volume": {},
            },
            {
                "type": "bind",
                "source": str(MANIFEST_PATH),
                "target": "/acceptance/launch/manifest.json",
                "read_only": True,
                "bind": {"create_host_path": False},
            },
        ],
    }


def _compose(canary_value: str = "PRIVATE-CANARY") -> dict[str, object]:
    canonical = {
        "type": "volume",
        "source": "acceptance-canonical",
        "target": "/app/acceptance/canonical",
        "read_only": True,
        "volume": {},
    }
    services: dict[str, object] = {
        "api": {
            "image": IMAGE_REFERENCE,
            "networks": {"acceptance-backend": None, "acceptance-edge": None},
            "read_only": True,
            "volumes": [canonical],
        },
        "worker": {
            "image": IMAGE_REFERENCE,
            "networks": {"acceptance-backend": None},
            "read_only": True,
            "volumes": [canonical],
        },
        "mcp": {
            "image": IMAGE_REFERENCE,
            "networks": {"acceptance-backend": None, "acceptance-edge": None},
            "read_only": True,
            "volumes": [canonical],
        },
    }
    for name in REQUIRED_LAUNCH_SERVICES - {"api", "worker", "mcp"}:
        services[name] = _phase(name, canary_value)
    return {
        "name": "operator-private-project",
        "services": services,
        "networks": {
            "acceptance-backend": {"internal": True},
            "acceptance-edge": {"internal": True},
        },
        "secrets": {"bootstrap": {"file": "/PRIVATE/PATH/bootstrap-secret"}},
    }


def _inputs(tmp_path: Path, compose: dict[str, object] | None = None) -> tuple[Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    package_digest = package_sha256(Path(__file__).resolve().parents[2] / "src" / "anva")
    provenance = tmp_path / "anva-build-provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product_commit": COMMIT,
                "build_input_sha256": BUILD_INPUT,
                "package_sha256": package_digest,
            }
        ),
        encoding="utf-8",
    )
    provenance.chmod(0o444)
    resolved = tmp_path / "resolved.json"
    resolved.write_text(json.dumps(compose or _compose()), encoding="utf-8")
    inspect = tmp_path / "inspect.json"
    inspect.write_text(
        json.dumps(
            [
                {
                    "Id": f"sha256:{IMAGE_SHA}",
                    "Config": {"Labels": {"org.opencontainers.image.revision": COMMIT}},
                }
            ]
        ),
        encoding="utf-8",
    )
    return resolved, inspect, provenance


def _generate(tmp_path: Path, compose: dict[str, object] | None = None) -> dict[str, object]:
    resolved, inspect, provenance = _inputs(tmp_path, compose)
    return generate_launch_manifest(
        resolved,
        inspect,
        build_provenance_path=provenance,
        product_commit=COMMIT,
        build_input_sha256=BUILD_INPUT,
        product_image_sha256=IMAGE_SHA,
        image_reference=IMAGE_REFERENCE,
        launch_manifest_source=MANIFEST_PATH,
    )


@pytest.mark.unit
def test_generated_manifest_is_deterministic_schema_valid_secret_free_and_accepted(
    tmp_path: Path,
) -> None:
    first = _generate(tmp_path / "first")
    second_root = tmp_path / "second"
    second_root.mkdir()
    second = _generate(second_root, _compose("DIFFERENT-PRIVATE-CANARY"))

    assert first == second
    validate_payload("launch-manifest", first)
    assert set(cast(dict[str, object], first["services"])) == REQUIRED_LAUNCH_SERVICES
    encoded = launch_manifest_bytes(first)
    assert b"PRIVATE" not in encoded
    assert b"/protected" not in encoded
    assert encoded == launch_manifest_bytes(second)
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(encoded)
    manifest.chmod(0o444)
    assert (
        attest_launch_manifest(
            manifest,
            expected_commit=COMMIT,
            expected_build_input_sha256=BUILD_INPUT,
            expected_package_sha256=cast(str, first["package_sha256"]),
            expected_image_sha256=IMAGE_SHA,
            expected_image_reference=IMAGE_REFERENCE,
            expected_service="acceptance-product-start",
        )
        == hashlib.sha256(encoded).hexdigest()
    )


@pytest.mark.unit
def test_schema_service_inventory_matches_runtime_and_old_valid_manifest_is_accepted(
    tmp_path: Path,
) -> None:
    service_schema = cast(
        dict[str, object],
        cast(dict[str, object], SCHEMAS["launch-manifest"]["properties"])["services"],
    )
    assert set(cast(dict[str, object], service_schema["properties"])) == REQUIRED_LAUNCH_SERVICES
    legacy = deepcopy(EXAMPLES["launch-manifest"])
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    path.chmod(0o444)
    assert attest_launch_manifest(
        path,
        expected_commit="d" * 40,
        expected_build_input_sha256="b" * 64,
        expected_package_sha256="c" * 64,
        expected_image_sha256="e" * 64,
        expected_image_reference="anva:0.1.6",
        expected_service="acceptance-review-submit",
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutation", "reason_code"),
    [
        (
            lambda value: cast(dict[str, object], value["services"]).pop("mcp"),
            "launch_service_set_mismatch",
        ),
        (
            lambda value: cast(
                dict[str, object], cast(dict[str, object], value["services"])["api"]
            ).__setitem__("image", "other:latest"),
            "launch_image_reference_mismatch",
        ),
        (
            lambda value: cast(
                dict[str, object],
                cast(dict[str, object], value["services"])["acceptance-product-start"],
            ).__setitem__("user", "0:0"),
            "launch_runtime_mismatch",
        ),
        (
            lambda value: cast(
                list[dict[str, object]],
                cast(
                    dict[str, object],
                    cast(dict[str, object], value["services"])["acceptance-product-start"],
                )["volumes"],
            )[1].__setitem__("read_only", False),
            "launch_bind_mismatch",
        ),
        (
            lambda value: cast(
                dict[str, object],
                cast(
                    list[dict[str, object]],
                    cast(
                        dict[str, object],
                        cast(dict[str, object], value["services"])["acceptance-product-start"],
                    )["volumes"],
                )[1]["bind"],
            ).__setitem__("create_host_path", True),
            "launch_bind_mismatch",
        ),
    ],
)
def test_generator_fails_closed_for_service_image_runtime_and_bind_changes(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], object],
    reason_code: str,
) -> None:
    compose = _compose()
    mutation(compose)
    with pytest.raises(AcceptanceProvenanceError) as captured:
        _generate(tmp_path, compose)
    assert captured.value.reason_code == reason_code


@pytest.mark.unit
@pytest.mark.parametrize(
    ("transform", "reason_code"),
    [
        (lambda payload: b"{not-json", "launch_manifest_malformed"),
        (lambda payload: json.dumps({**payload, "extra": True}).encode(), "launch_manifest_schema"),
        (
            lambda payload: json.dumps({**payload, "product_commit": "a" * 40}).encode(),
            "launch_manifest_product_commit_mismatch",
        ),
        (
            lambda payload: json.dumps(
                {**payload, "engine_image_id": f"sha256:{'a' * 64}"}
            ).encode(),
            "launch_manifest_image_mismatch",
        ),
        (
            lambda payload: json.dumps({**payload, "build_input_sha256": "a" * 64}).encode(),
            "launch_manifest_build_input_mismatch",
        ),
        (
            lambda payload: json.dumps({**payload, "package_sha256": "a" * 64}).encode(),
            "launch_manifest_package_mismatch",
        ),
        (
            lambda payload: json.dumps({**payload, "image_reference": "other:latest"}).encode(),
            "launch_manifest_image_reference_mismatch",
        ),
        (
            lambda payload: json.dumps(
                {
                    **payload,
                    "services": {
                        key: value
                        for key, value in cast(dict[str, object], payload["services"]).items()
                        if key != "mcp"
                    },
                }
            ).encode(),
            "launch_manifest_service_set_mismatch",
        ),
    ],
)
def test_manifest_rejections_have_stable_actionable_reason_codes(
    tmp_path: Path,
    transform: Callable[[dict[str, object]], bytes],
    reason_code: str,
) -> None:
    payload = _generate(tmp_path)
    path = tmp_path / "candidate.json"
    path.write_bytes(transform(payload))
    path.chmod(0o444)
    with pytest.raises(AcceptanceProvenanceError) as captured:
        attest_launch_manifest(
            path,
            expected_commit=COMMIT,
            expected_build_input_sha256=BUILD_INPUT,
            expected_package_sha256=cast(str, payload["package_sha256"]),
            expected_image_sha256=IMAGE_SHA,
            expected_image_reference=IMAGE_REFERENCE,
            expected_service="acceptance-product-start",
        )
    assert captured.value.reason_code == reason_code


@pytest.mark.unit
def test_manifest_rejects_unsupported_launch_service_with_stable_code(tmp_path: Path) -> None:
    payload = _generate(tmp_path)
    path = tmp_path / "candidate.json"
    path.write_bytes(launch_manifest_bytes(payload))
    path.chmod(0o444)

    with pytest.raises(AcceptanceProvenanceError) as captured:
        attest_launch_manifest(
            path,
            expected_commit=COMMIT,
            expected_build_input_sha256=BUILD_INPUT,
            expected_package_sha256=cast(str, payload["package_sha256"]),
            expected_image_sha256=IMAGE_SHA,
            expected_image_reference=IMAGE_REFERENCE,
            expected_service="acceptance-unknown",
        )

    assert captured.value.reason_code == "launch_manifest_service_mismatch"


@pytest.mark.unit
def test_missing_and_mutable_manifest_emit_private_pre_state_diagnostic(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    package_digest = package_sha256(Path(__file__).resolve().parents[2] / "src" / "anva")
    provenance = tmp_path / "provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product_commit": COMMIT,
                "build_input_sha256": BUILD_INPUT,
                "package_sha256": package_digest,
            }
        ),
        encoding="utf-8",
    )
    provenance.chmod(0o444)
    config = RunnerConfig(
        api_url="http://api:8000/api/v1",
        mcp_url="http://mcp:8001/mcp",
        canonical_root=tmp_path / "unreached",
        state_path=state / "resume.json",
        output_root=tmp_path / "output",
        manifest_sha256="a" * 64,
        source_fingerprint="a" * 64,
        canonical_manifest_sha256="a" * 64,
        product_commit=COMMIT,
        product_image_sha256=IMAGE_SHA,
        product_image_reference=IMAGE_REFERENCE,
        build_input_sha256=BUILD_INPUT,
        launch_service="acceptance-product-start",
        build_provenance_path=provenance,
        launch_manifest_path=tmp_path / "missing.json",
    )
    with pytest.raises(AcceptanceRunnerError):
        AcceptanceRunner(config)
    diagnostic = json.loads((state / "operator-diagnostic.json").read_bytes())
    assert diagnostic == {
        "schema_version": 1,
        "status": "FAILED",
        "run_id": "unavailable",
        "stage": "launch_manifest_preflight",
        "reason_code": "launch_manifest_missing",
    }
    assert b"PRIVATE" not in json.dumps(diagnostic).encode()

    candidate = tmp_path / "missing.json"
    candidate.write_bytes(launch_manifest_bytes(_generate(tmp_path / "generated")))
    candidate.chmod(0o644)
    with pytest.raises(AcceptanceProvenanceError) as captured:
        attest_launch_manifest(
            candidate,
            expected_commit=COMMIT,
            expected_build_input_sha256=BUILD_INPUT,
            expected_package_sha256=package_digest,
            expected_image_sha256=IMAGE_SHA,
            expected_image_reference=IMAGE_REFERENCE,
            expected_service="acceptance-product-start",
        )
    assert captured.value.reason_code == "launch_manifest_permissions"
