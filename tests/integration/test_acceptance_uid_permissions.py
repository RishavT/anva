"""Rootless acceptance bind permissions exercise the resolved Compose topology."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.integration
def test_uid_1000_can_use_private_acceptance_binds_but_an_unrelated_uid_cannot(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("requires Docker")

    protected = tmp_path / "protected"
    paths = {
        name: protected / name
        for name in ("input", "state", "credentials", "handoff", "reviewer", "results")
    }
    for path in (protected, *paths.values()):
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    (paths["input"] / "raw.txt").write_text("public\n", encoding="utf-8")
    launch = protected / "launch.json"
    launch.write_text("{}\n", encoding="utf-8")
    secret = protected / "bootstrap.secret"
    secret.write_text("private\n", encoding="utf-8")
    for file_path in (launch, secret):
        file_path.chmod(0o600)

    project = f"anva-issue138-permissions-{os.getpid()}"
    compose = [
        docker,
        "compose",
        "-p",
        project,
        "-f",
        "compose.yaml",
        "-f",
        "compose.acceptance.yaml",
        "--profile",
        "acceptance",
    ]
    environment = os.environ.copy() | {
        "ANVA_ACCEPTANCE_UID": "1000",
        "ANVA_ACCEPTANCE_GID": "1000",
        "ANVA_ACCEPTANCE_INPUT_DIR": str(paths["input"]),
        "ANVA_ACCEPTANCE_STATE_DIR": str(paths["state"]),
        "ANVA_ACCEPTANCE_CREDENTIAL_DIR": str(paths["credentials"]),
        "ANVA_ACCEPTANCE_HANDOFF_DIR": str(paths["handoff"]),
        "ANVA_ACCEPTANCE_REVIEW_RESULT_DIR": str(paths["reviewer"]),
        "ANVA_ACCEPTANCE_RESULTS_DIR": str(paths["results"]),
        "ANVA_ACCEPTANCE_LAUNCH_MANIFEST": str(launch),
        "ANVA_TST009_BOOTSTRAP_SECRET_FILE": str(secret),
        "ANVA_BOOTSTRAP_SECRET": "PRIVATE-LEGACY-CANARY",
    }

    repository = environment.get("ANVA_IMAGE_REPOSITORY", "anva")
    version = environment.get("ANVA_VERSION", "0.1.7")
    image = f"{repository}:{version}"

    def protect_as(uid: int, gid: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [
                docker,
                "run",
                "--rm",
                "--user",
                "0:0",
                "--volume",
                f"{protected}:/protected",
                image,
                "sh",
                "-c",
                f"chown -R {uid}:{gid} /protected && "
                "find /protected -type d -exec chmod 0700 {} + && "
                "find /protected -type f -exec chmod 0600 {} +",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def run(
        service: str, code: str, *, env: dict[str, str] = environment
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [*compose, "run", "--rm", "--no-deps", "--entrypoint", "python", service, "-c", code],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    try:
        prepared = protect_as(1000, 1000)
        assert prepared.returncode == 0, prepared.stderr
        resolved = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [*compose, "config", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        start_environment = json.loads(resolved.stdout)["services"]["acceptance-product-start"][
            "environment"
        ]
        assert "ANVA_BOOTSTRAP_SECRET" not in start_environment

        created = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [*compose, "create", "--no-build", "acceptance-product-start"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        assert created.returncode == 0, created.stderr
        container_id = subprocess.run(  # noqa: S603
            [*compose, "ps", "--all", "--quiet", "acceptance-product-start"],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout.strip()
        inspected = subprocess.run(  # noqa: S603
            [docker, "inspect", "--format", "{{json .Config.Env}}", container_id],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        container_environment = json.loads(inspected.stdout)
        assert not any(
            value.startswith("ANVA_BOOTSTRAP_SECRET=") for value in container_environment
        )
        assert "PRIVATE-LEGACY-CANARY" not in inspected.stdout
        subprocess.run(  # noqa: S603
            [*compose, "rm", "--force", "--stop", "acceptance-product-start"],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        checks = {
            "acceptance-adapter": (
                "from pathlib import Path;"
                "Path('/acceptance/raw/raw.txt').read_text();"
                "Path('/app/run/adapter').write_text('ok');"
                "Path('/app/acceptance/canonical/adapter').write_text('ok')"
            ),
            "api": (
                "from pathlib import Path;"
                "Path('/run/secrets/anva_bootstrap_secret').read_text();"
                "Path('/app/run/api').write_text('ok')"
            ),
            "acceptance-product-start": (
                "import os;"
                "from pathlib import Path;"
                "assert 'ANVA_BOOTSTRAP_SECRET' not in os.environ;"
                "Path('/run/secrets/anva_bootstrap_secret').read_text();"
                "Path('/app/run/start').write_text('ok');"
                "Path('/acceptance/state/start').write_text('ok');"
                "Path('/acceptance/credentials/start').write_text('ok')"
            ),
            "acceptance-review-request": (
                "from pathlib import Path;"
                "Path('/app/run/request').write_text('ok');"
                "Path('/acceptance/state/request').write_text('ok');"
                "Path('/acceptance/handoff/request').write_text('ok')"
            ),
            "acceptance-review-submit": (
                "from pathlib import Path;"
                "Path('/app/run/submit').write_text('ok');"
                "Path('/acceptance/state/submit').write_text('ok');"
                "Path('/acceptance/handoff/submit').write_text('ok')"
            ),
            "acceptance-product-finalize": (
                "from pathlib import Path;"
                "Path('/app/run/finalize').write_text('ok');"
                "Path('/acceptance/state/finalize').write_text('ok');"
                "Path('/acceptance/results/finalize').write_text('ok')"
            ),
        }
        for service, code in checks.items():
            completed = run(service, code)
            assert completed.returncode == 0, completed.stderr

        unrelated = environment | {"ANVA_ACCEPTANCE_UID": "10002", "ANVA_ACCEPTANCE_GID": "10002"}
        denied = run(
            "acceptance-product-start",
            "from pathlib import Path; Path('/acceptance/state/denied').write_text('bad')",
            env=unrelated,
        )
        assert denied.returncode != 0
        verified = subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [
                docker,
                "run",
                "--rm",
                "--user",
                "0:0",
                "--volume",
                f"{protected}:/protected:ro",
                image,
                "sh",
                "-c",
                "test ! -e /protected/state/denied && "
                'test "$(stat -c %a /protected/bootstrap.secret)" = 600 && '
                'test -z "$(find /protected -type d ! -perm 0700 -print -quit)"',
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        assert verified.returncode == 0, verified.stderr
    finally:
        subprocess.run(  # noqa: S603 - executable resolved by shutil.which
            [*compose, "down", "--volumes", "--remove-orphans"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        restored = protect_as(os.getuid(), os.getgid())
        assert restored.returncode == 0, restored.stderr


@pytest.mark.integration
def test_container_cli_reads_file_secret_and_creates_one_time_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the installed CLI and real runner while faking only public network peers."""
    executable = shutil.which("anva")
    if executable is None or not Path("/.dockerenv").exists():
        pytest.skip("requires the project test container")

    unit_boundaries = Path("tests/unit/test_acceptance_runner_boundaries.py").resolve()
    runner, _product = runpy.run_path(str(unit_boundaries))["_runner"](tmp_path, monkeypatch)
    config = runner.config
    secret = tmp_path / "bootstrap.secret"
    secret.write_text("PRIVATE-FILE-CANARY", encoding="utf-8")
    secret.chmod(0o400)

    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "sitecustomize.py").write_text(
        "import runpy\n"
        "import django\n"
        "django.setup()\n"
        "import anva.acceptance.runner as acceptance_runner\n"
        f"symbols = runpy.run_path({str(unit_boundaries)!r})\n"
        "product = symbols['FakeProduct']()\n"
        "acceptance_runner.PublicAPI = lambda _url, token=None: "
        "symbols['FakeAPI'](product, token)\n"
        "acceptance_runner.StreamableHTTPMCP = lambda _url, token: "
        "symbols['FakeMCP'](product, token)\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("ANVA_BOOTSTRAP_SECRET", None)
    environment.setdefault("DJANGO_SETTINGS_MODULE", "anva.config.settings")
    environment["ANVA_BOOTSTRAP_SECRET_FILE"] = str(secret)
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(probe), str(Path.cwd()), environment.get("PYTHONPATH", ""))
    )
    completed = subprocess.run(  # noqa: S603 - installed project executable
        [
            executable,
            "acceptance",
            "start",
            "--api-url",
            config.api_url,
            "--mcp-url",
            config.mcp_url,
            "--canonical-root",
            str(config.canonical_root),
            "--state",
            str(config.state_path),
            "--output",
            str(config.output_root),
            "--manifest-sha256",
            config.manifest_sha256,
            "--source-fingerprint",
            config.source_fingerprint,
            "--canonical-manifest-sha256",
            config.canonical_manifest_sha256,
            "--product-commit",
            config.product_commit,
            "--product-image-sha256",
            config.product_image_sha256,
            "--product-image-reference",
            config.product_image_reference,
            "--build-input-sha256",
            config.build_input_sha256,
            "--launch-service",
            config.launch_service,
            "--build-provenance",
            str(config.build_provenance_path),
            "--launch-manifest",
            str(config.launch_manifest_path),
            "--credential-output",
            str(config.credential_output),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr
    assert "PRIVATE-FILE-CANARY" not in completed.stdout + completed.stderr
    assert config.credential_output is not None
    credentials = json.loads(config.credential_output.read_bytes())
    assert credentials["anva_token"] == "initiator-token-material"  # noqa: S105
    assert credentials["reviewer_token"] == "reviewer-token-material"  # noqa: S105
