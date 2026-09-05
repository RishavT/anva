"""Rootless acceptance bind permissions exercise the resolved Compose topology."""

from __future__ import annotations

import os
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
    }

    repository = environment.get("ANVA_IMAGE_REPOSITORY", "anva")
    version = environment.get("ANVA_VERSION", "0.1.6")
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
                "from pathlib import Path;"
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
