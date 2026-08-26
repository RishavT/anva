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
    assert '[[ "$EVENT_REF" == "refs/tags/${tag}" ]]' in text
    assert "gh attestation verify" in text
    assert 'docker pull "$image"' in text
    assert 'archive.extractall(os.environ["INSTALL_ROOT"], filter="data")' in text
    assert "up --no-build --wait" in text
