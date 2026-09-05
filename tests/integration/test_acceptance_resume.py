"""Production-boundary regression coverage for acceptance checkpoint replay."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
import uvicorn
from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import connections
from django.utils import timezone

from anva.acceptance.client import AcceptanceBoundaryError, PublicAPI
from anva.acceptance.corpus import canonicalize_corpus
from anva.acceptance.provenance import REQUIRED_LAUNCH_SERVICES, package_sha256
from anva.acceptance.runner import AcceptanceRunner, RunnerConfig
from anva.acceptance.state import load_state
from anva.contracts.catalog import EXAMPLES
from anva.core.models import (
    AccessGrant,
    AccessScope,
    AssuranceRun,
    Evidence,
    EvidenceBlob,
    EvidenceManifest,
    Policy,
    RepositoryAccessToken,
    SourceChunk,
    SourceConnection,
    SourceDocument,
    SyncRun,
    WorkItem,
)
from anva.core.services.authorization import Action
from anva.core.services.context import ActorContext
from anva.core.services.ingestion import execute_ingestion_job
from anva.core.services.jobs import claim_next_job, complete_job
from anva.core.services.tokens import authenticate_bearer

SOURCE_TEXT = (
    "# Checkout ownership exact-head evidence policy\n\n"
    "The Payments Platform team owns checkout. Review the Ember change against authorized "
    "organization context. The first operator sample used a long-lived shared bearer token "
    "in a shell script. The one-hour demonstration sample was never approved as an "
    "authentication standard.\n"
)


def _write_corpus(raw: Path) -> str:
    payload = raw / "payload" / "organization"
    payload.mkdir(parents=True)
    contents: dict[str, bytes] = {"payload/organization/decision.md": SOURCE_TEXT.encode()}
    for index in range(106):
        contents[f"payload/organization/support-{index:03d}.md"] = (
            f"Archive note {index:03d}. Routine record {index:03d}: queue {index % 11}; shard "
            f"{(index * 17) % 97}.\n"
        ).encode()
    target_bytes = 214_313
    padding_path = "payload/organization/support-105.md"
    padding_wrapper = b"\n<!-- deterministic public-corpus padding\n\n-->\n"
    padding_size = target_bytes - sum(map(len, contents.values())) - len(padding_wrapper)
    assert padding_size > 0
    contents[padding_path] += padding_wrapper[:-5] + (b"x" * padding_size) + padding_wrapper[-5:]
    assert sum(map(len, contents.values())) == target_bytes
    files: list[dict[str, object]] = []
    for relative, content in sorted(contents.items()):
        path = raw / relative
        path.write_bytes(content)
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        )
    manifest = {
        "schema_version": "1.0",
        "corpus_id": "issue-130-real-checkpoint-replay",
        "generated_at": "2026-08-07T00:00:00Z",
        "source_commit": "a" * 40,
        "files": files,
        "limits": {
            "max_files": 107,
            "max_total_bytes": sum(cast(int, item["size_bytes"]) for item in files),
            "max_file_bytes": max(cast(int, item["size_bytes"]) for item in files),
            "max_depth": 2,
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (raw / "acceptance-corpus.json").write_bytes(manifest_bytes)
    return hashlib.sha256(manifest_bytes).hexdigest()


def _write_provenance(tmp_path: Path) -> tuple[Path, Path]:
    package_digest = package_sha256(Path(__file__).resolve().parents[2] / "src" / "anva")
    provenance = tmp_path / "anva-build-provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product_commit": "d" * 40,
                "build_input_sha256": "b" * 64,
                "package_sha256": package_digest,
            }
        ),
        encoding="utf-8",
    )
    provenance.chmod(0o444)
    launch = tmp_path / "launch-manifest.json"
    launch.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "anva-docker-launch",
                "product_commit": "d" * 40,
                "build_input_sha256": "b" * 64,
                "package_sha256": package_digest,
                "engine_image_id": f"sha256:{'e' * 64}",
                "image_reference": "anva:test",
                "resolved_compose_sha256": "a" * 64,
                "services": {
                    service: {
                        "config_sha256": "f" * 64,
                        "engine_image_id": f"sha256:{'e' * 64}",
                        "image_reference": "anva:test",
                    }
                    for service in REQUIRED_LAUNCH_SERVICES
                },
            }
        ),
        encoding="utf-8",
    )
    launch.chmod(0o444)
    return provenance, launch


def _runner(tmp_path: Path, *, api_url: str, mcp_url: str) -> AcceptanceRunner:
    raw = tmp_path / "raw"
    canonical = tmp_path / "canonical"
    raw.mkdir()
    canonical.mkdir()
    pin = _write_corpus(raw)
    corpus = canonicalize_corpus(
        raw_root=raw,
        canonical_root=canonical,
        manifest_sha256=pin,
    )
    assert corpus.file_count == 107
    assert corpus.total_bytes == 214_313
    provenance, launch = _write_provenance(tmp_path)
    case_path = tmp_path / "acceptance-case.json"
    acceptance_case = deepcopy(EXAMPLES["acceptance-case"])
    retrieval = cast(dict[str, object], acceptance_case["retrieval"])
    retrieval["context_task"] = (
        "Review the checkout ownership exact-head evidence policy for the Ember change against "
        "authorized organization context."
    )
    case_path.write_text(json.dumps(acceptance_case), encoding="utf-8")
    for private in (tmp_path / "state", tmp_path / "credentials", tmp_path / "handoff"):
        private.mkdir(mode=0o700)
    (tmp_path / "results").mkdir()
    return AcceptanceRunner(
        RunnerConfig(
            api_url=api_url,
            mcp_url=mcp_url,
            canonical_root=canonical,
            state_path=tmp_path / "state" / "resume.json",
            output_root=tmp_path / "results" / "sealed",
            manifest_sha256=corpus.manifest_sha256,
            source_fingerprint=corpus.source_fingerprint,
            canonical_manifest_sha256=corpus.canonical_manifest_sha256,
            product_commit="d" * 40,
            product_image_sha256="e" * 64,
            product_image_reference="anva:test",
            build_input_sha256="b" * 64,
            launch_service="acceptance-product-start",
            case_path=case_path,
            build_provenance_path=provenance,
            launch_manifest_path=launch,
            credential_output=tmp_path / "credentials" / "credentials.json",
            sync_timeout_seconds=2,
        )
    )


@contextmanager
def _live_mcp_server() -> Iterator[str]:
    """Serve the production official-SDK MCP app over a genuine TCP boundary."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = cast(tuple[str, int], listener.getsockname())[1]
    base_url = f"http://127.0.0.1:{port}"
    settings.ANVA_MCP_PUBLIC_BASE_URL = base_url
    settings.ALLOWED_HOSTS = [*settings.ALLOWED_HOSTS, "127.0.0.1"]
    from anva.entrypoints.mcp import create_application

    server = uvicorn.Server(
        uvicorn.Config(
            create_application(),
            lifespan="on",
            log_level="warning",
            access_log=False,
        )
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        name="issue-130-mcp-server",
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()
        raise RuntimeError("MCP integration server did not start")
    try:
        yield f"{base_url}/mcp"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        if thread.is_alive():
            raise RuntimeError("MCP integration server did not stop")
        asyncio.run(sync_to_async(connections.close_all, thread_sensitive=True)())


def _expect_resume_auth_rejection(runner: AcceptanceRunner, token: str) -> None:
    started_at = time.monotonic()
    with pytest.raises(AcceptanceBoundaryError) as captured:
        runner.start(bootstrap_secret=None, token=token)
    assert time.monotonic() - started_at < 1
    assert captured.value.status == 401
    diagnostic = json.loads(
        (runner.config.state_path.parent / "operator-diagnostic.json").read_bytes()
    )
    assert diagnostic["stage"] == "source_sync_wait"
    assert diagnostic["reason_code"] == "authorization_rejected"
    assert token not in json.dumps(diagnostic)


@pytest.fixture
def live_mcp_url() -> Iterator[str]:
    with _live_mcp_server() as url:
        yield url


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_real_107_file_completed_sync_checkpoint_resumes_once_and_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    live_server: object,
    live_mcp_url: str,
) -> None:
    settings.ALLOWED_HOSTS = [*settings.ALLOWED_HOSTS, "127.0.0.1"]
    runner = _runner(
        tmp_path,
        api_url=f"{live_server}/api/v1",
        mcp_url=live_mcp_url,
    )
    monkeypatch.setenv(
        "ANVA_FILESYSTEM_ALLOWED_ROOTS",
        str(runner.config.canonical_root / "payload"),
    )
    state = runner._new_state()
    runner._save(state)
    api, original_token = runner._bootstrap("test-only-bootstrap-secret", state)
    credentials = json.loads(runner.config.credential_output.read_bytes())  # type: ignore[union-attr]
    original_reviewer_token = cast(str, credentials["reviewer_token"])

    source = api.request(
        "POST",
        "/source-connections/filesystem",
        payload={
            "repository_id": state.identities["repository_id"],
            "access_scope_id": state.identities["access_scope_id"],
            "external_key": runner.case.section("source")["external_key"],
            "display_name": runner.case.section("source")["display_name"],
            "root": f"{runner.config.canonical_root.as_posix()}/payload",
        },
        expected=frozenset({200, 201}),
        operation_id="connectFilesystemSource",
    ).payload
    state.identities["source_connection_id"] = cast(str, source["id"])
    sync = api.request(
        "POST",
        f"/source-connections/{source['id']}/sync",
        payload={"scan_mode": "FULL"},
        expected=frozenset({202}),
        operation_id="syncSourceConnection",
    ).payload
    state.identities["sync_run_id"] = cast(str, sync["id"])
    runner._save(state)

    claimed = claim_next_job(worker_id="issue-130-integration", lease_seconds=600)
    assert claimed is not None
    SyncRun.objects.filter(id=cast(str, sync["id"])).update(
        started_at=timezone.now() - timedelta(seconds=21)
    )
    completed = execute_ingestion_job(job=claimed, worker_id="issue-130-integration")
    complete_job(
        actor=ActorContext(
            organization_id=completed.organization_id,
            actor_type="SERVICE",
            actor_id="issue-130-integration",
            authorization_path="internal:integration-worker",
            request_id=uuid.uuid4(),
        ),
        job_id=claimed.id,
        worker_id="issue-130-integration",
        now=timezone.now(),
    )
    completed.refresh_from_db()
    assert completed.state == SyncRun.State.COMPLETED
    assert completed.completed_at is not None
    assert (completed.completed_at - completed.started_at).total_seconds() > 20
    assert (
        completed.discovered_count,
        completed.processed_count,
        completed.failed_count,
        completed.tombstoned_count,
    ) == (107, 107, 0, 0)
    assert SourceDocument.objects.count() == 107
    chunk_count = SourceChunk.objects.count()
    assert chunk_count >= 107

    scope = AccessScope.objects.get(id=state.identities["access_scope_id"])
    assert (scope.all_memberships, scope.all_repositories, scope.all_service_identities) == (
        False,
        False,
        False,
    )
    assert set(
        AccessGrant.objects.filter(
            service_identity_id=uuid.UUID(state.identities["reviewer_service_identity_id"])
        ).values_list("action", flat=True)
    ) == {Action.ASSURANCE_REVIEW.value}
    assert SourceConnection.objects.count() == SyncRun.objects.count() == 1
    assert SourceDocument.objects.count() == 107
    assert SourceChunk.objects.count() == chunk_count

    _expect_resume_auth_rejection(runner, "wrong-issue-130-token")
    original_credential_id = authenticate_bearer(f"Bearer {original_token}").credential_id
    assert original_credential_id is not None
    original_record = RepositoryAccessToken.objects.get(id=original_credential_id)
    RepositoryAccessToken.objects.filter(id=original_record.id).update(
        issued_at=timezone.now() - timedelta(hours=2),
        expires_at=timezone.now() - timedelta(hours=1),
    )
    _expect_resume_auth_rejection(runner, original_token)

    recovered = (
        PublicAPI(runner.config.api_url)
        .request(
            "POST",
            "/bootstrap",
            payload=runner._bootstrap_payload(state),
            headers={"X-Anva-Bootstrap-Secret": "test-only-bootstrap-secret"},
            expected=frozenset({201}),
            operation_id="bootstrapOrganization",
        )
        .payload
    )
    assert recovered["recovered"] is True
    first_replacement_token = cast(str, recovered["token"])
    first_replacement_reviewer_token = cast(str, recovered["reviewer_token"])
    assert (
        recovered["reviewer_service_identity_id"]
        == state.identities["reviewer_service_identity_id"]
    )
    state.identities["reviewer_token_id"] = cast(str, recovered["reviewer_token_id"])
    runner._save(state)
    assert (
        RepositoryAccessToken.objects.get(id=cast(str, credentials["reviewer_token_id"])).revoked_at
        is not None
    )

    second_recovery = (
        PublicAPI(runner.config.api_url)
        .request(
            "POST",
            "/bootstrap",
            payload=runner._bootstrap_payload(state),
            headers={"X-Anva-Bootstrap-Secret": "test-only-bootstrap-secret"},
            expected=frozenset({201}),
            operation_id="bootstrapOrganization",
        )
        .payload
    )
    assert second_recovery["recovered"] is True
    replacement_token = cast(str, second_recovery["token"])
    replacement_reviewer_token = cast(str, second_recovery["reviewer_token"])
    state.identities["reviewer_token_id"] = cast(str, second_recovery["reviewer_token_id"])
    runner._save(state)
    _expect_resume_auth_rejection(runner, first_replacement_token)
    assert (
        RepositoryAccessToken.objects.get(id=cast(str, recovered["reviewer_token_id"])).revoked_at
        is not None
    )

    awaiting = runner.start(bootstrap_secret=None, token=replacement_token)
    assert awaiting.status == "AWAITING_EXTERNAL_REVIEW"
    assert awaiting.identities["source_connection_id"] == str(source["id"])
    assert awaiting.identities["sync_run_id"] == str(sync["id"])
    assert SourceConnection.objects.count() == SyncRun.objects.count() == 1
    assert SourceDocument.objects.count() == 107
    assert SourceChunk.objects.count() == chunk_count
    assert WorkItem.objects.count() == 1
    assert Policy.objects.count() == 1
    assert EvidenceBlob.objects.count() == 1
    assert EvidenceBlob.objects.get().storage_state == EvidenceBlob.StorageState.AVAILABLE
    assert EvidenceManifest.objects.count() == 1
    assert Evidence.objects.count() == 1
    assert AssuranceRun.objects.count() == 2
    assert AssuranceRun.objects.get(id=awaiting.identities["stale_probe_run_id"]).state == (
        AssuranceRun.State.STALE
    )
    persisted_counts = {
        model: model.objects.count()
        for model in (
            SourceConnection,
            SyncRun,
            SourceDocument,
            SourceChunk,
            WorkItem,
            Policy,
            EvidenceBlob,
            EvidenceManifest,
            Evidence,
            AssuranceRun,
        )
    }
    assert runner.start(bootstrap_secret=None, token=replacement_token).status == (
        "AWAITING_EXTERNAL_REVIEW"
    )
    assert {model: model.objects.count() for model in persisted_counts} == persisted_counts

    handoff_path = tmp_path / "handoff" / "review.json"
    claimed_state = runner.create_review_handoff(
        reviewer_token=replacement_reviewer_token,
        output=handoff_path,
    )
    assert claimed_state.status == "REVIEW_CLAIMED"
    handoff = json.loads(handoff_path.read_bytes())
    request = cast(dict[str, object], handoff["request"])
    result = deepcopy(EXAMPLES["evaluator-result"])
    result.update(
        {
            "request_id": request["request_id"],
            "organization_id": awaiting.identities["organization_id"],
            "commit_sha": awaiting.hashes["head_commit"],
            "completion": "COMPLETE",
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "findings": [],
            "limitations": [],
            "evaluated_at": "2026-08-07T00:00:00Z",
        }
    )
    result_path = tmp_path / "external-result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    submitted = runner.submit_review(
        reviewer_token=replacement_reviewer_token,
        handoff_path=handoff_path,
        result_path=result_path,
    )
    assert submitted.status == "EXTERNAL_REVIEW_SUBMITTED"
    assert not handoff_path.exists()
    assert AssuranceRun.objects.get(id=submitted.identities["assurance_run_id"]).state == (
        AssuranceRun.State.COMPLETED
    )

    complete = runner.finalize(token=replacement_token)
    assert complete.status == "COMPLETE"
    sealed_hash = complete.hashes["sealed_manifest_sha256"]
    sealed_bytes = {
        path.relative_to(runner.config.output_root): path.read_bytes()
        for path in runner.config.output_root.rglob("*")
        if path.is_file()
    }
    replayed = runner.finalize(token=replacement_token)
    assert replayed.hashes["sealed_manifest_sha256"] == sealed_hash
    assert {
        path.relative_to(runner.config.output_root): path.read_bytes()
        for path in runner.config.output_root.rglob("*")
        if path.is_file()
    } == sealed_bytes
    assert {model: model.objects.count() for model in persisted_counts} == persisted_counts

    secret_values = (
        original_token,
        original_reviewer_token,
        first_replacement_token,
        first_replacement_reviewer_token,
        replacement_token,
        replacement_reviewer_token,
    )
    public_transcript = b"".join(
        [
            runner.config.state_path.read_bytes(),
            (runner.config.state_path.parent / "operator-diagnostic.json").read_bytes(),
            *sealed_bytes.values(),
        ]
    )
    assert all(secret.encode() not in public_transcript for secret in secret_values)
    assert load_state(runner.config.state_path).status == "COMPLETE"
