"""Restart-safe product acceptance orchestration through public boundaries only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from anva import __version__
from anva.acceptance.client import MCPBoundary, PublicAPI, StreamableHTTPMCP
from anva.acceptance.corpus import CANONICAL_MANIFEST_NAME, verify_canonical_corpus
from anva.acceptance.export import (
    canonical_bytes,
    seal_results,
    sha256_bytes,
    verify_sealed_results,
)
from anva.acceptance.provenance import (
    AcceptanceProvenanceError,
    attest_build_provenance,
    attest_launch_manifest,
)
from anva.acceptance.state import ResumeState, load_state, save_state
from anva.contracts.validation import validate_payload

TERMINAL_SYNC_STATES = frozenset({"COMPLETED", "PARTIALLY_COMPLETED", "FAILED", "CANCELLED"})
REFERENCE_GRACE_SECONDS = 300
COMMIT_PATTERN = re.compile(r"^[a-f0-9]{40}$")


class AcceptanceRunnerError(ValueError):
    """The runner stopped at a safe, resumable boundary."""


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    api_url: str
    mcp_url: str
    canonical_root: Path
    state_path: Path
    output_root: Path
    manifest_sha256: str
    source_fingerprint: str
    canonical_manifest_sha256: str
    product_commit: str
    product_image_sha256: str
    product_image_reference: str
    build_input_sha256: str
    launch_service: str
    build_provenance_path: Path = Path("/app/anva-build-provenance.json")
    launch_manifest_path: Path = Path("/acceptance/launch/manifest.json")
    credential_output: Path | None = None
    sync_timeout_seconds: int = 300


def _canonical_manifest(root: Path) -> dict[str, object]:
    path = root / CANONICAL_MANIFEST_NAME
    raw = path.read_bytes()
    if len(raw) > 1_000_000:
        raise AcceptanceRunnerError("Canonical manifest exceeds its bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise AcceptanceRunnerError("Canonical manifest is invalid")
    return cast(dict[str, object], value)


def _uuid(namespace: uuid.UUID, name: str) -> str:
    return str(uuid.uuid5(namespace, name))


def _hash40(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:40]


def _run_reference_time(
    corpus_generated_at: str,
    *,
    now: datetime,
    sync_timeout_seconds: int,
) -> str:
    """Precommit a replay-stable instant after bounded in-run evidence activation."""
    corpus_time = datetime.fromisoformat(corpus_generated_at.replace("Z", "+00:00"))
    if corpus_time.tzinfo is None or now.tzinfo is None:
        raise AcceptanceRunnerError("Acceptance reference times must include a timezone")
    baseline = max(corpus_time.astimezone(UTC), now.astimezone(UTC).replace(microsecond=0))
    reference = baseline + timedelta(seconds=sync_timeout_seconds + REFERENCE_GRACE_SECONDS)
    return reference.isoformat().replace("+00:00", "Z")


def _state_namespace(state: ResumeState) -> uuid.UUID:
    try:
        return uuid.UUID(state.run_id.removeprefix("anva:"))
    except ValueError as error:
        raise AcceptanceRunnerError("Acceptance run identity is invalid") from error


def _string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise AcceptanceRunnerError("Anva response is missing a required identity")
    return value


def _write_secret_handoff(path: Path, payload: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise AcceptanceRunnerError("Secret handoff path must not already exist")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) & 0o077:
        raise AcceptanceRunnerError("Secret handoff directory is unsafe")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(payload, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _read_secret_handoff(path: Path) -> dict[str, object]:
    if (
        path.parent.is_symlink()
        or not path.parent.is_dir()
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o077
        or path.is_symlink()
        or not path.is_file()
        or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise AcceptanceRunnerError("External-review handoff is unsafe")
    raw = path.read_bytes()
    if len(raw) > 1_500_000:
        raise AcceptanceRunnerError("External-review handoff exceeds its bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise AcceptanceRunnerError("External-review handoff is invalid")
    return cast(dict[str, object], value)


class AcceptanceRunner:
    """Drive TST-004 through TST-007 without importing product models or services."""

    def __init__(self, config: RunnerConfig) -> None:
        if COMMIT_PATTERN.fullmatch(config.product_commit) is None:
            raise AcceptanceRunnerError("Product commit must be exact 40-character lowercase hex")
        if re.fullmatch(r"[a-f0-9]{64}", config.product_image_sha256) is None or not any(
            character != "0" for character in config.product_image_sha256
        ):
            raise AcceptanceRunnerError("Product image must be pinned by a non-zero SHA-256 digest")
        if re.fullmatch(r"[a-f0-9]{64}", config.build_input_sha256) is None or not any(
            character != "0" for character in config.build_input_sha256
        ):
            raise AcceptanceRunnerError("Build input must be pinned by a non-zero SHA-256 digest")
        if not 1 <= config.sync_timeout_seconds <= 3_600:
            raise AcceptanceRunnerError("Source sync timeout is outside its bound")
        self.config = config
        try:
            provenance = attest_build_provenance(
                config.build_provenance_path,
                expected_commit=config.product_commit,
                expected_build_input_sha256=config.build_input_sha256,
            )
            launch_manifest_sha256 = attest_launch_manifest(
                config.launch_manifest_path,
                expected_commit=config.product_commit,
                expected_build_input_sha256=config.build_input_sha256,
                expected_package_sha256=provenance["package_sha256"],
                expected_image_sha256=config.product_image_sha256,
                expected_image_reference=config.product_image_reference,
                expected_service=config.launch_service,
            )
        except AcceptanceProvenanceError as error:
            raise AcceptanceRunnerError(str(error)) from error
        self.product_package_sha256 = provenance["package_sha256"]
        self.launch_manifest_sha256 = launch_manifest_sha256
        self.corpus = verify_canonical_corpus(
            config.canonical_root,
            expected_manifest_sha256=config.manifest_sha256,
            expected_source_fingerprint=config.source_fingerprint,
            expected_canonical_manifest_sha256=config.canonical_manifest_sha256,
        )
        manifest = _canonical_manifest(config.canonical_root)
        self.corpus_commit = _string(manifest, "source_commit")
        self.corpus_generated_at = _string(manifest, "generated_at")
        files = manifest.get("files")
        if not isinstance(files, list) or not files:
            raise AcceptanceRunnerError("Canonical manifest has no semantic source inventory")
        expected_sources: list[tuple[str, str]] = []
        for item in files[:10]:
            if not isinstance(item, dict):
                raise AcceptanceRunnerError("Canonical semantic source inventory is invalid")
            path = _string(cast(dict[str, object], item), "path")
            digest = _string(cast(dict[str, object], item), "sha256")
            if not path.startswith("payload/") or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
                raise AcceptanceRunnerError("Canonical semantic source inventory is invalid")
            expected_sources.append((path.removeprefix("payload/"), digest))
        self.expected_sources = tuple(expected_sources)
        self.namespace = uuid.uuid5(uuid.NAMESPACE_URL, self.corpus.source_fingerprint)

    def _semantic_query(self) -> str:
        fragments = ["organization goals products decisions systems requirements"]
        for relative, _digest in self.expected_sources:
            path = self.config.canonical_root / "payload" / relative
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise AcceptanceRunnerError("Canonical semantic source is unreadable") from error
            fragments.append(relative.replace("/", " "))
            fragments.append(" ".join(text.split())[:240])
        return " ".join(fragments)[:500]

    def _validate_semantic_journey(
        self,
        state: ResumeState,
        *,
        search: dict[str, object],
        context: dict[str, object],
        canvas: dict[str, object],
    ) -> None:
        if set(search) != {"contract_version", "tool", "data", "next_cursor"} or (
            search.get("contract_version") != "1" or search.get("tool") != "anva.search"
        ):
            raise AcceptanceRunnerError("MCP search contract envelope is invalid")
        if set(context) != {"contract_version", "tool", "data"} or (
            context.get("contract_version") != "1"
            or context.get("tool") != "anva.get_context_packet"
        ):
            raise AcceptanceRunnerError("MCP context contract envelope is invalid")
        search_data = search.get("data")
        results = search_data.get("results") if isinstance(search_data, dict) else None
        if not isinstance(results, list) or not results:
            raise AcceptanceRunnerError("Canonical source was not retrievable through MCP search")
        context_data = context.get("data")
        packet = context_data.get("packet") if isinstance(context_data, dict) else None
        items = packet.get("items") if isinstance(packet, dict) else None
        if not isinstance(items, list) or not items:
            raise AcceptanceRunnerError("Canonical source was absent from the context packet")
        citations = [
            citation
            for item in items
            if isinstance(item, dict)
            for citation in cast(list[object], item.get("anva_sources", []))
            if isinstance(citation, dict)
        ]
        for relative, digest in self.expected_sources:
            search_match = any(
                isinstance(item, dict)
                and item.get("content_hash") == digest
                and str(item.get("canonical_url", "")).endswith(relative)
                for item in results
            )
            citation_match = any(
                item.get("source_content_hash") == digest
                and str(item.get("canonical_url", "")).endswith(relative)
                and all(
                    isinstance(item.get(key), str) and item.get(key)
                    for key in (
                        "source_location_id",
                        "source_observation_id",
                        "access_snapshot_id",
                    )
                )
                for item in citations
            )
            if not search_match or not citation_match:
                raise AcceptanceRunnerError(
                    "Canonical source path, content hash, or citation was not preserved"
                )
        nodes = canvas.get("nodes")
        edges = canvas.get("edges")
        repositories = canvas.get("repositories")
        counts = canvas.get("counts")
        if (
            canvas.get("schema_version") != "1"
            or not isinstance(nodes, list)
            or not nodes
            or not isinstance(edges, list)
            or not isinstance(repositories, list)
            or not any(
                isinstance(item, dict) and item.get("id") == state.identities["repository_id"]
                for item in repositories
            )
            or not isinstance(counts, dict)
            or counts != {"nodes": len(nodes), "edges": len(edges)}
            or not any(
                isinstance(node, dict)
                and isinstance(node.get("provenance"), dict)
                and cast(dict[str, object], node["provenance"]).get("kind") == "SOURCE_BACKED"
                and state.identities["repository_id"] in node.get("repository_ids", [])
                for node in nodes
            )
        ):
            raise AcceptanceRunnerError("Canvas lacks non-empty source-backed organization data")

    def _new_state(self, *, reference_time: str | None = None) -> ResumeState:
        committed_reference = reference_time or _run_reference_time(
            self.corpus_generated_at,
            now=datetime.now(UTC),
            sync_timeout_seconds=self.config.sync_timeout_seconds,
        )
        run_uuid = _uuid(self.namespace, f"acceptance-run:{committed_reference}")
        state = ResumeState(
            corpus_id=self.corpus.corpus_id,
            run_id=f"anva:{run_uuid}",
            reference_time=committed_reference,
            product_version=__version__,
            status="BOOTSTRAP_PREPARED",
            hashes={
                "manifest_sha256": self.corpus.manifest_sha256,
                "source_fingerprint": self.corpus.source_fingerprint,
                "canonical_manifest_sha256": self.corpus.canonical_manifest_sha256,
                "canonical_input_sha256": self.corpus.canonical_manifest_sha256,
                "product_commit": self.config.product_commit,
                "product_image_sha256": self.config.product_image_sha256,
                "build_input_sha256": self.config.build_input_sha256,
                "product_package_sha256": self.product_package_sha256,
                "launch_manifest_sha256": self.launch_manifest_sha256,
                "corpus_commit": self.corpus_commit,
                "reference_time_sha256": sha256_bytes(committed_reference.encode()),
                "base_commit": _hash40(f"{self.corpus.source_fingerprint}:base"),
                "head_commit": _hash40(f"{self.corpus.source_fingerprint}:head"),
                "new_head_commit": _hash40(f"{self.corpus.source_fingerprint}:new-head"),
            },
        )
        state.hashes["bootstrap_idempotency_sha256"] = sha256_bytes(
            f"bootstrap:{state.run_id}".encode()
        )
        state.hashes["bootstrap_request_sha256"] = sha256_bytes(
            canonical_bytes(self._bootstrap_payload(state, include_idempotency=False))
        )
        return state

    def _bootstrap_payload(
        self, state: ResumeState, *, include_idempotency: bool = True
    ) -> dict[str, object]:
        slug = f"anva-acceptance-{state.hashes['reference_time_sha256'][:12]}"
        payload: dict[str, object] = {
            "organization_slug": slug,
            "organization_name": f"Anva Acceptance {self.corpus.corpus_id}",
            "admin_email": f"{slug}@anva.invalid",
            "admin_display_name": "Anva acceptance operator",
            "repository_external_id": f"acceptance:{self.corpus.source_fingerprint}",
            "repository_name": self.corpus.corpus_id,
            "independent_reviewer_name": "Independent acceptance evaluator",
        }
        if include_idempotency:
            payload["idempotency_key"] = state.hashes["bootstrap_idempotency_sha256"]
        return payload

    def _load_matching_state(self) -> ResumeState:
        state = load_state(self.config.state_path)
        expected = self._new_state(reference_time=state.reference_time)
        for key, value in expected.hashes.items():
            if state.hashes.get(key) != value:
                raise AcceptanceRunnerError("Acceptance resume record does not match exact inputs")
        if (
            state.corpus_id != expected.corpus_id
            or state.run_id != expected.run_id
            or state.reference_time != expected.reference_time
            or state.product_version != expected.product_version
        ):
            raise AcceptanceRunnerError("Acceptance resume record does not match exact inputs")
        return state

    def _save(self, state: ResumeState) -> None:
        save_state(self.config.state_path, state)

    def _bootstrap(self, bootstrap_secret: str, state: ResumeState) -> tuple[PublicAPI, str]:
        if not bootstrap_secret:
            raise AcceptanceRunnerError("Bootstrap secret is required for a fresh run")
        response = (
            PublicAPI(self.config.api_url)
            .request(
                "POST",
                "/bootstrap",
                payload=self._bootstrap_payload(state),
                headers={"X-Anva-Bootstrap-Secret": bootstrap_secret},
                expected=frozenset({201}),
            )
            .payload
        )
        token = _string(response, "token")
        reviewer_token = _string(response, "reviewer_token")
        if response.get("bootstrap_request_sha256") != state.hashes["bootstrap_request_sha256"]:
            raise AcceptanceRunnerError(
                "Recovered bootstrap does not match the precommitted request"
            )
        for key in ("organization_id", "repository_id", "access_scope_id"):
            state.identities[key] = _string(response, key)
        if self.config.credential_output is None:
            raise AcceptanceRunnerError("A fresh run requires a one-time credential output path")
        _write_secret_handoff(
            self.config.credential_output,
            {
                "schema_version": 1,
                "run_id": state.run_id,
                "bootstrap_request_sha256": state.hashes["bootstrap_request_sha256"],
                "organization_id": state.identities["organization_id"],
                "repository_id": state.identities["repository_id"],
                "access_scope_id": state.identities["access_scope_id"],
                "anva_token": token,
                "reviewer_token": reviewer_token,
                "expires_at": _string(response, "expires_at"),
                "reviewer_expires_at": _string(response, "reviewer_expires_at"),
            },
        )
        state.status = "PREPARING"
        self._save(state)
        return PublicAPI(self.config.api_url, token), token

    def _reconcile_bootstrap_handoff(self, state: ResumeState) -> tuple[PublicAPI, str] | None:
        path = self.config.credential_output
        if path is None or not path.exists():
            return None
        handoff = _read_secret_handoff(path)
        if (
            handoff.get("schema_version") != 1
            or handoff.get("run_id") != state.run_id
            or handoff.get("bootstrap_request_sha256") != state.hashes["bootstrap_request_sha256"]
        ):
            raise AcceptanceRunnerError("Bootstrap credential handoff does not match this run")
        for key in ("organization_id", "repository_id", "access_scope_id"):
            state.identities[key] = _string(handoff, key)
        token = _string(handoff, "anva_token")
        _string(handoff, "reviewer_token")
        _string(handoff, "expires_at")
        _string(handoff, "reviewer_expires_at")
        state.status = "PREPARING"
        self._save(state)
        return PublicAPI(self.config.api_url, token), token

    def _wait_for_sync(self, api: PublicAPI, source_id: str, sync_id: str) -> None:
        deadline = time.monotonic() + self.config.sync_timeout_seconds
        while time.monotonic() < deadline:
            payload = api.request("GET", f"/source-connections/{source_id}/sync-runs").payload
            runs = payload.get("sync_runs")
            if not isinstance(runs, list):
                raise AcceptanceRunnerError("Source sync response is invalid")
            selected = next(
                (item for item in runs if isinstance(item, dict) and item.get("id") == sync_id),
                None,
            )
            if selected is not None:
                status = selected.get("state")
                if status in TERMINAL_SYNC_STATES:
                    if status != "COMPLETED":
                        raise AcceptanceRunnerError("Canonical source sync failed")
                    return
            time.sleep(0.5)
        raise AcceptanceRunnerError("Canonical source sync did not complete before its bound")

    def _work_payload(self, state: ResumeState) -> dict[str, object]:
        organization_id = state.identities["organization_id"]
        repository_id = state.identities["repository_id"]
        access_scope_id = state.identities["access_scope_id"]
        return {
            "schema_version": "1.0",
            "organization_id": organization_id,
            "repository_id": repository_id,
            "access_scope_id": access_scope_id,
            "work_item_id": _uuid(_state_namespace(state), "work-item"),
            "external_key": f"ACCEPTANCE-{self.corpus.source_fingerprint[:16]}",
            "origin": "sealed-acceptance",
            "work_type": "FEATURE",
            "title": "Exercise exact-head production acceptance",
            "summary": "Validate connected context, governance, evidence, and assurance.",
            "status": "READY",
            "revision": 1,
            "source_references": [f"acceptance:{self.corpus.source_fingerprint}"],
            "requirements": [
                {
                    "code": "REQ_EXACT_HEAD",
                    "normalized_text": (
                        "Readiness uses only evidence for the exact pull request head."
                    ),
                    "origin": "acceptance",
                    "owner": "platform",
                    "status": "CONFIRMED",
                    "source_references": [f"acceptance:{self.corpus.source_fingerprint}"],
                    "related_entity_ids": [],
                    "requires_approval": False,
                }
            ],
            "acceptance_criteria": [
                {
                    "code": "EXACT_HEAD_PROOF",
                    "requirement_code": "REQ_EXACT_HEAD",
                    "normalized_text": "Exact-head acceptance evidence is present.",
                    "required_evidence_types": ["TEST_RESULT"],
                    "manual_approval_allowed": False,
                }
            ],
            "non_requirements": [],
            "assumptions": [],
            "decisions": [],
            "summaries": [],
        }

    def _policy_payload(self, state: ResumeState) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "organization_id": state.identities["organization_id"],
            "access_scope_id": state.identities["access_scope_id"],
            "policy_id": _uuid(_state_namespace(state), "policy"),
            "version": 1,
            "name": "Exact-head acceptance",
            "owner": "platform",
            "status": "ACTIVE",
            "effective_at": state.reference_time,
            "expires_at": None,
            "binding": {
                "scope_level": "REPOSITORY",
                "repository_ids": [state.identities["repository_id"]],
                "entity_ids": [],
                "entity_types": [],
                "path_patterns": [],
                "target_branches": ["main"],
                "work_item_types": [],
                "mandatory": True,
            },
            "requirements": [
                {
                    "requirement_id": _uuid(_state_namespace(state), "policy-requirement"),
                    "code": "EXACT_HEAD_PROOF",
                    "description": "Exact-head acceptance evidence is required.",
                    "enforcement": "BLOCKING",
                    "check_type": "EVIDENCE",
                    "required_evidence": ["TEST_RESULT"],
                    "required_approval": False,
                    "required_reviewers": [],
                    "report_sections": ["tests"],
                }
            ],
        }

    def _diff_payload(
        self, state: ResumeState, head: str, *, suffix: str = ""
    ) -> dict[str, object]:
        return {
            "access_scope_id": state.identities["access_scope_id"],
            "base_commit": state.hashes["base_commit"],
            "head_commit": head,
            "title": f"Acceptance exact-head change{suffix}",
            "description": "Bounded synthetic diff supplied through the public manual-diff API.",
            "target_branch": "main",
            "is_draft": False,
            "state": "OPEN",
            "unified_diff": (
                "diff --git a/acceptance/candidate.py b/acceptance/candidate.py\n"
                "--- a/acceptance/candidate.py\n"
                "+++ b/acceptance/candidate.py\n"
                "@@ -1,1 +1,2 @@\n"
                " value = 1\n"
                f"+head = '{head}'\n"
            ),
        }

    def _submit_evidence(self, api: PublicAPI, state: ResumeState) -> list[str]:
        repository_id = state.identities["repository_id"]
        head = state.hashes["head_commit"]
        evidence_bytes = canonical_bytes(
            {
                "schema_version": 1,
                "head_sha": head,
                "checks": [{"name": "EXACT_HEAD_PROOF", "status": "PASSED"}],
            }
        )
        evidence_hash = sha256_bytes(evidence_bytes)
        if "evidence_blob_id" not in state.identities:
            idempotency_key = f"acceptance-upload-{evidence_hash}"
            authorization: dict[str, object] | None = None
            upload_token: str | None = None
            # An upload secret is deliberately disclosed only once. If a process
            # dies after issuance or acceptance but before saving the blob id, a
            # replay safely returns the opaque authorization id and no secret.
            # Derive a new bounded idempotency key from that public id so a fresh
            # process can continue without persisting any upload credential.
            for _attempt in range(16):
                authorization = api.request(
                    "POST",
                    (
                        f"/repositories/{repository_id}/pull-requests/817/"
                        "evidence-upload-authorizations"
                    ),
                    payload={
                        "schema_version": "1.0",
                        "access_scope_id": state.identities["access_scope_id"],
                        "commit_sha": head,
                        "filename": "exact-head-result.json",
                        "declared_sha256": evidence_hash,
                        "declared_size": len(evidence_bytes),
                        "idempotency_key": idempotency_key,
                    },
                    expected=frozenset({200, 201}),
                ).payload
                candidate = authorization.get("upload_token")
                if isinstance(candidate, str) and candidate:
                    upload_token = candidate
                    break
                authorization_id = _string(authorization, "authorization_id")
                idempotency_key = (
                    "acceptance-upload-"
                    + hashlib.sha256(f"{idempotency_key}:{authorization_id}".encode()).hexdigest()
                )
            if authorization is None or upload_token is None:
                raise AcceptanceRunnerError(
                    "Evidence upload could not obtain a fresh bounded authorization"
                )
            upload = api.request(
                "PUT",
                _string(authorization, "upload_path").removeprefix("/api/v1"),
                content=evidence_bytes,
                headers={
                    "X-Anva-Evidence-Upload-Token": upload_token,
                    "X-Anva-Content-SHA256": evidence_hash,
                },
                expected=frozenset({201}),
            ).payload
            state.identities["evidence_blob_id"] = _string(upload, "evidence_blob_id")
            self._save(state)
        instant = datetime.fromisoformat(state.reference_time.replace("Z", "+00:00"))
        expires = instant + timedelta(days=365)
        manifest = {
            "schema_version": "1.0",
            "manifest_id": _uuid(_state_namespace(state), "evidence-manifest"),
            "organization_id": state.identities["organization_id"],
            "repository_id": repository_id,
            "access_scope_id": state.identities["access_scope_id"],
            "pull_request_number": 817,
            "work_item_revision_id": state.identities["work_item_revision_id"],
            "commit_sha": head,
            "created_at": state.reference_time,
            "producer": "anva-acceptance-runner",
            "producer_version": __version__,
            "producer_mode": "MANUAL",
            "entries": [
                {
                    "evidence_id": _uuid(_state_namespace(state), "evidence"),
                    "kind": "TEST_RESULT",
                    "name": "Exact-head public boundary acceptance",
                    "status": "PASSED",
                    "command": "anva acceptance start",
                    "artifact_reference": "accepted/exact-head-result.json",
                    "artifact_blob_id": state.identities["evidence_blob_id"],
                    "source_url": None,
                    "content_hash": evidence_hash,
                    "started_at": state.reference_time,
                    "completed_at": state.reference_time,
                    "producer": "anva-acceptance-runner",
                    "producer_version": __version__,
                    "approval_id": None,
                    "retention_class": "ASSURANCE_1Y",
                    "retention_expires_at": expires.astimezone(UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "limitations": ["External provider execution is outside this runner."],
                    "criterion_codes": ["EXACT_HEAD_PROOF"],
                    "environment": "sealed-acceptance",
                    "scenario": "TST-007",
                }
            ],
        }
        response = api.request(
            "POST",
            f"/repositories/{repository_id}/pull-requests/817/evidence",
            payload=manifest,
            expected=frozenset({200, 201}),
        ).payload
        state.identities["evidence_manifest_id"] = _string(response, "manifest_id")
        evidence_ids = response.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not all(
            isinstance(item, str) for item in evidence_ids
        ):
            raise AcceptanceRunnerError("Evidence response is invalid")
        self._save(state)
        return cast(list[str], evidence_ids)

    def _start_assurance(
        self,
        api: PublicAPI,
        state: ResumeState,
        revision_id: str,
        evidence_ids: list[str],
        *,
        trigger: str,
    ) -> dict[str, object]:
        return api.request(
            "POST",
            f"/pull-request-revisions/{revision_id}/assurance-runs",
            payload={
                "policy_version_ids": [state.identities["policy_version_id"]],
                "reference_time": state.reference_time,
                "deterministic_checks": [
                    {
                        "code": "EXACT_HEAD_PROOF",
                        "status": "PASSED",
                        "blocking": True,
                        "summary": "Exact-head evidence was accepted through public boundaries.",
                        "evidence_ids": evidence_ids,
                    }
                ],
                "work_item_revision_id": state.identities["work_item_revision_id"],
                "evaluator_version": "external-acceptance-v1",
                "prompt_version": "acceptance-review-v1",
                "trigger_key": hashlib.sha256(trigger.encode()).hexdigest(),
            },
            expected=frozenset({200, 201}),
        ).payload

    def start(self, *, bootstrap_secret: str | None, token: str | None) -> ResumeState:
        if self.config.state_path.exists():
            state = self._load_matching_state()
            if state.status == "BOOTSTRAP_PREPARED":
                reconciled = self._reconcile_bootstrap_handoff(state)
                if reconciled is None:
                    api, active_token = self._bootstrap(bootstrap_secret or "", state)
                else:
                    api, active_token = reconciled
            elif state.status != "PREPARING":
                return state
            else:
                if not token:
                    raise AcceptanceRunnerError("ANVA_ACCEPTANCE_TOKEN is required to resume")
                api = PublicAPI(self.config.api_url, token)
                active_token = token
        else:
            state = self._new_state()
            self._save(state)
            api, active_token = self._bootstrap(bootstrap_secret or "", state)
        mcp: MCPBoundary = StreamableHTTPMCP(self.config.mcp_url, active_token)

        source = api.request(
            "POST",
            "/source-connections/filesystem",
            payload={
                "repository_id": state.identities["repository_id"],
                "access_scope_id": state.identities["access_scope_id"],
                "external_key": f"acceptance:{self.corpus.source_fingerprint}",
                "display_name": self.corpus.corpus_id,
                "root": f"{self.config.canonical_root.as_posix()}/payload",
            },
            expected=frozenset({200, 201}),
        ).payload
        state.identities["source_connection_id"] = _string(source, "id")
        self._save(state)
        sync = api.request(
            "POST",
            f"/source-connections/{state.identities['source_connection_id']}/sync",
            payload={"scan_mode": "FULL"},
            expected=frozenset({202}),
        ).payload
        state.identities["sync_run_id"] = _string(sync, "id")
        self._save(state)
        self._wait_for_sync(
            api,
            state.identities["source_connection_id"],
            state.identities["sync_run_id"],
        )
        search = mcp.call(
            "anva.search",
            {
                "contract_version": "1",
                "repository_id": state.identities["repository_id"],
                "query": self._semantic_query(),
                "phase": "PREPARE",
                "limit": 50,
            },
        )
        context = mcp.call(
            "anva.get_context_packet",
            {
                "contract_version": "1",
                "repository_id": state.identities["repository_id"],
                "task": (
                    "Review an exact-head acceptance change against connected organization context"
                ),
                "phase": "ASSURANCE",
                "budget": {
                    "max_items": 50,
                    "max_tokens": 8000,
                    "max_bytes": 100000,
                    "max_citations": 100,
                },
            },
        )
        canvas = api.request(
            "POST",
            "/canvas/query",
            payload={
                "repository_ids": [state.identities["repository_id"]],
                "layers": ["execution", "dependencies", "governance", "provenance"],
                "depth": 4,
                "node_limit": 300,
                "edge_limit": 600,
            },
        ).payload
        self._validate_semantic_journey(
            state,
            search=search,
            context=context,
            canvas=canvas,
        )

        work = api.request(
            "POST",
            "/work-items/import",
            payload=self._work_payload(state),
            expected=frozenset({200, 201}),
        ).payload
        state.identities["work_item_id"] = _string(work, "work_item_id")
        state.identities["work_item_revision_id"] = _string(work, "work_item_revision_id")
        self._save(state)
        policy = api.request(
            "POST",
            "/policies/import",
            payload=self._policy_payload(state),
            expected=frozenset({200, 201}),
        ).payload
        state.identities["policy_id"] = _string(policy, "policy_id")
        state.identities["policy_version_id"] = _string(policy, "policy_version_id")
        self._save(state)
        api.request(
            "POST",
            "/policies/simulate",
            payload={
                "repository_id": state.identities["repository_id"],
                "pull_request_number": 817,
                "commit_sha": state.hashes["head_commit"],
                "policy_version_ids": [state.identities["policy_version_id"]],
                "reference_time": state.reference_time,
                "affected_paths": ["acceptance/candidate.py"],
                "affected_entities": [],
                "target_branch": "main",
                "work_item_revision_id": state.identities["work_item_revision_id"],
            },
            expected=frozenset({200, 201}),
        )
        primary = api.request(
            "POST",
            f"/repositories/{state.identities['repository_id']}/pull-requests/817/manual-diff",
            payload=self._diff_payload(state, state.hashes["head_commit"]),
            expected=frozenset({200, 201}),
        ).payload
        state.identities["pull_request_revision_id"] = _string(primary, "pull_request_revision_id")
        state.hashes["diff_hash"] = _string(primary, "diff_hash")
        self._save(state)
        evidence_ids = self._submit_evidence(api, state)
        started = self._start_assurance(
            api,
            state,
            state.identities["pull_request_revision_id"],
            evidence_ids,
            trigger=f"{state.run_id}:primary",
        )
        state.identities["assurance_run_id"] = _string(started, "assurance_run_id")
        state.identities["evaluator_task_id"] = _string(started, "evaluator_task_id")
        state.hashes["input_hash"] = _string(started, "input_hash")
        self._save(state)

        probe_first = api.request(
            "POST",
            f"/repositories/{state.identities['repository_id']}/pull-requests/818/manual-diff",
            payload=self._diff_payload(state, state.hashes["head_commit"], suffix=" stale probe"),
            expected=frozenset({200, 201}),
        ).payload
        probe_run = self._start_assurance(
            api,
            state,
            _string(probe_first, "pull_request_revision_id"),
            [],
            trigger=f"{state.run_id}:stale-probe",
        )
        state.identities["stale_probe_run_id"] = _string(probe_run, "assurance_run_id")
        self._save(state)
        api.request(
            "POST",
            f"/repositories/{state.identities['repository_id']}/pull-requests/818/manual-diff",
            payload=self._diff_payload(state, state.hashes["new_head_commit"], suffix=" new head"),
            expected=frozenset({201}),
        )
        stale = api.request(
            "GET", f"/assurance-runs/{state.identities['stale_probe_run_id']}"
        ).payload
        if stale.get("state") != "STALE" or stale.get("readiness") != "STALE":
            raise AcceptanceRunnerError("A newer head did not stale the prior assurance run")
        state.status = "AWAITING_EXTERNAL_REVIEW"
        self._save(state)
        return state

    def create_review_handoff(self, *, reviewer_token: str, output: Path) -> ResumeState:
        state = self._load_matching_state()
        if state.status == "REVIEW_CLAIMED":
            handoff = _read_secret_handoff(output)
            if sha256_bytes(canonical_bytes(handoff)) != state.hashes.get("review_handoff_sha256"):
                raise AcceptanceRunnerError(
                    "External-review handoff does not match the resume record"
                )
            return state
        if state.status not in {"AWAITING_EXTERNAL_REVIEW", "REVIEW_CLAIMING"}:
            raise AcceptanceRunnerError("Acceptance run is not awaiting external review")
        if output.exists() or output.is_symlink():
            handoff = _read_secret_handoff(output)
            if (
                handoff.get("run_id") != state.run_id
                or handoff.get("task_id") != state.identities["evaluator_task_id"]
            ):
                raise AcceptanceRunnerError("External-review handoff identity is invalid")
            state.hashes["review_handoff_sha256"] = sha256_bytes(canonical_bytes(handoff))
            state.status = "REVIEW_CLAIMED"
            self._save(state)
            return state
        if state.status == "AWAITING_EXTERNAL_REVIEW":
            state.hashes["review_claim_idempotency_sha256"] = sha256_bytes(
                f"review-claim:{state.run_id}:{state.identities['evaluator_task_id']}".encode()
            )
            state.status = "REVIEW_CLAIMING"
            self._save(state)
        api = PublicAPI(self.config.api_url, reviewer_token)
        claim = api.request(
            "POST",
            f"/repositories/{state.identities['repository_id']}/evaluator-tasks/claim",
            payload={
                "claimant": "independent-acceptance-evaluator",
                "lease_seconds": 3600,
                "claim_idempotency_key": state.hashes["review_claim_idempotency_sha256"],
            },
        ).payload
        if (
            claim.get("status") == "EMPTY"
            or _string(claim, "task_id") != state.identities["evaluator_task_id"]
        ):
            raise AcceptanceRunnerError("Independent evaluator task was not available")
        request = claim.get("request")
        if not isinstance(request, dict):
            raise AcceptanceRunnerError("Independent evaluator request is invalid")
        handoff = {
            "schema_version": 1,
            "run_id": state.run_id,
            "task_id": state.identities["evaluator_task_id"],
            "claim_token": _string(claim, "claim_token"),
            "request": request,
        }
        _write_secret_handoff(output, handoff)
        state.hashes["review_handoff_sha256"] = sha256_bytes(canonical_bytes(handoff))
        state.status = "REVIEW_CLAIMED"
        self._save(state)
        return state

    def _validated_review_inputs(
        self, state: ResumeState, handoff_path: Path, result_path: Path
    ) -> tuple[dict[str, object], dict[str, object], str]:
        handoff = _read_secret_handoff(handoff_path)
        if sha256_bytes(canonical_bytes(handoff)) != state.hashes.get("review_handoff_sha256"):
            raise AcceptanceRunnerError("External-review handoff does not match the resume record")
        if (
            handoff.get("run_id") != state.run_id
            or handoff.get("task_id") != state.identities["evaluator_task_id"]
        ):
            raise AcceptanceRunnerError("External-review handoff identity is invalid")
        if (
            result_path.is_symlink()
            or not result_path.is_file()
            or result_path.stat().st_size > 1_200_000
        ):
            raise AcceptanceRunnerError("External evaluator result is unsafe")
        value = json.loads(result_path.read_bytes())
        if not isinstance(value, dict):
            raise AcceptanceRunnerError("External evaluator result is invalid")
        result = cast(dict[str, object], value)
        validate_payload("evaluator-result", result)
        request = handoff.get("request")
        if not isinstance(request, dict):
            raise AcceptanceRunnerError("External-review handoff request is invalid")
        if (
            result.get("request_id") != request.get("request_id")
            or result.get("organization_id") != state.identities["organization_id"]
            or result.get("commit_sha") != state.hashes["head_commit"]
        ):
            raise AcceptanceRunnerError("External evaluator result does not match the exact run")
        return handoff, result, sha256_bytes(canonical_bytes(result))

    def submit_review(
        self, *, reviewer_token: str, handoff_path: Path, result_path: Path
    ) -> ResumeState:
        state = self._load_matching_state()
        if state.status in {"EXTERNAL_REVIEW_SUBMITTED", "COMPLETE"}:
            if handoff_path.exists() or handoff_path.is_symlink():
                _handoff, _result, digest = self._validated_review_inputs(
                    state, handoff_path, result_path
                )
                if digest != state.hashes.get("review_result_sha256"):
                    raise AcceptanceRunnerError(
                        "External evaluator result does not match the submitted review"
                    )
                handoff_path.unlink()
            return state
        if state.status not in {"REVIEW_CLAIMED", "REVIEW_SUBMITTING"}:
            raise AcceptanceRunnerError("Acceptance run does not have a claimed external review")
        handoff, result, result_digest = self._validated_review_inputs(
            state, handoff_path, result_path
        )
        if state.status == "REVIEW_CLAIMED":
            state.status = "REVIEW_SUBMITTING"
            self._save(state)
        response = (
            PublicAPI(self.config.api_url, reviewer_token)
            .request(
                "POST",
                f"/evaluator-tasks/{state.identities['evaluator_task_id']}/submit",
                payload={"claim_token": _string(handoff, "claim_token"), "result": result},
                expected=frozenset({200, 201}),
            )
            .payload
        )
        if _string(response, "assurance_run_id") != state.identities["assurance_run_id"]:
            raise AcceptanceRunnerError("External evaluator submission returned the wrong run")
        state.identities["report_id"] = _string(response, "report_id")
        state.hashes["review_result_sha256"] = result_digest
        state.status = "EXTERNAL_REVIEW_SUBMITTED"
        self._save(state)
        handoff_path.unlink(missing_ok=True)
        return state

    def finalize(self, *, token: str, mcp: MCPBoundary | None = None) -> ResumeState:
        state = self._load_matching_state()
        if state.status == "COMPLETE":
            observed = self._verify_existing_seal(state)
            if observed != state.hashes.get("sealed_manifest_sha256"):
                raise AcceptanceRunnerError("Sealed acceptance manifest no longer matches state")
            return state
        if state.status != "EXTERNAL_REVIEW_SUBMITTED":
            raise AcceptanceRunnerError("Authenticated external review has not been submitted")
        if self.config.output_root.exists() or self.config.output_root.is_symlink():
            state.hashes["sealed_manifest_sha256"] = self._verify_existing_seal(state)
            state.status = "COMPLETE"
            self._save(state)
            return state
        api = PublicAPI(self.config.api_url, token)
        run = api.request("GET", f"/assurance-runs/{state.identities['assurance_run_id']}").payload
        if (
            run.get("state") != "COMPLETED"
            or run.get("head_commit") != state.hashes["head_commit"]
            or run.get("readiness") == "STALE"
        ):
            raise AcceptanceRunnerError("Assurance completion is not for the exact current head")
        boundary = mcp or StreamableHTTPMCP(self.config.mcp_url, token)
        search = boundary.call(
            "anva.search",
            {
                "contract_version": "1",
                "repository_id": state.identities["repository_id"],
                "query": self._semantic_query(),
                "phase": "ASSURANCE",
                "limit": 50,
            },
        )
        context = boundary.call(
            "anva.get_context_packet",
            {
                "contract_version": "1",
                "repository_id": state.identities["repository_id"],
                "task": (
                    "Review an exact-head acceptance change against connected organization context"
                ),
                "phase": "ASSURANCE",
                "budget": {
                    "max_items": 50,
                    "max_tokens": 8000,
                    "max_bytes": 100000,
                    "max_citations": 100,
                },
            },
        )
        canvas = api.request(
            "POST",
            "/canvas/query",
            payload={
                "repository_ids": [state.identities["repository_id"]],
                "layers": ["execution", "dependencies", "governance", "provenance"],
                "depth": 4,
                "node_limit": 300,
                "edge_limit": 600,
            },
        ).payload
        report = api.request(
            "GET", f"/assurance-runs/{state.identities['assurance_run_id']}/report"
        ).payload
        findings = api.request(
            "GET", f"/assurance-runs/{state.identities['assurance_run_id']}/findings"
        ).payload
        self._validate_semantic_journey(
            state,
            search=search,
            context=context,
            canvas=canvas,
        )
        sealed_hash = seal_results(
            output_root=self.config.output_root,
            corpus_id=state.corpus_id,
            manifest_sha256=state.hashes["manifest_sha256"],
            source_fingerprint=state.hashes["source_fingerprint"],
            run_id=state.run_id,
            started_at=state.reference_time,
            completed_at=state.reference_time,
            product_version=state.product_version,
            product_commit=state.hashes["product_commit"],
            product_image_sha256=state.hashes["product_image_sha256"],
            product_image_reference=self.config.product_image_reference,
            build_input_sha256=state.hashes["build_input_sha256"],
            product_package_sha256=state.hashes["product_package_sha256"],
            launch_manifest_sha256=state.hashes["launch_manifest_sha256"],
            corpus_commit=state.hashes["corpus_commit"],
            canonical_manifest_sha256=state.hashes["canonical_manifest_sha256"],
            canonical_input_sha256=state.hashes["canonical_input_sha256"],
            head_commit=state.hashes["head_commit"],
            assurance_input_sha256=state.hashes["input_hash"],
            reference_time_sha256=state.hashes["reference_time_sha256"],
            review_result_sha256=state.hashes["review_result_sha256"],
            search_output=search,
            context_output=context,
            canvas_output=canvas,
            report_output=report,
            findings_output=findings,
        )
        state.hashes["sealed_manifest_sha256"] = sealed_hash
        state.status = "COMPLETE"
        self._save(state)
        return state

    def _verify_existing_seal(self, state: ResumeState) -> str:
        return verify_sealed_results(
            output_root=self.config.output_root,
            corpus_id=state.corpus_id,
            manifest_sha256=state.hashes["manifest_sha256"],
            source_fingerprint=state.hashes["source_fingerprint"],
            run_id=state.run_id,
            reference_time=state.reference_time,
            product_version=state.product_version,
            product_commit=state.hashes["product_commit"],
            product_image_sha256=state.hashes["product_image_sha256"],
            product_image_reference=self.config.product_image_reference,
            build_input_sha256=state.hashes["build_input_sha256"],
            product_package_sha256=state.hashes["product_package_sha256"],
            launch_manifest_sha256=state.hashes["launch_manifest_sha256"],
            corpus_commit=state.hashes["corpus_commit"],
            canonical_input_sha256=state.hashes["canonical_input_sha256"],
            canonical_manifest_sha256=state.hashes["canonical_manifest_sha256"],
            head_commit=state.hashes["head_commit"],
            assurance_input_sha256=state.hashes["input_hash"],
            reference_time_sha256=state.hashes["reference_time_sha256"],
            review_result_sha256=state.hashes["review_result_sha256"],
        )
