"""Standalone public operation contracts for sealed acceptance drivers."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from copy import deepcopy
from functools import lru_cache
from typing import Final, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from anva.contracts.catalog import (
    EVALUATOR_REQUEST_SCHEMA,
    EXAMPLES,
    RETRIEVAL_CITATION,
)

UUID: Final[dict[str, str]] = {"type": "string", "format": "uuid"}
SHA256: Final[dict[str, str]] = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
COMMIT: Final[dict[str, str]] = {"type": "string", "pattern": "^[a-f0-9]{40}$"}
DATE_TIME: Final[dict[str, str]] = {"type": "string", "format": "date-time"}


def _closed(
    properties: dict[str, object],
    required: tuple[str, ...],
    *,
    one_of: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(required),
    }
    if one_of is not None:
        schema["oneOf"] = one_of
    return schema


def _nullable(schema: Mapping[str, object]) -> dict[str, object]:
    return {"oneOf": [deepcopy(dict(schema)), {"type": "null"}]}


STRING_LIST: Final[dict[str, object]] = {
    "type": "array",
    "items": {"type": "string", "maxLength": 2_000},
    "maxItems": 1_000,
}
UUID_LIST: Final[dict[str, object]] = {
    "type": "array",
    "items": UUID,
    "maxItems": 1_000,
    "uniqueItems": True,
}
BOUNDED_MAP: Final[dict[str, object]] = {
    "type": "object",
    "maxProperties": 200,
}

SOURCE_CONNECTION_REQUEST: Final[dict[str, object]] = _closed(
    {
        "repository_id": UUID,
        "access_scope_id": UUID,
        "external_key": {"type": "string", "minLength": 1, "maxLength": 300},
        "display_name": {"type": "string", "minLength": 1, "maxLength": 300},
        "root": {"type": "string", "minLength": 1, "maxLength": 1_000},
    },
    ("repository_id", "access_scope_id", "external_key", "display_name", "root"),
)
SYNC_START_REQUEST: Final[dict[str, object]] = _closed(
    {"scan_mode": {"type": "string", "enum": ["FULL", "INCREMENTAL"]}},
    (),
)
SOURCE_CONNECTION_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "state": {
            "type": "string",
            "enum": [
                "DRAFT",
                "AUTHORIZING",
                "ACTIVE",
                "DEGRADED",
                "REVOKED",
                "DISABLED",
                "FAILED",
            ],
        },
        "revision": {"type": "integer", "minimum": 1},
        "created": {"type": "boolean"},
    },
    ("id", "state", "revision", "created"),
)
SYNC_START_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "source_connection_id": UUID,
        "access_snapshot_id": UUID,
        "scan_mode": {"type": "string", "enum": ["FULL", "INCREMENTAL"]},
        "state": {
            "type": "string",
            "enum": [
                "REQUESTED",
                "DISCOVERING",
                "FETCHING",
                "PARSING",
                "INDEXING",
                "EXTRACTING",
                "RESOLVING",
                "PUBLISHING",
            ],
        },
        "created": {"type": "boolean"},
    },
    ("id", "source_connection_id", "access_snapshot_id", "scan_mode", "state", "created"),
)
SYNC_STATUS: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "state": {
            "type": "string",
            "enum": [
                "REQUESTED",
                "DISCOVERING",
                "FETCHING",
                "PARSING",
                "INDEXING",
                "EXTRACTING",
                "RESOLVING",
                "PUBLISHING",
                "COMPLETED",
                "PARTIALLY_COMPLETED",
                "FAILED",
                "CANCELLED",
            ],
        },
        "scan_mode": {"type": "string", "enum": ["FULL", "INCREMENTAL"]},
        "discovered_count": {"type": "integer", "minimum": 0},
        "processed_count": {"type": "integer", "minimum": 0},
        "failed_count": {"type": "integer", "minimum": 0},
        "tombstoned_count": {"type": "integer", "minimum": 0},
        "failure_code": {"type": "string", "maxLength": 100},
        "started_at": DATE_TIME,
        "completed_at": _nullable(DATE_TIME),
    },
    (
        "id",
        "state",
        "scan_mode",
        "discovered_count",
        "processed_count",
        "failed_count",
        "tombstoned_count",
        "failure_code",
        "started_at",
        "completed_at",
    ),
)
SYNC_RUNS_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "sync_runs": {
            "type": "array",
            "items": SYNC_STATUS,
            "maxItems": 50,
        }
    },
    ("sync_runs",),
)

CANVAS_PROVENANCE: Final[dict[str, object]] = _closed(
    {
        "kind": {"type": "string", "enum": ["SOURCE_BACKED", "INFERENCE", "IDENTITY_ONLY"]},
        "observed_at": _nullable(DATE_TIME),
        "confidence": _nullable({"type": "number", "minimum": 0, "maximum": 1}),
    },
    ("kind", "observed_at", "confidence"),
)
CANVAS_NODE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "type": {"type": "string", "minLength": 1, "maxLength": 100},
        "label": {"type": "string", "minLength": 1, "maxLength": 500},
        "canonical_key": {"type": "string", "minLength": 1, "maxLength": 500},
        "owner": {"type": "string", "maxLength": 300},
        "status": {"type": "string", "maxLength": 100},
        "risk": {"type": "string", "maxLength": 100},
        "freshness": {"type": "string", "enum": ["CURRENT", "STALE", "UNKNOWN"]},
        "is_inferred": {"type": "boolean"},
        "has_conflict": {"type": "boolean"},
        "provenance": CANVAS_PROVENANCE,
        "repository_ids": UUID_LIST,
        "position": _closed(
            {"x": {"type": "number"}, "y": {"type": "number"}},
            ("x", "y"),
        ),
        "is_pinned": {"type": "boolean"},
        "revision": {"type": "integer", "minimum": 1},
    },
    (
        "id",
        "type",
        "label",
        "canonical_key",
        "owner",
        "status",
        "risk",
        "freshness",
        "is_inferred",
        "has_conflict",
        "provenance",
        "repository_ids",
        "position",
        "is_pinned",
        "revision",
    ),
)
CANVAS_EDGE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "type": {"type": "string", "minLength": 1, "maxLength": 100},
        "source": UUID,
        "target": UUID,
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "observed_at": DATE_TIME,
        "repository_id": UUID,
        "directed": {"type": "boolean", "const": True},
        "review_state": {"type": "string", "maxLength": 100},
        "freshness": {"type": "string", "enum": ["CURRENT", "STALE", "UNKNOWN"]},
        "basis": {"type": "string", "maxLength": 100},
        "provenance": _closed({"assertion_id": UUID}, ("assertion_id",)),
    },
    (
        "id",
        "type",
        "source",
        "target",
        "confidence",
        "observed_at",
        "repository_id",
        "directed",
        "review_state",
        "freshness",
        "basis",
        "provenance",
    ),
)
CANVAS_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "schema_version": {"type": "string", "const": "1"},
        "semantic_query": BOUNDED_MAP,
        "view": _closed(
            {
                "id": _nullable(UUID),
                "name": {"type": "string", "minLength": 1, "maxLength": 300},
                "type": {"type": "string", "minLength": 1, "maxLength": 100},
                "revision": {"type": "integer", "minimum": 0},
                "content_hash": {"type": "string", "pattern": "^(?:|[a-f0-9]{64})$"},
            },
            ("id", "name", "type", "revision", "content_hash"),
        ),
        "repositories": {
            "type": "array",
            "items": _closed(
                {"id": UUID, "name": {"type": "string", "minLength": 1, "maxLength": 300}},
                ("id", "name"),
            ),
            "maxItems": 100,
        },
        "nodes": {"type": "array", "items": CANVAS_NODE, "maxItems": 500},
        "edges": {"type": "array", "items": CANVAS_EDGE, "maxItems": 1_000},
        "annotations": {"type": "array", "items": BOUNDED_MAP, "maxItems": 100},
        "counts": _closed(
            {
                "nodes": {"type": "integer", "minimum": 0, "maximum": 500},
                "edges": {"type": "integer", "minimum": 0, "maximum": 1_000},
            },
            ("nodes", "edges"),
        ),
        "limits": _closed(
            {
                "nodes": {"type": "integer", "minimum": 1, "maximum": 500},
                "edges": {"type": "integer", "minimum": 1, "maximum": 1_000},
                "depth": {"type": "integer", "minimum": 1, "maximum": 6},
                "repositories": {"type": "integer", "minimum": 1, "maximum": 100},
                "payload_bytes": {"type": "integer", "minimum": 1, "maximum": 768_000},
            },
            ("nodes", "edges", "depth", "repositories", "payload_bytes"),
        ),
        "truncated": {"type": "boolean"},
        "limitations": STRING_LIST,
        "layout": _closed(
            {
                "algorithm": {"type": "string", "minLength": 1, "maxLength": 100},
                "version": {"type": "string", "minLength": 1, "maxLength": 100},
                "checksum": SHA256,
            },
            ("algorithm", "version", "checksum"),
        ),
        "generated_at": DATE_TIME,
        "as_of": _nullable(DATE_TIME),
    },
    (
        "schema_version",
        "semantic_query",
        "view",
        "repositories",
        "nodes",
        "edges",
        "annotations",
        "counts",
        "limits",
        "truncated",
        "limitations",
        "layout",
        "generated_at",
        "as_of",
    ),
)

WORK_IMPORT_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "work_item_id": UUID,
        "work_item_revision_id": UUID,
        "revision": {"type": "integer", "minimum": 1},
        "content_hash": SHA256,
        "created": {"type": "boolean"},
    },
    ("work_item_id", "work_item_revision_id", "revision", "content_hash", "created"),
)
POLICY_IMPORT_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "policy_id": UUID,
        "policy_version_id": UUID,
        "version": {"type": "integer", "minimum": 1},
        "content_hash": SHA256,
        "created": {"type": "boolean"},
    },
    ("policy_id", "policy_version_id", "version", "content_hash", "created"),
)
POLICY_SIMULATION_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "policy_evaluation_id": UUID,
        "input_hash": SHA256,
        "output_hash": SHA256,
        "output": BOUNDED_MAP,
        "created": {"type": "boolean"},
    },
    ("policy_evaluation_id", "input_hash", "output_hash", "output", "created"),
)
EVIDENCE_MANIFEST_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "manifest_id": UUID,
        "payload_hash": SHA256,
        "evidence_ids": UUID_LIST,
        "created": {"type": "boolean"},
    },
    ("manifest_id", "payload_hash", "evidence_ids", "created"),
)
EVIDENCE_MANIFEST_DETAIL_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "repository_id": UUID,
        "pull_request_number": {"type": "integer", "minimum": 1},
        "commit_sha": COMMIT,
        "payload_hash": SHA256,
        "manifest": BOUNDED_MAP,
    },
    ("id", "repository_id", "pull_request_number", "commit_sha", "payload_hash", "manifest"),
)
MANUAL_DIFF_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "pull_request_id": UUID,
        "pull_request_revision_id": UUID,
        "revision": {"type": "integer", "minimum": 1},
        "head_commit": COMMIT,
        "diff_artifact_id": UUID,
        "diff_hash": SHA256,
        "changed_paths": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 1_000},
            "maxItems": 500,
            "uniqueItems": True,
        },
        "classification_summary": {
            "type": "object",
            "additionalProperties": {"type": "integer", "minimum": 0},
            "maxProperties": 16,
        },
        "limitations": STRING_LIST,
        "created": {"type": "boolean"},
    },
    (
        "pull_request_id",
        "pull_request_revision_id",
        "revision",
        "head_commit",
        "diff_artifact_id",
        "diff_hash",
        "changed_paths",
        "classification_summary",
        "limitations",
        "created",
    ),
)
ASSURANCE_START_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "assurance_run_id": UUID,
        "evaluator_task_id": UUID,
        "state": {"type": "string", "minLength": 1, "maxLength": 32},
        "head_commit": COMMIT,
        "input_hash": SHA256,
        "created": {"type": "boolean"},
    },
    ("assurance_run_id", "evaluator_task_id", "state", "head_commit", "input_hash", "created"),
)
ASSURANCE_DETAIL_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "state": {"type": "string", "minLength": 1, "maxLength": 32},
        "readiness": _nullable({"type": "string", "minLength": 1, "maxLength": 64}),
        "revision": {"type": "integer", "minimum": 1},
        "pull_request_number": {"type": "integer", "minimum": 1},
        "pull_request_revision_id": UUID,
        "head_commit": COMMIT,
        "input_hash": SHA256,
        "requirements_hash": SHA256,
        "policy_bundle_hash": SHA256,
        "evidence_bundle_hash": SHA256,
        "evaluator_version": {"type": "string", "minLength": 1, "maxLength": 100},
        "prompt_version": {"type": "string", "minLength": 1, "maxLength": 100},
        "limitations": STRING_LIST,
    },
    (
        "id",
        "state",
        "readiness",
        "revision",
        "pull_request_number",
        "pull_request_revision_id",
        "head_commit",
        "input_hash",
        "requirements_hash",
        "policy_bundle_hash",
        "evidence_bundle_hash",
        "evaluator_version",
        "prompt_version",
        "limitations",
    ),
)

PUBLIC_FINDING: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "fingerprint": SHA256,
        "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
        "kind": {"type": "string", "minLength": 1, "maxLength": 32},
        "severity": {"type": "string", "minLength": 1, "maxLength": 32},
        "confidence": {"type": "string", "minLength": 1, "maxLength": 32},
        "title": {"type": "string", "minLength": 1, "maxLength": 300},
        "explanation": {"type": "string", "minLength": 1, "maxLength": 10_000},
        "path": {"type": "string", "maxLength": 1_000},
        "line": _nullable({"type": "integer", "minimum": 1}),
        "citations": {"type": "array", "items": BOUNDED_MAP, "maxItems": 20},
        "evidence_ids": UUID_LIST,
        "criterion_codes": {
            "type": "array",
            "items": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
            "maxItems": 500,
            "uniqueItems": True,
        },
        "uncertainty": {"type": "string", "minLength": 1, "maxLength": 2_000},
        "suggested_resolution": {"type": "string", "minLength": 1, "maxLength": 2_000},
        "state": {"type": "string", "minLength": 1, "maxLength": 32},
        "revision": {"type": "integer", "minimum": 1},
    },
    (
        "id",
        "fingerprint",
        "code",
        "kind",
        "severity",
        "confidence",
        "title",
        "explanation",
        "path",
        "line",
        "citations",
        "evidence_ids",
        "criterion_codes",
        "uncertainty",
        "suggested_resolution",
        "state",
        "revision",
    ),
)
ASSURANCE_FINDINGS_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "assurance_run_id": UUID,
        "findings": {"type": "array", "items": PUBLIC_FINDING, "maxItems": 500},
    },
    ("assurance_run_id", "findings"),
)
ASSURANCE_REPORT_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "id": UUID,
        "assurance_run_id": UUID,
        "readiness": {"type": "string", "minLength": 1, "maxLength": 64},
        "head_commit": COMMIT,
        "renderer_version": {"type": "string", "minLength": 1, "maxLength": 100},
        "content_hash": SHA256,
        "markdown": {"type": "string", "minLength": 1, "maxLength": 200_000},
        "html": {"type": "string", "minLength": 1, "maxLength": 300_000},
        "limitations": STRING_LIST,
    },
    (
        "id",
        "assurance_run_id",
        "readiness",
        "head_commit",
        "renderer_version",
        "content_hash",
        "markdown",
        "html",
        "limitations",
    ),
)

CLAIMED_BY: Final[dict[str, object]] = _closed(
    {
        "actor_type": {"type": "string", "enum": ["USER", "SERVICE"]},
        "actor_id": {"type": "string", "minLength": 1, "maxLength": 200},
        "credential_id": _nullable(UUID),
    },
    ("actor_type", "actor_id", "credential_id"),
)
EVALUATOR_CLAIM_RESPONSE: Final[dict[str, object]] = {
    "oneOf": [
        _closed({"status": {"type": "string", "const": "EMPTY"}}, ("status",)),
        _closed(
            {
                "status": {"type": "string", "const": "CLAIMED"},
                "task_id": UUID,
                "assurance_run_id": UUID,
                "request_id": UUID,
                "input_hash": SHA256,
                "head_commit": COMMIT,
                "claimant": {"type": "string", "minLength": 1, "maxLength": 200},
                "claimed_by": CLAIMED_BY,
                "attempt": {"type": "integer", "minimum": 1},
                "lease_expires_at": DATE_TIME,
                "claim_token": {"type": "string", "minLength": 32, "maxLength": 200},
                "replayed": {"type": "boolean"},
                "request": deepcopy(EVALUATOR_REQUEST_SCHEMA),
            },
            (
                "status",
                "task_id",
                "assurance_run_id",
                "request_id",
                "input_hash",
                "head_commit",
                "claimant",
                "claimed_by",
                "attempt",
                "lease_expires_at",
                "claim_token",
                "replayed",
                "request",
            ),
        ),
    ]
}
EVALUATOR_SUBMIT_RESPONSE: Final[dict[str, object]] = _closed(
    {
        "task_id": UUID,
        "assurance_run_id": UUID,
        "input_hash": SHA256,
        "head_commit": COMMIT,
        "result_hash": SHA256,
        "state": {"type": "string", "const": "COMPLETED"},
        "readiness": {"type": "string", "minLength": 1, "maxLength": 64},
        "reason_codes": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 100},
            "maxItems": 100,
            "uniqueItems": True,
        },
        "report_id": UUID,
        "finding_ids": UUID_LIST,
        "created": {"type": "boolean"},
        "replayed": {"type": "boolean"},
    },
    (
        "task_id",
        "assurance_run_id",
        "input_hash",
        "head_commit",
        "result_hash",
        "state",
        "readiness",
        "reason_codes",
        "report_id",
        "finding_ids",
        "created",
        "replayed",
    ),
)


def _ids(number: int) -> str:
    return f"00000000-0000-4000-8000-{number:012d}"


EVIDENCE_UPLOAD_EXAMPLE_BYTES: Final[bytes] = (
    b'{"checks":[{"name":"EXACT_HEAD_PROOF","status":"PASSED"}],'
    b'"head_sha":"dddddddddddddddddddddddddddddddddddddddd","schema_version":1}\n'
)
EVIDENCE_UPLOAD_EXAMPLE_SHA256: Final[str] = hashlib.sha256(
    EVIDENCE_UPLOAD_EXAMPLE_BYTES
).hexdigest()


HTTP_OPERATION_EXAMPLES: Final[dict[str, dict[str, object]]] = {
    "bootstrapOrganization": {
        "request": {
            "organization_slug": "anva-acceptance-ember",
            "organization_name": "Ember Organization",
            "admin_email": "operator@ember.invalid",
            "admin_display_name": "Acceptance initiator",
            "repository_external_id": "github:synthetic/ember",
            "repository_name": "ember",
            "independent_reviewer_name": "Independent reviewer",
            "idempotency_key": "1" * 64,
        },
        "201": {
            "organization_id": _ids(1),
            "user_id": _ids(2),
            "membership_id": _ids(3),
            "repository_id": _ids(4),
            "service_identity_id": _ids(5),
            "access_scope_id": _ids(6),
            "token_id": _ids(7),
            "token": "example-only-opaque-value-never-issued-0001",
            "expires_at": "2026-08-10T12:00:00Z",
            "bootstrap_request_sha256": "1" * 64,
            "recovered": False,
            "reviewer_service_identity_id": _ids(8),
            "reviewer_token_id": _ids(9),
            "reviewer_token": "example-only-opaque-value-never-issued-0002",
            "reviewer_expires_at": "2026-08-10T12:00:00Z",
        },
    },
    "connectFilesystemSource": {
        "request": {
            "repository_id": _ids(4),
            "access_scope_id": _ids(6),
            "external_key": "tst-009:ember:knowledge",
            "display_name": "Ember knowledge",
            "root": "/app/acceptance/canonical/payload",
        },
        "201": {"id": _ids(10), "state": "ACTIVE", "revision": 1, "created": True},
        "200": {"id": _ids(10), "state": "ACTIVE", "revision": 1, "created": False},
    },
    "syncSourceConnection": {
        "request": {"scan_mode": "FULL"},
        "202": {
            "id": _ids(11),
            "source_connection_id": _ids(10),
            "access_snapshot_id": _ids(12),
            "scan_mode": "FULL",
            "state": "REQUESTED",
            "created": True,
        },
    },
    "listSourceSyncRuns": {
        "200": {
            "sync_runs": [
                {
                    "id": _ids(11),
                    "state": "COMPLETED",
                    "scan_mode": "FULL",
                    "discovered_count": 4,
                    "processed_count": 4,
                    "failed_count": 0,
                    "tombstoned_count": 0,
                    "failure_code": "",
                    "started_at": "2026-08-10T12:00:00Z",
                    "completed_at": "2026-08-10T12:00:01Z",
                }
            ]
        },
    },
    "queryOrganizationalCanvas": {
        "request": {
            "repository_ids": [_ids(4)],
            "layers": ["execution", "dependencies", "governance", "provenance"],
            "depth": 4,
            "node_limit": 300,
            "edge_limit": 600,
        },
        "200": {
            "schema_version": "1",
            "semantic_query": {"repository_ids": [_ids(4)], "depth": 4},
            "view": {
                "id": None,
                "name": "Live organizational view",
                "type": "CUSTOM",
                "revision": 0,
                "content_hash": "",
            },
            "repositories": [{"id": _ids(4), "name": "ember"}],
            "nodes": [],
            "edges": [],
            "annotations": [],
            "counts": {"nodes": 0, "edges": 0},
            "limits": {
                "nodes": 300,
                "edges": 600,
                "depth": 4,
                "repositories": 100,
                "payload_bytes": 768_000,
            },
            "truncated": False,
            "limitations": [],
            "layout": {
                "algorithm": "deterministic-semantic-columns",
                "version": "anva-layered-v1",
                "checksum": "2" * 64,
            },
            "generated_at": "2026-08-10T12:00:02Z",
            "as_of": None,
        },
    },
    "importWorkItemRevision": {
        "request": EXAMPLES["work-item-import"],
        "201": {
            "work_item_id": _ids(20),
            "work_item_revision_id": _ids(21),
            "revision": 1,
            "content_hash": "3" * 64,
            "created": True,
        },
        "200": {
            "work_item_id": _ids(20),
            "work_item_revision_id": _ids(21),
            "revision": 1,
            "content_hash": "3" * 64,
            "created": False,
        },
    },
    "importPolicyVersion": {
        "request": EXAMPLES["policy"],
        "201": {
            "policy_id": _ids(22),
            "policy_version_id": _ids(23),
            "version": 1,
            "content_hash": "4" * 64,
            "created": True,
        },
        "200": {
            "policy_id": _ids(22),
            "policy_version_id": _ids(23),
            "version": 1,
            "content_hash": "4" * 64,
            "created": False,
        },
    },
    "simulatePolicy": {
        "request": {
            "repository_id": _ids(4),
            "pull_request_number": 17,
            "commit_sha": "d" * 40,
            "policy_version_ids": [_ids(23)],
            "reference_time": "2026-08-10T12:00:00Z",
            "affected_paths": ["src/checkout.py"],
            "affected_entities": [],
            "target_branch": "main",
            "work_item_revision_id": _ids(21),
        },
        "201": {
            "policy_evaluation_id": _ids(24),
            "input_hash": "5" * 64,
            "output_hash": "6" * 64,
            "output": {"status": "PASSED"},
            "created": True,
        },
        "200": {
            "policy_evaluation_id": _ids(24),
            "input_hash": "5" * 64,
            "output_hash": "6" * 64,
            "output": {"status": "PASSED"},
            "created": False,
        },
    },
    "createEvidenceUploadAuthorization": {
        "request": {
            **EXAMPLES["evidence-upload-authorization"],
            "commit_sha": "d" * 40,
            "declared_sha256": EVIDENCE_UPLOAD_EXAMPLE_SHA256,
            "declared_size": len(EVIDENCE_UPLOAD_EXAMPLE_BYTES),
        },
        "201": {
            "authorization_id": _ids(50),
            "repository_id": _ids(4),
            "access_scope_id": _ids(6),
            "pull_request_number": 17,
            "commit_sha": "d" * 40,
            "declared_sha256": EVIDENCE_UPLOAD_EXAMPLE_SHA256,
            "declared_size": len(EVIDENCE_UPLOAD_EXAMPLE_BYTES),
            "state": "ISSUED",
            "expires_at": "2026-08-10T12:05:00Z",
            "upload_path": f"/api/v1/evidence-upload-authorizations/{_ids(50)}/content",
            "upload_token": "example-only-opaque-value-never-issued-0004",
            "replayed": False,
        },
        "200": {
            "authorization_id": _ids(50),
            "repository_id": _ids(4),
            "access_scope_id": _ids(6),
            "pull_request_number": 17,
            "commit_sha": "d" * 40,
            "declared_sha256": EVIDENCE_UPLOAD_EXAMPLE_SHA256,
            "declared_size": len(EVIDENCE_UPLOAD_EXAMPLE_BYTES),
            "state": "ISSUED",
            "expires_at": "2026-08-10T12:05:00Z",
            "upload_path": f"/api/v1/evidence-upload-authorizations/{_ids(50)}/content",
            "upload_token": None,
            "replayed": True,
        },
    },
    "uploadEvidenceContent": {
        "request": base64.b64encode(EVIDENCE_UPLOAD_EXAMPLE_BYTES).decode(),
        "201": {
            "evidence_blob_id": _ids(51),
            "authorization_id": _ids(50),
            "sha256": EVIDENCE_UPLOAD_EXAMPLE_SHA256,
            "verified_size": len(EVIDENCE_UPLOAD_EXAMPLE_BYTES),
            "detected_type": "application/json",
            "archive_summary": {
                "format": "JSON",
                "member_count": 1,
                "compressed_bytes": len(EVIDENCE_UPLOAD_EXAMPLE_BYTES),
                "expanded_bytes": len(EVIDENCE_UPLOAD_EXAMPLE_BYTES),
                "results_sha256": EVIDENCE_UPLOAD_EXAMPLE_SHA256,
                "check_count": 1,
            },
            "storage_state": "AVAILABLE",
        },
    },
    "submitEvidenceManifest": {
        "request": EXAMPLES["evidence-manifest"],
        "201": {
            "manifest_id": _ids(25),
            "payload_hash": "8" * 64,
            "evidence_ids": [_ids(26)],
            "created": True,
        },
        "200": {
            "manifest_id": _ids(25),
            "payload_hash": "8" * 64,
            "evidence_ids": [_ids(26)],
            "created": False,
        },
    },
    "getEvidenceManifest": {
        "200": {
            "id": _ids(25),
            "repository_id": _ids(4),
            "pull_request_number": 17,
            "commit_sha": "d" * 40,
            "payload_hash": "8" * 64,
            "manifest": EXAMPLES["evidence-manifest"],
        }
    },
    "ingestManualPullRequestDiff": {
        "request": {
            "access_scope_id": _ids(6),
            "base_commit": "c" * 40,
            "head_commit": "d" * 40,
            "title": "Bound checkout retry behavior",
            "description": "Public acceptance change.",
            "target_branch": "main",
            "is_draft": False,
            "state": "OPEN",
            "unified_diff": "diff --git a/src/a.py b/src/a.py\n@@ -1 +1 @@\n-old\n+new\n",
        },
        "201": {
            "pull_request_id": _ids(27),
            "pull_request_revision_id": _ids(28),
            "revision": 1,
            "head_commit": "d" * 40,
            "diff_artifact_id": _ids(29),
            "diff_hash": "9" * 64,
            "changed_paths": ["src/a.py"],
            "classification_summary": {"SOURCE": 1},
            "limitations": ["Manual diff provenance was supplied by an authorized operator."],
            "created": True,
        },
        "200": {
            "pull_request_id": _ids(27),
            "pull_request_revision_id": _ids(28),
            "revision": 1,
            "head_commit": "d" * 40,
            "diff_artifact_id": _ids(29),
            "diff_hash": "9" * 64,
            "changed_paths": ["src/a.py"],
            "classification_summary": {"SOURCE": 1},
            "limitations": ["Manual diff provenance was supplied by an authorized operator."],
            "created": False,
        },
    },
    "startManualDiffAssurance": {
        "request": {
            "policy_version_ids": [_ids(23)],
            "reference_time": "2026-08-10T12:00:00Z",
            "deterministic_checks": [],
            "work_item_revision_id": _ids(21),
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "trigger_key": "a" * 64,
        },
        "201": {
            "assurance_run_id": _ids(30),
            "evaluator_task_id": _ids(31),
            "state": "MODEL_REVIEW",
            "head_commit": "d" * 40,
            "input_hash": "b" * 64,
            "created": True,
        },
        "200": {
            "assurance_run_id": _ids(30),
            "evaluator_task_id": _ids(31),
            "state": "MODEL_REVIEW",
            "head_commit": "d" * 40,
            "input_hash": "b" * 64,
            "created": False,
        },
    },
    "getAssuranceRun": {
        "200": {
            "id": _ids(30),
            "state": "MODEL_REVIEW",
            "readiness": None,
            "revision": 4,
            "pull_request_number": 17,
            "pull_request_revision_id": _ids(28),
            "head_commit": "d" * 40,
            "input_hash": "b" * 64,
            "requirements_hash": "c" * 64,
            "policy_bundle_hash": "d" * 64,
            "evidence_bundle_hash": "e" * 64,
            "evaluator_version": "external-acceptance-v1",
            "prompt_version": "acceptance-review-v1",
            "limitations": ["Manual diff provenance was supplied by an authorized operator."],
        }
    },
    "listAssuranceFindings": {
        "200": {"assurance_run_id": _ids(30), "findings": []},
    },
    "getAssuranceReport": {
        "200": {
            "id": _ids(32),
            "assurance_run_id": _ids(30),
            "readiness": "READY_WITH_WARNINGS",
            "head_commit": "d" * 40,
            "renderer_version": "assurance-report-v1",
            "content_hash": "f" * 64,
            "markdown": "# Anva assurance\n",
            "html": "<h1>Anva assurance</h1>",
            "limitations": ["No repository code was executed."],
        }
    },
    "claimManualEvaluatorTask": {
        "request": {
            "claimant": "independent-acceptance-evaluator",
            "lease_seconds": 3_600,
            "claim_idempotency_key": "1" * 64,
            "task_id": _ids(31),
            "assurance_run_id": _ids(30),
            "input_hash": "b" * 64,
            "head_commit": "d" * 40,
        },
        "200": {
            "status": "CLAIMED",
            "task_id": _ids(31),
            "assurance_run_id": _ids(30),
            "request_id": cast(str, EXAMPLES["evaluator-request"]["request_id"]),
            "input_hash": "b" * 64,
            "head_commit": "d" * 40,
            "claimant": "independent-acceptance-evaluator",
            "claimed_by": {
                "actor_type": "SERVICE",
                "actor_id": _ids(8),
                "credential_id": _ids(9),
            },
            "attempt": 1,
            "lease_expires_at": "2026-08-10T13:00:00Z",
            "claim_token": "example-only-opaque-value-never-issued-0003",
            "replayed": False,
            "request": EXAMPLES["evaluator-request"],
        },
    },
    "submitManualEvaluatorResult": {
        "request": {
            "claim_token": "example-only-opaque-value-never-issued-0003",
            "result": EXAMPLES["evaluator-result"],
        },
        "201": {
            "task_id": _ids(31),
            "assurance_run_id": _ids(30),
            "input_hash": "b" * 64,
            "head_commit": "d" * 40,
            "result_hash": "2" * 64,
            "state": "COMPLETED",
            "readiness": "READY_WITH_WARNINGS",
            "reason_codes": ["MODEL_CONCERNS"],
            "report_id": _ids(32),
            "finding_ids": [],
            "created": True,
            "replayed": False,
        },
        "200": {
            "task_id": _ids(31),
            "assurance_run_id": _ids(30),
            "input_hash": "b" * 64,
            "head_commit": "d" * 40,
            "result_hash": "2" * 64,
            "state": "COMPLETED",
            "readiness": "READY_WITH_WARNINGS",
            "reason_codes": ["MODEL_CONCERNS"],
            "report_id": _ids(32),
            "finding_ids": [],
            "created": False,
            "replayed": True,
        },
    },
}

HTTP_RESPONSE_OVERRIDES: Final[dict[str, dict[str, object]]] = {
    "connectFilesystemSource": SOURCE_CONNECTION_RESPONSE,
    "syncSourceConnection": SYNC_START_RESPONSE,
    "listSourceSyncRuns": SYNC_RUNS_RESPONSE,
    "queryOrganizationalCanvas": CANVAS_RESPONSE,
    "importWorkItemRevision": WORK_IMPORT_RESPONSE,
    "importPolicyVersion": POLICY_IMPORT_RESPONSE,
    "simulatePolicy": POLICY_SIMULATION_RESPONSE,
    "submitEvidenceManifest": EVIDENCE_MANIFEST_RESPONSE,
    "getEvidenceManifest": EVIDENCE_MANIFEST_DETAIL_RESPONSE,
    "ingestManualPullRequestDiff": MANUAL_DIFF_RESPONSE,
    "startManualDiffAssurance": ASSURANCE_START_RESPONSE,
    "getAssuranceRun": ASSURANCE_DETAIL_RESPONSE,
    "listAssuranceFindings": ASSURANCE_FINDINGS_RESPONSE,
    "getAssuranceReport": ASSURANCE_REPORT_RESPONSE,
    "claimManualEvaluatorTask": EVALUATOR_CLAIM_RESPONSE,
    "submitManualEvaluatorResult": EVALUATOR_SUBMIT_RESPONSE,
}
HTTP_REQUEST_OVERRIDES: Final[dict[str, dict[str, object]]] = {
    "connectFilesystemSource": SOURCE_CONNECTION_REQUEST,
    "syncSourceConnection": SYNC_START_REQUEST,
}

ACCEPTANCE_HTTP_OPERATION_IDS: Final[tuple[str, ...]] = tuple(HTTP_OPERATION_EXAMPLES)


def _http_operations(document: dict[str, object]) -> dict[str, tuple[str, str, dict[str, object]]]:
    operations: dict[str, tuple[str, str, dict[str, object]]] = {}
    paths = cast(dict[str, object], document["paths"])
    for path, path_item_value in paths.items():
        path_item = cast(dict[str, object], path_item_value)
        for method in ("get", "post", "put", "patch", "delete"):
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            operation = cast(dict[str, object], raw)
            operation_id = operation.get("operationId")
            if isinstance(operation_id, str):
                operations[operation_id] = (method.upper(), path, operation)
    return operations


def apply_acceptance_http_contracts(document: dict[str, object]) -> None:
    """Attach canonical examples and strict success responses to the OpenAPI document."""
    operations = _http_operations(document)
    missing = set(ACCEPTANCE_HTTP_OPERATION_IDS) - set(operations)
    if missing:
        raise ValueError(f"Acceptance OpenAPI operations are missing: {sorted(missing)}")
    components = cast(dict[str, object], document["components"])
    schemas = cast(dict[str, object], components["schemas"])
    for operation_id in ACCEPTANCE_HTTP_OPERATION_IDS:
        _method, _path, operation = operations[operation_id]
        # The base OpenAPI generator reuses response template dictionaries.
        # Detach this operation before adding a strict acceptance schema so one
        # operation can never overwrite another operation's public response.
        operation["responses"] = deepcopy(operation["responses"])
        examples = HTTP_OPERATION_EXAMPLES[operation_id]
        request_body = operation.get("requestBody")
        request_schema = HTTP_REQUEST_OVERRIDES.get(operation_id)
        request_schema_ref: dict[str, str] | None = None
        if request_schema is not None:
            request_component = f"acceptance-{operation_id}-request"
            schemas[request_component] = deepcopy(request_schema)
            request_schema_ref = {"$ref": f"#/components/schemas/{request_component}"}
        if request_body is None and request_schema is not None:
            request_body = {
                "required": True,
                "content": {"application/json": {"schema": request_schema_ref}},
            }
            operation["requestBody"] = request_body
        if isinstance(request_body, dict) and "request" in examples:
            content = cast(dict[str, object], request_body["content"])
            media = next(iter(content.values()))
            if isinstance(media, dict):
                if request_schema_ref is not None:
                    media["schema"] = request_schema_ref
                media["example"] = deepcopy(examples["request"])
        responses = cast(dict[str, object], operation["responses"])
        response_schema = HTTP_RESPONSE_OVERRIDES.get(operation_id)
        response_schema_ref: dict[str, str] | None = None
        if response_schema is not None:
            response_component = f"acceptance-{operation_id}-response"
            schemas[response_component] = deepcopy(response_schema)
            response_schema_ref = {"$ref": f"#/components/schemas/{response_component}"}
        for status, example in examples.items():
            if status == "request":
                continue
            response = responses.get(status)
            if response is None and status.startswith("2"):
                response = {
                    "description": "Documented acceptance success response.",
                }
                responses[status] = response
            if not isinstance(response, dict):
                continue
            content = response.setdefault("content", {"application/json": {}})
            media = cast(dict[str, object], cast(dict[str, object], content)["application/json"])
            if response_schema_ref is not None:
                media["schema"] = response_schema_ref
            media["example"] = deepcopy(example)
        if response_schema_ref is not None:
            for status in ("200", "201", "202"):
                response = responses.get(status)
                if not isinstance(response, dict):
                    continue
                content = response.setdefault("content", {"application/json": {}})
                media = cast(
                    dict[str, object], cast(dict[str, object], content)["application/json"]
                )
                media["schema"] = response_schema_ref


def _resolve_pointer(document: dict[str, object], pointer: str) -> object:
    if not pointer.startswith("#/"):
        raise ValueError("Acceptance contracts permit only local OpenAPI references")
    value: object = document
    for component in pointer.removeprefix("#/").split("/"):
        if not isinstance(value, dict) or component not in value:
            raise ValueError(f"Unresolvable acceptance OpenAPI reference: {pointer}")
        value = value[component]
    return value


def _inline_refs(
    value: object,
    document: dict[str, object],
    *,
    local_root: dict[str, object] | None = None,
) -> object:
    if isinstance(value, list):
        return [_inline_refs(item, document, local_root=local_root) for item in value]
    if not isinstance(value, dict):
        return value
    scope = value if "$defs" in value else local_root
    if set(value) == {"$ref"} and isinstance(value.get("$ref"), str):
        pointer = cast(str, value["$ref"])
        root = document if pointer.startswith("#/components/") else scope
        if root is None:
            raise ValueError(f"Unscoped acceptance schema reference: {pointer}")
        resolved = deepcopy(_resolve_pointer(root, pointer))
        next_scope = (
            cast(dict[str, object], resolved)
            if pointer.startswith("#/components/") and isinstance(resolved, dict)
            else scope
        )
        return _inline_refs(resolved, document, local_root=next_scope)
    return {key: _inline_refs(item, document, local_root=scope) for key, item in value.items()}


@lru_cache(maxsize=1)
def _success_response_contracts() -> dict[tuple[str, int], dict[str, object]]:
    from anva.contracts.generate import openapi_document

    document = openapi_document()
    schemas: dict[tuple[str, int], dict[str, object]] = {}
    for operation_id, (_method, _path, operation) in _http_operations(document).items():
        if operation_id not in ACCEPTANCE_HTTP_OPERATION_IDS:
            continue
        responses = cast(dict[str, object], operation["responses"])
        for raw_status, response_value in responses.items():
            if not raw_status.startswith("2") or not isinstance(response_value, dict):
                continue
            content = response_value.get("content")
            if not isinstance(content, dict):
                continue
            media = content.get("application/json")
            if not isinstance(media, dict) or not isinstance(media.get("schema"), dict):
                continue
            inlined = _inline_refs(media["schema"], document)
            if isinstance(inlined, dict):
                schemas[(operation_id, int(raw_status))] = cast(dict[str, object], inlined)
    return schemas


def validate_acceptance_http_response(
    operation_id: str,
    status: int,
    payload: dict[str, object],
) -> None:
    """Fail closed when a successful public response drifts from its published contract."""
    schema = _success_response_contracts().get((operation_id, status))
    if schema is None:
        raise ValueError("Acceptance response contract is unavailable")
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
    except ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise ValueError(
            f"Acceptance response contract failed at {location}: {error.message}"
        ) from error


def acceptance_operation_document(
    openapi: dict[str, object],
    mcp: dict[str, object],
) -> dict[str, object]:
    """Return a self-contained, deterministic contract bundle for non-Anva clients."""
    operations = _http_operations(openapi)
    http_values: list[dict[str, object]] = []
    for operation_id in ACCEPTANCE_HTTP_OPERATION_IDS:
        method, path, operation = operations[operation_id]
        request: object = None
        request_body = operation.get("requestBody")
        if isinstance(request_body, dict):
            request = _inline_refs(request_body, openapi)
        responses = _inline_refs(operation["responses"], openapi)
        http_values.append(
            {
                "operation_id": operation_id,
                "method": method,
                "path": path,
                "request": request,
                "responses": responses,
            }
        )
    tools = cast(list[dict[str, object]], mcp["tools"])
    by_name = {cast(str, tool["name"]): tool for tool in tools}
    mcp_examples: dict[str, dict[str, object]] = {
        "anva.search": {
            "input": {
                "contract_version": "1",
                "repository_id": _ids(4),
                "query": "checkout ownership policy",
                "phase": "ASSURANCE",
                "limit": 50,
            },
            "output": {
                "contract_version": "1",
                "tool": "anva.search",
                "data": {
                    "results": [
                        {
                            "chunk_id": _ids(40),
                            "text": "Checkout is owned by Payments.",
                            "content_hash": "a" * 64,
                            "pointer": "/text",
                            "canonical_url": "file:///knowledge/checkout.md",
                            "access_scope_id": _ids(6),
                            "source_location_id": _ids(41),
                            "source_observation_id": _ids(42),
                            "access_snapshot_id": _ids(43),
                            "observed_at": "2026-08-10T12:00:00Z",
                            "explanation": {
                                "lexical_rank": 1,
                                "semantic_rank": 1,
                                "reciprocal_rank_score": 0.032786885,
                                "phase": "ASSURANCE",
                                "phase_terms": [
                                    "evidence",
                                    "policy",
                                    "incident",
                                    "control",
                                    "decision",
                                ],
                            },
                        }
                    ]
                },
                "next_cursor": None,
            },
        },
        "anva.get_context_packet": {
            "input": {
                "contract_version": "1",
                "repository_id": _ids(4),
                "task": "Review checkout against authorized context.",
                "phase": "ASSURANCE",
                "budget": {
                    "max_items": 50,
                    "max_tokens": 8_000,
                    "max_bytes": 100_000,
                    "max_citations": 100,
                },
            },
            "output": {
                "contract_version": "1",
                "tool": "anva.get_context_packet",
                "data": {
                    "packet_id": cast(str, EXAMPLES["context-packet"]["packet_id"]),
                    "created": True,
                    "packet": EXAMPLES["context-packet"],
                },
            },
        },
    }
    mcp_values: list[dict[str, object]] = []
    for name in ("anva.search", "anva.get_context_packet"):
        tool = by_name[name]
        mcp_values.append(
            {
                "tool": name,
                "transport": "STREAMABLE_HTTP_MCP",
                "input_schema": deepcopy(tool["inputSchema"]),
                "input_example": mcp_examples[name]["input"],
                "output_schema": deepcopy(tool["outputSchema"]),
                "output_example": mcp_examples[name]["output"],
            }
        )
    return {
        "schema_version": "1.0",
        "http_base_path": "/api/v1",
        "mcp_transport": "STREAMABLE_HTTP",
        "http_operations": http_values,
        "mcp_operations": mcp_values,
        "provenance_contract": deepcopy(RETRIEVAL_CITATION),
        "case_schema_id": "https://schemas.anva.dev/v1/acceptance-case.schema.json",
    }
