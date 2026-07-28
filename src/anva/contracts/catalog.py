"""Canonical source definitions for Anva's version 1 external contracts."""

from __future__ import annotations

from copy import deepcopy
from typing import Final

SCHEMA_VERSION: Final = "1.0"
SCHEMA_BASE_URI: Final = "https://schemas.anva.dev/v1"
SHA256_PATTERN: Final = "^[a-f0-9]{64}$"
COMMIT_PATTERN: Final = "^[a-f0-9]{7,64}$"


def versioned_schema(
    name: str,
    title: str,
    properties: dict[str, object],
    required: list[str],
    *,
    definitions: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build a closed, independently versioned JSON Schema."""
    schema: dict[str, object] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{SCHEMA_BASE_URI}/{name}.schema.json",
        "title": title,
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "string", "const": SCHEMA_VERSION},
            **properties,
        },
        "required": ["schema_version", *required],
    }
    if definitions is not None:
        schema["$defs"] = definitions
    return schema


UUID_FIELD: Final[dict[str, str]] = {"type": "string", "format": "uuid"}
DATE_TIME_FIELD: Final[dict[str, str]] = {"type": "string", "format": "date-time"}
SHA256_FIELD: Final[dict[str, str]] = {"type": "string", "pattern": SHA256_PATTERN}
COMMIT_FIELD: Final[dict[str, str]] = {"type": "string", "pattern": COMMIT_PATTERN}

SOURCE_REFERENCE: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "source_id": UUID_FIELD,
        "source_type": {
            "type": "string",
            "enum": ["DOCUMENT", "CODE", "POLICY", "DECISION", "HUMAN_APPROVAL", "EVIDENCE"],
        },
        "revision_id": {"oneOf": [UUID_FIELD, {"type": "null"}]},
        "canonical_url": {"oneOf": [{"type": "string", "format": "uri"}, {"type": "null"}]},
        "content_hash": {"oneOf": [SHA256_FIELD, {"type": "null"}]},
        "observed_at": DATE_TIME_FIELD,
        "locator": {"type": "string", "minLength": 1, "maxLength": 500},
    },
    "required": [
        "source_id",
        "source_type",
        "revision_id",
        "canonical_url",
        "content_hash",
        "observed_at",
        "locator",
    ],
}

RETRIEVAL_CITATION: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "source_location_id": UUID_FIELD,
        "source_observation_id": UUID_FIELD,
        "access_snapshot_id": UUID_FIELD,
        "canonical_url": {"type": "string", "format": "uri"},
        "locator": {"type": "string", "minLength": 1, "maxLength": 1_000},
        "source_content_hash": SHA256_FIELD,
        "observed_at": DATE_TIME_FIELD,
    },
    "required": [
        "source_location_id",
        "source_observation_id",
        "access_snapshot_id",
        "canonical_url",
        "locator",
        "source_content_hash",
        "observed_at",
    ],
}

CONTEXT_ITEM: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "item_id": UUID_FIELD,
        "kind": {
            "type": "string",
            "enum": [
                "POLICY",
                "RELATIONSHIP",
                "ASSERTION",
                "SOURCE_EXCERPT",
                "DECISION",
                "INCIDENT",
                "CONFLICT",
            ],
        },
        "item_key": {"type": "string", "minLength": 1, "maxLength": 500},
        "summary": {"type": "string", "minLength": 1, "maxLength": 10_000},
        "is_inferred": {"type": "boolean"},
        "freshness": {"type": "string", "enum": ["CURRENT", "STALE", "UNKNOWN"]},
        "selection_reason": {"type": "string", "minLength": 1, "maxLength": 500},
        "rank_score": {"type": "number", "minimum": 0},
        "payload": {"type": "object"},
        "anva_sources": {
            "type": "array",
            "items": {"$ref": "#/$defs/retrieval_citation"},
            "minItems": 1,
        },
    },
    "required": [
        "item_id",
        "kind",
        "item_key",
        "summary",
        "is_inferred",
        "freshness",
        "selection_reason",
        "rank_score",
        "payload",
        "anva_sources",
    ],
}

CONTEXT_PACKET_SCHEMA = versioned_schema(
    "context-packet",
    "Anva Context Packet",
    {
        "packet_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "repository_id": UUID_FIELD,
        "work_item_id": {"oneOf": [UUID_FIELD, {"type": "null"}]},
        "revision": {"type": "integer", "minimum": 1},
        "generated_at": DATE_TIME_FIELD,
        "content_hash": SHA256_FIELD,
        "phase": {
            "type": "string",
            "enum": ["PREPARE", "BUILD", "PREFLIGHT", "ASSURANCE"],
        },
        "request": {"type": "object"},
        "authorization_hash": SHA256_FIELD,
        "selection_hash": SHA256_FIELD,
        "retrieval_watermark": {"type": "integer", "minimum": 1},
        "retrieval_algorithm_version": {"type": "string", "minLength": 1},
        "index_version": {"type": "string", "minLength": 1},
        "embedding_version": {"type": "string", "minLength": 1},
        "budget": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "max_items": {"type": "integer", "minimum": 1},
                "max_tokens": {"type": "integer", "minimum": 1},
                "max_bytes": {"type": "integer", "minimum": 1},
                "max_citations": {"type": "integer", "minimum": 1},
                "selected_items": {"type": "integer", "minimum": 0},
                "selected_tokens": {"type": "integer", "minimum": 0},
                "selected_bytes": {"type": "integer", "minimum": 0},
                "selected_citations": {"type": "integer", "minimum": 0},
            },
            "required": [
                "max_items",
                "max_tokens",
                "max_bytes",
                "max_citations",
                "selected_items",
                "selected_tokens",
                "selected_bytes",
                "selected_citations",
            ],
        },
        "items": {
            "type": "array",
            "items": {"$ref": "#/$defs/context_item"},
            "maxItems": 500,
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 2_000},
        },
    },
    [
        "packet_id",
        "organization_id",
        "repository_id",
        "work_item_id",
        "revision",
        "generated_at",
        "content_hash",
        "phase",
        "request",
        "authorization_hash",
        "selection_hash",
        "retrieval_watermark",
        "retrieval_algorithm_version",
        "index_version",
        "embedding_version",
        "budget",
        "items",
        "limitations",
    ],
    definitions={
        "retrieval_citation": RETRIEVAL_CITATION,
        "context_item": CONTEXT_ITEM,
    },
)

EVIDENCE_ENTRY: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "evidence_id": UUID_FIELD,
        "kind": {
            "type": "string",
            "enum": ["TEST", "LINT", "TYPECHECK", "BUILD", "MIGRATION", "BROWSER", "MANUAL"],
        },
        "status": {"type": "string", "enum": ["PASSED", "FAILED", "UNKNOWN"]},
        "artifact_uri": {"type": "string", "format": "uri"},
        "content_hash": SHA256_FIELD,
        "created_at": DATE_TIME_FIELD,
        "producer": {"type": "string", "minLength": 1, "maxLength": 200},
    },
    "required": [
        "evidence_id",
        "kind",
        "status",
        "artifact_uri",
        "content_hash",
        "created_at",
        "producer",
    ],
}

EVIDENCE_MANIFEST_SCHEMA = versioned_schema(
    "evidence-manifest",
    "Anva Evidence Manifest",
    {
        "manifest_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "commit_sha": COMMIT_FIELD,
        "created_at": DATE_TIME_FIELD,
        "entries": {
            "type": "array",
            "items": {"$ref": "#/$defs/evidence_entry"},
            "maxItems": 2_000,
        },
    },
    ["manifest_id", "organization_id", "commit_sha", "created_at", "entries"],
    definitions={"evidence_entry": EVIDENCE_ENTRY},
)

FINDING_SCHEMA = versioned_schema(
    "finding",
    "Anva Assurance Finding",
    {
        "finding_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
        "severity": {"type": "string", "enum": ["BLOCKING", "ADVISORY"]},
        "title": {"type": "string", "minLength": 1, "maxLength": 300},
        "description": {"type": "string", "minLength": 1, "maxLength": 10_000},
        "anva_sources": {
            "type": "array",
            "items": {"$ref": "#/$defs/source_reference"},
            "minItems": 1,
        },
        "evidence_ids": {"type": "array", "items": UUID_FIELD, "uniqueItems": True},
        "limitations": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 2_000},
        },
    },
    [
        "finding_id",
        "organization_id",
        "code",
        "severity",
        "title",
        "description",
        "anva_sources",
        "evidence_ids",
        "limitations",
    ],
    definitions={"source_reference": SOURCE_REFERENCE},
)

EVALUATOR_REQUEST_SCHEMA = versioned_schema(
    "evaluator-request",
    "Anva Evaluator Request",
    {
        "request_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "commit_sha": COMMIT_FIELD,
        "policy_id": UUID_FIELD,
        "policy_version": {"type": "integer", "minimum": 1},
        "context_packet_id": UUID_FIELD,
        "evidence_manifest_id": UUID_FIELD,
        "untrusted_change": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "title": {"type": "string", "maxLength": 1_000},
                "description": {"type": "string", "maxLength": 50_000},
                "diff_reference": {"type": "string", "format": "uri"},
            },
            "required": ["title", "description", "diff_reference"],
        },
    },
    [
        "request_id",
        "organization_id",
        "commit_sha",
        "policy_id",
        "policy_version",
        "context_packet_id",
        "evidence_manifest_id",
        "untrusted_change",
    ],
)


def embedded_schema(schema: dict[str, object]) -> dict[str, object]:
    """Copy a schema for use inside another schema's `$defs`."""
    result = deepcopy(schema)
    result.pop("$schema", None)
    result.pop("$id", None)
    result.pop("$defs", None)
    return result


EVALUATOR_RESULT_SCHEMA = versioned_schema(
    "evaluator-result",
    "Anva Evaluator Result",
    {
        "request_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "commit_sha": COMMIT_FIELD,
        "outcome": {"type": "string", "enum": ["READY", "NOT_READY", "UNKNOWN"]},
        "findings": {
            "type": "array",
            "items": {"$ref": "#/$defs/finding"},
            "maxItems": 500,
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 2_000},
        },
        "evaluated_at": DATE_TIME_FIELD,
    },
    [
        "request_id",
        "organization_id",
        "commit_sha",
        "outcome",
        "findings",
        "limitations",
        "evaluated_at",
    ],
    definitions={
        "finding": embedded_schema(FINDING_SCHEMA),
        "source_reference": SOURCE_REFERENCE,
    },
)

POLICY_REQUIREMENT: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "requirement_id": UUID_FIELD,
        "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
        "description": {"type": "string", "minLength": 1, "maxLength": 5_000},
        "enforcement": {"type": "string", "enum": ["BLOCKING", "ADVISORY"]},
        "check_type": {
            "type": "string",
            "enum": ["DETERMINISTIC", "EVIDENCE", "MODEL_REVIEW", "MANUAL_APPROVAL"],
        },
        "required_evidence": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["TEST", "LINT", "TYPECHECK", "BUILD", "MIGRATION", "BROWSER", "MANUAL"],
            },
            "uniqueItems": True,
        },
    },
    "required": [
        "requirement_id",
        "code",
        "description",
        "enforcement",
        "check_type",
        "required_evidence",
    ],
}

POLICY_SCHEMA = versioned_schema(
    "policy",
    "Anva Assurance Policy",
    {
        "policy_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "version": {"type": "integer", "minimum": 1},
        "name": {"type": "string", "minLength": 1, "maxLength": 300},
        "effective_at": DATE_TIME_FIELD,
        "requirements": {
            "type": "array",
            "items": {"$ref": "#/$defs/policy_requirement"},
            "minItems": 1,
            "maxItems": 500,
        },
    },
    ["policy_id", "organization_id", "version", "name", "effective_at", "requirements"],
    definitions={"policy_requirement": POLICY_REQUIREMENT},
)

KNOWLEDGE_PROPOSAL_SCHEMA = versioned_schema(
    "knowledge-proposal",
    "Anva Knowledge Proposal",
    {
        "proposal_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "proposal_version": {"type": "integer", "minimum": 1},
        "state": {
            "type": "string",
            "enum": [
                "PROPOSED",
                "VALIDATING",
                "AWAITING_REVIEW",
                "ACCEPTED",
                "REJECTED",
                "SUPERSEDED",
                "FAILED",
            ],
        },
        "summary": {"type": "string", "minLength": 1, "maxLength": 5_000},
        "changes": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "operation": {"type": "string", "enum": ["ADD", "CORRECT", "SUPERSEDE"]},
                    "target_id": {"oneOf": [UUID_FIELD, {"type": "null"}]},
                    "predicate": {"type": "string", "minLength": 1, "maxLength": 200},
                    "value": {},
                    "is_inferred": {"type": "boolean"},
                },
                "required": ["operation", "target_id", "predicate", "value", "is_inferred"],
            },
        },
        "anva_sources": {
            "type": "array",
            "items": {"$ref": "#/$defs/source_reference"},
            "minItems": 1,
        },
        "submitted_by": UUID_FIELD,
        "created_at": DATE_TIME_FIELD,
    },
    [
        "proposal_id",
        "organization_id",
        "proposal_version",
        "state",
        "summary",
        "changes",
        "anva_sources",
        "submitted_by",
        "created_at",
    ],
    definitions={"source_reference": SOURCE_REFERENCE},
)

SCHEMAS: Final[dict[str, dict[str, object]]] = {
    "context-packet": CONTEXT_PACKET_SCHEMA,
    "evidence-manifest": EVIDENCE_MANIFEST_SCHEMA,
    "evaluator-request": EVALUATOR_REQUEST_SCHEMA,
    "evaluator-result": EVALUATOR_RESULT_SCHEMA,
    "finding": FINDING_SCHEMA,
    "knowledge-proposal": KNOWLEDGE_PROPOSAL_SCHEMA,
    "policy": POLICY_SCHEMA,
}

SOURCE_EXAMPLE: Final[dict[str, object]] = {
    "source_id": "00000000-0000-4000-8000-000000000101",
    "source_type": "DECISION",
    "revision_id": "00000000-0000-4000-8000-000000000102",
    "canonical_url": "https://example.test/decisions/checkout",
    "content_hash": "a" * 64,
    "observed_at": "2026-07-28T00:00:00Z",
    "locator": "ADR-42",
}

FINDING_EXAMPLE: Final[dict[str, object]] = {
    "schema_version": SCHEMA_VERSION,
    "finding_id": "00000000-0000-4000-8000-000000000201",
    "organization_id": "00000000-0000-4000-8000-000000000001",
    "code": "MISSING_MIGRATION_EVIDENCE",
    "severity": "BLOCKING",
    "title": "Migration evidence is missing",
    "description": "The policy requires a migration compatibility check.",
    "anva_sources": [SOURCE_EXAMPLE],
    "evidence_ids": [],
    "limitations": ["No deployment environment was evaluated."],
}

RETRIEVAL_CITATION_EXAMPLE: Final[dict[str, object]] = {
    "source_location_id": "00000000-0000-4000-8000-000000000104",
    "source_observation_id": "00000000-0000-4000-8000-000000000105",
    "access_snapshot_id": "00000000-0000-4000-8000-000000000106",
    "canonical_url": "https://example.test/decisions/checkout",
    "locator": "ADR-42",
    "source_content_hash": "a" * 64,
    "observed_at": "2026-07-28T00:00:00Z",
}

EXAMPLES: Final[dict[str, dict[str, object]]] = {
    "context-packet": {
        "schema_version": SCHEMA_VERSION,
        "packet_id": "00000000-0000-4000-8000-000000000301",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "repository_id": "00000000-0000-4000-8000-000000000304",
        "work_item_id": "00000000-0000-4000-8000-000000000302",
        "revision": 1,
        "generated_at": "2026-07-28T00:00:00Z",
        "content_hash": "b" * 64,
        "phase": "PREFLIGHT",
        "request": {
            "task": "Prepare checkout for deployment",
            "phase": "PREFLIGHT",
            "budget": {
                "max_items": 50,
                "max_tokens": 8000,
                "max_bytes": 100000,
                "max_citations": 100,
            },
        },
        "authorization_hash": "c" * 64,
        "selection_hash": "b" * 64,
        "retrieval_watermark": 1,
        "retrieval_algorithm_version": "permission-first-rrf-v1",
        "index_version": "fts-vector-v1",
        "embedding_version": "hash-32-v1",
        "budget": {
            "max_items": 50,
            "max_tokens": 8000,
            "max_bytes": 100000,
            "max_citations": 100,
            "selected_items": 1,
            "selected_tokens": 12,
            "selected_bytes": 256,
            "selected_citations": 1,
        },
        "items": [
            {
                "item_id": "00000000-0000-4000-8000-000000000303",
                "kind": "DECISION",
                "item_key": "assertion:00000000-0000-4000-8000-000000000303",
                "summary": "Checkout is owned by the payments team.",
                "is_inferred": False,
                "freshness": "CURRENT",
                "selection_reason": "Relevant decision",
                "rank_score": 1.0,
                "payload": {"assertion_id": "00000000-0000-4000-8000-000000000303"},
                "anva_sources": [RETRIEVAL_CITATION_EXAMPLE],
            }
        ],
        "limitations": [],
    },
    "evidence-manifest": {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": "00000000-0000-4000-8000-000000000401",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "commit_sha": "a" * 40,
        "created_at": "2026-07-28T00:01:00Z",
        "entries": [
            {
                "evidence_id": "00000000-0000-4000-8000-000000000402",
                "kind": "TEST",
                "status": "PASSED",
                "artifact_uri": "s3://anva/evidence/tests.json",
                "content_hash": "c" * 64,
                "created_at": "2026-07-28T00:01:00Z",
                "producer": "github-actions",
            }
        ],
    },
    "finding": FINDING_EXAMPLE,
    "evaluator-request": {
        "schema_version": SCHEMA_VERSION,
        "request_id": "00000000-0000-4000-8000-000000000501",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "commit_sha": "d" * 40,
        "policy_id": "00000000-0000-4000-8000-000000000502",
        "policy_version": 3,
        "context_packet_id": "00000000-0000-4000-8000-000000000301",
        "evidence_manifest_id": "00000000-0000-4000-8000-000000000401",
        "untrusted_change": {
            "title": "Change checkout retry handling",
            "description": "Pull request text is untrusted input.",
            "diff_reference": "https://example.test/pulls/17.diff",
        },
    },
    "evaluator-result": {
        "schema_version": SCHEMA_VERSION,
        "request_id": "00000000-0000-4000-8000-000000000501",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "commit_sha": "d" * 40,
        "outcome": "NOT_READY",
        "findings": [FINDING_EXAMPLE],
        "limitations": ["Runtime performance was not measured."],
        "evaluated_at": "2026-07-28T00:02:00Z",
    },
    "policy": {
        "schema_version": SCHEMA_VERSION,
        "policy_id": "00000000-0000-4000-8000-000000000502",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "version": 3,
        "name": "Default repository assurance",
        "effective_at": "2026-07-01T00:00:00Z",
        "requirements": [
            {
                "requirement_id": "00000000-0000-4000-8000-000000000503",
                "code": "TESTS_PASS",
                "description": "Repository tests must pass.",
                "enforcement": "BLOCKING",
                "check_type": "EVIDENCE",
                "required_evidence": ["TEST"],
            }
        ],
    },
    "knowledge-proposal": {
        "schema_version": SCHEMA_VERSION,
        "proposal_id": "00000000-0000-4000-8000-000000000601",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "proposal_version": 1,
        "state": "PROPOSED",
        "summary": "Record the checkout ownership correction.",
        "changes": [
            {
                "operation": "CORRECT",
                "target_id": "00000000-0000-4000-8000-000000000602",
                "predicate": "owned_by",
                "value": {"team": "payments-platform"},
                "is_inferred": False,
            }
        ],
        "anva_sources": [SOURCE_EXAMPLE],
        "submitted_by": "00000000-0000-4000-8000-000000000603",
        "created_at": "2026-07-28T00:03:00Z",
    },
}
