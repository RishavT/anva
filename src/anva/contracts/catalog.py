"""Canonical source definitions for Anva's version 1 external contracts."""

from __future__ import annotations

from copy import deepcopy
from typing import Final

SCHEMA_VERSION: Final = "1.0"
SCHEMA_BASE_URI: Final = "https://schemas.anva.dev/v1"
SHA256_PATTERN: Final = "^[a-f0-9]{64}$"
COMMIT_PATTERN: Final = "^[a-f0-9]{40}$"
EVIDENCE_KINDS: Final[list[str]] = [
    "CHECK_STATUS",
    "TEST_RESULT",
    "BUILD_RESULT",
    "TYPECHECK_RESULT",
    "LINT_RESULT",
    "SCREENSHOT",
    "VIDEO",
    "CONSOLE_LOG",
    "NETWORK_TRACE",
    "API_ASSERTION",
    "STATIC_ANALYSIS",
    "SECURITY_SCAN",
    "DEPENDENCY_SCAN",
    "MIGRATION_RESULT",
    "PERFORMANCE_RESULT",
    "ACCESSIBILITY_RESULT",
    "MANUAL_APPROVAL",
    "SOURCE_REFERENCE",
    "DIFF_REFERENCE",
]


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

WORK_ITEM_IMPORT_SCHEMA = versioned_schema(
    "work-item-import",
    "Anva Versioned Work Item Import",
    {
        "work_item_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "repository_id": UUID_FIELD,
        "access_scope_id": UUID_FIELD,
        "revision": {"type": "integer", "minimum": 1},
        "external_key": {
            "oneOf": [
                {"type": "string", "minLength": 1, "maxLength": 300},
                {"type": "null"},
            ]
        },
        "title": {"type": "string", "minLength": 1, "maxLength": 500},
        "work_type": {
            "type": "string",
            "enum": ["FEATURE", "BUG", "SECURITY", "MIGRATION", "OPERATIONS", "OTHER"],
        },
        "status": {"type": "string", "enum": ["DRAFT", "READY", "APPROVED", "CLOSED"]},
        "summary": {"type": "string", "maxLength": 20_000},
        "origin": {"type": "string", "minLength": 1, "maxLength": 100},
        "source_references": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 1_000},
            "uniqueItems": True,
            "maxItems": 500,
        },
        "requirements": {
            "type": "array",
            "items": {"$ref": "#/$defs/requirement"},
            "maxItems": 500,
        },
        "non_requirements": {
            "type": "array",
            "items": {"$ref": "#/$defs/non_requirement"},
            "maxItems": 500,
        },
        "assumptions": {
            "type": "array",
            "items": {"$ref": "#/$defs/assumption"},
            "maxItems": 500,
        },
        "acceptance_criteria": {
            "type": "array",
            "items": {"$ref": "#/$defs/acceptance_criterion"},
            "minItems": 1,
            "maxItems": 500,
        },
        "decisions": {
            "type": "array",
            "items": {"$ref": "#/$defs/decision"},
            "maxItems": 500,
        },
        "summaries": {
            "type": "array",
            "items": {"$ref": "#/$defs/work_summary"},
            "maxItems": 100,
        },
    },
    [
        "work_item_id",
        "organization_id",
        "repository_id",
        "access_scope_id",
        "revision",
        "external_key",
        "title",
        "work_type",
        "status",
        "summary",
        "origin",
        "source_references",
        "requirements",
        "non_requirements",
        "assumptions",
        "acceptance_criteria",
        "decisions",
        "summaries",
    ],
    definitions={
        "requirement": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
                "normalized_text": {"type": "string", "minLength": 1, "maxLength": 10_000},
                "origin": {"type": "string", "minLength": 1, "maxLength": 100},
                "owner": {"type": "string", "maxLength": 300},
                "status": {"type": "string", "minLength": 1, "maxLength": 24},
                "source_references": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 1_000},
                    "uniqueItems": True,
                    "maxItems": 100,
                },
                "related_entity_ids": {
                    "type": "array",
                    "items": UUID_FIELD,
                    "uniqueItems": True,
                    "maxItems": 500,
                },
                "requires_approval": {"type": "boolean"},
            },
            "required": [
                "code",
                "normalized_text",
                "origin",
                "owner",
                "status",
                "source_references",
                "related_entity_ids",
                "requires_approval",
            ],
        },
        "non_requirement": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
                "normalized_text": {"type": "string", "minLength": 1, "maxLength": 10_000},
                "rationale": {"type": "string", "maxLength": 10_000},
            },
            "required": ["code", "normalized_text", "rationale"],
        },
        "assumption": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
                "normalized_text": {"type": "string", "minLength": 1, "maxLength": 10_000},
                "status": {"type": "string", "enum": ["OPEN", "VALIDATED", "INVALIDATED"]},
                "validation_reference": {"type": "string", "maxLength": 1_000},
            },
            "required": ["code", "normalized_text", "status", "validation_reference"],
        },
        "acceptance_criterion": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
                "requirement_code": {
                    "oneOf": [
                        {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
                        {"type": "null"},
                    ]
                },
                "normalized_text": {"type": "string", "minLength": 1, "maxLength": 10_000},
                "required_evidence_types": {
                    "type": "array",
                    "items": {"type": "string", "enum": EVIDENCE_KINDS},
                    "uniqueItems": True,
                    "minItems": 1,
                    "maxItems": 20,
                },
                "manual_approval_allowed": {"type": "boolean"},
            },
            "required": [
                "code",
                "requirement_code",
                "normalized_text",
                "required_evidence_types",
                "manual_approval_allowed",
            ],
        },
        "decision": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "code": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
                "title": {"type": "string", "minLength": 1, "maxLength": 500},
                "outcome": {"type": "string", "minLength": 1, "maxLength": 10_000},
                "rationale": {"type": "string", "maxLength": 10_000},
                "status": {
                    "type": "string",
                    "enum": ["PROPOSED", "ACCEPTED", "REJECTED", "SUPERSEDED"],
                },
            },
            "required": ["code", "title", "outcome", "rationale", "status"],
        },
        "work_summary": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "summary_type": {"type": "string", "minLength": 1, "maxLength": 40},
                "structured_data": {"type": "object"},
                "producer": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "required": ["summary_type", "structured_data", "producer"],
        },
    },
)

EVIDENCE_ENTRY: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "evidence_id": UUID_FIELD,
        "kind": {
            "type": "string",
            "enum": EVIDENCE_KINDS,
        },
        "name": {"type": "string", "minLength": 1, "maxLength": 300},
        "status": {"type": "string", "enum": ["PASSED", "FAILED", "UNKNOWN"]},
        "command": {"type": "string", "maxLength": 2_000},
        "artifact_reference": {
            "type": "string",
            "maxLength": 2_000,
            "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\)(?!.*\\x00).*$",
        },
        "source_url": {
            "oneOf": [
                {"type": "string", "format": "uri", "maxLength": 2_000},
                {"type": "null"},
            ]
        },
        "content_hash": SHA256_FIELD,
        "started_at": {"oneOf": [DATE_TIME_FIELD, {"type": "null"}]},
        "completed_at": DATE_TIME_FIELD,
        "producer": {"type": "string", "minLength": 1, "maxLength": 200},
        "producer_version": {"type": "string", "minLength": 1, "maxLength": 100},
        "approval_id": {"oneOf": [UUID_FIELD, {"type": "null"}]},
        "retention_class": {"type": "string", "minLength": 1, "maxLength": 100},
        "retention_expires_at": {"oneOf": [DATE_TIME_FIELD, {"type": "null"}]},
        "limitations": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "minLength": 1, "maxLength": 2_000},
        },
        "criterion_codes": {
            "type": "array",
            "maxItems": 500,
            "uniqueItems": True,
            "items": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{2,63}$"},
        },
        "environment": {"type": "string", "maxLength": 200},
        "scenario": {"type": "string", "maxLength": 500},
    },
    "required": [
        "evidence_id",
        "kind",
        "name",
        "status",
        "command",
        "artifact_reference",
        "source_url",
        "content_hash",
        "started_at",
        "completed_at",
        "producer",
        "producer_version",
        "approval_id",
        "retention_class",
        "retention_expires_at",
        "limitations",
        "criterion_codes",
        "environment",
        "scenario",
    ],
}

EVIDENCE_MANIFEST_SCHEMA = versioned_schema(
    "evidence-manifest",
    "Anva Evidence Manifest",
    {
        "manifest_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "repository_id": UUID_FIELD,
        "access_scope_id": UUID_FIELD,
        "pull_request_number": {"type": "integer", "minimum": 1},
        "work_item_revision_id": {"oneOf": [UUID_FIELD, {"type": "null"}]},
        "commit_sha": COMMIT_FIELD,
        "created_at": DATE_TIME_FIELD,
        "producer": {"type": "string", "minLength": 1, "maxLength": 200},
        "producer_version": {"type": "string", "minLength": 1, "maxLength": 100},
        "producer_mode": {"type": "string", "enum": ["MANUAL", "CI"]},
        "entries": {
            "type": "array",
            "items": {"$ref": "#/$defs/evidence_entry"},
            "maxItems": 500,
        },
    },
    [
        "manifest_id",
        "organization_id",
        "repository_id",
        "access_scope_id",
        "pull_request_number",
        "work_item_revision_id",
        "commit_sha",
        "created_at",
        "producer",
        "producer_version",
        "producer_mode",
        "entries",
    ],
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
            "items": {"type": "string", "enum": EVIDENCE_KINDS},
            "uniqueItems": True,
        },
        "required_reviewers": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 100},
            "uniqueItems": True,
        },
        "required_approval": {"type": "boolean"},
        "report_sections": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 100},
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
        "required_reviewers",
        "required_approval",
        "report_sections",
    ],
}

POLICY_BINDING: Final[dict[str, object]] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "scope_level": {
            "type": "string",
            "enum": ["ORGANIZATION", "PRODUCT", "SYSTEM", "REPOSITORY", "PATH"],
        },
        "mandatory": {"type": "boolean"},
        "repository_ids": {
            "type": "array",
            "items": UUID_FIELD,
            "uniqueItems": True,
            "maxItems": 500,
        },
        "entity_ids": {
            "type": "array",
            "items": UUID_FIELD,
            "uniqueItems": True,
            "maxItems": 500,
        },
        "entity_types": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": [
                    "TEAM",
                    "REPOSITORY",
                    "SERVICE",
                    "COMPONENT",
                    "API",
                    "DATA_ASSET",
                    "DECISION",
                    "POLICY",
                    "REQUIREMENT",
                    "UNKNOWN",
                ],
            },
            "uniqueItems": True,
            "maxItems": 100,
        },
        "path_patterns": {
            "type": "array",
            "items": {
                "type": "string",
                "minLength": 1,
                "maxLength": 500,
                "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\)(?!.*\\x00).*$",
            },
            "uniqueItems": True,
            "maxItems": 500,
        },
        "work_item_types": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["FEATURE", "BUG", "SECURITY", "MIGRATION", "OPERATIONS", "OTHER"],
            },
            "uniqueItems": True,
        },
        "target_branches": {
            "type": "array",
            "items": {"type": "string", "minLength": 1, "maxLength": 300},
            "uniqueItems": True,
            "maxItems": 100,
        },
    },
    "required": [
        "scope_level",
        "mandatory",
        "repository_ids",
        "entity_ids",
        "entity_types",
        "path_patterns",
        "work_item_types",
        "target_branches",
    ],
}

POLICY_SCHEMA = versioned_schema(
    "policy",
    "Anva Assurance Policy",
    {
        "policy_id": UUID_FIELD,
        "organization_id": UUID_FIELD,
        "access_scope_id": UUID_FIELD,
        "version": {"type": "integer", "minimum": 1},
        "name": {"type": "string", "minLength": 1, "maxLength": 300},
        "owner": {"type": "string", "minLength": 1, "maxLength": 300},
        "status": {"type": "string", "enum": ["DRAFT", "ACTIVE", "DISABLED"]},
        "effective_at": DATE_TIME_FIELD,
        "expires_at": {"oneOf": [DATE_TIME_FIELD, {"type": "null"}]},
        "binding": {"$ref": "#/$defs/policy_binding"},
        "requirements": {
            "type": "array",
            "items": {"$ref": "#/$defs/policy_requirement"},
            "minItems": 1,
            "maxItems": 500,
        },
    },
    [
        "policy_id",
        "organization_id",
        "access_scope_id",
        "version",
        "name",
        "owner",
        "status",
        "effective_at",
        "expires_at",
        "binding",
        "requirements",
    ],
    definitions={
        "policy_binding": POLICY_BINDING,
        "policy_requirement": POLICY_REQUIREMENT,
    },
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
    "work-item-import": WORK_ITEM_IMPORT_SCHEMA,
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
        "repository_id": "00000000-0000-4000-8000-000000000304",
        "access_scope_id": "00000000-0000-4000-8000-000000000504",
        "pull_request_number": 17,
        "work_item_revision_id": None,
        "commit_sha": "a" * 40,
        "created_at": "2026-07-28T00:01:00Z",
        "producer": "github-actions",
        "producer_version": "1",
        "producer_mode": "CI",
        "entries": [
            {
                "evidence_id": "00000000-0000-4000-8000-000000000402",
                "kind": "TEST_RESULT",
                "name": "unit tests",
                "status": "PASSED",
                "command": "pytest -m unit",
                "artifact_reference": "artifacts/tests.json",
                "source_url": "https://example.test/runs/17",
                "content_hash": "c" * 64,
                "started_at": "2026-07-28T00:00:00Z",
                "completed_at": "2026-07-28T00:01:00Z",
                "producer": "github-actions",
                "producer_version": "1",
                "approval_id": None,
                "retention_class": "ASSURANCE_1Y",
                "retention_expires_at": "2027-07-28T00:01:00Z",
                "limitations": [],
                "criterion_codes": ["TESTS_PASS"],
                "environment": "ci",
                "scenario": "unit",
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
        "access_scope_id": "00000000-0000-4000-8000-000000000504",
        "version": 3,
        "name": "Default repository assurance",
        "owner": "platform",
        "status": "ACTIVE",
        "effective_at": "2026-07-01T00:00:00Z",
        "expires_at": None,
        "binding": {
            "scope_level": "REPOSITORY",
            "mandatory": True,
            "repository_ids": ["00000000-0000-4000-8000-000000000304"],
            "entity_ids": [],
            "entity_types": [],
            "path_patterns": [],
            "work_item_types": [],
            "target_branches": ["main"],
        },
        "requirements": [
            {
                "requirement_id": "00000000-0000-4000-8000-000000000503",
                "code": "TESTS_PASS",
                "description": "Repository tests must pass.",
                "enforcement": "BLOCKING",
                "check_type": "EVIDENCE",
                "required_evidence": ["TEST_RESULT"],
                "required_reviewers": [],
                "required_approval": False,
                "report_sections": ["tests"],
            }
        ],
    },
    "work-item-import": {
        "schema_version": SCHEMA_VERSION,
        "work_item_id": "00000000-0000-4000-8000-000000000701",
        "organization_id": "00000000-0000-4000-8000-000000000001",
        "repository_id": "00000000-0000-4000-8000-000000000304",
        "access_scope_id": "00000000-0000-4000-8000-000000000504",
        "revision": 1,
        "external_key": "ANVA-6",
        "title": "Deterministic intent and evidence",
        "work_type": "FEATURE",
        "status": "READY",
        "summary": "Version intent and map evidence.",
        "origin": "github-issue",
        "source_references": ["https://example.test/issues/6"],
        "requirements": [
            {
                "code": "REQ_VERSION_INTENT",
                "normalized_text": "Version normalized intent.",
                "origin": "issue",
                "owner": "platform",
                "status": "CONFIRMED",
                "source_references": ["https://example.test/issues/6"],
                "related_entity_ids": [],
                "requires_approval": False,
            }
        ],
        "non_requirements": [
            {
                "code": "NONREQ_RUN_ARTIFACTS",
                "normalized_text": "Do not execute submitted artifacts.",
                "rationale": "Evidence ingestion is declarative.",
            }
        ],
        "assumptions": [
            {
                "code": "ASM_CI_TRUST",
                "normalized_text": "CI producer identity is configured.",
                "status": "OPEN",
                "validation_reference": "",
            }
        ],
        "acceptance_criteria": [
            {
                "code": "TESTS_PASS",
                "requirement_code": "REQ_VERSION_INTENT",
                "normalized_text": "Tests pass for the exact commit.",
                "required_evidence_types": ["TEST_RESULT"],
                "manual_approval_allowed": False,
            }
        ],
        "decisions": [
            {
                "code": "DEC_MANIFEST_ONLY",
                "title": "Manifest-only ingestion",
                "outcome": "Never fetch or execute artifacts during ingestion.",
                "rationale": "Treat all manifest fields as hostile input.",
                "status": "ACCEPTED",
            }
        ],
        "summaries": [
            {
                "summary_type": "PLAN",
                "structured_data": {"text": "Context only; never evidence."},
                "producer": "anva-cli",
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
