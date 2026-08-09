"""Deterministically generate and validate versioned contract artifacts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator

from anva.contracts.catalog import EXAMPLES, KNOWLEDGE_CHANGE, SCHEMAS
from anva.contracts.validation import validate_payload
from anva.mcp.contracts import TOOL_CONTRACTS, mcp_contract_document

REPOSITORY_ROOT = Path.cwd()
CONTRACT_ROOT = REPOSITORY_ROOT / "contracts"


def canonical_json(value: object) -> bytes:
    """Return stable human-readable JSON bytes."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def openapi_document() -> dict[str, object]:
    """Generate the initial HTTP contract from the canonical schemas."""
    mutation_parameters: list[dict[str, object]] = [
        {"$ref": "#/components/parameters/CorrelationId"},
    ]
    upload_authorization_response_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "authorization_id": {"type": "string", "format": "uuid"},
            "repository_id": {"type": "string", "format": "uuid"},
            "access_scope_id": {"type": "string", "format": "uuid"},
            "pull_request_number": {"type": "integer", "minimum": 1},
            "commit_sha": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "declared_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "declared_size": {"type": "integer", "minimum": 1, "maximum": 4_096},
            "state": {
                "type": "string",
                "enum": [
                    "ISSUED",
                    "RECEIVING",
                    "RECOVERING",
                    "ACCEPTED",
                    "REJECTED",
                    "EXPIRED",
                    "REVOKED",
                ],
            },
            "expires_at": {"type": "string", "format": "date-time"},
            "upload_path": {
                "type": "string",
                "pattern": ("^/api/v1/evidence-upload-authorizations/[a-f0-9-]{36}/content$"),
            },
            "upload_token": {
                "oneOf": [
                    {"type": "string", "minLength": 32, "maxLength": 512},
                    {"type": "null"},
                ]
            },
            "replayed": {"type": "boolean"},
        },
        "required": [
            "authorization_id",
            "repository_id",
            "access_scope_id",
            "pull_request_number",
            "commit_sha",
            "declared_sha256",
            "declared_size",
            "state",
            "expires_at",
            "upload_path",
            "upload_token",
            "replayed",
        ],
    }
    evidence_blob_response_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "evidence_blob_id": {"type": "string", "format": "uuid"},
            "authorization_id": {"type": "string", "format": "uuid"},
            "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "verified_size": {"type": "integer", "minimum": 1, "maximum": 4_096},
            "detected_type": {
                "type": "string",
                "enum": ["application/json", "application/zip", "application/x-tar"],
            },
            "archive_summary": {"type": "object", "maxProperties": 32},
            "storage_state": {"type": "string", "const": "AVAILABLE"},
        },
        "required": [
            "evidence_blob_id",
            "authorization_id",
            "sha256",
            "verified_size",
            "detected_type",
            "archive_summary",
            "storage_state",
        ],
    }
    structured_errors: dict[str, object] = {
        "400": {"$ref": "#/components/responses/StructuredError"},
        "401": {"$ref": "#/components/responses/StructuredError"},
        "404": {"$ref": "#/components/responses/StructuredError"},
        "409": {"$ref": "#/components/responses/StructuredError"},
        "429": {"$ref": "#/components/responses/StructuredError"},
    }
    authorized_responses: dict[str, object] = {
        "200": {"description": "Authorized tenant-scoped response."},
        **structured_errors,
    }
    accepted_responses: dict[str, object] = {
        "202": {"description": "Authorized request accepted."},
        **structured_errors,
    }
    decommission_responses: dict[str, object] = {
        **accepted_responses,
        "403": {"description": "CSRF validation failed before domain dispatch."},
    }
    created_responses: dict[str, object] = {
        "201": {"description": "Tenant-scoped resource created."},
        **structured_errors,
    }
    created_or_replayed_responses: dict[str, object] = {
        "200": {"description": "Existing resource returned for an exact canonical replay."},
        "201": {"description": "Tenant-scoped resource created."},
        **structured_errors,
    }
    upload_authorization_responses: dict[str, object] = {
        "200": {
            "description": (
                "Exact authorization replay; the original upload secret is not re-emitted."
            ),
            "content": {"application/json": {"schema": upload_authorization_response_schema}},
        },
        "201": {
            "description": "Short-lived upload authorization issued.",
            "content": {"application/json": {"schema": upload_authorization_response_schema}},
        },
        **structured_errors,
    }
    upload_responses: dict[str, object] = {
        "201": {
            "description": "Evidence bytes were accepted and retained.",
            "content": {"application/json": {"schema": evidence_blob_response_schema}},
        },
        **structured_errors,
        "413": {"$ref": "#/components/responses/StructuredError"},
        "415": {"$ref": "#/components/responses/StructuredError"},
        "422": {"$ref": "#/components/responses/StructuredError"},
        "503": {"$ref": "#/components/responses/StructuredError"},
    }
    organization_parameter = {
        "name": "organization_id",
        "in": "path",
        "required": True,
        "schema": {"type": "string", "format": "uuid"},
    }
    repository_parameter = {
        "name": "repository_id",
        "in": "path",
        "required": True,
        "schema": {"type": "string", "format": "uuid"},
    }
    resource_parameter = {
        "name": "resource_id",
        "in": "path",
        "required": True,
        "schema": {"type": "string", "format": "uuid"},
    }
    repository_query_parameter = {
        "name": "repository_id",
        "in": "query",
        "required": True,
        "schema": {"type": "string", "format": "uuid"},
    }
    work_approval_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repository_id": {"type": "string", "format": "uuid"},
            "status": {"type": "string", "enum": ["APPROVED", "REJECTED"]},
            "target_kind": {
                "type": "string",
                "enum": [
                    "WORK_ITEM_REVISION",
                    "REQUIREMENT",
                    "ACCEPTANCE_CRITERION",
                    "DECISION",
                ],
            },
            "target_key": {"type": "string", "minLength": 1, "maxLength": 200},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "expires_at": {
                "oneOf": [
                    {"type": "string", "format": "date-time"},
                    {"type": "null"},
                ]
            },
        },
        "required": [
            "repository_id",
            "status",
            "target_kind",
            "target_key",
            "reason",
        ],
    }
    revocation_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repository_id": {"type": "string", "format": "uuid"},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2_000},
        },
        "required": ["repository_id", "reason"],
    }
    evidence_mapping_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repository_id": {"type": "string", "format": "uuid"},
            "pull_request_number": {"type": "integer", "minimum": 1},
            "commit_sha": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "reference_time": {"type": "string", "format": "date-time"},
        },
        "required": [
            "repository_id",
            "pull_request_number",
            "commit_sha",
            "reference_time",
        ],
    }
    affected_entity = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "id": {"type": "string", "format": "uuid"},
            "type": {
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
        },
        "required": ["id", "type"],
    }
    policy_simulation_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repository_id": {"type": "string", "format": "uuid"},
            "pull_request_number": {"type": "integer", "minimum": 1},
            "commit_sha": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "policy_version_ids": {
                "type": "array",
                "items": {"type": "string", "format": "uuid"},
                "minItems": 1,
                "maxItems": 100,
                "uniqueItems": True,
            },
            "reference_time": {"type": "string", "format": "date-time"},
            "affected_paths": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 500},
                "maxItems": 1_000,
                "uniqueItems": True,
            },
            "affected_entities": {
                "type": "array",
                "items": affected_entity,
                "maxItems": 1_000,
                "uniqueItems": True,
            },
            "target_branch": {"type": "string", "minLength": 1, "maxLength": 300},
            "work_item_revision_id": {
                "oneOf": [
                    {"type": "string", "format": "uuid"},
                    {"type": "null"},
                ]
            },
        },
        "required": [
            "repository_id",
            "pull_request_number",
            "commit_sha",
            "policy_version_ids",
            "reference_time",
            "affected_paths",
            "affected_entities",
            "target_branch",
        ],
    }
    policy_override_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repository_id": {"type": "string", "format": "uuid"},
            "policy_evaluation_id": {"type": "string", "format": "uuid"},
            "policy_version_id": {"type": "string", "format": "uuid"},
            "requirement_code": {
                "type": "string",
                "pattern": "^[A-Z][A-Z0-9_]{2,63}$",
            },
            "pull_request_number": {"type": "integer", "minimum": 1},
            "commit_sha": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "expires_at": {
                "oneOf": [
                    {"type": "string", "format": "date-time"},
                    {"type": "null"},
                ]
            },
        },
        "required": [
            "repository_id",
            "policy_evaluation_id",
            "policy_version_id",
            "requirement_code",
            "pull_request_number",
            "commit_sha",
            "reason",
        ],
    }
    manual_diff_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "access_scope_id": {"type": "string", "format": "uuid"},
            "base_commit": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "head_commit": {"type": "string", "pattern": "^[a-f0-9]{40}$"},
            "title": {"type": "string", "minLength": 1, "maxLength": 1_000},
            "description": {"type": "string", "maxLength": 50_000},
            "target_branch": {"type": "string", "minLength": 1, "maxLength": 300},
            "is_draft": {"type": "boolean"},
            "state": {"type": "string", "enum": ["OPEN", "MERGED", "CLOSED"]},
            "unified_diff": {"type": "string", "minLength": 1, "maxLength": 1_000_000},
        },
        "required": [
            "access_scope_id",
            "base_commit",
            "head_commit",
            "title",
            "description",
            "target_branch",
            "is_draft",
            "state",
            "unified_diff",
        ],
    }
    deterministic_check = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "code": {"type": "string", "minLength": 1, "maxLength": 100},
            "status": {
                "type": "string",
                "enum": ["PASSED", "FAILED", "NOT_AVAILABLE"],
            },
            "blocking": {"type": "boolean"},
            "summary": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "evidence_ids": {
                "type": "array",
                "items": {"type": "string", "format": "uuid"},
                "uniqueItems": True,
                "maxItems": 100,
            },
        },
        "required": ["code", "status", "blocking", "summary", "evidence_ids"],
    }
    assurance_start_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "policy_version_ids": {
                "type": "array",
                "items": {"type": "string", "format": "uuid"},
                "minItems": 1,
                "maxItems": 100,
                "uniqueItems": True,
            },
            "reference_time": {"type": "string", "format": "date-time"},
            "deterministic_checks": {
                "type": "array",
                "items": deterministic_check,
                "maxItems": 200,
            },
            "work_item_revision_id": {"type": "string", "format": "uuid"},
            "evaluator_version": {"type": "string", "minLength": 1, "maxLength": 100},
            "prompt_version": {"type": "string", "minLength": 1, "maxLength": 100},
            "trigger_key": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        },
        "required": ["policy_version_ids", "reference_time", "deterministic_checks"],
    }
    evaluator_claim_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "claimant": {
                "type": "string",
                "minLength": 1,
                "maxLength": 200,
                "description": (
                    "Audit-only evaluator/provider label; authenticated actor and "
                    "credential identity own the claim."
                ),
            },
            "lease_seconds": {"type": "integer", "minimum": 60, "maximum": 3_600},
        },
        "required": ["claimant"],
    }
    evaluator_submit_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "claimant": {
                "type": "string",
                "minLength": 1,
                "maxLength": 200,
                "description": (
                    "Optional backwards-compatible display label. It is not an "
                    "authorization factor; claim-time metadata remains authoritative."
                ),
            },
            "claim_token": {"type": "string", "minLength": 1, "maxLength": 200},
            "result": {"$ref": "#/components/schemas/evaluator-result"},
        },
        "required": ["claim_token", "result"],
    }
    finding_decision_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "repository_id": {"type": "string", "format": "uuid"},
            "target_state": {
                "type": "string",
                "enum": ["DISMISSED", "RISK_ACCEPTED", "RESOLVED", "OPEN"],
            },
            "expected_revision": {"type": "integer", "minimum": 1},
            "reason": {"type": "string", "minLength": 1, "maxLength": 2_000},
        },
        "required": ["repository_id"],
    }
    post_merge_proposals_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "proposals": {
                "type": "array",
                "minItems": 1,
                "maxItems": 50,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "summary": {"type": "string", "minLength": 1, "maxLength": 5_000},
                        "changes": {
                            "type": "array",
                            "items": KNOWLEDGE_CHANGE,
                            "minItems": 1,
                            "maxItems": 100,
                        },
                        "context_citation_ids": {
                            "type": "array",
                            "items": {"type": "string", "format": "uuid"},
                            "minItems": 1,
                            "uniqueItems": True,
                        },
                        "classification": {
                            "type": "string",
                            "enum": ["MECHANICAL", "INTERPRETIVE"],
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["HIGH", "MEDIUM", "LOW"],
                        },
                    },
                    "required": [
                        "summary",
                        "changes",
                        "context_citation_ids",
                        "classification",
                        "confidence",
                    ],
                },
            }
        },
        "required": ["proposals"],
    }
    github_permissions = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "actions": {"type": "string", "const": "read"},
            "checks": {"type": "string", "const": "write"},
            "contents": {"type": "string", "const": "read"},
            "issues": {"type": "string", "const": "write"},
            "metadata": {"type": "string", "const": "read"},
            "pull_requests": {"type": "string", "enum": ["read", "write"]},
        },
        "required": ["checks", "contents", "issues", "pull_requests"],
    }
    github_binding_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "access_scope_id": {"type": "string", "format": "uuid"},
            "installation_id": {"type": "integer", "minimum": 1},
            "account_id": {"type": "integer", "minimum": 1},
            "account_login": {"type": "string", "minLength": 1, "maxLength": 300},
            "account_type": {"type": "string", "enum": ["Organization", "User"]},
            "repository_selection": {"type": "string", "enum": ["all", "selected"]},
            "permissions": github_permissions,
            "external_repository_id": {"type": "integer", "minimum": 1},
            "full_name": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$",
            },
            "default_branch": {"type": "string", "minLength": 1, "maxLength": 300},
            "private": {"type": "boolean"},
            "archived": {"type": "boolean"},
            "auto_assurance": {"type": "boolean"},
            "policy_version_ids": {
                "type": "array",
                "items": {"type": "string", "format": "uuid"},
                "maxItems": 100,
                "uniqueItems": True,
            },
            "work_item_revision_id": {
                "oneOf": [
                    {"type": "string", "format": "uuid"},
                    {"type": "null"},
                ]
            },
        },
        "required": [
            "access_scope_id",
            "installation_id",
            "account_id",
            "account_login",
            "account_type",
            "repository_selection",
            "permissions",
            "external_repository_id",
            "full_name",
            "default_branch",
            "private",
            "archived",
            "auto_assurance",
            "policy_version_ids",
        ],
    }
    empty_object_request = {
        "type": "object",
        "additionalProperties": False,
        "maxProperties": 0,
    }
    canvas_entity_types = [
        "GOAL",
        "METRIC",
        "INITIATIVE",
        "PRODUCT",
        "OWNER",
        "ENVIRONMENT",
        "CUSTOMER_COMMITMENT",
        "ARCHITECTURAL_DECISION",
        "ACCEPTANCE_CRITERION",
        "RELEASE",
        "TEAM",
        "REPOSITORY",
        "SERVICE",
        "COMPONENT",
        "API",
        "DATA_ASSET",
        "WORK_ITEM",
        "TASK",
        "PULL_REQUEST",
        "EVIDENCE",
        "RISK",
        "INCIDENT",
        "CONTROL",
        "DECISION",
        "POLICY",
        "REQUIREMENT",
        "UNKNOWN",
    ]
    canvas_relationship_types = [
        "GOAL_MEASURED_BY_METRIC",
        "INITIATIVE_SUPPORTS_GOAL",
        "INITIATIVE_OWNED_BY_TEAM",
        "INITIATIVE_AFFECTS_PRODUCT",
        "PRODUCT_IMPLEMENTED_BY_REPOSITORY",
        "COMPONENT_BELONGS_TO_PRODUCT",
        "REPOSITORY_OWNED_BY_TEAM",
        "REPOSITORY_CONTAINS_COMPONENT",
        "SERVICE_IMPLEMENTED_BY_REPOSITORY",
        "SERVICE_DEPENDS_ON_SERVICE",
        "API_PROVIDED_BY_SERVICE",
        "API_CONSUMED_BY_COMPONENT",
        "DATA_ASSET_USED_BY_SERVICE",
        "DECISION_APPLIES_TO_ENTITY",
        "POLICY_APPLIES_TO_ENTITY",
        "RISK_AFFECTS_ENTITY",
        "INCIDENT_AFFECTED_ENTITY",
        "REQUIREMENT_SUPPORTS_INITIATIVE",
        "REQUIREMENT_IMPLEMENTED_BY_PULL_REQUEST",
        "ACCEPTANCE_CRITERION_VERIFIED_BY_EVIDENCE",
        "TASK_CHANGES_ENTITY",
        "PULL_REQUEST_CHANGES_ENTITY",
        "ENTITY_OWNED_BY_OWNER",
        "ENTITY_REVIEWED_BY_TEAM",
    ]
    canvas_semantic_properties: dict[str, object] = {
        "root_entity_id": {"type": "string", "format": "uuid"},
        "repository_ids": {
            "type": "array",
            "items": {"type": "string", "format": "uuid"},
            "maxItems": 100,
            "uniqueItems": True,
        },
        "entity_types": {
            "type": "array",
            "items": {"type": "string", "enum": canvas_entity_types},
            "maxItems": len(canvas_entity_types),
            "uniqueItems": True,
        },
        "owner": {"type": "string", "maxLength": 500},
        "status": {"type": "string", "maxLength": 500},
        "risk": {"type": "string", "maxLength": 500},
        "freshness": {
            "type": "string",
            "enum": [
                "FRESH",
                "AGING",
                "STALE",
                "CONTRADICTED",
                "SOURCE_UNAVAILABLE",
                "UNKNOWN",
            ],
        },
        "as_of": {"type": "string", "format": "date-time"},
        "search": {"type": "string", "maxLength": 500},
        "layers": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": [
                    "execution",
                    "ownership",
                    "dependencies",
                    "governance",
                    "provenance",
                ],
            },
            "maxItems": 5,
            "uniqueItems": True,
        },
        "depth": {"type": "integer", "minimum": 1, "maximum": 4},
    }
    canvas_query_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "view_id": {"type": "string", "format": "uuid"},
            "view_revision": {"type": "integer", "minimum": 1},
            **{
                key: value
                for key, value in canvas_semantic_properties.items()
                if key != "root_entity_id"
            },
            "as_of": {
                "oneOf": [
                    {"type": "string", "format": "date-time"},
                    {"type": "null"},
                ]
            },
            "anchor_id": {
                "oneOf": [
                    {"type": "string", "format": "uuid"},
                    {"type": "null"},
                ]
            },
            "node_limit": {"type": "integer", "minimum": 1, "maximum": 300},
            "edge_limit": {"type": "integer", "minimum": 1, "maximum": 600},
        },
    }
    canvas_path_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "source_id": {"type": "string", "format": "uuid"},
            "target_id": {"type": "string", "format": "uuid"},
            "repository_ids": canvas_semantic_properties["repository_ids"],
            "max_depth": {"type": "integer", "minimum": 1, "maximum": 6},
        },
        "required": ["source_id", "target_id"],
    }
    canvas_semantic_query = {
        "type": "object",
        "additionalProperties": False,
        "properties": canvas_semantic_properties,
    }
    canvas_presentation = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "placements": {
                "type": "array",
                "maxItems": 300,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "entity_id": {"type": "string", "format": "uuid"},
                        "x": {"type": "number", "minimum": -1_000_000, "maximum": 1_000_000},
                        "y": {"type": "number", "minimum": -1_000_000, "maximum": 1_000_000},
                        "is_pinned": {"type": "boolean"},
                        "is_hidden": {"type": "boolean"},
                        "group_index": {
                            "oneOf": [
                                {"type": "integer", "minimum": 0, "maximum": 49},
                                {"type": "null"},
                            ]
                        },
                    },
                    "required": [
                        "entity_id",
                        "x",
                        "y",
                        "is_pinned",
                        "is_hidden",
                        "group_index",
                    ],
                },
            },
            "filters": {
                "type": "array",
                "maxItems": 20,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "field": {
                            "type": "string",
                            "enum": [
                                "entity_type",
                                "owner",
                                "status",
                                "time",
                                "risk",
                                "freshness",
                            ],
                        },
                        "operator": {
                            "type": "string",
                            "enum": ["EQUALS", "CONTAINS", "IN", "SINCE"],
                        },
                        "value": {"$ref": "#/components/schemas/canvas-filter-value"},
                    },
                    "required": ["field", "operator", "value"],
                },
            },
            "layers": {
                "type": "array",
                "maxItems": 20,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "key": {
                            "type": "string",
                            "enum": [
                                "execution",
                                "ownership",
                                "dependencies",
                                "governance",
                                "provenance",
                            ],
                        },
                        "label": {"type": "string", "maxLength": 100},
                        "is_visible": {"type": "boolean"},
                    },
                    "required": ["key", "label", "is_visible"],
                },
            },
            "groups": {
                "type": "array",
                "maxItems": 50,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "label": {"type": "string", "maxLength": 200},
                        "x": {"type": "number", "minimum": -1_000_000, "maximum": 1_000_000},
                        "y": {"type": "number", "minimum": -1_000_000, "maximum": 1_000_000},
                        "width": {"type": "number", "exclusiveMinimum": 0, "maximum": 1_000_000},
                        "height": {"type": "number", "exclusiveMinimum": 0, "maximum": 1_000_000},
                    },
                    "required": ["label", "x", "y", "width", "height"],
                },
            },
            "annotations": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "entity_id": {"type": ["string", "null"], "format": "uuid"},
                        "body": {"type": "string", "maxLength": 2_000},
                        "x": {"type": "number", "minimum": -1_000_000, "maximum": 1_000_000},
                        "y": {"type": "number", "minimum": -1_000_000, "maximum": 1_000_000},
                    },
                    "required": ["entity_id", "body", "x", "y"],
                },
            },
        },
        "required": ["placements", "filters", "layers", "groups", "annotations"],
    }
    canvas_view_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 200},
            "description": {"type": "string", "maxLength": 1_000},
            "view_type": {
                "type": "string",
                "enum": [
                    "STRATEGY",
                    "PRODUCT_SYSTEM",
                    "INITIATIVE",
                    "RISK_POLICY",
                    "CHANGE_HISTORY",
                    "CUSTOM",
                ],
            },
            "semantic_query": canvas_semantic_query,
            "repository_id": {"type": "string", "format": "uuid"},
            "access_scope_id": {"type": "string", "format": "uuid"},
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "required": ["name", "view_type", "semantic_query", "idempotency_key"],
    }
    canvas_revision_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "expected_revision": {"type": "integer", "minimum": 1},
            "semantic_query": canvas_semantic_query,
            "presentation": canvas_presentation,
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "required": [
            "expected_revision",
            "semantic_query",
            "presentation",
            "idempotency_key",
        ],
    }
    canvas_share_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "recipient_membership_id": {"type": "string", "format": "uuid"},
            "expires_at": {"type": "string", "format": "date-time"},
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "required": ["idempotency_key"],
    }
    canvas_share_revoke_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "expected_view_revision": {"type": "integer", "minimum": 1},
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "required": ["expected_view_revision", "idempotency_key"],
    }
    canvas_relationship_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "source_id": {"type": "string", "format": "uuid"},
            "target_id": {"type": "string", "format": "uuid"},
            "relationship_type": {"type": "string", "enum": canvas_relationship_types},
            "repository_id": {"type": "string", "format": "uuid"},
            "expected_source_revision": {"type": "integer", "minimum": 1},
            "expected_target_revision": {"type": "integer", "minimum": 1},
            "rationale": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 500},
        },
        "required": [
            "source_id",
            "target_id",
            "relationship_type",
            "repository_id",
            "expected_source_revision",
            "expected_target_revision",
            "rationale",
            "idempotency_key",
        ],
    }
    evaluator_responses: dict[str, object] = {
        "200": {
            "description": "Stored evaluator result.",
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/evaluator-result"}}
            },
        },
        **structured_errors,
    }
    proposal_responses: dict[str, object] = {
        "202": {
            "description": "Proposal accepted for validation, not approved.",
        },
        **structured_errors,
    }
    mcp_responses: dict[str, object] = {
        "200": {"description": "Authenticated MCP compatibility response."},
        **structured_errors,
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Anva API",
            "version": "1.0.0",
            "description": "Versioned, authenticated Anva contract skeleton.",
        },
        "servers": [{"url": "/api/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/webhooks/github": {
                "post": {
                    "operationId": "acceptGitHubWebhook",
                    "description": (
                        "Verify the raw-body HMAC before parsing and acknowledge mapped, "
                        "unmapped, or duplicate GitHub deliveries without a tenant oracle."
                    ),
                    "servers": [{"url": "/"}],
                    "security": [],
                    "parameters": [
                        {
                            "name": "X-Hub-Signature-256",
                            "in": "header",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "pattern": "^sha256=[a-f0-9]{64}$",
                            },
                        },
                        {
                            "name": "X-GitHub-Delivery",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string", "format": "uuid"},
                        },
                        {
                            "name": "X-GitHub-Event",
                            "in": "header",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "enum": [
                                    "installation",
                                    "installation_repositories",
                                    "repository",
                                    "pull_request",
                                    "check_run",
                                    "check_suite",
                                    "workflow_run",
                                ],
                            },
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"},
                            }
                        },
                    },
                    "responses": {
                        "202": {"description": "Verified delivery acknowledged."},
                        "400": {"$ref": "#/components/responses/StructuredError"},
                        "401": {"$ref": "#/components/responses/StructuredError"},
                        "409": {"$ref": "#/components/responses/StructuredError"},
                        "413": {"$ref": "#/components/responses/StructuredError"},
                        "503": {"$ref": "#/components/responses/StructuredError"},
                    },
                }
            },
            "/capabilities": {
                "get": {
                    "operationId": "getCapabilities",
                    "responses": {
                        "200": {
                            "description": "Supported external contract versions.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "additionalProperties": False,
                                        "properties": {
                                            "api_version": {"const": "1"},
                                            "schema_versions": {
                                                "type": "array",
                                                "items": {"type": "string"},
                                            },
                                            "mcp_version": {"const": "1"},
                                        },
                                        "required": [
                                            "api_version",
                                            "schema_versions",
                                            "mcp_version",
                                        ],
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "/evaluator/evaluate": {
                "post": {
                    "operationId": "evaluateChange",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/evaluator-request"}
                            }
                        },
                    },
                    "responses": evaluator_responses,
                }
            },
            "/knowledge-proposals": {
                "post": {
                    "operationId": "submitKnowledgeProposal",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/knowledge-proposal"}
                            }
                        },
                    },
                    "responses": proposal_responses,
                }
            },
            "/work-items": {
                "post": {
                    "operationId": "createWorkItem",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/work-item-import"}
                            }
                        },
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/work-items/import": {
                "post": {
                    "operationId": "importWorkItemRevision",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/work-item-import"}
                            }
                        },
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/work-items/{resource_id}": {
                "get": {
                    "operationId": "getWorkItem",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/work-item-revisions/{resource_id}/approvals": {
                "post": {
                    "operationId": "approveWorkItemRevision",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": work_approval_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/work-approvals/{resource_id}/revoke": {
                "post": {
                    "operationId": "revokeWorkApproval",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": revocation_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/work-item-revisions/{resource_id}/evidence-map": {
                "post": {
                    "operationId": "mapCriterionEvidence",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": evidence_mapping_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/policies": {
                "post": {
                    "operationId": "createPolicy",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/policy"}}
                        },
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/policies/import": {
                "post": {
                    "operationId": "importPolicyVersion",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/policy"}}
                        },
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/policies/simulate": {
                "post": {
                    "operationId": "simulatePolicy",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": policy_simulation_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/policies/{resource_id}": {
                "get": {
                    "operationId": "getPolicy",
                    "parameters": [
                        resource_parameter,
                        repository_query_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/repositories/{repository_id}/pull-requests/{pull_request_number}/evidence": {
                "post": {
                    "operationId": "submitEvidenceManifest",
                    "parameters": [
                        *mutation_parameters,
                        repository_parameter,
                        {
                            "name": "pull_request_number",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "minimum": 1},
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/evidence-manifest"}
                            }
                        },
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            (
                "/repositories/{repository_id}/pull-requests/{pull_request_number}/"
                "evidence-upload-authorizations"
            ): {
                "post": {
                    "operationId": "createEvidenceUploadAuthorization",
                    "description": (
                        "Issue one short-lived, single-use upload secret bound to the "
                        "authenticated tenant, repository, scope, pull request, and commit. "
                        "An exact replay returns metadata but never re-emits the secret."
                    ),
                    "parameters": [
                        *mutation_parameters,
                        repository_parameter,
                        {
                            "name": "pull_request_number",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "minimum": 1},
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": ("#/components/schemas/evidence-upload-authorization")
                                }
                            }
                        },
                    },
                    "responses": upload_authorization_responses,
                }
            },
            "/evidence-upload-authorizations/{resource_id}/content": {
                "put": {
                    "operationId": "uploadEvidenceContent",
                    "description": (
                        "Stream evidence bytes through bounded validation. Client filenames "
                        "and content types are not trusted; rejected bytes are not retained."
                    ),
                    "security": [
                        {"bearerAuth": [], "evidenceUploadToken": []},
                    ],
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                        {
                            "name": "X-Anva-Content-SHA256",
                            "in": "header",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "pattern": "^[a-f0-9]{64}$",
                            },
                            "description": (
                                "Declared SHA-256; the server recomputes it from streamed bytes."
                            ),
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/octet-stream": {
                                "schema": {"type": "string", "format": "binary"}
                            }
                        },
                    },
                    "responses": upload_responses,
                }
            },
            "/evidence-manifests/{resource_id}": {
                "get": {
                    "operationId": "getEvidenceManifest",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/policy-overrides/{resource_id}/revoke": {
                "post": {
                    "operationId": "revokePolicyOverride",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": revocation_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/bootstrap": {
                "post": {
                    "operationId": "bootstrapOrganization",
                    "description": (
                        "Create the one initial tenant and return one-time credentials. "
                        "When independent_reviewer_name is supplied, a distinct least-privilege "
                        "assurance reviewer credential is emitted once and stored only as a hash. "
                        "An exact idempotency retry revokes and reissues only the bound "
                        "credentials."
                    ),
                    "security": [],
                    "parameters": [
                        {
                            "name": "X-Anva-Bootstrap-Secret",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string", "minLength": 1},
                        },
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        **{
                                            name: {
                                                "type": "string",
                                                "minLength": 1,
                                                "maxLength": 300,
                                            }
                                            for name in (
                                                "organization_slug",
                                                "organization_name",
                                                "admin_email",
                                                "admin_display_name",
                                                "repository_external_id",
                                                "repository_name",
                                                "independent_reviewer_name",
                                            )
                                        },
                                        "idempotency_key": {
                                            "type": "string",
                                            "pattern": "^[a-f0-9]{64}$",
                                        },
                                    },
                                    "required": [
                                        "organization_slug",
                                        "organization_name",
                                        "admin_email",
                                        "admin_display_name",
                                        "repository_external_id",
                                        "repository_name",
                                    ],
                                }
                            }
                        },
                    },
                    "responses": cast(
                        dict[str, object],
                        {
                            **created_responses,
                            "201": {
                                "description": "Initial tenant and one-time credential created.",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "additionalProperties": False,
                                            "properties": {
                                                "organization_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "user_id": {"type": "string", "format": "uuid"},
                                                "membership_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "repository_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "service_identity_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "access_scope_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "token_id": {"type": "string", "format": "uuid"},
                                                "token": {"type": "string", "minLength": 32},
                                                "expires_at": {
                                                    "type": "string",
                                                    "format": "date-time",
                                                },
                                                "bootstrap_request_sha256": {
                                                    "type": "string",
                                                    "pattern": "^[a-f0-9]{64}$",
                                                },
                                                "recovered": {"type": "boolean"},
                                                "reviewer_service_identity_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "reviewer_token_id": {
                                                    "type": "string",
                                                    "format": "uuid",
                                                },
                                                "reviewer_token": {
                                                    "type": "string",
                                                    "minLength": 32,
                                                },
                                                "reviewer_expires_at": {
                                                    "type": "string",
                                                    "format": "date-time",
                                                },
                                            },
                                            "required": [
                                                "organization_id",
                                                "user_id",
                                                "membership_id",
                                                "repository_id",
                                                "service_identity_id",
                                                "access_scope_id",
                                                "token_id",
                                                "token",
                                                "expires_at",
                                                "bootstrap_request_sha256",
                                                "recovered",
                                            ],
                                        }
                                    }
                                },
                            },
                        },
                    ),
                }
            },
            "/organizations/{organization_id}": {
                "get": {
                    "operationId": "getOrganization",
                    "parameters": [
                        organization_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/organizations/{organization_id}/retention-runs": {
                "post": {
                    "operationId": "runOrganizationRetention",
                    "description": (
                        "Run one bounded retention pass. Governed audit and provenance "
                        "history remains append-only."
                    ),
                    "parameters": [
                        organization_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "dry_run": {"type": "boolean"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": created_responses,
                }
            },
            "/organizations/{organization_id}/decommission": {
                "post": {
                    "operationId": "decommissionOrganization",
                    "description": (
                        "Revoke tenant access and sources from a recently authenticated "
                        "human browser session after exact slug and acknowledgement "
                        "confirmations. Repository bearer tokens are rejected. Governed "
                        "history is retained; this is not physical erasure."
                    ),
                    "security": [{"browserSession": []}],
                    "parameters": [
                        organization_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                        {
                            "name": "X-CSRFToken",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string", "minLength": 1, "maxLength": 128},
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "confirmation": {
                                            "type": "string",
                                            "minLength": 1,
                                            "maxLength": 80,
                                        },
                                        "acknowledgement": {
                                            "type": "string",
                                            "minLength": 14,
                                            "maxLength": 93,
                                            "description": (
                                                "Exact text DECOMMISSION followed by a space "
                                                "and the confirmed organization slug."
                                            ),
                                        },
                                    },
                                    "required": ["confirmation", "acknowledgement"],
                                }
                            }
                        },
                    },
                    "responses": decommission_responses,
                }
            },
            "/organizations/{organization_id}/members": {
                "get": {
                    "operationId": "listMemberships",
                    "parameters": [
                        organization_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                },
                "post": {
                    "operationId": "createMembership",
                    "parameters": [
                        organization_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": created_responses,
                },
            },
            "/organizations/{organization_id}/members/{resource_id}": {
                "patch": {
                    "operationId": "updateMembership",
                    "parameters": [
                        organization_parameter,
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                },
                "delete": {
                    "operationId": "deactivateMembership",
                    "parameters": [
                        organization_parameter,
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                },
            },
            "/repositories/{repository_id}/tokens": {
                "post": {
                    "operationId": "issueRepositoryToken",
                    "description": "Returns plaintext token material exactly once.",
                    "parameters": [
                        repository_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": created_responses,
                }
            },
            "/repositories/{repository_id}/github-binding": {
                "get": {
                    "operationId": "getGitHubRepositoryBinding",
                    "parameters": [
                        repository_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                },
                "post": {
                    "operationId": "configureGitHubRepositoryBinding",
                    "parameters": [*mutation_parameters, repository_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": github_binding_request}},
                    },
                    "responses": created_or_replayed_responses,
                },
            },
            "/repositories/{repository_id}/github-binding/revoke": {
                "post": {
                    "operationId": "revokeGitHubRepositoryBinding",
                    "parameters": [*mutation_parameters, repository_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": empty_object_request}},
                    },
                    "responses": authorized_responses,
                }
            },
            "/tokens/{resource_id}/rotate": {
                "post": {
                    "operationId": "rotateRepositoryToken",
                    "description": "Revokes the predecessor and returns its replacement once.",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": created_responses,
                }
            },
            "/tokens/{resource_id}": {
                "delete": {
                    "operationId": "revokeRepositoryToken",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/search": {
                "post": {
                    "operationId": "searchAuthorizedKnowledge",
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "responses": authorized_responses,
                }
            },
            "/query": {
                "post": {
                    "operationId": "queryAuthorizedKnowledge",
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "responses": authorized_responses,
                }
            },
            "/canvas/query": {
                "post": {
                    "operationId": "queryOrganizationalCanvas",
                    "description": (
                        "Return a deterministic, bounded union of independently authorized "
                        "repository projections. Hidden records never enter counts or layout."
                    ),
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_query_request}},
                    },
                    "responses": authorized_responses,
                }
            },
            "/canvas/path": {
                "post": {
                    "operationId": "explainOrganizationalCanvasPath",
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_path_request}},
                    },
                    "responses": authorized_responses,
                }
            },
            "/canvas/entities/{resource_id}": {
                "get": {
                    "operationId": "getOrganizationalCanvasEntity",
                    "parameters": [
                        resource_parameter,
                        {
                            "name": "repository_id",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "array",
                                "items": {"type": "string", "format": "uuid"},
                                "maxItems": 100,
                            },
                        },
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/canvas/views": {
                "get": {
                    "operationId": "listOrganizationalCanvasViews",
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "responses": authorized_responses,
                },
                "post": {
                    "operationId": "createOrganizationalCanvasView",
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_view_request}},
                    },
                    "responses": created_or_replayed_responses,
                },
            },
            "/canvas/views/{resource_id}/revisions": {
                "post": {
                    "operationId": "appendOrganizationalCanvasViewRevision",
                    "parameters": [resource_parameter, *mutation_parameters],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_revision_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/canvas/views/{resource_id}/shares": {
                "post": {
                    "operationId": "shareOrganizationalCanvasViewRevision",
                    "description": "Create a sign-in-required deep link that grants no authority.",
                    "parameters": [resource_parameter, *mutation_parameters],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_share_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/canvas/shares/{resource_id}/revoke": {
                "post": {
                    "operationId": "revokeOrganizationalCanvasShare",
                    "description": (
                        "Immediately close one sign-in-required link without deleting its "
                        "pinned immutable view revision."
                    ),
                    "parameters": [resource_parameter, *mutation_parameters],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_share_revoke_request}},
                    },
                    "responses": authorized_responses,
                }
            },
            "/canvas/relationship-proposals": {
                "post": {
                    "operationId": "proposeOrganizationalCanvasRelationship",
                    "description": (
                        "Create review state only; this endpoint never writes a canonical edge."
                    ),
                    "parameters": mutation_parameters,
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": canvas_relationship_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/context-packets": {
                "post": {
                    "operationId": "buildContextPacket",
                    "parameters": mutation_parameters,
                    "responses": created_responses,
                }
            },
            "/context-packets/{resource_id}": {
                "get": {
                    "operationId": "getContextPacket",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/entities/{resource_id}/relationships": {
                "get": {
                    "operationId": "getEntityRelationships",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/entities/{resource_id}/history": {
                "get": {
                    "operationId": "getEntityHistory",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/entities/{resource_id}/sources": {
                "get": {
                    "operationId": "getEntitySources",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/assertions/{resource_id}/explanation": {
                "get": {
                    "operationId": "getAssertionExplanation",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/canvas/assertions/{resource_id}": {
                "get": {
                    "operationId": "getCanvasAssertion",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/mcp/context": {
                "post": {
                    "operationId": "getMcpContext",
                    "description": (
                        "Compatibility endpoint returning authenticated gateway diagnostics; "
                        "call /mcp/tools/{tool_name} for canonical HTTP parity."
                    ),
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "responses": mcp_responses,
                }
            },
            "/mcp/diagnostics": {
                "get": {
                    "operationId": "diagnoseMcpGateway",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Non-secret MCP compatibility and availability data."
                        }
                    },
                }
            },
            "/mcp/tools/{tool_name}": {
                "post": {
                    "operationId": "callMcpParityTool",
                    "description": (
                        "Calls the same canonical domain facade as MCP tools and returns "
                        "a semantically identical structured result."
                    ),
                    "parameters": [
                        {
                            "name": "tool_name",
                            "in": "path",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "enum": [contract["name"] for contract in TOOL_CONTRACTS],
                            },
                        },
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "oneOf": [
                                        contract["input_schema"] for contract in TOOL_CONTRACTS
                                    ]
                                }
                            }
                        },
                    },
                    "responses": authorized_responses,
                }
            },
            "/artifacts/{resource_id}": {
                "get": {
                    "operationId": "getAuthorizedArtifact",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/knowledge/assertions/{resource_id}/review": {
                "post": {
                    "operationId": "reviewKnowledgeAssertion",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/assurance-runs/{resource_id}/transition": {
                "post": {
                    "operationId": "transitionAssuranceRun",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/repositories/{repository_id}/pull-requests/{pull_request_number}/manual-diff": {
                "post": {
                    "operationId": "ingestManualPullRequestDiff",
                    "parameters": [
                        *mutation_parameters,
                        repository_parameter,
                        {
                            "name": "pull_request_number",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "minimum": 1},
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": manual_diff_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/pull-request-revisions/{resource_id}/assurance-runs": {
                "post": {
                    "operationId": "startManualDiffAssurance",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": assurance_start_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/repositories/{repository_id}/evaluator-tasks/claim": {
                "post": {
                    "operationId": "claimManualEvaluatorTask",
                    "description": (
                        "Requires assurance.review. The run initiator is ineligible; "
                        "source-scope authorization is rechecked before returning the request."
                    ),
                    "parameters": [*mutation_parameters, repository_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": evaluator_claim_request}},
                    },
                    "responses": authorized_responses,
                }
            },
            "/evaluator-tasks/{resource_id}/submit": {
                "post": {
                    "operationId": "submitManualEvaluatorResult",
                    "description": (
                        "Requires the same active authenticated actor and credential that "
                        "claimed the live lease."
                    ),
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": evaluator_submit_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/assurance-runs/{resource_id}": {
                "get": {
                    "operationId": "getAssuranceRun",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/assurance-runs/{resource_id}/findings": {
                "get": {
                    "operationId": "listAssuranceFindings",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/assurance-runs/{resource_id}/report": {
                "get": {
                    "operationId": "getAssuranceReport",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/assurance-runs/{resource_id}/post-merge-proposals": {
                "post": {
                    "operationId": "proposePostMergeKnowledge",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": post_merge_proposals_request}},
                    },
                    "responses": created_responses,
                }
            },
            "/findings/{resource_id}/dismiss": {
                "post": {
                    "operationId": "dismissFinding",
                    "description": "Apply an authorized explicit finding lifecycle decision.",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": finding_decision_request}},
                    },
                    "responses": authorized_responses,
                }
            },
            "/policies/{resource_id}/override": {
                "post": {
                    "operationId": "overridePolicy",
                    "description": (
                        "Create an authority-checked exception pinned to an exact "
                        "policy version, repository, pull request, and commit."
                    ),
                    "parameters": [*mutation_parameters, resource_parameter],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": policy_override_request}},
                    },
                    "responses": created_or_replayed_responses,
                }
            },
            "/source-connections/{resource_id}/revoke": {
                "post": {
                    "operationId": "revokeSourceConnection",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/source-connections/filesystem": {
                "post": {
                    "operationId": "connectFilesystemSource",
                    "description": "Connect a configured read-only mounted filesystem root.",
                    "parameters": mutation_parameters,
                    "responses": created_responses,
                }
            },
            "/source-connections/{resource_id}": {
                "get": {
                    "operationId": "inspectSourceConnection",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
            "/source-connections/{resource_id}/sync": {
                "post": {
                    "operationId": "syncSourceConnection",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "responses": accepted_responses,
                }
            },
            "/source-connections/{resource_id}/resync": {
                "post": {
                    "operationId": "resyncSourceConnection",
                    "parameters": [*mutation_parameters, resource_parameter],
                    "responses": accepted_responses,
                }
            },
            "/source-connections/{resource_id}/sync-runs": {
                "get": {
                    "operationId": "listSourceSyncRuns",
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": authorized_responses,
                }
            },
        },
        "components": {
            "schemas": {
                **SCHEMAS,
                "canvas-filter-value": {
                    "oneOf": [
                        {"type": "null"},
                        {"type": "boolean"},
                        {"type": "number"},
                        {"type": "string", "maxLength": 2_000},
                        {
                            "type": "array",
                            "maxItems": 2_000,
                            "items": {"$ref": "#/components/schemas/canvas-filter-value"},
                        },
                        {
                            "type": "object",
                            "maxProperties": 2_000,
                            "propertyNames": {"maxLength": 500},
                            "additionalProperties": {
                                "$ref": "#/components/schemas/canvas-filter-value"
                            },
                        },
                    ]
                },
                "structured-error": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "code": {"type": "string", "minLength": 1, "maxLength": 100},
                        "message": {"type": "string", "minLength": 1, "maxLength": 2_000},
                        "correlation_id": {"type": "string", "format": "uuid"},
                    },
                    "required": ["code", "message", "correlation_id"],
                },
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "AnvaRepositoryToken",
                },
                "browserSession": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "sessionid",
                    "description": (
                        "Recently authenticated human browser session; unsafe requests also "
                        "require Django's X-CSRFToken header."
                    ),
                },
                "evidenceUploadToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Anva-Evidence-Upload-Token",
                    "description": (
                        "Short-lived single-use opaque evidence-upload secret; required in "
                        "addition to the normal actor bearer credential."
                    ),
                },
            },
            "parameters": {
                "CorrelationId": {
                    "name": "X-Correlation-ID",
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                }
            },
            "responses": {
                "StructuredError": {
                    "description": "Structured error with a stable code.",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/structured-error"}
                        }
                    },
                }
            },
        },
    }


def mcp_document() -> dict[str, object]:
    """Generate the complete versioned MCP tool/resource contract."""
    return mcp_contract_document()


def rendered_artifacts() -> dict[Path, bytes]:
    """Render every checked-in contract artifact from one source catalog."""
    artifacts: dict[Path, bytes] = {}
    for name, schema in sorted(SCHEMAS.items()):
        artifacts[Path("json-schema/v1") / f"{name}.schema.json"] = canonical_json(schema)
    for name, example in sorted(EXAMPLES.items()):
        artifacts[Path("examples/v1") / f"{name}.json"] = canonical_json(example)
    artifacts[Path("openapi/v1/openapi.json")] = canonical_json(openapi_document())
    artifacts[Path("mcp/v1/tools.json")] = canonical_json(mcp_document())
    return artifacts


def validate_catalog() -> None:
    """Validate schema definitions and every associated example."""
    if set(SCHEMAS) != set(EXAMPLES):
        raise ValueError("Every schema must have exactly one canonical example")
    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)
    for name, example in EXAMPLES.items():
        validate_payload(name, example)


def write_artifacts(artifacts: Mapping[Path, bytes]) -> None:
    """Write generated files without timestamps or environment-dependent data."""
    for relative_path, content in artifacts.items():
        output_path = CONTRACT_ROOT / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(content)


def check_artifacts(artifacts: Mapping[Path, bytes]) -> None:
    """Fail clearly if checked-in generated contracts have drifted."""
    drift: list[str] = []
    for relative_path, expected in artifacts.items():
        output_path = CONTRACT_ROOT / relative_path
        if not output_path.exists() or output_path.read_bytes() != expected:
            drift.append(str(relative_path))
    if drift:
        formatted = ", ".join(sorted(drift))
        raise ValueError(f"Generated contract drift: {formatted}. Run `make contracts`.")


def build_parser() -> argparse.ArgumentParser:
    """Build the deterministic generator CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    parser.add_argument("--validate-examples", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Generate or verify the checked-in contract surface."""
    arguments = build_parser().parse_args(argv)
    if arguments.validate_examples:
        validate_catalog()
    artifacts = rendered_artifacts()
    if arguments.write:
        write_artifacts(artifacts)
    else:
        check_artifacts(artifacts)
    print(f"{'wrote' if arguments.write else 'verified'} {len(artifacts)} contract artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
