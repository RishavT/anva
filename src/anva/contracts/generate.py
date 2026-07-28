"""Deterministically generate and validate versioned contract artifacts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from jsonschema import Draft202012Validator

from anva.contracts.catalog import EXAMPLES, KNOWLEDGE_CHANGE, SCHEMA_VERSION, SCHEMAS
from anva.contracts.validation import validate_payload

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
    structured_errors: dict[str, object] = {
        "400": {"$ref": "#/components/responses/StructuredError"},
        "401": {"$ref": "#/components/responses/StructuredError"},
        "404": {"$ref": "#/components/responses/StructuredError"},
        "409": {"$ref": "#/components/responses/StructuredError"},
    }
    authorized_responses: dict[str, object] = {
        "200": {"description": "Authorized tenant-scoped response."},
        **structured_errors,
    }
    accepted_responses: dict[str, object] = {
        "202": {"description": "Authorized request accepted."},
        **structured_errors,
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
            "claimant": {"type": "string", "minLength": 1, "maxLength": 200},
            "lease_seconds": {"type": "integer", "minimum": 60, "maximum": 3_600},
        },
        "required": ["claimant"],
    }
    evaluator_submit_request = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "claimant": {"type": "string", "minLength": 1, "maxLength": 200},
            "claim_token": {"type": "string", "minLength": 1, "maxLength": 200},
            "result": {"$ref": "#/components/schemas/evaluator-result"},
        },
        "required": ["claimant", "claim_token", "result"],
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
        "501": {"description": "MCP transport is not implemented."},
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
                    "responses": created_responses,
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
                    "description": "Reserved for issue #9; returns 501 after authorization.",
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
                    "responses": mcp_responses,
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
                }
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
    """Generate versioned MCP tool skeletons from the same schema source."""
    return {
        "contract_version": "1",
        "schema_versions": [SCHEMA_VERSION],
        "capabilities": {
            "resources": False,
            "tools": True,
            "write_operations_require_explicit_confirmation": True,
        },
        "tools": [
            {
                "name": "anva.evaluate_change",
                "description": (
                    "Evaluate a change against stored policy and evidence; "
                    "does not claim production readiness without evidence."
                ),
                "inputSchema": SCHEMAS["evaluator-request"],
                "outputSchema": SCHEMAS["evaluator-result"],
                "readOnlyHint": True,
            },
            {
                "name": "anva.submit_knowledge_proposal",
                "description": (
                    "Submit a proposed knowledge change for validation and human review; "
                    "never directly mutates approved knowledge."
                ),
                "inputSchema": SCHEMAS["knowledge-proposal"],
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "proposal_id": {"type": "string", "format": "uuid"},
                        "state": {"const": "PROPOSED"},
                    },
                    "required": ["proposal_id", "state"],
                },
                "readOnlyHint": False,
            },
        ],
    }


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
