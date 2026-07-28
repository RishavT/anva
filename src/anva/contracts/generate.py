"""Deterministically generate and validate versioned contract artifacts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from jsonschema import Draft202012Validator

from anva.contracts.catalog import EXAMPLES, SCHEMA_VERSION, SCHEMAS
from anva.contracts.validation import validate_payload

REPOSITORY_ROOT = Path.cwd()
CONTRACT_ROOT = REPOSITORY_ROOT / "contracts"


def canonical_json(value: object) -> bytes:
    """Return stable human-readable JSON bytes."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def openapi_document() -> dict[str, object]:
    """Generate the initial HTTP contract from the canonical schemas."""
    mutation_parameters: list[dict[str, object]] = [
        {
            "name": "Idempotency-Key",
            "in": "header",
            "required": True,
            "schema": {"type": "string", "minLength": 1, "maxLength": 200},
        },
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
                    "parameters": [{"$ref": "#/components/parameters/CorrelationId"}],
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
            "/findings/{resource_id}/dismiss": {
                "post": {
                    "operationId": "dismissFinding",
                    "description": (
                        "Authorization boundary; mutation arrives with the finding model."
                    ),
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": accepted_responses,
                }
            },
            "/policies/{resource_id}/override": {
                "post": {
                    "operationId": "overridePolicy",
                    "description": (
                        "Authorization boundary; mutation arrives with policy persistence."
                    ),
                    "parameters": [
                        resource_parameter,
                        {"$ref": "#/components/parameters/CorrelationId"},
                    ],
                    "responses": accepted_responses,
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
