# ADR-025: Versioned authenticated MCP gateway

- Status: Accepted
- Date: 2026-07-30
- Owners: Platform and Security

## Context

Developer agents need live Anva context without unrestricted database access.
The interface must preserve authorization, provenance, context-packet, policy,
work-intent, and proposal invariants from MVP-003, MVP-005, and MVP-006. MCP and
HTTP clients must observe the same authorized meaning.

The stable Python MCP SDK supports protocol revisions `2024-11-05`,
`2025-03-26`, `2025-06-18`, and `2025-11-25`. Its Streamable HTTP engine already
implements lifecycle, protocol negotiation, media types, and version rejection.

## Decision

Use official Python MCP SDK `1.28.1` with its low-level `Server`, stateless
`StreamableHTTPSessionManager`, and JSON Streamable HTTP responses. Run the ASGI
application with Uvicorn in the dedicated Compose `mcp` service.

All tools and HTTP parity requests call `dispatch_tool`. The facade:

1. validates the pinned Anva contract and closed input schema;
2. authorizes organization, exact repository, action, and content scope before
   target lookup;
3. invokes bounded domain services, never a generic model/query interface;
4. validates and byte-bounds structured output;
5. records content-free immutable invocation audit.

Existing `RepositoryAccessToken` credentials remain the MVP bearer mechanism.
They are keyed-hash-only, issuer/audience checked, time bounded, rotatable,
revocable, organization-owned, exact-repository-bound, and action limited. An
organization-wide bearer is deliberately not introduced: organization identity
is one dimension of every credential, while repository binding preserves least
privilege and MVP-003 compatibility.

Anva tool contracts use version `1`. Capability discovery reports SDK-supported
protocol revisions. Unsupported contract versions and protocol headers fail
with actionable bounded errors.

Proposal tools create a `KnowledgeProposal` in `PROPOSED` state plus immutable
`MCPProposalSubmission` provenance. The wrapper records repository, scope, kind,
actor, credential, keyed payload hash, and keyed idempotency hash. It cannot
approve knowledge. Read-only deployments omit proposal tools and reject direct
calls.

Resources project the same facade. Signed cursors bind tool, organization,
repository, actor, credential, and stable request hash.

## Consequences

- MCP and HTTP parity results share one implementation and output contract.
- The official SDK owns protocol framing and version semantics.
- Domain authorization rechecks credential revocation after initial parsing.
- Source excerpts use current visibility and are labeled untrusted inert text.
- OAuth handoff and organization-wide bearer remain later capabilities.
- Stateless JSON responses do not provide resumable streams; current tools are
  bounded request/response operations.

## Rejected alternatives

- Hand-written JSON-RPC/Streamable HTTP handling: protocol divergence risk.
- Direct ORM tools: bypass permission filtering and enable exfiltration.
- Separate MCP and REST business logic: semantic drift.
- Direct agent writes to approved models: violates human authority.
