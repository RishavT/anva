# MCP gateway threat model

## Scope and assets

This covers `/mcp`, HTTP parity tools, resources, bearer authentication,
pagination, source excerpts, proposals, diagnostics, and invocation audit.
Protected assets are tenant knowledge, normalized provenance, source text,
policy/intent, credentials, proposal authority, and access patterns.

## Trust boundaries

- MCP clients, hosts, tool arguments, and source text are untrusted.
- The official SDK owns MCP framing, initialization, and version negotiation.
- Anva authentication runs before tools/resources perform target lookup.
- `dispatch_tool` is the only MCP/HTTP domain facade.
- Existing retrieval/context/graph services are the visibility boundary.
- PostgreSQL composite foreign keys are the final tenant boundary.

## Threats and controls

### Identifier probing

Tokens are organization-owned and exact-repository-bound. Every tool requires a
repository ID and authorizes before target lookup. Queries include organization
and repository predicates. Foreign and absent IDs share `resource_not_found`.
Proposal/audit tables have composite tenant/repository foreign keys.

### Invalid or revoked credentials

Only keyed SHA-256 hashes are stored. Authentication verifies structure,
constant-time digest equality, issuer, audience, expiry, active principal/repo,
and revocation. Domain authorization re-reads token actions/revocation. Rotation
revokes the predecessor immediately.

### Capability escalation

Each facade call checks its stable `Action`. Source/entity/assertion access also
checks current scopes. Callers cannot assert organization/actor claims.
Read-only mode hides and rejects proposal tools.

### Prompt injection in source text

Chunks are data, never gateway instructions. Excerpts use current normalized
visibility, are capped at 4,000 characters, and carry
`UNTRUSTED_INERT_SOURCE_TEXT`. No tool parses text as method names, arguments,
cursors, credentials, or authorization decisions. Hostile `tools/call` text is
tested as inert output.

### Derived-provenance leakage

Assertion explanation ignores legacy JSON provenance. It uses normalized
`AssertionProvenance`, current documents/revisions/observations, active sources,
unrevoked snapshots, and currently visible scopes. Exact excerpts use equivalent
normalized visibility.

### Cursor replay or tampering

Cursors are HMAC signed and bind contract, tool, organization, repository,
actor, credential, and stable request hash. Cross-credential/tool/query or
altered cursors fail closed. Page and total-result caps prevent enumeration.

### Proposal self-approval, replay, or widening

Targets and sources are reauthorized and must match the declared visible scope.
The wrapper stores repository, scope, actor, kind, keyed payload hash, and keyed
idempotency hash. Exact retries return the same `PROPOSED` record; changed
retries conflict. Outputs always include `approved: false`. No tool transitions
or mutates approved knowledge.

### Amplification and audit leakage

Inputs are schema bounded and both input/output are capped at 250 KB. Lists have
page caps. Invocation audit stores keyed hashes and identifiers, never
arguments, text, headers, or plaintext tokens. Authenticated contract,
authorization, and execution failures are audited after rollback.
Audit/proposal wrappers are DB-immutable.

### Protocol downgrade and network abuse

The SDK validates protocol headers against supported revisions. Anva separately
rejects unknown contract versions. Diagnostics disclose only versions, bounds,
auth shape, endpoint, and read-only state. SDK DNS-rebinding protection uses
explicit hosts/origin; there is no wildcard browser CORS policy.

## Residual risks

- OAuth and organization-wide service credentials are outside this MVP.
- Distributed rate limiting is an ingress responsibility.
- Stateless JSON transport has no resumable event streams.
- Repository profiles expose only currently modeled identity/state.
- Proposal review UI and acceptance transitions remain separate governed work.

## Verification

- Unit: schemas, cursors, diagnostics, hostile inert text.
- Integration: proposal state/idempotency/audit, composite FKs, immutable rows,
  hidden tenants, read-only, and contract errors.
- Compose: real Python MCP client, MCP/HTTP equality, protocol rejection,
  read-only discovery/rejection, revocation, and unavailable endpoint behavior.
