# Issue 009 self-review

## Scope

MVP-009 Streamable HTTP MCP, HTTP parity, read/resource/proposal tools, bearer
auth/revocation, diagnostics, contracts, audit, pagination, read-only mode,
Compose client acceptance, and operator/security docs.

## Architecture and security review

- Official SDK owns protocol lifecycle and version validation.
- MCP/HTTP call one output-validating domain facade.
- No generic model, SQL, query, or unrestricted-source tool exists.
- Read paths reuse central auth/current retrieval/context/graph visibility.
- Explanations/excerpts avoid raw legacy provenance.
- Contracts are closed/versioned; outputs are schema and byte bounded.
- Cursors are signed and identity/request bound.
- Auth precedes lookup; credentials are hashed, exact-repo/action scoped,
  expiring, rotatable, revocable, issuer/audience checked, and rechecked.
- Foreign/missing IDs share a hidden response.
- Wrapper/audit rows have composite tenant FKs and immutable triggers.
- Proposals stay `PROPOSED`, undecided, and `approved: false`.
- Read-only hides/rejects proposal tools.
- Source text is inert/untrusted and never routing/authorization input.
- Audit stores hashes/IDs, not arguments, text, or credentials.

## Verification evidence

- Targeted MCP unit/handler tests: 8 passed.
- Targeted MCP integration tests: 3 passed, plus the existing tenant hiding
  surface.
- Generated contracts: 24 deterministic artifacts verified with example and
  JSON Schema validation.
- Full Docker gate: Ruff/format clean; strict MyPy clean across 114 source
  files; 448 passed, 2 intentionally skipped; aggregate coverage 85%.
- Migration check: no model drift; migration 0013 applied on fresh PostgreSQL.
- Production-configured Compose: official Python client 2 passed; protocol
  negotiation, 16 tools, one static resource, four resource templates,
  MCP/HTTP parity, read-only, unsupported version, revocation, and unavailable
  server behavior verified.
- Process/secret boundary: API/MCP/read-only were healthy distinct processes,
  all UID 10001; production debug was false; synthetic secrets were absent from
  service, migration, and client logs.
- Cleanup/footprint: task-scoped Compose volumes/network and image tags are
  removed after hosted verification; exact figures are recorded in the PR
  handoff.
- Hosted CI: authoritative result is recorded on the linked pull request.

## Limitations

- No OAuth user handoff or organization-wide service credential; the MVP uses
  organization-owned exact-repository service credentials.
- Distributed rate limiting remains an ingress responsibility.
- Repository profiles contain only modeled identity/state.
- No resumable streams/resource subscriptions for stateless bounded tools.
- Proposal review/acceptance UI is outside this issue.

## Conclusion

MVP-009 satisfies its bounded retrieval, review-only proposal, authentication,
tenant isolation, versioning, parity, diagnostics, and deployment acceptance
criteria. The limitations above are explicit follow-up scope rather than hidden
claims.
