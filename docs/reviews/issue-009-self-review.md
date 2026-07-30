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
  files; 452 passed, 2 intentionally skipped; aggregate coverage 85%.
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

## Pull-request review remediation

- Proposal inputs now undergo recursive credential detection before contract
  lookup, hashing, idempotency, audit, outbox, or proposal persistence.
  Review-only results explicitly return `review_required: true`.
- PostgreSQL migration 0014 makes proposal tenant/content/source/change fields
  immutable and permits only one-use, service-guarded lifecycle transitions
  that independently satisfy the proposal state machine.
- Pagination cursors contain bounded issued/expiry times and bind the
  credential, actor, tool, repository, query, current grants/scopes, and
  retrieval/source visibility watermark. Every page reauthorizes before
  validating that watermark.
- Every nested object in tool and resource input/output schemas is closed or a
  recursively typed, size-bounded map. Official SDK `tools/list` schemas are
  exact contract copies.
- Authenticated unknown-tool and pre-dispatch validation failures record one
  content-free stable audit. Unauthenticated HTTP calls do not create a
  tenant-attributed audit.
- Validation failures expose stable path/reason codes without submitted values;
  MCP, HTTP, audit, and process-log regressions cover `ghp_` and canary
  non-disclosure.
- Remediation-focused Docker evidence: 8 unit/handler tests and 7 PostgreSQL
  integration tests passed; migration 0014 applied, rolled back to 0013, and
  reapplied; all 24 generated artifacts exact-checked; focused Ruff and strict
  MyPy passed; the live official-client acceptance test passed with no
  secret/canary matches in process logs.
- The post-remediation full gate passed 452 tests with 2 intentional skips and
  85% aggregate coverage. Fresh production-configured Compose applied migration
  0014, ran all four long-lived processes as UID 10001 with debug disabled,
  and passed both official-client smoke tests. Peak unique task storage was
  approximately 0.59 GB against the 5 GB cap; every task container, network,
  volume, image tag, and exact BuildKit record was removed afterward.

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
