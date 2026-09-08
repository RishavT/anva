# Issue 164 self-review

## Outcome

PASS. The protected bootstrap response and official Python acceptance handoff now expose and
verify closed, non-secret credential metadata for the primary and reviewer credentials. No broad
credential-introspection boundary was added.

## Reviewed invariants

- Metadata is serialized from the committed repository-token and service-identity models and is
  bound to the response token, identity, repository, access scope, and expiry fields.
- Scoped acceptance requires the exact sorted 15-action primary set, including `token.manage`,
  and exactly `assurance.review` for the distinct reviewer identity and token.
- New handoffs verify the same bindings both before publication and during recovery. Older
  schema-version 1 handoffs remain resumable only when metadata is absent; malformed,
  incomplete, reordered, inactive, revoked, cross-boundary, or extra-field metadata fails closed.
- Metadata contains neither plaintext credentials nor token digests. Existing plaintext values
  remain confined to the protected mode-`0600` one-time handoff.
- Both token IDs continue to work with the supported public revocation operation.

## Verification

- Focused runner and contract tests: 50 passed.
- Real PostgreSQL bootstrap integration: 16 passed.
- Format, Ruff, MyPy (113 source files), generated-contract validation (35 artifacts): passed.
- Clean broad suite: 1,751 passed and 9 skipped; its sole unrelated near-deadline timing failure
  passed unchanged in isolation and is tracked by issue 165. The earlier retained-MinIO failures
  did not recur after the exact isolated project reset tracked by issue 163.

## Residual risk

The protected handoff remains privileged mode-`0600` secret material and must be handled as such.
Credential metadata is an issuance-time attestation, not a new live introspection API; later
revocation is authoritatively exercised through the existing public token operation.
