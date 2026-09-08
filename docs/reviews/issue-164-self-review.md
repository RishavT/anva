# Issue 164 self-review

## Outcome

PASS. The protected bootstrap response and official Python acceptance handoff now expose and
verify closed, non-secret credential metadata for the primary and reviewer credentials. No broad
credential-introspection boundary was added.

## Reviewed invariants

- Metadata is serialized as a committed issuance snapshot from the repository-token and
  service-identity models. It is bound to the response token, identity, repository, access scope,
  expiry, request hash, observation time, generation, and credential-set ID.
- Scoped acceptance requires the exact sorted 15-action primary set, including `token.manage`,
  and exactly `assurance.review` for the distinct reviewer identity and token.
- New handoffs verify the same bindings and authenticate both bearers through side-effect-free MCP
  capability discovery before publication and during recovery. Older
  schema-version 1 handoffs remain resumable only when metadata is absent; malformed,
  incomplete, reordered, inactive, revoked, cross-boundary, or extra-field metadata fails closed.
- Metadata contains neither plaintext credentials nor token digests. Existing plaintext values
  remain confined to the protected mode-`0600` one-time handoff.
- Both token IDs continue to work with the supported public revocation operation.

## Verification

- Focused runner boundary tests after final envelope binding: 45 passed.
- Real PostgreSQL bootstrap and resume integration: 18 passed.
- Format, Ruff, MyPy (114 source files), generated-contract validation (35 artifacts): passed.
- Final stable-tree broad suite: 1,759 passed and 9 skipped. An earlier unrelated canvas wall-clock
  timing failure passed unchanged in isolation and is tracked by issue 167. The earlier unrelated
  near-deadline failure remains tracked by issue 165, and retained-MinIO failures remain tracked
  by issue 163.

## Residual risk

The protected handoff remains privileged mode-`0600` secret material and must be handled as such.
Credential metadata is an issuance-time attestation, not a new live introspection API. A bearer
may be revoked immediately after a successful liveness probe; later revocation is authoritatively
exercised through the existing public token operation.
