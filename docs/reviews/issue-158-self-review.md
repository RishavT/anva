# Issue 158 self-review

## Scope and contract

The patch does not increase or disable the four-second authorized scan bound. It implements the
one-second ranking, sealing, reauthorization, and publication reserve already required by the v3
five-second context target. Both deadlines are absolute offsets from the same initial monotonic
timestamp, so phase entry cannot renew elapsed time.

The transition occurs only after assertion and conflict row/operation scans have produced a
`complete=true` accounting record. Row, operation, or scan-time exhaustion therefore still raises
before the active deadline changes and before scopes, artifacts, packets, items, or citations are
created. Required anchor resolution and the complete conflict digest are unchanged.

## SQL and transaction safety

The PostgreSQL execute wrapper reads the active absolute phase deadline before every statement and
continues to clamp `statement_timeout`; lock and idle-transaction limits remain unchanged. The
publication reserve cannot let retrieval continue because all retrieval queries and completeness
proof occur before the transition. Current authorization/watermark revalidation and every write
remain inside the outer atomic transaction and the final absolute deadline.

## Verification

- Deterministic phase-edge tests prove 4.5-second ranking succeeds only after complete scan entry,
  exact 4.0/5.0-second boundaries reject, SQL timeouts follow the active phase, and an overrun
  leaves zero publication deltas.
- Existing invalid bulk-member and slow publication tests retain atomic rollback behavior.
- The unchanged cold 115-file corpus passed on its first MCP call in 1.558245 seconds with 1,989
  processed rows and exact 151/1,613 assertion/conflict accounting.
- Existing high-cardinality, idempotency, MCP, authorization, and fail-closed tests pass.

No P0 or P1 issue was found in the final diff. Residual risk is limited to scheduler/storage
variance consuming the fixed one-second publication reserve; such variance fails closed and does
not publish partial data.
