# Issue 158 self-review

## Scope and contract

The patch does not increase or disable the four-second authorized scan bound. It implements an
800-millisecond ranking, sealing, reauthorization, and publication reserve within the v3
five-second context target. Both deadlines are absolute offsets from the same initial monotonic
timestamp, so phase entry cannot renew elapsed time. The 4.8-second internal ceiling leaves
headroom for the enclosing public assurance operation; the measured fixed-corpus publication tail
was 0.410494 seconds, leaving about 95% margin inside the reserve.

The transition occurs only after the assertion and conflict row/operation scans have each returned
immutable `complete=true` results. Row, operation, or scan-time exhaustion therefore still raises
before the active deadline changes and before scopes, artifacts, packets, items, or citations are
created. Canonical serialization and hashing of those proven-complete results occur after the
transition, under the final deadline. Required anchor resolution and the complete conflict digest
are unchanged.

## SQL and transaction safety

The PostgreSQL execute wrapper reads the active absolute phase deadline before every statement and
continues to clamp `statement_timeout`; lock and idle-transaction limits remain unchanged. The
publication reserve cannot let retrieval continue because all retrieval queries and completeness
proof occur before the transition. Current authorization/watermark revalidation and every write
remain inside the outer atomic transaction and the final absolute deadline.

## Verification

- Deterministic phase-edge tests prove 4.2-second archive-heavy digest sealing and 4.5-second
  ranking succeed only after complete scan entry; exact 4.0/4.8-second production boundaries
  reject, SQL timeouts follow the active phase, and an overrun leaves zero publication deltas.
- Existing invalid bulk-member and slow publication tests retain atomic rollback behavior.
- The unchanged cold 115-file corpus passed on its first MCP call in 1.558245 seconds with 1,989
  processed rows and exact 151/1,613 assertion/conflict accounting.
- Existing high-cardinality, idempotency, MCP, authorization, and fail-closed tests pass.

No P0 or P1 issue was found in the final diff. Residual risk is limited to scheduler/storage
variance consuming the fixed 800-millisecond publication reserve; such variance fails closed and
does not publish partial data.
