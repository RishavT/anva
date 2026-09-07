# Issue 158 self-review

## Scope and contract

The patch does not increase or disable the four-second authorized scan bound. It implements a
500-millisecond ranking, sealing, reauthorization, finalization, and commit-cancel reserve within
the v3 five-second context target. Both deadlines are absolute offsets from the same initial
monotonic timestamp, so phase entry cannot renew elapsed time. The 4.5-second cancellation ceiling
leaves measured response/cancellation headroom; the fixed-corpus publication tail was 0.410494
seconds, leaving 89.506 milliseconds (21.8%) inside the successful-publication reserve.

The transition occurs only after the assertion and conflict row/operation scans have each returned
immutable `complete=true` results. Row, operation, or scan-time exhaustion therefore still raises
before the active deadline changes and before scopes, artifacts, packets, items, or citations are
created. Canonical serialization and hashing of those proven-complete results occur after the
transition, under the final deadline. Required anchor resolution and the complete conflict digest
are unchanged.

## SQL and transaction safety

The PostgreSQL execute wrapper reads the active absolute phase deadline before every statement and
continues to clamp `statement_timeout`; lock and idle-transaction limits remain unchanged. An
empirical deferred-trigger test proved that `SET LOCAL statement_timeout` does **not** interrupt
the Django/psycopg COMMIT path, so the implementation does not claim otherwise. Immediately before
the actual outermost COMMIT it starts a daemon watchdog against the captured psycopg connection;
the watchdog uses psycopg 3's cross-thread `cancel_safe(timeout=0.25)`. Every exit disarms and joins
the watchdog before connection reuse. Only a confirmed PostgreSQL query cancellation (SQLSTATE
57014, cancellation sent, no cancellation transport failure) is normalized as deadline
exhaustion; ambiguous database/connection failures remain database errors.

Standalone packet publication owns its outer transaction. Assurance owns one outer transaction
from its canonical row locks and idempotency checks through packet rows, a locked pull-request head
check, current authorization, run/artifact binding, evaluator request/task creation, and actual
COMMIT. Callback, head-change, revocation, task-creation, or delayed-COMMIT failures roll back the
entire transaction; only the pre-existing provisional request identity is then finalized FAILED in
a separate transaction. Both public entry points reject real ambient atomic blocks before writes,
so the measured COMMIT cannot silently become a savepoint. Django-marked TestCase wrappers are the
only test-only exception. REST and acceptance HTTP call sites are non-atomic and
`ATOMIC_REQUESTS` is not enabled. MCP dispatch explicitly lets new packet publication own its
transaction, then records the success audit separately; an audit-store outage cannot turn a
durably published packet into a reported failure or a duplicate on retry. Other MCP tools retain
their generic atomic boundary. GitHub retains its locked provider refresh, ingestion, observation,
and final provider-head recheck transaction, then starts assurance after that transaction commits;
a failed assurance start marks the delivery retryable and the retry reuses the committed revision.
No task/worker directly calls the service.

## Verification

- Deterministic phase-edge tests prove archive-heavy digest sealing and ranking succeed only after
  complete scan entry; exact 4.0/4.5-second production boundaries
  reject, SQL timeouts follow the active phase, and an overrun leaves zero publication deltas.
- A real `DEFERRABLE INITIALLY DEFERRED` trigger sleeps only during COMMIT. Standalone REST cancels
  and returns the stable 409 error in 4.73-4.83 seconds with exact zero row deltas. Assurance
  cancels and durably records only the failed run in 4.661635 seconds, with null packet/artifact
  identifiers and no evaluator task. The same connection is reusable immediately afterward.
- A successful delayed COMMIT, a post-deadline reuse/cached repeat, identical concurrent starters,
  head mutation, authorization revocation, and evaluator-task failure all pass. Identical starts
  converge on one MODEL_REVIEW run and one task; every failure has exact zero scope/artifact/packet/
  item/citation residue.
- Existing invalid bulk-member and slow publication tests retain atomic rollback behavior.
- The unchanged cold 115-file corpus passed on its first MCP call in 1.558245 seconds with 1,989
  processed rows and exact 151/1,613 assertion/conflict accounting.
- Existing high-cardinality, idempotency, MCP, authorization, and fail-closed tests pass.

No P0 or P1 issue was found in the final diff. Residual risk is limited to scheduler/storage
variance consuming the fixed 500-millisecond publication reserve or delaying cancellation delivery;
the former fails closed, while cancellation transport ambiguity remains an unnormalized database
error rather than an unsupported rollback claim.
