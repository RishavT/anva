# Issue 158 cold-context evidence

The unchanged sealed `anva.outbox-stable-key.v6` case and exact 115-file public corpus were run
from a fresh Compose stack against product commit `360c4ede3636b5c9acf5b0a36b8ba8f6988d30e4`.
The first and only cold product invocation reached `AWAITING_EXTERNAL_REVIEW`; it did not require a
retry or cache warm-up.

## Immutable inputs

- Image ID: `sha256:ff43aebf7401c59b49fbddc49edc932bc637cd13614e0ebee4a3bd5f47493823`
- Product package SHA-256: `a6540b9da10cce3a44f7038605097705593c65f6de0e2f246eb7524ac9adfd19`
- Corpus commit: `48209b315f47acc8ec99a4c0cacda26e6488df62`
- Raw manifest SHA-256: `91c70a2bd13a67f907f720568d39904f490b7dc9aef77ff5e88531c243f789ca`
- Canonical manifest SHA-256: `7d22101e7a070673bdfdc38d64de2bb5176ce5bed84fb5198799cff701fd147d`
- Source fingerprint: `6849425b5fcafe40b82ba3dfc9d19026c86a34f9f44de5315b12e3293bfa6f3d`
- Case SHA-256: `8826dafb9eadf4bb57db6d6ede7a34920b589b9488c76ec29224a69b12ccb0af`

## First-call result

- Run ID: `anva:a252be9d-cc10-57f9-89af-dfeeec506939`
- Context packet ID: `06c72435-36d2-4314-9f58-d146283537d1`
- Official Streamable HTTP MCP call: `2026-09-07T01:41:36.489125Z` to
  `2026-09-07T01:41:38.047370Z` (`1.558245s`)
- Packet generation timestamp: `2026-09-07T01:41:37.636876Z`; this bounds work before the
  generated record to `1.147751s` and the remaining publication/response tail to `0.410494s`.
- Complete scan: 1,989 processed rows, 151 exact eligible assertions, 1,613 exact eligible
  conflicts, digest `d4d2240fdd9f9b23036d8a4338eda38c40e37cfc78fa0b471589689210ca3861`.
- Both required search anchors are present ahead of optional material.
- Packet caps: 100/100 items, 19,917/20,000 tokens, 32,022/250,000 bytes, and 101/200 citations.

The runner continued through assurance and the stale-head probe to the sealed external-review
handoff. The failed pre-fix cold transaction had published no packet; this fresh stack contained
only the successful fixed-product packets.

## Final bound tightening and rerun note

Full-suite validation exposed that an internal five-second SQL timeout could make the enclosing
public assurance operation exceed its five-second target by about 62 milliseconds. The final
implementation therefore retains the four-second complete-scan bound and now uses a 500-millisecond
sealing/finalization/commit reserve. The measured fixed-corpus publication/response tail above was
0.410494 seconds. A deterministic 501-archive regression crosses the scan edge during canonical
digest sealing and verifies that a 4.5-second overrun publishes no scope, artifact, packet, item,
or citation.

Independent review found that the earlier implementation measured transaction-body exit rather
than the actual COMMIT. A real deferred PostgreSQL trigger then established that `SET LOCAL
statement_timeout` did not cancel the Django/psycopg COMMIT. The remediated exact transaction owner
uses psycopg's bounded cross-thread cancellation and joins its watchdog before connection reuse.
Production-scale deferred-COMMIT evidence returned REST fail-closed in 4.73-4.83 seconds; the
assurance owner returned in exactly 4.661635 seconds, persisted only a FAILED provisional run with
null context identifiers, and left no scope, artifact, packet, item, citation, or evaluator task.
Head-change, authorization-revocation, task-creation-failure, near-deadline success, cached reuse,
and identical concurrent-start cases also passed. REST is non-atomic and `ATOMIC_REQUESTS` is
disabled. New-packet MCP dispatch delegates transaction ownership to publication and persists its
success audit afterward; a simulated audit-store outage returned the committed packet, logged only
the stable tool name, and a retry reused that packet before persisting one SUCCEEDED audit. GitHub
commits its locked ingestion and final provider-head recheck before starting assurance; a simulated
start failure left one reusable revision/observation, marked the delivery FAILED, and a retry
created one run without duplicating ingestion. Both service entries reject ambient production
transactions.

A fresh local rerun canonicalized the same 115 files and exact corpus identities, but the recovered
launch workspace was rejected before bootstrap or context retrieval with stable reason
`launch_bind_mismatch`; no product context call occurred. The rejected stack was removed. The
unchanged sealed case is therefore scheduled for the authoritative fresh blind acceptance after
merge rather than treating a reconstructed provenance boundary as valid evidence.
