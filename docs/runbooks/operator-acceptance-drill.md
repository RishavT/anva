# Disposable operator acceptance drill harness

This harness prepares safe, synthetic evidence for issue #44. It does not close #44,
execute the genuine human exercise, or authorize a release. Every generated
record starts `PENDING_RISHAV_EXECUTION`; command success must not be inferred as
human review, an operator decision, or signoff.

## Release boundary

The product services run the canonical public v0.1.0 image at
`sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d`.
That image predates the supported #73 retry CLI. The current-source
`drill-decommission-operator` is therefore a source-bound development helper,
not evidence that v0.1.0 contains the recovery surface. The collector records
`NOT_ACCEPTED` for this combination. Final #44 acceptance must refuse to proceed
until a future product image (the exact v0.1.4 candidate) is bound to the same
source commit as the operator CLI and proves that CLI is in the product image.
This constraint does not narrow any other #44 exercise requirement.

## Automated preparation

Use a unique metrics token and operator credential supplied outside the
repository. Keep `DRILL_PROJECT` disposable. The preflight compares the exact
configured IPv4 subnet with every existing Docker subnet and refuses any
overlap; it also requires one usable exact proxy address.

```sh
export ANVA_DRILL_METRICS_TOKEN='<unique out-of-band value>'
export ANVA_DRILL_SECRET_KEY='<unique out-of-band value>'
export ANVA_DRILL_TOKEN_PEPPER='<unique out-of-band value>'
export ANVA_DRILL_BOOTSTRAP_SECRET='<unique out-of-band value>'
export ANVA_DRILL_OBJECT_STORAGE_SECRET='<unique out-of-band value>'
export ANVA_DRILL_SUBNET='<unused RFC1918 /24 selected for this host>'
export ANVA_DRILL_PROXY_IP='<one usable exact address in that /24>'
make drill-network-preflight
make drill-up
make drill-probes
```

The certificate container creates a two-day local CA and server certificate in
a disposable volume. Only `127.0.0.1:8443` is published, using TLS; the API has
no host port. The scrape probe requires `404/404/200` for missing, wrong, and
correct metrics credentials. The backend-only untrusted probe supplies spoofed
forwarded headers and must receive the exact production HTTP-to-HTTPS redirect
(`301`). A connection error (`000`), server error, or other response fails.

The restore fault target first verifies the active manifest, stops only running
writers, injects deterministic object-restore exit `44`, and fails if any writer
resumes. Run it only after creating a synthetic backup in this project:

```sh
make drill-restore-fault
```

Storage interruption controls are explicit and reversible:

```sh
make drill-storage-interrupt
# exercise synthetic retention/decommission failure and record only safe IDs/counts
make drill-storage-resume
```

The #73 helper requires exact organization/run/hash/attempt selectors, a fresh
correlation UUID, and the full confirmation string. On v0.1.0 it may demonstrate
the current-source helper only and must remain `NOT_ACCEPTED` for final release
evidence.

## Evidence and redaction

The tracked schema guide is `deploy/drill/evidence-template.json`. Create a new
uniquely named append-only JSONL ledger; never edit the guide into evidence:

```sh
make drill-evidence-template DRILL_ID='<fresh UUIDv4>'
make drill-evidence-record EVIDENCE_FILE='<generated basename>' CHECK_JSON='<one scrubbed check JSON>'
make drill-evidence-decision-proposal EVIDENCE_FILE='<generated basename>' DECISION_JSON='<coded proposal JSON>'
make drill-evidence-cleanup EVIDENCE_FILE='<generated basename>' CLEANUP_JSON='<cleanup JSON>'
make drill-evidence-provisional-validate EVIDENCE_FILE='<generated basename>'
```

Each event has a monotonic identifier, previous-event hash, and event hash.
Validation fails on edits, deletion, reordering, duplicate identifiers, events
after signoff, or signoff before completed cleanup. The validator rejects
sensitive fields and values including auth/bearer/basic material, cookies, API
keys, tokens, email addresses, raw IPs, canaries, credentials, passwords,
secrets, object keys/URLs, and unclassified digest-like strings. Do not capture
raw metrics, request bodies, customer content, logs, credentials, or addresses.

## Genuine Rishav actions

Only Rishav may perform and attest the release-owner decisions required by #44:
credential rotation/revocation, suspected permission-leak response, failed
restore recovery, retention/decommission interruption, metrics/proxy triage,
escalation decisions, and final cleanup/signoff. These actions must be observed
against an eligible release candidate, timestamped by the human participant,
and entered honestly. They must not be inferred from command success or filled
by automation. Until then signoff remains null and status remains
`PENDING_RISHAV_EXECUTION` or `NOT_ACCEPTED`.

Local records are closed-schema machine facts: enumerated check/decision/cleanup
codes, UUIDs, integers, and exact SHA-256 values. Free text and local human
approval/signoff events are forbidden. After an eligible same-source candidate
exists, dispatch `.github/workflows/operator-drill-signoff.yml` from `main` with
the exact drill UUID, complete ledger SHA-256, tail hash, product and operator
source commits, and canonical ordered decision-code hash. Rishav must approve
the protected `release` environment in the GitHub UI; no agent or API may do so.
Download the emitted anchor artifact, then run:

```sh
make drill-evidence-finalize EVIDENCE_FILE='<generated basename>' ANCHOR_JSON='<downloaded anchor JSON>' GH_CONFIG_DIR='<narrow authenticated gh config directory>'
make drill-evidence-final-validate EVIDENCE_FILE='<generated basename>' GH_CONFIG_DIR='<narrow authenticated gh config directory>'
```

Provisional validation checks only the local hash chain and closed schemas; it
never means accepted. Final validation is the required acceptance path and
re-verifies the external proof every time. Both final commands run only in the
nonroot `drill-finalizer` container with a read-only root, dropped capabilities,
the evidence directory, one anchor-input directory, the read-only GitHub CLI
config directory, the exact CLI executable, and an egress-only network. No host
Python finalization path exists.

Before finalization the ledger must contain, in order, exactly the five checks
`METRICS_AUTH`, `PROXY_SPOOF`, `RESTORE_FAULT`, `STORAGE_INTERRUPT`, and
`DECOMMISSION_RETRY`; then exactly all six tracked decision codes; then the one
successful zero-resource cleanup event. Every check must pass with a positive
sample count. Every decision must record participant code `RISHAVT` and its
closed decision-specific role code. Missing, failed, duplicated, reordered, or
empty evidence is rejected.

Each automated result uses its own closed observation fields. Metrics requires
the complete missing/wrong/correct token pattern `404/404/200` and a positive
metric sample count. Proxy spoofing requires exactly `301`. Restore requires
exit `44`, marker `DRILL_OBJECT_RESTORE_FAULT`, and zero running writers.
Storage interruption requires `UNAVAILABLE`, the exact
`DECOMMISSION_STORAGE_CLEANUP_RETRY_REQUIRED` failure, then `AVAILABLE`.
Decommission retry requires `FAILED` with that exact error to become
`COMPLETED` with `NONE`, advancing the attempt by exactly one. Any mismatch is
rejected rather than summarized into a generic integer.

Finalization verifies both the standard/custom GitHub attestations with the
exact signer workflow and predicate, then uses GitHub's review-history API to
require a successful `main` workflow-dispatch run and exact `release` approval
by `RishavT`. It refuses truncation, prefixes, stale ledger hashes/tails,
identity mismatches, fabricated anchors, or the current v0.1.0 `NOT_ACCEPTED`
boundary. Automation never pre-populates completion or approval.
After the genuine drill, validate the scrubbed record, review it manually, and
run `make drill-down`. Confirm no containers, networks, or volumes remain for
the exact drill project. Never run the final human drill as part of CI or this
enabling issue.
