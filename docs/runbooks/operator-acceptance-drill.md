# Disposable operator acceptance drill harness

This harness prepared safe, synthetic evidence for the now-complete issue #44
exercise and remains the procedure for future release drills. It does not by
itself execute a genuine human exercise or authorize a release. Every new
eligible record starts `PENDING_RISHAV_EXECUTION`; an ineligible image remains
in its exact `NOT_ACCEPTED` state. Command success must not be inferred as human
review, an operator decision, or signoff.

## Release boundary

The completed target was published v0.1.6 at product source
`e89b06aed8207cc32eee0eeebde4a2731f0c0203` and image digest
`sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`.
Operator-signoff run `33910747236` anchored the completed ledger. A future
release must supply its own exact source and digest at runtime; the harness
compares that source with the pinned image's OCI revision and records the
harness source separately.

The predecessor product services run the canonical public v0.1.5 image at
`sha256:19488230c6f7900cda33bd11adc7f1ad824d23b77ee87fd65ac883cd0dacc725`,
whose product source is `491cdd7830a7f4d6af7140f6a4744f95c80c46a9`. Publication and immutable
install verification completed in release workflow `33727525411`.

That predecessor image predates the corrected product/operator source-role
contract. Running its `drill-tool` with a later product or operator source
correctly yields `NOT_ACCEPTED`; current-source code must not be substituted for
a pinned image. v0.1.6 supplied the generic same-image source binding used by
the completed exercise. No future operator exercise may begin during release
preparation.

## Automated preparation

Use a unique metrics token and operator credential supplied outside the
repository. Keep `DRILL_PROJECT` disposable. The preflight compares the exact
configured IPv4 subnet with every existing Docker subnet and refuses any
overlap; it also requires one usable exact proxy address. Every Anva-derived
runtime and operations helper uses the exact immutable `ANVA_DRILL_IMAGE`; none
build from the drill worktree or fall back to a local tag.

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
resumes. The database and object backup/restore helpers join only the internal
backend network so they can reach Postgres and MinIO without publishing either
store. Run it only after creating a synthetic backup in this project:

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
correlation UUID, and the full confirmation string. It runs from the same exact
immutable image as the other drill services, but v0.1.5 cannot produce final
eligible evidence for the source-role reason above.

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

Only Rishav may perform and attest the release-owner decisions required by a
genuine drill:
credential rotation/revocation, suspected permission-leak response, failed
restore recovery, retention/decommission interruption, metrics/proxy triage,
escalation decisions, and final cleanup/signoff. These actions must be observed
against an eligible release candidate, timestamped by the human participant,
and entered honestly. They must not be inferred from command success or filled
by automation. Until then signoff remains null. New eligible records remain
`PENDING_RISHAV_EXECUTION`; the historical v0.1.5 boundary remains
`NOT_ACCEPTED_OPERATOR_TOOL_PREDATES_SOURCE_ROLE_CONTRACT`. The completed
v0.1.6 record is externally anchored and final rather than pending.

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
identity mismatches or fabricated anchors. Automation never pre-populates
completion or approval.
After the genuine drill, validate the scrubbed record, review it manually, and
run `make drill-down`. Confirm no containers, networks, or volumes remain for
the exact drill project. Never run the final human drill as part of CI or this
enabling issue.
