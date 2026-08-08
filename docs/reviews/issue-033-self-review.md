# Issue 33 self-review: sealed product acceptance runner

## Scope and outcome

This slice turns the public acceptance-corpus foundation into a product-level runner for TST-004
through TST-007. It drives only supported HTTP APIs and the official Streamable HTTP MCP client,
pauses for an independently authenticated evaluator, resumes from content-minimized state, and
atomically seals deterministic public artifacts. It also adds an opt-in bootstrap reviewer identity
with only `ASSURANCE_REVIEW` permission.

External Codex/Claude execution, human timing, private scoring, release publication, tags, merge,
and workflow changes remain out of scope. The runner never mounts or reads a private oracle/grader
and never authors the evaluator judgment it submits.

## Acceptance mapping

| Requirement | Implemented control | Evidence |
| --- | --- | --- |
| Supported public boundaries | Dedicated `PublicAPI` client plus official MCP `ClientSession`/Streamable HTTP client; runner imports no product model or service | Boundary-only fake lifecycle, real Compose HTTP/MCP lifecycle, static import review |
| Canonical corpus only | Reverify operator-preserved raw-manifest, source-fingerprint, and canonical-manifest pins before every phase; source root is canonical `payload/` | Corpus adversarial suite, resolved Compose, live canonicalization |
| Organization bootstrap | Create organization, repository, access scope, initiator, and opt-in distinct reviewer through `/bootstrap`; reviewer has one `ASSURANCE_REVIEW` grant | Bootstrap integration and generated OpenAPI contract tests |
| Connected product exercise | Source sync, search, context packet, Canvas, work import, policy import/simulation, accepted byte upload, evidence manifest, exact diff, and assurance use HTTP/MCP only | Fake call ledger and complete live lifecycle |
| Exact-head and staleness | PR 817 assurance binds accepted evidence to its exact head; PR 818 starts a separate run and ingests a newer head; prior run must report state/readiness `STALE` | Unit boundary assertion and live run |
| Independent review | Product start stops at `AWAITING_EXTERNAL_REVIEW`; reviewer-only claim and submit run in fresh hardened services; result must match task/request/org/head | Tampered handoff/result tests and independent live evaluator |
| Restart safety | Mode-`0600` closed state contains only allowlisted opaque UUIDs/hashes; exact run reference is precommitted and hashed; single-disclosure upload replays derive a fresh idempotency key without storing a token | State tamper/permissions, future-clock, upload-replay, and fresh-process live resume tests |
| Deterministic public export | Canonical JSON/JSONL, content-minimized MCP/Canvas/report/finding views, exact provenance/input/reference/head hashes, complete manifest and `SHA256SUMS`, fsync/read-only/atomic rename | Byte-identical dual export test, schema validation, live checksum validation |
| Hardened lifecycle | Four phase-specific services; read-only root, non-root UID, all capabilities dropped, no privilege escalation, bounded memory/swap/PIDs/tmpfs/logs, disjoint mounts, no Docker socket/raw/oracle/grader | Static Compose tests and resolved configuration |
| Sustainable cleanup | Named Compose projects and `acceptance-down`/`test-down` remove only task containers, networks, and volumes; no engine-wide prune | Make/Compose tests and scoped cleanup inspection |

## Live evidence

The provisional real-boundary run used the public fixture and these preserved pins:

- raw manifest: `6870cff283da05922cbd711711ea0428e0e5766c62932c6169217add907fc04f`;
- source fingerprint: `573320567d6626d3036cf712c7995e01c9345cdc6f3722d1cbdcef1ecb2ce363`;
- canonical manifest: `f1552ee5f06c2b9ee069fe1b5e2d6a6ced04cd4b7d9918775d2d88a2cb332c4d`.

Fresh processes completed start, reviewer claim, reviewer submit, and finalization. Start stopped at
`AWAITING_EXTERNAL_REVIEW`; an independent evaluator consumed only the public handoff and returned
a contract-valid `COMPLETE` result with no findings; authenticated submission moved the state to
`EXTERNAL_REVIEW_SUBMITTED`; finalization moved it to `COMPLETE`. A second fresh finalizer returned
`COMPLETE` without rewriting the sealed directory.

The sealed `acceptance-result.json` SHA-256 was
`40b45c94373d3b05bcfdacb3589298cf236cfb5b059cd34309d41086e1b6647e`.
The external result, assurance input, and reference-time hashes were respectively
`868426e93b0e4f5ed0354ee6335b216a4a404a94f36c8128752f2b3d51f52e2f`,
`801a9d046c6ff5154ebc9eb3e366b20e3690905e370946789258583a1094fd81`, and
`d00a6ec5584934e705f3ddb5f155539c0119fa5886b8f87b84b6313fa15a827e`.
All seven checksum entries verified. Six public artifacts and the result envelope were read-only;
the output validated against `acceptance-result` version `1.0`. The consumed claim handoff was
deleted. Exact generated credential values and the `claim_token` marker were absent from Compose
logs and every sealed artifact.

## Defects found by live execution

1. The adapter originally ran as capability-less UID 0 against an image-seeded volume owned by UID
   10001. It could neither create output nor restore permissions during cleanup, so it correctly
   failed with `canonical_cleanup_failed`. Running as the fixed unprivileged owner repaired the
   boundary without weakening cleanup; a Dockerfile/Compose identity regression ties both sides.
2. The first evidence upload used a descriptive runner record instead of the accepted public
   evidence JSON shape. The product rejected it with 422. The runner now uploads the exact
   `{schema_version, head_sha, checks}` shape, and restart recovery handles a consumed one-time
   authorization without persisting its secret.
3. Corpus generation time preceded the evidence-retention activation event, so exact-time
   assurance correctly hid the new evidence. A new run now precommits the later of corpus time and
   rounded runner start plus the bounded sync/grace interval, persists and hashes it, and reuses it
   exactly on restart. New independent runs receive distinct UUIDv5 namespaces.

## Verification evidence

- Final focused bootstrap/corpus/Compose/runner/export/contract suite: 50 passed in 45.14 seconds.
- Repository-wide Ruff passed across 202 files. Strict MyPy passed across `src` and every touched
  Python test (109 files). Migration drift reported no changes; all 30 generated contract artifacts
  and examples verified.
- Canonical broad non-browser regression: 882 passed, one expected unmounted MCP-profile skip, and
  two browser deselections in 275.34 seconds.
- Task-owned images were approximately 1.01 GB nominal (`anva:0.1.0` and the test image), plus tiny
  scoped containers/volumes. This stayed below the 5 GB task ceiling. Pre-existing engine assets
  were neither attributed to this task nor pruned.

## Residual and deferred risk

A Docker/host administrator can inspect mounts, environment, or process memory and remains a
privileged trust assumption. This public product run proves boundary orchestration and deterministic
export, not private grading truth. An external harness must still launch native coding agents,
measure any human timing criteria, isolate the private scorer with no network, compare held controls,
and independently decide the overall release gate.
