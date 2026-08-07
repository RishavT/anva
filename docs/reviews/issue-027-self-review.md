# Issue 27 self-review: public acceptance corpus isolation

## Scope and outcome

This slice freezes the public `acceptance-corpus` and `acceptance-result` version `1.0` contracts,
adds the only raw-input adapter, and supplies the acceptance Compose/CLI/Make foundation. It removes
the previous sibling-repository corpus override because that topology exposed mixed public/private
repository content directly to product and test services.

No database model or migration changed. No workflow, release tag, publication, private exporter,
held grader, native-agent run, or human acceptance is part of this issue.

## Acceptance mapping

| Requirement | Implemented control | Evidence |
| --- | --- | --- |
| Public-only closed manifest | Exact regular-file paths, SHA-256, byte sizes, bounded identity metadata and limits; closed generated JSON Schema and example | Contract generation/check plus schema tests |
| Operator commitment | SHA-256 of exact raw manifest bytes is required before parsing; verification separately requires operator-preserved raw-manifest, source-fingerprint, and canonical-manifest identities | Wrong-pin, missing-pin, and self-consistent volume-substitution tests |
| Hostile path/inventory rejection | POSIX `payload/**`; traversal/absolute/drive/backslash/NUL/duplicates/unsorted/control paths; no symlink, hardlink, special, unlisted, missing, oversized, over-deep, size-mismatched, or hash-mismatched input | Adversarial unit suite |
| Only adapter sees raw input | Resolved Compose has one read-only raw bind, on `acceptance-adapter`; product and runner services receive only the canonical named volume read-only | Static and resolved-Compose inspection |
| Adapter isolation | Read-only root, UID 0 with every Linux capability dropped, `no-new-privileges`, no network, 256 MiB/no-extra-swap memory, 64 PIDs, bounded tmpfs, exec-form command, no product secrets | Static, resolved-Compose, and live container proof |
| Safe canonical output | Fresh/empty volume, bounded streaming inventory, atomic same-directory publication after write/fsync, deterministic fingerprint/manifest, 0555 directories, 0444 files, cleanup on failure | Large-inventory, injected partial-write/fsync, unit, and live verification |
| Non-root product compatibility | UID 10001 read the canonical source and independently verified it; a mutation attempt failed | Live volume proof |
| Supported connector only | Filesystem connector root is the canonical `payload/` child, excluding the generated control manifest | Integration test |
| Public result boundary | COMPLETE/PARTIAL require checksummed `knowledge_retrieval_results`; FAILED can fail closed with a structured error and no artifacts; artifact paths remain beneath `results/` | Generated schema/example and contract tests |
| Scoped lifecycle | Make targets use the `anva-acceptance` project; cleanup removes only its containers/network/ephemeral volume | Make/static test and operator runbook |

## Test evidence

- Final focused adversarial corpus/CLI/Compose suite: 65 passed in 0.73 seconds.
- Focused corpus/integration/generated-contract run: 30 passed in 1.04 seconds.
- Broad non-Selenium suite against a read-only source bind and task-owned writable performance
  evidence volume: 794 passed and one expected live-MCP-profile skip in 233.86 seconds; zero
  product or acceptance failures.
- Strict MyPy: no issues in 162 source files.
- Ruff: 186 files formatted; repository-wide lint passed.
- Contracts: 28 deterministic artifacts generated and verified with valid examples.
- Migration drift: no changes detected.
- Live positive bundle: input manifest
  `6870cff283da05922cbd711711ea0428e0e5766c62932c6169217add907fc04f`, source
  fingerprint `573320567d6626d3036cf712c7995e01c9345cdc6f3722d1cbdcef1ecb2ce363`, and
  canonical manifest
  `f1552ee5f06c2b9ee069fe1b5e2d6a6ced04cd4b7d9918775d2d88a2cb332c4d` were
  identical at adapter and runner verification.
- Live negative bundles: a wrong raw-manifest pin exited `2` with a path-free structured message
  and left a fresh canonical volume empty; a wrong preserved verification pin also exited `2` with
  generic `verification_pin_mismatch` output.

The measured conservative post-rebuild peak for task-owned/used Docker assets was about 4.279 GB:
2.690 GB named-builder cache, a 647,833,907-byte test image, a roughly 243 MB builder container
image, and about 698 MB of shared PostgreSQL/MinIO/MinIO-client virtual images used by the scoped
test project. This remained below the 5 GB ceiling. The superseded task image was removed exactly.
All remaining task containers, volumes, networks, named builder/cache, and the temporary test image
are removed after review; unrelated and retained MVP-013 assets are not touched.

## Security self-review and residual risk

Independent review of the first implementation commit found three release blockers. The final
implementation (1) tracks temporary and final paths before creation, publishes only complete
fsynced files, and suppresses cleanup tracebacks while requiring the ephemeral volume to be
discarded if cleanup cannot be proven; (2) streams bounded directory inventories and constrains
adapter memory/PIDs; and (3) anchors verification in three identities preserved by the operator,
not values supplied by a self-consistent canonical volume. Adversarial regression tests exercise
each finding before exact-commit re-review.

The live test found and fixed a named-volume ownership defect: Docker initializes the volume root
as UID 0, so the original non-root adapter could not create `payload/`. The final adapter uses UID 0
only at this isolated boundary, with all capabilities dropped, no privilege escalation, no network,
and a read-only root filesystem. Only bounded tmpfs and the canonical volume are writable. Output
is sealed 0555/0444 so image-default UID 10001 consumers can read but cannot mutate it.

This is intentionally not the sealed acceptance gate. A host/Docker administrator can still alter
mounts, images, or environment and therefore requires independent evidence capture. The private
exporter must prove its allowlist and exclusion commitment; the disconnected grader must verify
canaries and outcomes; native hosts and human reviewers remain separate release gates. A fresh
independent reviewer must challenge the UID 0/capability boundary and resolved Compose before this
branch is merged.
