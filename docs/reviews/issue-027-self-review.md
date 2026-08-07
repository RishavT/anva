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
| Operator commitment | SHA-256 of exact raw manifest bytes is required and constant-time compared before JSON parsing | Wrong-pin unit and live Compose rejection |
| Hostile path/inventory rejection | POSIX `payload/**`; traversal/absolute/drive/backslash/NUL/duplicates/unsorted/control paths; no symlink, hardlink, special, unlisted, missing, oversized, over-deep, size-mismatched, or hash-mismatched input | Adversarial unit suite |
| Only adapter sees raw input | Resolved Compose has one read-only raw bind, on `acceptance-adapter`; product and runner services receive only the canonical named volume read-only | Static and resolved-Compose inspection |
| Adapter isolation | Read-only root, UID 0 with every Linux capability dropped, `no-new-privileges`, no network, bounded tmpfs, exec-form command, no product secrets | Static, resolved-Compose, and live container proof |
| Safe canonical output | Fresh/empty volume, exclusive writes, deterministic fingerprint/manifest, 0555 directories, 0444 files, cleanup on failure | Unit and live canonicalization/verification |
| Non-root product compatibility | UID 10001 read the canonical source and independently verified it; a mutation attempt failed | Live volume proof |
| Supported connector only | Filesystem connector root is the canonical `payload/` child, excluding the generated control manifest | Integration test |
| Public result boundary | COMPLETE/PARTIAL require checksummed `knowledge_retrieval_results`; FAILED can fail closed with a structured error and no artifacts; artifact paths remain beneath `results/` | Generated schema/example and contract tests |
| Scoped lifecycle | Make targets use the `anva-acceptance` project; cleanup removes only its containers/network/ephemeral volume | Make/static test and operator runbook |

## Test evidence

- Focused unit/integration/contract/CLI/Compose suite: 60 passed in 1.04 seconds.
- Broad non-Selenium suite: 786 passed, one expected live-MCP-profile skip, and two historical
  performance tests could not write to the deliberately read-only source bind. Those exact two
  passed separately against a task-owned writable copy volume: two passed, 16 deselected. Combined
  selected result: 788 passed and one expected skip; zero product/acceptance failures.
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
- Live negative bundle: wrong pin exited `2` with a path-free structured message and left the
  canonical volume empty.

The measured conservative peak for task-owned/used Docker assets was about 3.675 GB: 2.086 GB
named-builder cache, a 647,797,037-byte test image, a 243 MB builder container image, and about
698 MB of shared PostgreSQL/MinIO/MinIO-client virtual images used by the scoped test project. This
remained below the 5 GB ceiling. All task containers, volumes, networks, named builder/cache, and
the temporary test image are removed after review; unrelated and retained MVP-013 assets are not
touched.

## Security self-review and residual risk

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
