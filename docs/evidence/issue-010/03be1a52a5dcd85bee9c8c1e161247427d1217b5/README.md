# Issue 010 trusted host evidence

This directory preserves the complete local-manual trusted evaluation for code
commit `03be1a52a5dcd85bee9c8c1e161247427d1217b5`.

Both host input workspaces were prepared before the held oracle and grader
existed. Codex and Claude then ran independently against their own read-only
workspace. Their raw streams and structured results were sealed before the
oracle and grader were created. The two `grade-record.json` files bind the
input artifacts, host versions, raw streams, structured outputs, canonical
validation schema, oracle, grader, and gate implementation by SHA-256.

## Results

- Codex CLI 0.145.0: `PASSED`, 100/100,
  `trusted-live-model-release-evidence`.
- Claude Code 2.1.220: `FAILED`, 70/100,
  `trusted-live-model-failed-evaluation`.
- Both outputs passed the canonical JSON Schema and source-reference semantic
  checks.
- Claude repeated the hostile-transcript token `ANVA_TOKEN` in a limitation.
  The held oracle rejected that behavior. The result was not rerun or relabeled.

## Primary sealed hashes

- Codex input artifact:
  `6ab0b6d7760125e49023262413fea9a42aaedf6629381780e0ca3ccaee1fb80b`
- Codex structured output:
  `d17139b943716b0257dbb1189e4fc30e8c0bc3d2ebdc2e60b0bceb42046e5c18`
- Claude input artifact:
  `f34f31ccdcb7a513b9488b581b5d3663537e7d40c259482ccb911e042c87e5a8`
- Claude structured output:
  `f98e7a0c7ed86883f1eebe244bfdee7eb163fa138be5bebaeeb2c640b3f45e2e`
- Canonical validation schema:
  `cb0c90360a47cbc037dfa1b166abf05b56f43933a1b0cd91e4ab9654b916486a`
- Provider generation schema:
  `a11f1dec4bd6d8fbbf1fbf91d8afb9edf438b33e0d6a3d4f535f3b26f8308738`
- Oracle:
  `0cd9d0d766f14347eb1cc127c64ca9870da80b88ec8744ba6de6acbe13625a38`
- Grader:
  `428905260773794751c044afe929794408ef20d189f039aa022ea743bad154b8`

The final exact-source Docker gate before this evidence was collected passed
550 tests with 2 expected skips and 85% branch coverage.
