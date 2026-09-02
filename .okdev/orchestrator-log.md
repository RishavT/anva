# Bugfix orchestrator log

- 2026-09-02 — environment: HAClean clear; Docker/Compose and authenticated
  GitHub access available; `.okdev/bin/okdev-state` absent, so state is recorded
  in ordinary `.okdev` files.
- 2026-09-02 — specify: live run `33533018419` and an isolated fresh Compose
  project reproduced the root-owned cache/non-root scanner failure; delegated
  requirements pass found expected behavior unambiguous.
- 2026-09-02 — specify complete: created GitHub issue #67 with the reproduction,
  security invariants, regression criteria, and immutable-tag recovery contract.
- 2026-09-02 — implement: started branch
  `fix/release-trivy-cache-recovery` from `d919a2c`.
- 2026-09-02 — review round 1: CHANGES REQUESTED. Review found that checking
  out the immutable tag also restored its broken Compose cache definition, so
  dispatch-from-main alone could not recover v0.1.0.
- 2026-09-02 — implement follow-up: added workflow-owned, non-root preparation
  of only the labeled run cache before tag checkout. Regression proves the
  tagged old `/cache` scan fails unprepared and passes/reuses cache after the
  preparation. Focused release suite: 46 passed; scoped resources cleaned.
- 2026-09-02 — review round 2: CHANGES REQUESTED. Cache recovery was accepted,
  but the verify job did not yet re-bind its checkout to the build job's exact
  source commit if the remote tag moved between publish and verification.
- 2026-09-02 — testing: independent test-planner pass was green (46/46 release
  tests, real old-fail/new-pass cache scans, security controls, and cleanup).
  Hosted publication remains deliberately deferred until after merge.
- 2026-09-02 — implement follow-up: publish and verify now each check out the
  build-verified source SHA and independently require the remote tag, pinned
  commit, output SHA, and HEAD to agree before side effects. Adjacent release
  suite: 48/48; Docker cache/foreign-collision regression passed and cleaned.
- 2026-09-02 — review round 3: APPROVED with no MUST FIX findings. Independent
  rerun passed 18 focused tests and the real pinned-Trivy regression; live tag
  remained pinned and no review resources remained.
- 2026-09-02 — spot-check: PASS 10/10. Reproduced the original permission
  failure, observed two prepared real scans and cache reuse, confirmed effective
  controls, preserved a foreign collision, rechecked tag identity, and audited
  zero task resources.
- 2026-09-02 — delivery: `.okdev/delivery-report.md` records the approved fix,
  verification evidence, immutable recovery command, and hosted validation
  deferred until after merge. This task does not merge or retry the release.
- 2026-09-02 — PR CI: initial run failed only the Ruff format check for
  `tests/unit/test_release_workflow.py`. Applied the mechanical formatter;
  format check and the 18 focused tests passed in Compose before repush.
- 2026-09-02 — issue #71 environment/specify: HAClean clear; clean protected
  `main` at `e56fd613`; live tag still `d919a2c`; Docker, Compose, GitHub auth,
  API, and repository reachability passed. Run `33592278376` proved all build,
  publication, and attestation gates passed before `gh release create
  --verify-tag --target d919...` returned 403; Release API remained 404.
- 2026-09-02 — issue #71 implement: branch
  `fix/release-create-existing-tag`; retain `--verify-tag`, omit unnecessary
  `--target`, and add adjacent pre-mutation plus post-mutation remote-tag/source
  equality guards. No release retry or tag/package/settings/release mutation.
- 2026-09-02 — issue #71 testing: focused Docker release contracts 26/26;
  full `make check` passed 1,074 tests, 85% coverage, and Chromium 2/2; pinned
  real-Trivy regression passed. Generated browser evidence restored and all
  task Docker resources removed.
- 2026-09-02 — issue #71 recovery audit: canonical digest
  `sha256:71a484754b92bf06c35c075eba7b86419f1da0980b7794f53d59f8cc0f6f2f20`
  is live with two attestations; Release remains absent; tag rules block update
  and deletion. Original run is bound to broken workflow SHA `e56fd613`, so the
  post-merge recovery must be a new corrected-main dispatch, not a failed-job
  rerun.
- 2026-09-02 — issue #71 review round 1: CHANGES REQUESTED. Bash can clear
  `errexit` inside command substitutions, so resolver-internal failures needed
  explicit propagation. Added `|| return 1` throughout and an executable mock
  regression covering nonzero partial, missing, malformed, duplicate direct,
  duplicate peeled, and valid tag responses. Focused Docker gate: 27/27.
- 2026-09-02 — issue #71 review round 2: APPROVED. Independent Docker review
  confirmed the explicit resolver failure propagation, executable failure-path
  regression, release side-effect ordering, recovery decision, Ruff, format,
  and `git diff --check`; no remaining findings.
