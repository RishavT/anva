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
