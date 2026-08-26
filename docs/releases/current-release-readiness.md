# Current install-ready MVP release readiness

This is a documentation-only audit of the frozen runtime product and its
test-only descendant under the [release-freeze contract](release-freeze-contract.md).
It does not publish an artifact, approve vulnerability risk, perform an
operator exercise, or turn a historical result into exact-current evidence.

## Authoritative identities

| Identity | Value | Meaning |
| --- | --- | --- |
| Runtime source | `dce714a346826235b4b1d918d2f7370649c4d49f` | Frozen product source exercised by the final seal and exact-current product gate |
| Runtime tree | `333d6063692bc283477da60b53ee6d3ebc4d9dc3` | Tree embedded in the sealed runtime provenance |
| Local runtime image | `sha256:189788fd23dc852c7192c0f37448bdf5c2ab48a24863b8c507b94d945e818f85` | Locally built and checksummed image; not a registry digest or publication |
| Audit-input/test descendant | `996e8ebd39b735db27e56227ff2cb6c4a70fe386` | Test-only descendant of `dce714a`; later documentation-only descendants do not create a new runtime identity |

`git diff dce714a..996e8eb` changes only
`tests/unit/test_assurance_review_fixes.py` (three assertion substitutions).
Product source, contracts, dependency inputs, packaging, Dockerfile, and
Compose inputs are unchanged. Accordingly, `dce714a`/`189788...` remains the
runtime identity; `996e8eb` records the corrected test contract and must not be
presented as a separately built product image.

## Proven local gates

- The [final seal](../../evidence/final-seal-dce714a-20260826/RESULTS.md)
  binds the clean archive, runtime image, installed package, SBOMs, scans, and
  lifecycle evidence. Its 35-file `SHA256SUMS` and manifest checksum verify.
  The changed-surface/contracts/smoke selection passed 190 tests; Ruff lint and
  format passed. Fresh install, readiness, demo scope discovery,
  preserve/reinstall, and clean uninstall passed.
- The [exact-current product gate](../../evidence/issue-43-exact-current-dce714a/RESULTS.md)
  ran the full Compose matrix once: 1,007 passed, five documented skips, and
  one legacy assertion failure. Issue #54 corrected only that test assertion;
  its focused neighborhood then passed 16/16 with Ruff checks. No runtime defect
  was identified and the broad run was not repeated.
- The same exact-current gate passed the single predeclared Chromium journey
  2/2 and passed all 31 public policy imports and all 31 exact replays. The
  networkless clean reader rejected omission, duplication, reorder, product
  identity substitution, and semantic mutation. Tenant foreign-authority and
  inert-canary checks passed.
- The [five-source prompt-injection gate](../../evidence/live31-prompt-product-final-20260826/RESULTS.md)
  passed for requirements, policy, evidence, pull-request diff, and
  operator/reviewer context. Its carry-forward is limited to unchanged product
  boundaries; it does not substitute for the 31-case gate.
- One independent, context-free representative review over the messy corpus
  completed at `5f3b1fa`. It found two minor product defects, fixed and
  focused-tested by #52 and #53 before the frozen runtime. This direct review
  is distinct from the still-broken multi-stage automation in
  `RishavT/anva-test#18`.
- The exact image scan reports 3 critical and 13 high package tuples across 13
  CVEs, with no scanner-recorded fixed version. Exact source reports zero high,
  zero critical, and zero secrets. These are scan facts, not risk acceptance;
  #47 and #50 remain open.

## Open release blockers

| Blocker | Current disposition | Tracking |
| --- | --- | --- |
| Immutable publication and installation | Local checksummed source/image lifecycle is proven. No authoritative release version/tag, registry/package publication, published digest, signature, or provenance attestation exists. | [#42](https://github.com/RishavT/anva/issues/42) |
| Exact-gate aggregation | The exact-current broad, browser, 31-case, prompt-injection, and representative direct-review lanes now have evidence, but the aggregate issue remains open pending reconciliation with the selected descendant and all other authoritative blockers. | [#43](https://github.com/RishavT/anva/issues/43) |
| Residual vulnerability risk | The 16 high/critical no-fix tuples are unchanged from the prior base. Fourteen expired exception IDs and two SQLite CVEs have not been accepted by accountable security/application/platform/release owners. | [#47](https://github.com/RishavT/anva/issues/47), [#50](https://github.com/RishavT/anva/issues/50) |
| Essential operator exercise | [Release ownership](release-ownership.md) names Rishav Thakker of AI Soft Work as the MVP release, security, application, platform, and operations/on-call owner and records the escalation contacts. The timestamped operator exercise and deployment TLS/proxy boundary evidence are still absent. | [#44](https://github.com/RishavT/anva/issues/44) |
| MVP umbrella audit | Reconcile all applicable gates above without converting local evidence into publication, risk acceptance, or human ownership. | [#13](https://github.com/RishavT/anva/issues/13) |

The release is therefore **not complete**. The absence of scanner-recorded
fixes does not approve residual vulnerability risk.

## Explicit post-MVP boundary

- Supported human session entry after logout or expiry: [#37](https://github.com/RishavT/anva/issues/37).
- External object-store and deployment-sized recovery: [#38](https://github.com/RishavT/anva/issues/38).
- Persistent aggregation, dashboards, managed alerts, and distributed tracing:
  [#39](https://github.com/RishavT/anva/issues/39).
- Managed-deployment security and operations baseline: [#40](https://github.com/RishavT/anva/issues/40).
- Canvas 300-node p95 reproducibility and correctness-preserving optimization:
  [#49](https://github.com/RishavT/anva/issues/49). The owner explicitly deferred
  this minor performance variability after reviewing the observed results. The
  250 ms target is unchanged, the 235.4 ms pass and 354.1 ms failure remain in
  the record, and no failed result is reclassified.
- The multi-stage acceptance harness contracts-root defect:
  [RishavT/anva-test#18](https://github.com/RishavT/anva-test/issues/18).

The first four are legitimate deferrals only for the self-hosted install-ready
MVP. `anva-test#18` remains an open harness defect, but it neither proves nor
invalidates the separately completed direct context-free review and is not a
reason to rebuild the frozen harness before this product release.

## Completion rule

Close each blocker only from its own authoritative evidence. A human must make
human-owned risk and operations decisions; an authorized publisher must create
and verify external artifacts. Do not rerun an already passing lane unless a
changed dependency, contract, migration, authorization boundary, package, or
runtime image makes the scoped retest rule applicable.
