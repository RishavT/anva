# MVP-013 requirement-to-evidence matrix

This matrix is an audit index, not execution evidence. Status terms:

- **exact-runtime-verified** — exercised against runtime source
  `dce714a346826235b4b1d918d2f7370649c4d49f`, tree
  `333d6063692bc283477da60b53ee6d3ebc4d9dc3`, and local image
  `sha256:189788fd23dc852c7192c0f37448bdf5c2ab48a24863b8c507b94d945e818f85`;
- **verified-carried** — valid evidence from an earlier identity whose relevant
  product boundary is proven unchanged, with the limitation stated;
- **partial** — some required evidence exists, but the release requirement is
  not closed;
- **missing** — required closure evidence does not exist;
- **deferred** — explicitly outside the self-hosted install-ready MVP boundary.

Audit-input commit `996e8ebd39b735db27e56227ff2cb6c4a70fe386` is a test-only
descendant of `dce714a`: its diff changes only three assertions in
`tests/unit/test_assurance_review_fixes.py`. It is not a new runtime identity.
Later documentation-only descendants likewise do not create a new runtime
identity.
Technical publication, signature, immutable installation, and digest-bound risk
evidence exist for `v0.1.5` at product source `491cdd7830a7f4d6af7140f6a4744f95c80c46a9`,
image digest `sha256:19488230c6f7900cda33bd11adc7f1ad824d23b77ee87fd65ac883cd0dacc725`,
and successful release run `33727525411`; no status below implies completed
#43/#44 human gates. Ownership is recorded in
[`release-ownership.md`](release-ownership.md).

| Authority | Requirement | Status | Authoritative current evidence | Remaining closure |
| --- | --- | --- | --- | --- |
| Issue 13 | Compose fresh install/bootstrap/demo | exact-runtime-verified | Run `33727525411` pulled and installed the immutable published v0.1.5 digest, migrated, checked readiness, and seeded the demo | Human operator exercise remains #44 |
| Issue 13 | Versioned image/packages/checksums | exact-runtime-verified | Public `v0.1.5`, source `491cdd7...`, image `sha256:1948823...`, 12 assets, checksums, and standard/custom attestations | Human operator exercise remains distinct under #44 |
| Issue 13; OPS-002 | Backup/restore/migration/rollback | exact-runtime-verified | Prior exact local lifecycle evidence plus final-seal preserve/reinstall prove the Compose-managed path and identity preservation | External-store and deployment-sized recovery are explicit post-MVP #38; do not overclaim them |
| Issue 13/29; SEC-006–008 | Retention/deletion | partial | Server-owned time, tenant cleanup, governed evidence deletion, and decommission safety have focused and matrix coverage | Supported post-expiry human entry is #37; external erasure/regulatory claims are not made |
| Issue 13; V3 20.2 | Rate limits/abuse protection | exact-runtime-verified | Exact full matrix includes fixed-window, actor/channel, retry, proxy-attribution, and bounded pre-auth tests | Deployment-specific capacity exercise belongs with real operator ownership (#44) |
| V3 24 | Health/readiness/logs/metrics | exact-runtime-verified | Exact full matrix and final lifecycle cover readiness, authenticated metrics/proxy contracts, identifiers, bounded structured logs, and redaction | Human-run deployment exercise remains #44; persistent dashboards/alerts/tracing are deferred #39 |
| V3 20.1; SEC-001 | Product threat model | exact-runtime-verified | Feature and umbrella threat models are linked to exact-current security/contract suites | Deployment-specific review remains part of #44/#50 decisions |
| V3 20.3; SEC-003 | Five-source prompt injection | verified-carried | `evidence/live31-prompt-product-final-20260826`: all five frozen source classes passed with inert excerpts, tenant isolation, no mutation, and cleanup | Carry-forward is limited to unchanged product/package/contracts/dependencies; it does not replace 31-case replay |
| V3 20.2/20.7; SEC-004 | Secret redaction | exact-runtime-verified | Final exact source scan reports zero secrets; exact gates assert log/result canary absence and one-time token redaction | Publication-wide scan must be repeated over the bytes actually published (#42) |
| V3 20.4; SEC-009 | Skill supply chain | partial | Deterministic archives/checksums and safe installer contracts are tested | Publish and verify current skill/package artifacts, provenance, security contact, and revocation record (#42) |
| Issue 13; V3 20.2 | Dependency/container scan and SBOM | exact-runtime-verified | Published scans/SBOMs and digest-bound acceptance prove the approved exact 13-CVE/16-tuple no-fix set through 2026-09-25 | Drift, a recorded fix, control change, or expiry fails closed |
| V3 20.9 | Source revocation | exact-runtime-verified | Exact full matrix covers source/GitHub/token revocation and permission-safe retrieval | Published/deployed operational exercise remains scoped to #42/#44 |
| V3 20.9 | Cross-tenant API/search/Canvas/MCP/artifact isolation | exact-runtime-verified | Exact full matrix plus 31-case foreign-authority indistinguishable 404 and inert-canary probes | No remaining local product gate identified; managed deployment remains #40 |
| Issue 29; SEC-010 | Artifact upload security | exact-runtime-verified | Authorization, archive bounds, object read-back, immutable evidence binding, deletion recovery, and six pinned byte classes are in exact-current suites | Deployment-specific S3/TLS/IAM/outage validation is not claimed; external-store scope is #38 |
| SEC-005 | External model data governance | deferred | No external model adapter is in the MVP runtime | Must be implemented before any provider integration |
| SEC-011/012 | Remote OAuth and external penetration test | deferred | Exact-repository bearer revocation exists; remote OAuth/commercial-beta penetration testing are outside self-hosted MVP | Required before shared remote/commercial deployment (#40) |
| SEC-013; OPS-012 | Security incident ownership and exercise | partial | Rishav Thakker of AI Soft Work is the named MVP release/security/application/platform/operations owner; primary and alternate escalation contacts are recorded in `release-ownership.md`; reusable incident and triage instructions exist | Deployment boundary and timestamped operator exercise remain #44; naming the owner does not prove the exercise |
| V3 23.2–23.6 | Unit/integration/contract/E2E/security suites | exact-runtime-verified | Single exact full run: 1,007 passed, five documented skips, one stale assertion failure; #54 corrected only that test and the focused neighborhood passed 16/16. Final changed-surface seal separately passed 190 with Ruff | This is honestly a runtime pass plus disclosed test-contract correction, not a fabricated 1,013/1,013 rerun |
| V3 23.7–23.9 | Retrieval/skill/assurance evaluations | exact-runtime-verified | 31/31 imports and 31/31 idempotent replays passed with stable identities, double aggregate, clean-reader mutation probes, foreign-authority denial, and inert canary | Aggregate with other #43 evidence; do not substitute private 31-review ceremonies |
| V3 23.7–23.9 | Representative context-free manual review | verified-carried | One independent direct review over the messy corpus passed at `5f3b1fa`, found two minor defects, and those defects were fixed/tested in #52/#53 before `dce714a` | `anva-test#18` remains a separate automation defect and is not evidence for or against this direct review |
| V3 23.10 | External model regression gate | deferred | No external model/prompt adapter is shipped | Mandatory before a model, prompt, or context-format integration ships |
| V3 23.14; 30 | Definition of completion | partial | Exact-current local gates, checksum-verifiable evidence, named MVP ownership, and the bounded #60 risk decision exist | #42, #44, and umbrella #13 remain open; #43 needs authoritative aggregation; release-time digest binding remains mandatory; #49 is explicitly deferred post-MVP |
| V3 24.6–24.8; OPS-003/004 | Tracing, alerts, runbooks | partial/deferred | Correlation/W3C trace IDs, authenticated process metrics, and triage instructions are implemented | MVP human exercise is #44; persistent aggregation, dashboards, alerts, and trace export are post-MVP #39 |
| V3 M6 | Performance budget | deferred | Exact-current 300-node gate passed once at 235.4 ms p95 but another exact-current run failed at 354.1 ms; prior results are variable. Rejected `longest-path` candidate broke interaction correctness. The owner explicitly deferred this minor performance variability post-MVP | Preserve the unchanged 250 ms p95 target and pursue reproducible measurement and/or correctness-preserving optimization under #49; do not reinterpret prior results |
| OPS-001/005–011 | Terraform, cost, quotas, flags, support, billing, pilot | deferred | Compose is the self-hosted MVP unit; no paid inference/billing boundary is shipped | Re-enter scope for managed/pilot/commercial deployment (#40) |
| OPS-013 | Processing/retention documentation | exact-runtime-verified | Current runbooks describe retention/decommission behavior and limitations | Deployment policy choices remain operator-owned; no regulatory-erasure claim |
| V3 Appendix E | Production readiness checklist | partial | Local product, lifecycle, security, replay, representative-review evidence, and named ownership are indexed | External publication/signing, operator exercise, and residual-risk approval remain open; performance follow-up is deferred #49 |
| Issue 13 | Signed/checksummed release commit/tag | exact-runtime-verified | Verified `v0.1.5` -> `491cdd7...`; public checksum closure, GHCR digest, and attestations passed in run `33727525411` | Human gates #43/#44 remain distinct |

## Exact evidence indexes

- `evidence/final-seal-dce714a-20260826/RESULTS.md` and `SHA256SUMS`
- `evidence/issue-43-exact-current-dce714a/RESULTS.md`, `SELF_REVIEW.md`,
  and `SHA256SUMS`
- `evidence/live31-prompt-product-final-20260826/RESULTS.md` and
  `SHA256SUMS`
- GitHub issues #42–#50, #60, and umbrella #13 provide the authoritative current
  decision state. Closed #45/#46 document resolved applicability groups; #60
  records the bounded owner approval for the exact residual set and requires a
  separately generated digest-bound acceptance artifact at publication.

The final-seal 35-file manifest and its manifest checksum, the exact-current
gate manifest, and the prompt-gate manifest have been revalidated during this
documentation audit. Evidence paths are repository-relative; v0.1.5 external
publication occurred in run `33727525411`; local archives remain historical evidence.

## Deferred-boundary statement

Issues [#37](https://github.com/RishavT/anva/issues/37) through
[#40](https://github.com/RishavT/anva/issues/40) are legitimate post-MVP
deferrals only for a local/self-hosted install-ready product. They do not
support managed-production, IITM-pilot, commercial-beta, OAuth, external-model,
billing, external-store, persistent-observability, or regulatory-erasure
claims.

[`RishavT/anva-test#18`](https://github.com/RishavT/anva-test/issues/18)
remains open because the multi-stage harness disagrees on its contracts-root
representation. No representative request was consumed by that failed path.
The separately completed direct representative review is the frozen product
release evidence; it does not claim to fix or prove the broken automation.
