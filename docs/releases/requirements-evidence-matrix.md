# MVP-013 requirement-to-evidence matrix

Status terms:

- **baseline** — implemented before MVP-013; exact release regression pending;
- **candidate** — present in the shared MVP-013 worktree but not release-tested;
- **worktree-verified** — implemented and exercised in the shared worktree, but
  not rerun and indexed from an exact clean release commit;
- **exact-local-verified** — exercised against source candidate
  `94231d7e57767b18a4cd9546ad5bf33afc13a735`, tree
  `43395db015a2205c739647c1b6dfb9b02626abd2`, and local runtime image
  `anva-mvp13:0.1.0` ID
  `sha256:c6ae3a8abfd4c54d91df94be0dfe7f1bc1c52e73da58a4617b2bc30a3b1f6f2c`;
  indexed under evidence archive SHA-256
  `d90916f8063911757a05f8e0b16e25e5a64063609046a04e44aea9065d6dbeb8`,
  but not published;
- **missing** — required closure is not present or not integrated;
- **deferred** — outside the install-ready self-hosted MVP boundary with an
  explicit rationale.

No implementation status is a passing publication claim. `exact-local-verified`
closes only the recorded local candidate gate; tag, provenance, publication,
external/manual, and explicitly deferred requirements remain separate.

| Authority | Requirement | Status | Current implementation/evidence | Required completion evidence |
| --- | --- | --- | --- | --- |
| Issue 13 | Compose fresh install/bootstrap/demo | worktree-verified | `make install-demo` builds/migrates and idempotently seeds; the demo is attached `run --rm` with Docker logging disabled so its fresh token is terminal-only; published-image install absent | Exact-commit clean-host install, idempotency, and token non-retention record against immutable published artifacts |
| Issue 13 | Versioned image/packages/checksums | exact-local-verified | Local runtime image `c6ae3a8a...` has OCI revision `94231d7e...`; clean-source manifest, complete `SHA256SUMS`, wheel, verified skill archives, SBOMs, scans, and immutable evidence archive are checksummed | Registry digest, signed/provenance-attested tag and publication record |
| Issue 13 | Backup/restore/migration/rollback drill | exact-local-verified | Exact-image unique paired generations atomically activate `current`; an incomplete generation preserved the prior pointer, hostile guards/mutex failed closed, failed restore left writers stopped, successful restore preserved model/migration state, and reversal/forward passed in a cleaned disposable database clone while live state remained invariant. Object evidence is limited to Compose-managed MinIO | External-store support decision, older-application compatibility decision and deployment-sized recovery evidence |
| Issue 13/29; V3 20.8, 28.16; SEC-006–008 | Retention and deletion | candidate | MVP-013 exact-source tests cover server-owned time, explicit expiry plus organization minimum, tenant-only bucket cleanup, recent human/CSRF/two-confirmation decommission, and bearer/CLI rejection. The issue 29 local candidate adds tenant-qualified, ownership-checked accepted-evidence byte deletion with retryable metadata while preserving governed history. No post-setup reauthentication exists, so decommission is unavailable after 15 minutes | Frozen issue 29 review, reauthentication flow, interruption/recovery and retained/deleted-data operational acceptance; no source-deletion or erasure overclaim |
| Issue 13; V3 20.2 | Rate limits/abuse protection | exact-local-verified | Exact-source suite covers PostgreSQL fixed windows, request-tier plus actor-tier MCP charging, stable HTTP retry contract, channel enforcement, proxy attribution and bounded pre-auth cleanup | Deployed multi-process capacity/bypass drill, metrics and operational review |
| Issue 13; V3 24 | Health/readiness/logs/traces/metrics | exact-local-verified | Exact-source contracts cover fail-closed metrics auth/HTTPS, exact trusted-peer forwarding, readiness dependencies, correlation/trace identifiers, redaction, bounded structured logs and retained server errors | Deployed scrape/proxy exercise; aggregation, alerts and distributed tracing remain outside current implementation |
| V3 20.1, 28.16; SEC-001 | Product threat model | candidate | Feature threat models plus new umbrella model | Security review record and threat-to-test links |
| V3 20.3, 28.16; SEC-003 | Prompt-injection corpus | missing | Inert parser/evaluator/skill fixtures; TST-007 is the separate artifact-integrity corpus and does not close prompt-injection coverage | Five-source-class product run with zero boundary mutation/leakage |
| V3 20.2, 20.7, 28.16; SEC-004 | Secret redaction | baseline | Structured logger and input rejection tests | Release-wide logs/traces/reports/packages/image canary scan |
| V3 20.4, 28.16; SEC-009 | Skill supply-chain checks | baseline | Deterministic archives, checksums, safe installer | Exact-release archive verification, version/source/security contact/revocation record |
| Issue 13; V3 20.2 | Dependency/container scans and SBOM | exact-local-verified | Checksummed SPDX/CycloneDX SBOMs and source/image reports bind to `94231d7e...`/`c6ae3a8a...`. The gate has zero unwaived/fixable high-critical image tuples; 14 reviewed exception IDs cover 24 no-fix tuples through 2026-08-18. Source residuals are one medium and three low fixable Django findings plus low `DS026`; secrets are zero | Re-review/fix/block before exception expiry, lower-finding disposition, license policy, registry digest and publication provenance |
| V3 20.9 | Source revocation | baseline | Source/GitHub/token revocation and retrieval tests | Central search/context/Canvas/MCP/artifact/queued-work release matrix |
| V3 20.9 | Cross-tenant API/search/Canvas/MCP/artifact isolation | baseline | Strong but distributed integration tests and database constraints | One complete release matrix with canaries and foreign/missing equivalence |
| Issue 29; V3 16.5, 28.16; SEC-010 | Artifact upload security | worktree-verified | Local issue 29 candidate has actor/credential/tenant/repository/scope/PR/exact-commit authorization, single-use bounded JSON/ZIP/TAR inspection, conditional object storage plus read-back verification, immutable blob/evidence binding, owned cleanup/deletion, and all six pinned TST-007 byte classes through Anva; see `docs/evidence/issue-029/README.md` | Frozen exact-commit independent security-review approval, focused PR/merge record, and deployment-specific S3/TLS/IAM/outage validation; no malware/signature overclaim |
| V3 20.5, 28.16; SEC-005 | Model data governance | deferred | External model processing is not in the release boundary | Enforce disabled/manual-only; implement before any provider integration |
| V3 28.16; SEC-011 | OAuth and token revocation | baseline/deferred | Exact-repository bearer-token revocation exists; remote OAuth is outside this release boundary | Exact-release revocation matrix; OAuth before shared remote deployment |
| V3 28.16; SEC-012 | External penetration test | deferred | Required before commercial beta, not self-hosted MVP | Track as commercial-beta blocker |
| V3 28.16; SEC-013 | Security incident runbook | missing | Feature notes and minimal telemetry triage only | Owned security incident, containment, notification and exercise record |
| V3 23.2–23.6 | Unit/integration/contract/E2E/security suites | exact-local-verified | Broad Compose: 761 passed, one expected separately executed live-MCP skip, three browser/corpus deselections, 85.41424161141758% coverage; exact corpus: 1 passed; live MCP: 2 passed; Chromium: 2 passed; zero failures/errors | Publication/external reviewer record; no substitution of the docs descendant for tested parent `94231d7e...` |
| V3 23.7–23.9 | Retrieval/skill/assurance evaluations | baseline/missing | Exact broad suite includes local retrieval/authored skill/deterministic assurance evals, and read-only `anva-test` corpus ingestion passed at `a66787b...`; the fixed release gate remains incomplete | Exact thresholds and pinned inputs; deterministic import/replay of all 31 public cases with clean-reader verification; one independent context-free manual review over the messy knowledge corpus without private oracle/grader access |
| V3 23.10 | Model regression gate | deferred | No external model adapter | Mandatory before a model/prompt/context-format change ships |
| V3 23.14; 30 | Definition of test/issue completion | candidate | Checksummed exact-candidate command log/evidence archive and aligned documentation exist; publication, fixed 31-case replay, representative independent manual review, and human acceptance do not | Close or explicitly accept every remaining release gate without substituting local evidence for publication/manual acceptance |
| V3 24.6–24.8 | Tracing, alerts and runbooks | candidate/missing | Correlation/W3C trace IDs, process metrics and runbook are implemented | Distributed trace export, persistent scrape, alert rules and incident drill |
| V3 M6 | Rate limits, retention, alerts, security review | candidate/missing | Limits and retention have exact-source test evidence; alerts and the completion security audit are absent | Deployed operational/security review; pilot-usage targets remain future outcomes |
| V3 28.17; OPS-001 | Production Terraform | deferred | Compose is the MVP deployment unit | Required before managed production deployment |
| V3 28.17; OPS-002 | Backup and restore | exact-local-verified | Exact-image atomic-generation paired backup/verify/restore, guard/mutex rejection, failure-safe writer handling, successful state invariance, and disposable-clone rehearsal passed using local MinIO; cleanup left no scoped residue | External-store support decision, scheduled/encrypted storage policy and deployment-sized timing |
| V3 28.17; OPS-003/004 | Dashboards and alerting | missing | Process-local metrics only | Provisioned queries/rules and alert exercise |
| V3 28.17; OPS-005 | Cost accounting | deferred | No external model/billing boundary | Implement before paid inference or commercial beta |
| V3 28.17; OPS-006–011 | Quotas, feature flags, support, pilot usage, billing export | deferred | Outside install-ready MVP | Re-enter scope for pilot/commercial beta |
| V3 28.17; OPS-012 | Status/incident communication | missing | Feature incident notes and minimal triage only | Operator incident runbook, owners and exercise |
| V3 28.17; OPS-013 | Processing/retention documentation | candidate | Retention/decommission runbook states current limits | Review against actual release behavior and policy |
| V3 Appendix E | Production readiness checklist | missing | Exact local candidate items are linked; publication, fixed external replay/manual-review, human, alerting and managed-production gates remain incomplete | Every remaining applicable item linked; deferred items visibly justified |
| Issue 13 | Release evidence and signed/checksummed commit/tag | missing | Immutable exact-source archive, final manifest and `SHA256SUMS` bind local image ID `c6ae3a8a...` to `94231d7e...`; no tag, signature, registry digest or publication exists | Verified signed/provenance-attested tag, registry/package identities and publication record |

## Deferred-boundary statement

The deferrals above are acceptable only for a local/self-hosted install-ready
MVP. They do not support a claim of managed-production, IITM-pilot, commercial
beta, regulatory erasure, OAuth, external-model, billing, or multi-browser
readiness.

Exact read-only `anva-test` corpus ingestion passed. The remaining deferral
covers that repository's full non-browser/browser baselines, deterministic
import/replay of all 31 public cases, one representative context-free manual
review over the messy knowledge corpus, and human user/operator/developer
acceptance. This work does not add, enable, or change a
GitHub Actions workflow; publication or an external runner must capture the
remaining evidence.

The immutable product/runtime evidence binds source parent `94231d7e...`, tree
`43395db...`, and image ID `c6ae3a8a...`. A documentation-only descendant may
record corrections, but is not the tested product identity.
