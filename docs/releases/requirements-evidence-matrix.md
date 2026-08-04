# MVP-013 requirement-to-evidence matrix

Status terms:

- **baseline** — implemented before MVP-013; exact release regression pending;
- **candidate** — present in the shared MVP-013 worktree but not release-tested;
- **worktree-verified** — implemented and exercised in the shared worktree, but
  not rerun and indexed from an exact clean release commit;
- **missing** — required closure is not present or not integrated;
- **deferred** — outside the install-ready self-hosted MVP boundary with an
  explicit rationale.

No implementation status is a passing publication claim. `worktree-verified`
results are useful development evidence, but remain insufficient for the final
exact-commit release gate.

| Authority | Requirement | Status | Current implementation/evidence | Required completion evidence |
| --- | --- | --- | --- | --- |
| Issue 13 | Compose fresh install/bootstrap/demo | worktree-verified | `make install-demo` builds/migrates and idempotently seeds; the demo is attached `run --rm` with Docker logging disabled so its fresh token is terminal-only; published-image install absent | Exact-commit clean-host install, idempotency, and token non-retention record against immutable published artifacts |
| Issue 13 | Versioned image/packages/checksums | candidate | Final manifest rejects tracked/untracked changes and OCI revision mismatch; release build rebuilds/verifies skills; local image, wheel, archives, SBOMs and reports exist | Registry digest, exact clean commit, release manifest, complete `SHA256SUMS`, signature/provenance and publication record |
| Issue 13 | Backup/restore/migration/rollback drill | worktree-verified | Unique paired generations atomically activate `current`; an incomplete generation preserved the prior pointer, a failed restore left writers stopped, a successful restore resumed them healthy, and reversal/forward passed in a cleaned disposable database clone while live remained at `0020`. Object backup evidence is limited to Compose-managed MinIO | Exact-commit current-control reports, external-store support decision, older-application compatibility decision and deployment-sized recovery evidence |
| Issue 13; V3 20.8, 28.16; SEC-006–008 | Retention and deletion | candidate | Retention uses server time, requires explicit expiry plus organization minimum, and purges only that tenant's buckets. Decommission requires a setup-authenticated web session no older than 15 minutes, CSRF and two exact confirmations; bearer/CLI is rejected. No post-setup reauthentication flow exists, so decommission is unavailable after that window; physical deletion is absent | Reauthentication flow before release, then exact-commit retained/deleted-data, caller-time rejection, tenant-bucket isolation, human/CSRF/bearer matrix, interruption/recovery; no erasure overclaim |
| Issue 13; V3 20.2 | Rate limits/abuse protection | worktree-verified | PostgreSQL fixed windows, stable HTTP retry contract and channel enforcement have focused coverage | Exact-commit multi-process capacity/bypass drill, metrics and operational review |
| Issue 13; V3 24 | Health/readiness/logs/traces/metrics | candidate | Metrics fail closed without a token and require production HTTPS; forwarded metadata requires exact trusted peer IP; structured request/server-error logs are retained while access logs are off and bounded. Earlier focused coverage predates all hardening | Exact-commit scrape, proxy, server-error and redaction record; aggregation, alerts and distributed tracing remain outside current implementation |
| V3 20.1, 28.16; SEC-001 | Product threat model | candidate | Feature threat models plus new umbrella model | Security review record and threat-to-test links |
| V3 20.3, 28.16; SEC-003 | Prompt-injection corpus | missing | Inert parser/evaluator/skill fixtures; TST-007 exists only in `anva-test` | Five-source-class product run with zero boundary mutation/leakage |
| V3 20.2, 20.7, 28.16; SEC-004 | Secret redaction | baseline | Structured logger and input rejection tests | Release-wide logs/traces/reports/packages/image canary scan |
| V3 20.4, 28.16; SEC-009 | Skill supply-chain checks | baseline | Deterministic archives, checksums, safe installer | Exact-release archive verification, version/source/security contact/revocation record |
| Issue 13; V3 20.2 | Dependency/container scans and SBOM | candidate | Local SPDX/CycloneDX SBOMs/reports exist. Source vuln/secret/misconfig gate excludes documented operator paths. Image gate records 14 reviewed no-vendor-fix exceptions expiring 2026-08-18 instead of silently ignoring them | Exact-commit checksummed reports, unexpired finding disposition, license policy, registry digest and publication provenance |
| V3 20.9 | Source revocation | baseline | Source/GitHub/token revocation and retrieval tests | Central search/context/Canvas/MCP/artifact/queued-work release matrix |
| V3 20.9 | Cross-tenant API/search/Canvas/MCP/artifact isolation | baseline | Strong but distributed integration tests and database constraints | One complete release matrix with canaries and foreign/missing equivalence |
| V3 16.5, 28.16; SEC-010 | Artifact upload security | missing | JSON schema/hash/path protections; no accepted byte/archive pipeline | All TST-007 malformed/oversize/schema/archive/secret cases through Anva |
| V3 20.5, 28.16; SEC-005 | Model data governance | deferred | External model processing is not in the release boundary | Enforce disabled/manual-only; implement before any provider integration |
| V3 28.16; SEC-011 | OAuth and token revocation | baseline/deferred | Exact-repository bearer-token revocation exists; remote OAuth is outside this release boundary | Exact-release revocation matrix; OAuth before shared remote deployment |
| V3 28.16; SEC-012 | External penetration test | deferred | Required before commercial beta, not self-hosted MVP | Track as commercial-beta blocker |
| V3 28.16; SEC-013 | Security incident runbook | missing | Feature notes and minimal telemetry triage only | Owned security incident, containment, notification and exercise record |
| V3 23.2–23.6 | Unit/integration/contract/E2E/security suites | worktree-verified | Broad Compose result: 721 passed, one expected live-MCP skip, three deselected, 85% branch coverage; focused result: 54 passed; fresh live MCP result: 2 passed; Chromium result: 2 passed | Exact clean-commit result manifest with environment identity and zero unexpected skips |
| V3 23.7–23.9 | Retrieval/skill/assurance evaluations | baseline/missing | Local retrieval and authored skill evals; `anva-test` replay integration absent | Exact thresholds, pinned inputs, all deterministic and native results |
| V3 23.10 | Model regression gate | deferred | No external model adapter | Mandatory before a model/prompt/context-format change ships |
| V3 23.14; 30 | Definition of test/issue completion | candidate | Worktree verification and aligned documentation exist; final exact-commit bundle and external acceptance do not | Full exact-commit command log, evidence index, traceability and no disabled gate |
| V3 24.6–24.8 | Tracing, alerts and runbooks | candidate/missing | Correlation/W3C trace IDs, process metrics and runbook are implemented | Distributed trace export, persistent scrape, alert rules and incident drill |
| V3 M6 | Rate limits, retention, alerts, security review | candidate/missing | Limits and retention are worktree-verified; alerts and the completion security audit are absent | Exact release evidence; pilot-usage targets remain future outcomes |
| V3 28.17; OPS-001 | Production Terraform | deferred | Compose is the MVP deployment unit | Required before managed production deployment |
| V3 28.17; OPS-002 | Backup and restore | worktree-verified | Atomic-generation paired backup/verify/restore, failure-safe writer handling, and successful resume passed against a distinct Compose project using local MinIO; external object-store operations are unsupported | Exact-commit recovery report, external-store support decision, scheduled/encrypted storage policy and deployment-sized timing |
| V3 28.17; OPS-003/004 | Dashboards and alerting | missing | Process-local metrics only | Provisioned queries/rules and alert exercise |
| V3 28.17; OPS-005 | Cost accounting | deferred | No external model/billing boundary | Implement before paid inference or commercial beta |
| V3 28.17; OPS-006–011 | Quotas, feature flags, support, pilot usage, billing export | deferred | Outside install-ready MVP | Re-enter scope for pilot/commercial beta |
| V3 28.17; OPS-012 | Status/incident communication | missing | Feature incident notes and minimal triage only | Operator incident runbook, owners and exercise |
| V3 28.17; OPS-013 | Processing/retention documentation | candidate | Retention/decommission runbook states current limits | Review against actual release behavior and policy |
| V3 Appendix E | Production readiness checklist | missing | The worktree snapshot is recorded, but publication and external/manual gates are incomplete | Every applicable item linked; deferred items visibly justified |
| Issue 13 | Release evidence and signed/checksummed commit/tag | missing | Worktree results are summarized; no exact release commit, final manifest, tag, signature, registry digest or publication exists | Indexed exact-commit evidence bundle and verified tag/commit/artifact identities |

## Deferred-boundary statement

The deferrals above are acceptable only for a local/self-hosted install-ready
MVP. They do not support a claim of managed-production, IITM-pilot, commercial
beta, regulatory erasure, OAuth, external-model, billing, or multi-browser
readiness.

The current deferral also covers the external `anva-test` corpus, sealed
fresh-agent Codex/Claude executions, and human user/operator/developer
acceptance. This work does not add, enable, or change a GitHub Actions workflow;
an external or local release runner must capture the remaining exact-commit
evidence.
