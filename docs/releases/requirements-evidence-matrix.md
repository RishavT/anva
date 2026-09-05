# MVP-013 requirement-to-evidence matrix

This is the current audit index for the published self-hosted v0.1.6 boundary.
Execution evidence remains in the linked runs/issues and checksummed local
roots; this document does not turn prose into evidence.

## Immutable release identity

- tag/source: `v0.1.6` / `e89b06aed8207cc32eee0eeebde4a2731f0c0203`;
- image: `ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`;
- release run: [33781714974](https://github.com/RishavT/anva/actions/runs/33781714974);
- operator signoff: [33910747236](https://github.com/RishavT/anva/actions/runs/33910747236);
- final operator ledger SHA-256:
  `2338af9ee4d83469e461d02394051b73c02845718741cdea3b7ae8afadfede41`.

| Authority | Requirement | Status | Current evidence / boundary |
| --- | --- | --- | --- |
| Issue #13 | Compose install/bootstrap/demo | verified | Release run pulled the immutable image, installed without rebuilding, migrated, readied, and seeded twice |
| Issue #13 | Versioned image/packages/checksums | verified | 12 public assets, checksum closure, standard/custom attestations and immutable GHCR digest |
| OPS-002 | Backup/restore/migration | verified | Paired Compose PostgreSQL/MinIO generations, clean-project restore, injected failure, writer recovery and disposable migration rehearsal; external store remains #38 |
| SEC-006–008 | Retention/decommission | verified with limits | Server-owned retention, access revocation, governed deletion and retained-data limitations; session re-entry remains #37 and legal erasure is not claimed |
| V3 20.2 | Rate limits/abuse protection | verified | Shared database-backed actor/channel limits, concurrent behavior and stable `429`/`Retry-After` contracts |
| V3 24 | Health/readiness/logs/metrics | verified with deferred infrastructure | Readiness, exact proxy boundary, authenticated metrics, correlation and redaction passed; durable dashboards/alerts/tracing remain #39 |
| SEC-001/003/004 | Threat model, injection, secrets | verified | Product threat models, five hostile source classes across two tenants, and release-wide secret/canary checks |
| SEC-009 | Skill supply chain | verified | Deterministic Codex/Claude archives, checksums, attestations, safe installer and compatibility diagnostics |
| SEC-010 | Evidence artifact security | verified | Six pinned byte classes, immutable bindings, authorization, archive bounds, read-back and deletion recovery |
| SEC-005/011/012 | External models, OAuth, commercial pen test | deferred | No external model adapter or OAuth claim; required before managed/commercial deployment under #40 |
| IAM / V3 20.9 | Tenant/source/token isolation | verified | Exact-current API/search/Canvas/MCP/artifact and revocation matrices plus foreign-authority 404 probes |
| V3 23.2–23.6 | Product test suites | verified | Exact post-fix main CI `33951634105`: 1,255 passed, six documented skips, then 2/2 Chromium journeys |
| V3 23.7–23.9 | Public acceptance breadth | verified | 31/31 imports and idempotent replays, stable aggregate, clean-reader tamper rejection and inert canary |
| V3 23.7–23.9 | Representative independent review | verified-carried | Messy-corpus review passed at `5f3b1fa`; its two minor defects were fixed/tested before the exact-current gate |
| `anva-test#18` | Multi-stage private grading harness | incomplete/non-release | Contracts-root representation remains a real harness defect; it is not claimed as product evidence or 31 private review completions |
| SEC-013 / OPS-012 | Incident ownership/operator exercise | verified | RishavT ownership/escalation plus exact metrics/proxy, credentials, permission leak, restore, storage and decommission drill/signoff |
| V3 M6 / #49 | Canvas 250 ms p95 | deferred | One exact-current 235.4 ms pass and one 354.1 ms failure remain unchanged; owner explicitly deferred variability post-MVP without weakening target |
| OPS-001/003–011 | Managed operations/commercial readiness | deferred | Terraform, durable dashboards/alerts, cost, quotas, billing and pilot/commercial operations remain #39/#40 |
| V3 30 / Appendix E | Self-hosted MVP completion evidence | verified | Release/product gate #43 and operator gate #44 are complete; artifacts, limitations and cleanup are indexed |

## Checksummed evidence indexes

- `evidence/final-seal-dce714a-20260826/`
- `evidence/issue-43-exact-current-dce714a/`
- `evidence/live31-prompt-product-final-20260826/`
- `RishavT/anva-test#8` independent messy-corpus review record
- `RishavT/anva-test#19` v0.1.6 operator-drill record

## Fix-forward boundary

Current source is a post-v0.1.6 descendant. Its documentation and finalizer
corrections do not change the immutable release above. `v0.1.7` is the next
patch; it remains pending fresh source/tag identity, scans, risk decision,
approvals, artifacts, attestations, publication, and install verification.
