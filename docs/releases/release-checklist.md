# MVP-013 release checklist

This is a fail-closed checklist. Check an item only after linking evidence from
the exact release commit. A command in documentation is not execution evidence.
The [evidence index](../evidence/issue-013/README.md) records successful
shared-worktree tests, scans, backup/restore, and migration rehearsal, but those
results intentionally do not check an exact-commit release box. Publication,
external corpus/fresh-agent, and human acceptance gates remain open. This work
does not add, enable, or change a GitHub Actions workflow.

## Identity and artifacts

- [ ] Release version has one authoritative source.
- [ ] Signed or otherwise provenance-attested release tag and exact commit are
  recorded and independently verified.
- [ ] Runtime image is published by version and commit and its registry digest
  is recorded.
- [ ] Worktree has no tracked or untracked changes, and the runtime image OCI
  revision exactly equals the clean candidate commit.
- [ ] Runtime base images and Compose dependencies are pinned by digest.
- [ ] Python wheel and Codex/Claude skill archives are rebuilt and verified in
  the release environment rather than copied from stale source artifacts.
- [ ] `SHA256SUMS` covers every downloadable artifact and the release manifest.
- [ ] CycloneDX or SPDX SBOMs cover the runtime image and Python/package inputs.
- [ ] Checksums verify from a clean environment.

## Install and lifecycle

- [ ] Production configuration records `ANVA_ENV=production`,
  `ANVA_DEBUG=false`, exact hosts/URLs, out-of-band unique secrets, a metrics
  token, TLS termination, exact trusted-proxy IPs, and reviewed resolved Compose
  configuration.
- [ ] Fresh-clone published-image Compose install passes without host Python,
  Node.js, npm, or Go.
- [ ] One-command synthetic demo/bootstrap passes and is idempotent or fails
  safely on replay.
- [ ] Demo token is observed only in the attached terminal; its `run --rm`
  container, Docker logs, redirected output, and operator transcript retain no
  token.
- [ ] Preserve-data uninstall is verified.
- [ ] Clean-data uninstall names and removes only the intended Compose volumes.
- [ ] Skill and MCP uninstall procedures refuse to overwrite or remove modified
  user content.

## Database and storage

- [ ] Zero-to-head migration passes on a clean database.
- [ ] Upgrade from the recorded pre-MVP-013 schema passes.
- [ ] Previous-application rollback on the upgraded schema or backup-based
  rollback is rehearsed and documented.
- [ ] PostgreSQL and object-storage backup writes a unique generation,
  verifies it, and atomically changes `current` without overwriting the last
  valid generation on failure.
- [ ] Backup restores into a distinct clean Compose project.
- [ ] Backup stops/resumes only writers that were running, and an injected
  restore failure leaves those writers stopped for operator recovery.
- [ ] Migration reversal/forward runs only on a guarded disposable restored
  database clone and proves that the live database was never reversed.
- [ ] Restored tenant, audit, provenance, artifact, and object identities match
  the backup manifest.

## Security and privacy

- [ ] Product threat model is reviewed.
- [ ] Cross-tenant API/search/Canvas/MCP/artifact matrix passes.
- [ ] Source and credential revocation matrix passes.
- [ ] TST-007 prompt-injection and artifact-security cases pass through Anva,
  not only through the fixture validator.
- [ ] Log, trace, metric, report, package and image secret-canary scans report
  zero leakage.
- [ ] Source vulnerability, secret, and misconfiguration scans exclude only the
  documented operator-owned paths and pass their high/critical gate.
- [ ] Every image high/critical finding is fixed or appears in the reviewed,
  unexpired exception file; all 14 current no-fix exceptions are re-reviewed no
  later than 2026-08-18.
- [ ] Dependency, container, license and repository scans pass under the
  documented severity policy.
- [ ] Retention behavior, decommission behavior, retained data, and unsupported
  erasure claims are documented exactly.
- [ ] Retention rejects caller time, requires explicit expiry and organization
  minimum, and never purges another tenant's rate buckets; decommission requires
  a <=15-minute human session, CSRF, and both exact confirmations while bearer
  and CLI attempts fail closed.

## Operations

- [ ] Liveness remains dependency-free.
- [ ] Readiness proves database access, migration currency, and authenticated
  access to the configured object-storage bucket.
- [ ] Rate-limit behavior and stable `429`/`Retry-After` contracts pass under
  concurrent processes.
- [ ] Structured logs carry correlation and trace identifiers without content
  or credentials.
- [ ] Metrics scrape, aggregation, dashboards and alert rules are verified.
- [ ] Empty/missing metrics token fails closed, the valid-token scrape uses
  HTTPS, and forwarded client/protocol headers are honored only from exact
  trusted proxy IPs.
- [ ] Application access logs remain disabled while structured request logs and
  server errors are retained under bounded logging.
- [ ] Incident, permission-leak, credential-rotation, restore, retention and
  decommission runbooks have named evidence and escalation owners.

## Test and evaluation

- [ ] Formatting, lint, typing, migration drift, generated contracts, skill
  packaging, coverage and browser stages pass.
- [ ] Unit, integration, contract, security, retrieval, assurance, skill,
  corpus and real MCP Compose stages pass with zero unexpected skips.
- [ ] Exact `anva-test` commit is pinned and its own non-browser and browser
  baselines pass.
- [ ] All 31 committed `anva-test` assurance scenarios match their isolated
  oracles when exercised through Anva.
- [ ] Declared fresh Codex and Claude cases pass from sealed inputs on the exact
  release commit with no hard failure.

## Completion record

- [ ] Full command/result log is stored without credentials.
- [ ] Screenshots, metrics, trace samples, scan reports, SBOMs, restore report,
  migration report and evaluation results are indexed.
- [ ] V3 requirements map to evidence or an explicit deferred/not-applicable
  decision.
- [ ] Known limitations and residual risks are reviewed.
- [ ] Every temporary Compose project, exact Anva image, and task-owned cache is
  removed without engine-wide pruning or touching unrelated Docker resources;
  measured task footprint is recorded against the 5 GB working limit.
- [ ] MVP-013 self-review contains no unverified completion claim.
