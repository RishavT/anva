# MVP-013 release checklist

This is a fail-closed checklist. Check an item only after linking evidence from
the exact release commit. A command in documentation is not execution evidence.
The [release-freeze contract](release-freeze-contract.md) fixes the remaining
scope, allowed exceptions, evidence, and retest rules.
The [evidence index](../evidence/issue-013/README.md) records checksummed local
candidate tests, exact read-only corpus ingestion, scans, backup/restore, and
migration rehearsal at source commit `94231d7e...`. Checked items below mean
that exact local evidence exists; they do not imply publication. Registry/tag/
signature, external baseline, fixed 31-case replay, representative independent
manual review, and human acceptance gates remain open. This work does not add,
enable, or change a
GitHub Actions workflow.

Checked local results bind to source commit
`94231d7e57767b18a4cd9546ad5bf33afc13a735`, tree
`43395db015a2205c739647c1b6dfb9b02626abd2`, runtime image
`anva-mvp13:0.1.0` ID
`sha256:c6ae3a8abfd4c54d91df94be0dfe7f1bc1c52e73da58a4617b2bc30a3b1f6f2c`,
and evidence archive SHA-256
`d90916f8063911757a05f8e0b16e25e5a64063609046a04e44aea9065d6dbeb8`.

## Identity and artifacts

- [ ] Release version has one authoritative source; the local manifest records
  `0.1.0`, but publication must designate and verify the authoritative version
  source.
- [ ] Signed or otherwise provenance-attested release tag and exact commit are
  recorded and independently verified.
- [ ] Runtime image is published by version and commit and its registry digest
  is recorded.
- [x] Worktree has no tracked or untracked changes, and the runtime image OCI
  revision exactly equals the clean candidate commit.
- [x] Runtime base images and Compose dependencies are pinned by digest.
- [x] Python wheel and Codex/Claude skill archives are rebuilt and verified in
  the release environment rather than copied from stale source artifacts.
- [x] `SHA256SUMS` covers every downloadable artifact and the release manifest.
- [x] CycloneDX and SPDX SBOMs cover the local runtime image and its installed
  Python/OS package inventory.
- [x] Checksums verify from the clean local candidate environment.

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

- [x] Zero-to-head migration passes on a clean database.
- [x] Forward migration from the recorded pre-MVP-013 `core.0019` schema passes
  in the guarded disposable clone.
- [ ] Previous-application rollback on the upgraded schema or backup-based
  rollback is rehearsed and documented.
- [x] PostgreSQL and object-storage backup writes a unique generation,
  verifies it, and atomically changes `current` without overwriting the last
  valid generation on failure.
- [ ] Backup restores into a distinct clean Compose project.
- [x] Backup stops/resumes only writers that were running, and an injected
  restore failure leaves those writers stopped for operator recovery.
- [x] Migration reversal/forward runs only on a guarded disposable restored
  database clone and proves that the live database was never reversed.
- [ ] Restored tenant, audit, provenance, artifact, and object identities match
  the backup manifest.

## Security and privacy

- [ ] Product threat model is reviewed.
- [ ] Cross-tenant API/search/Canvas/MCP/artifact matrix passes.
- [ ] Source and credential revocation matrix passes.
- [ ] TST-007 artifact-security cases pass through Anva on the exact release
  commit, not only through the fixture validator. The issue 29 local candidate
  passes all six pinned byte classes, but freeze, independent review, merge, and
  release indexing remain open.
- [ ] The separate five-source prompt-injection corpus passes through the
  product boundary with zero mutation or leakage; TST-007 artifact evidence
  does not satisfy this gate.
- [ ] Log, trace, metric, report, package and image secret-canary scans report
  zero leakage.
- [x] Source vulnerability, secret, and misconfiguration scans exclude only the
  documented operator-owned paths and pass their high/critical gate.
- [x] Every image high/critical finding is fixed or appears in the reviewed,
  unexpired exception file; all 14 current no-fix exceptions are re-reviewed no
  later than 2026-08-18.
- [ ] Dependency, container, license and repository scans pass under the
  documented severity policy.
- [x] Retention behavior, decommission behavior, retained data, and unsupported
  erasure claims are documented exactly.
- [x] Retention rejects caller time, requires explicit expiry and organization
  minimum, and never purges another tenant's rate buckets; decommission requires
  a <=15-minute human session, CSRF, and both exact confirmations while bearer
  and CLI attempts fail closed.

## Operations

- [x] Liveness remains dependency-free.
- [x] Readiness proves database access, migration currency, and authenticated
  access to the configured object-storage bucket.
- [ ] Rate-limit behavior and stable `429`/`Retry-After` contracts pass under
  concurrent processes.
- [x] Structured logs carry correlation and trace identifiers without content
  or credentials.
- [ ] Metrics scrape, aggregation, dashboards and alert rules are verified.
- [ ] Empty/missing metrics token fails closed, the valid-token scrape uses
  HTTPS, and forwarded client/protocol headers are honored only from exact
  trusted proxy IPs.
- [x] Application access logs remain disabled while structured request logs and
  server errors are retained under bounded logging.
- [ ] Incident, permission-leak, credential-rotation, restore, retention and
  decommission runbooks have named evidence and escalation owners.

## Test and evaluation

- [x] Formatting, lint, typing, migration drift, generated contracts, skill
  packaging, coverage and browser stages pass.
- [x] Unit, integration, contract, security, retrieval, assurance, skill,
  corpus and real MCP Compose stages pass with zero unexpected skips.
- [ ] Exact `anva-test` commit is pinned and its own non-browser and browser
  baselines pass.
- [ ] All 31 committed public `anva-test` cases import and replay through Anva
  with complete inventory, stable bindings, deterministic public results, and
  a clean-reader verification. This breadth gate does not require 31 separate
  human or native-agent review sessions.
- [ ] One representative context-free manual assurance review runs from sealed
  public inputs against the messy knowledge corpus on the exact release commit,
  using an independent reviewer identity with no private oracle/grader access.

## Completion record

- [x] Checksummed per-lane result logs and structured summaries are stored
  without credentials; this does not claim that every command invocation was
  recorded.
- [x] Screenshots, browser-performance and coverage results, scan reports,
  SBOMs, restore report, migration report and evaluation results are indexed.
- [x] V3 requirements map to evidence or an explicit deferred/not-applicable
  decision.
- [ ] Known limitations and residual risks are recorded, including lower source
  findings and the 2026-08-18 image-exception expiry; named release review is
  still required.
- [x] The evidenced `mvp13-runtime-final`,
  `mvp13-runtime-final-rehearsal`, and `mvp13-release` scan/manifest projects
  have zero scoped one-shots, networks, and volumes; browser/scanner resources
  were removed and the named builder cache was zero. Required local
  candidate/runtime artifacts were retained and the measured task footprint is
  recorded against the 5 GB working limit. This does not claim removal of
  legacy development/runtime support or MinIO client resources.
- [ ] MVP-013 self-review contains no unverified completion claim.

## Documentation descendant

All checked product/runtime boxes bind to source parent `94231d7e...`, tree
`43395db...`, and runtime image ID `c6ae3a8a...`. A docs-only descendant may
record these results without invalidating them, but it is not itself the tested
runtime commit. Any non-documentation change requires a new candidate and
reverification.
