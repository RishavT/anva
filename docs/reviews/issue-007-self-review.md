# Issue #7 self-review: Independent manual-diff assurance

## Scope and acceptance evidence

| Requirement | Implementation | Verification |
| --- | --- | --- |
| Exact PR revisions and immutable diffs | Current PR pointer, immutable metadata revisions, content-addressed raw diff, classified immutable chunks | Replay/new-head integration and DB immutability |
| Safe nonexecuting ingestion | Strict bounded unified parser, path/hunk/binary/secret checks; no fetch/apply/import/subprocess | Hostile parser suite |
| Debounced/stale assurance history | Canonical all-input hash, duplicate replay, state transitions, new revision staleness, attempt history | Lifecycle integration tests |
| Deterministic policy/context/evidence | Reuses exact production policy evaluation, ASSURANCE context packet, criterion mappings; stores every hash/version/limitation | Run and evaluator request assertions |
| Provider-neutral evaluator | `Evaluator` protocol, all v3 fake scenarios, leased claim/submit queue for a fresh context-limited reviewer | Unit/eval and PostgreSQL queue tests |
| Valid structured findings | Closed schema, confidence/uncertainty, exact diff or authorized-source citations, evidence/criterion allowlists, stable semantic fingerprint and occurrences | Contract, citation, fingerprint tests |
| Server-only readiness | Fixed precedence; evaluator result has no readiness/outcome; deterministic failure remains blocked | Contract and failure-wins integration test |
| Concise deterministic reports | Contract-bounded Markdown and escaped HTML, compact index of every finding, budgeted optional detail, exact versions/limitations, no deployment grant | Goldens, injection, maximum-shape unit and PostgreSQL tests |
| Post-merge proposal safety | Exact completed merged revision and authorized citations required; only `KnowledgeProposal` links created | Safety integration case |
| API/CLI/docs/generated artifacts | Versioned routes, bounded non-symlink CLI, JSON schemas/examples/OpenAPI/MCP, ADR/runbook/threat model | Contract drift and CLI tests |

## Self-review findings fixed

1. The previous run uniqueness used only repository/PR/head and would suppress same-head
   re-evaluation after policy/context/evidence/prompt changes. Identity now includes the complete
   exact canonical input.
2. The old evaluator result let the model emit `READY|NOT_READY|UNKNOWN`. That field was removed;
   the server alone computes readiness.
3. The first queue query locked outer-joined nullable relations, which PostgreSQL rejects. Locking
   is now restricted to the task row and nullable relations are loaded separately.
4. Initial staleness considered only a new head. Any new PR metadata revision—including same-head
   merge state—now stales the prior current result.
5. Inherent transparency limitations initially forced every otherwise-clean run into warnings.
   They remain visible in the report, while warnings are reserved for actual nonblocking concerns
   or incomplete evaluator coverage.
6. Model prose could carry HTML or deployment-claim language into the report. Rendering now escapes
   all untrusted fields and removes prohibited deployment claims.
7. The first evaluator envelope reused the broader diff scope even though it contained a
   principal-sealed context packet. Evaluator requests, results, and reports now use an actor-only
   scope derived from every exact input scope; claim, submit, read, and post-merge paths reauthorize
   that scope and fail after contributing-source revocation.
8. Citation and readiness validation initially queried every evidence mapping for the same
   PR/head/work revision. They now reconstruct only the mapping IDs sealed into the evaluator
   request and verify their payload, bundle hash, commit, PR, work revision, and reference time.
9. Deterministic-check evidence IDs initially received UUID syntax validation only. Every ID now
   resolves to retained, exact repository/PR/head/work/reference-time evidence under an authorized
   scope before the run is created.
10. A repeated evaluator observation could reopen a human-dismissed or risk-accepted finding.
    Re-observation now records a new occurrence while preserving human lifecycle decisions; only
    open findings affect a later readiness calculation.
11. Diff parsing initially trusted only the `diff --git` path pair. It now also requires matching
    `---`/`+++` headers and validates the only supported `/dev/null` add/delete forms.
12. Review also found incomplete standalone criteria, narrow finding fingerprints, and open
    post-merge change bodies. Criteria are complete, fingerprints include exact semantic citation
    anchors with collision rejection, and finding/post-merge inputs use closed canonical schemas.
13. A deletion could advertise an unrelated destination in `diff --git`, causing its source path,
    classification, and citations to be misattributed. File identity is now coherent across Git
    paths, unified headers, add/delete modes, rename metadata, and `/dev/null`; unsafe Windows,
    UNC, backslash, and traversal paths fail before classification.
14. Blocking findings were summarized only in Markdown and could be followed by a misleading
    no-concerns review section; reports also omitted their actionable detail. Markdown and escaped
    HTML now render every blocker and nonblocking review area deterministically with location,
    detail, uncertainty, suggested resolution, and fingerprint. Semantic merge/deploy safety claims
    are neutralized in every rendered untrusted field while legitimate review context remains.
15. Runs without a work item silently appeared to have clean requirement coverage. They now persist
    a deterministic requirement-traceability limitation, emit
    `REQUIREMENT_TRACEABILITY_NOT_ESTABLISHED`, and are at least `READY_WITH_WARNINGS` unless a
    stronger blocker applies. The mandatory limitation survives bounded evaluator output, and exact
    replay preserves report bytes and hashes.
16. Rendering every finding with all optional prose could exceed the assurance-report contract and
    roll back an otherwise-valid submission. Reports now index every finding with stable identity,
    severity, lifecycle, bounded title/location, and full fingerprint. Blockers receive first access
    to explicit per-field and aggregate optional-detail budgets; deterministic markers, counts, and
    a persisted limitation describe compaction. Limitation and reason display are separately
    bounded, while their stored exact values remain subject to the existing payload cap.

## Limitations

The diff is manually attested rather than fetched and signature-verified. Assurance does not run
code or independently verify CI artifact bytes; it consumes exact deterministic checks and existing
evidence metadata. Large/binary/combined/quoted-path diffs fail closed. There is no hosted evaluator
provider, webhook adapter, GitHub check publisher, reviewer-identity federation, UI, automatic
knowledge acceptance, retention quota, or proof of runtime/deployment safety in this slice.
The manual evaluator queue currently requires the claiming principal to be inside the run's sealed
input envelope; delegated evaluator identities need an explicit future federation design.

## Verification

The original isolated Docker/Compose gate passed 98 focused unit/contract/CLI/HTTP tests, seven
assurance lifecycle integrations, three legacy authorization/state regressions, Ruff, strict mypy
across eleven touched source files, deterministic validation of 22 generated contract artifacts,
and no migration drift. Its full repository gate passed 300 tests with one intentionally skipped
unmounted corpus and 86% combined branch coverage. Its production-mode smoke applied migration
`0011`; API, MCP, worker, PostgreSQL, and object storage became healthy; both readiness endpoints
reported database and object storage available.

The request-changes remediation first reproduced all three blockers in disposable Docker containers
against reviewed head `4337f0a`. The final focused Docker gate passed 93 unit regressions, the
PostgreSQL exact-replay/report lifecycle, Ruff, canonical formatting, and strict mypy for both
changed services. The remediation adds no contract or migration surface. Per review coordination,
the exact-head hosted full CI is the final broad gate; the local full and production suites were not
redundantly rerun.

The report-boundary remediation reproduced a 50-finding contract rejection at reviewed head
`9d6452a`: Markdown was 374,397 characters and HTML was 379,572 characters, and PostgreSQL proved
the failed completion rolled back every new artifact, finding, occurrence, readiness decision,
report, and submitted attempt. The final 500-finding maximum-field rendering is 101,389 Markdown
characters and 126,302 HTML characters. Its focused Docker gate passed 94 unit regressions and one
PostgreSQL maximum-shape completion/replay lifecycle, plus Ruff, canonical formatting, and strict
mypy for the changed service. The local full and production suites remain intentionally delegated
to exact-head hosted CI.
