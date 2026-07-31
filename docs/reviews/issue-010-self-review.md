# Issue 010 self-review

## Scope

MVP-010 host-neutral prepare/build/preflight/learn contracts, generated Codex
and Claude repository/plugin distributions, shared output schemas, Python
install/configure/diagnose/package commands, deterministic checksums,
host-specific evals, security/operations documentation, and current provider
format validation.

## Architecture and host neutrality

- One schema-validated portable source renders both host adapters.
- Normalization permits only documented host metadata/tool presentation.
- Workflow domain calls use the existing canonical MCP `dispatch_tool`
  boundary; diagnostics GET is the only non-domain HTTP call.
- No proprietary coding harness, agent runtime, direct API fallback, ORM path,
  hook, binary, or Node dependency was added.
- MCP registration is separate from immutable archives, so packages contain no
  customer endpoint or credential.

## Security and privacy

- Every material claim requires normalized URL/locator/hash/time provenance;
  missing provenance is a limitation, never an internal UUID citation.
- Normalized sources are the exact minimal closure of retained material
  references. Ignored hostile, injection-marked, and unrelated items contribute
  no source identity or payload and are described only generically.
- Facts, requirements, assumptions, conflicts, and limitations are visibly
  separate.
- Source text is inert and cannot widen scope, request secrets, select tools,
  or approve writes.
- Proposal workflows require exact preview, explicit intent, host approval,
  stable retry identity, and remain review-only `PROPOSED`.
- Preflight forbids authoritative assurance/deployment language.
- Installer operations are staged, replay-safe, non-overwriting, symlink/path
  safe, and rollback task-created output after interruption.
- Diagnostics and configuration expose environment names/presence only.
- Archives are deterministic, checksummed, file-only, and scanned for
  secrets, customer facts, hooks, executables, and Node metadata.

## Verification evidence

- Required `skill-creator` guidance and `openai_yaml` reference were read
  before design; all eight initial host skill scaffolds used `init_skill.py`.
- Deterministic fixture tests validate package semantics, safety boundaries,
  and the same strict structured-output schemas used by the live gate. These
  authored fixtures are package-native validation, not independent host or
  model evidence.
- Real-facade host parity integration validates the canonical MCP boundary. It
  does not show that a coding-agent host independently followed a skill.
- The reproducible trusted gate in
  [the live evaluation runbook](../runbooks/trusted-skill-evaluation.md)
  physically excludes evaluator contents, prior outputs, worktree, and ambient
  MCP configuration. Its v2 precommit flow binds both host artifacts, exact
  version targets, and oracle/grader hashes before either host runs, then
  withholds grading until both runs are terminal. V3 grading preserves exact
  raw bytes while sealing content-free channel/event attribution, distinguishes
  input reflection from agent emission, and records quality separately from
  hard gate status.
- A live Codex or Claude result is release evidence only with its complete
  immutable session and passing `grade-record.json`. Failed and `NOT_RUN`
  records remain preserved under their accurate evidence classes. Fresh-agent
  evaluations are labeled with their actual host and are never relabeled.
- All eight repo/plugin Codex skills passed the official `quick_validate.py`
  helper. Claude's plugin and repository marketplace each passed
  `claude plugin validate --strict`.
- Fresh isolated install/config regression tests pass for Codex and Claude,
  including ancestor/final symlinks, non-directories, unknown partial state,
  interruption, and concurrent race winners. No hook or executable is
  introduced by either package.
- Deterministic render/package checking reported no drift, and both committed
  archives passed checksum and member-safety verification.
- The full rebuilt-image Compose gate passed 591 tests with 2 expected skips
  and 85% branch coverage. The live official MCP client Compose smoke passed
  both contract/auth/read-only/revocation/HTTP-parity and safe-unavailable
  scenarios. Strict real `/diagnostics` checks passed against both the
  write-capable and read-only MCP services.
- Trusted native-model evidence, hosted exact-head CI, and final task-resource
  cleanup remain required release gates and are recorded only after they
  actually run.

## Current official documentation

Provider packaging/MCP behavior was revalidated on 2026-07-30. Exact official
references and tested host versions are recorded in
[ADR-026](../adr/ADR-026-host-neutral-developer-skills.md). Tested versions are
evidence, not invented support minimums.

## Limitations

- OAuth handoff is not implemented; current credentials are exact-repository
  bearer tokens inherited from MVP-009.
- Live provider/model evaluations remain an explicit trusted release gate;
  deterministic CI uses synthetic, secret-free fixtures.
- Skills guide workflow but cannot force a developer to invoke them or prevent
  deliberate host approval; server authorization and human proposal review
  remain authoritative.
- Repository profile command/owner discovery remains limited to currently
  modeled MCP fields.

## Conclusion

MVP-010 preserves Anva's knowledge/assurance boundary while giving both
supported coding hosts equivalent, installable, provenance-first workflows and
safe degraded behavior.
