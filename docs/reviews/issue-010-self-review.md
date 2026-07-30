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
- Focused package/install/eval tests: 35 passed.
- Real-facade host parity integration: 1 passed; both traces returned the same
  context packet identity and semantics for the same actor/task.
- Blind forward preparation was run independently from only the public task,
  transcript, and one host adapter. Codex and Claude each scored 14/14 against
  the hidden semantic oracle and each structured payload validated against
  `prepare.schema.json`. Both preserved all four exact provenance tuples,
  rejected the hostile scope/secret/proposal instruction, kept the current
  versus stale decision conflict blocking, left owners and budgets unknown,
  labeled task-only migration/browser scope unverified, stopped before
  implementation, and disclaimed authoritative assurance.
- Codex returned structured JSON while Claude returned a human-readable view
  plus matching structured JSON. This presentation difference is allowlisted;
  required semantics and the portable schema are host-neutral.
- The post-run evidence hashes were
  `e1160fa2c9f546a38429db60af39a46274fc7eba629fdb903d9325f7af3fd81a`
  (Codex JSON) and
  `9b821d75359e0948ec66c9fa31af073fd61f8cef2cf1aa972d7bf445264e0a27`
  (Claude response). Raw grading outputs were removed before commit.
- All eight repo/plugin Codex skills passed the official `quick_validate.py`
  helper. Claude's plugin and repository marketplace each passed
  `claude plugin validate --strict`.
- Fresh isolated native installs passed with Codex CLI `0.145.0` and Claude
  Code `2.1.220`; no MCP configuration, hook, or executable was introduced by
  either plugin install.
- Deterministic render/package checking reported no drift, and both committed
  archives passed checksum and member-safety verification.
- The full rebuilt-image Compose gate passed 490 tests with 2 expected skips
  and 85% branch coverage. The live official MCP client Compose smoke passed
  both contract/auth/read-only/revocation/HTTP-parity and safe-unavailable
  scenarios.
- Hosted exact-SHA CI and final storage cleanup are recorded in the PR
  evidence.

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
