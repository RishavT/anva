# Developer skills threat model

## Scope and assets

This covers canonical workflow sources, generated Codex and Claude adapters,
plugin archives, checksums, installation, MCP configuration handoff,
diagnostics, host traces, and local preflight. Protected assets are repository
scope, organizational knowledge, normalized provenance, credentials, proposal
authority, local source/diffs, and user intent.

## Trust boundaries

- Skill prompts, tasks, repository files, source excerpts, host-qualified tool
  names, network errors, and existing destination files are untrusted.
- The existing authenticated Anva MCP facade is the only knowledge/proposal
  authority.
- Plugin archives are inert instructions and references, not executable hooks.
- Host approval and Anva proposal review are separate required controls.
- Server-side PR assurance is independent of local preflight.

## Threats and controls

### Cross-host semantic drift

One schema-validated source renders both adapters. Contract tests normalize
allowlisted host metadata and require equality. Each adapter has separate
activation and package tests.

### Credential or customer-data packaging

Archives exclude MCP configuration, hooks, scripts, binaries, `.env`, Node
metadata, customer fixtures, and authorization values. Configuration stores
only environment-variable names. Diagnostics report token presence, never its
value. Tests scan source packages, archives, output, and error paths with
canaries.

### Prompt injection and retrieval widening

Skills label source excerpts inert and prohibit treating their text as tool
arguments, permissions, or instructions. Canonical tool allowlists and exact
repository/task/phase arguments prevent alternate API, ORM, hidden-source, or
unrelated-system discovery. Adversarial fixtures include scope expansion,
unauthorized/revoked sources, and malicious tool/write/secret requests.

### Unsupported claims and provenance laundering

Material claims require normalized source URL, locator, content hash, and
observation time from context packets. Internal policy, requirement, entity,
assertion, or work-item identifiers are not accepted as provenance. Missing or
revoked provenance becomes a visible limitation. Facts, requirements,
assumptions, conflicts, and limitations remain separate.

### Proposal escalation or replay

Only canonical proposal tools may write. Skills preview exact content and
sources, require explicit user intent and host approval, reuse the same
deterministic idempotency key only for an identical retry, and report
`PROPOSED`, `approved: false`, and `review_required: true`. Read-only or
declined approval yields `NOT_SUBMITTED`.

### False readiness

Preflight binds local evidence to the exact diff and commit, reports failed,
missing, skipped, and unavailable checks, and never claims authoritative
assurance or deployment safety. `READY`, `PASSED ASSURANCE`, and
`SAFE_TO_DEPLOY` wording is forbidden in evals.

### Tampered installation or archive traversal

The installer anchors traversal, copy, digest, cleanup, and final handoff to
open directory descriptors. It rejects traversal, every existing symlink or
non-directory ancestor (including derived host paths), unknown partial state,
and links or special files inside a skill. Unpredictable private stages use an
atomic no-clobber handoff; configuration uses an exclusive hard-link handoff.
Race winners are preserved, and interruption rolls back only trees created by
the current invocation.
Archive verification checks checksums, absolute/traversal paths, links, and
file-only members. Rebuilds must be byte-identical.

### Unavailable, revoked, or incompatible Anva

Diagnostics call only `/diagnostics`, validate MCP contract, protocol list,
host version, and read-only expectation, and return bounded safe failures.
Skills never fall back to direct HTTP or database access. Prepare/build require
user consent for limited local-only work; preflight remains `UNVERIFIED`;
learn creates nothing.

### CI or evaluation secret exposure

Deterministic fake-MCP fixtures and package checks need no live credentials.
The normal workflow retains `contents: read` and has no model/customer/token
secret path. Trusted host evaluation creates paired fresh read-only workspaces
from one packaged skill, the raw task, a synthetic MCP transcript, and bundled
generation and validation schemas. Codex denies agent reads outside its
workspace; Claude has no model tools. The environment is allowlisted,
model-command network is disabled, and ambient MCP configuration is excluded.
Before either host runs, an immutable hash-only commitment binds both prepared
artifacts, exact host versions, and the separately held oracle and grader.
Evaluator contents and prior outputs cannot enter `prepare`, `commit`, or
`run`; `grade` cannot read them until both hosts have sealed output or explicit
`NOT_RUN` records. Grade records hash typed rules and redact rejected values.
Unavailable native authentication is `NOT_RUN`, never provider evidence.

## Residual risks

- Current bearer handoff is less ergonomic than OAuth; OAuth is not implemented
  or claimed.
- Provider skill/plugin behavior can change after tested host versions.
- Text quality still requires periodic blind host evaluation in addition to
  deterministic contract grading.
- A user can deliberately bypass a skill or approve a risky host action;
  server authorization and proposal review remain authoritative.

## Verification

- Unit: install replay/tamper/interruption/symlinks, MCP handoffs, unavailable
  and unsupported diagnostics, race-winner preservation, response resource
  bounds, paired precommit isolation/tamper detection, contextual hard/scored
  evaluator rules, and secret-value non-disclosure.
- Contract: canonical tools/schemas, cross-host normalization, plugin hygiene,
  reproducible safe archives.
- Integration: both host traces use the same actor/task and exact authorized
  context packet through `dispatch_tool`.
- Eval: messy knowledge, conflicts, missing owner/budget, security policy,
  migration/browser evidence, injection, scope expansion, revocation,
  unreachable/read-only states, advisory wording, and proposal idempotency.
