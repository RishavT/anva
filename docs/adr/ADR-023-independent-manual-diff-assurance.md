# ADR-023: Independent manual-diff assurance

## Context

Assurance must review an exact pull-request revision without trusting mutable provider state,
executing changed code, or allowing model prose to decide readiness. A review must remain
reconstructable after the pull request, policy, requirements, evidence, context, evaluator, or
prompt changes.

## Decision

An authorized operator supplies a bounded Git unified diff and exact PR metadata. Anva validates
full commits, normalized relative paths, hunk counts, size/count limits, secret patterns, and
unsupported binary/combined formats. It stores a content-addressed diff artifact plus immutable
classified chunks. It never fetches, applies, imports, or executes the diff.

Every assurance run is identified by a canonical hash covering the exact PR revision/diff,
work-revision hash, requirements hash, deterministic policy input/output, criterion/evidence
mappings, permission-safe context packet and retrieval versions, explicit reference time,
deterministic checks, parser/schema/evaluator/prompt versions, and limitations. A new PR revision
or exact input supersedes the prior current run while preserving its report and occurrences.

The evaluator boundary is provider-neutral and stateless. A leased claim returns only a sealed
request: hostile PR prose and chunks, exact requirements/policy/evidence/checks, authorized context,
explicit safety instructions, and version identities. Submit accepts only the closed result schema.
The server validates every diff coordinate, context-citation UUID, evidence UUID, criterion code,
commit, request, tenant, evaluator version, and prompt version before persisting it.

The run stores an immutable initiating actor and credential. Claim/submit require the separate
`assurance.review` action, and the initiator is ineligible to review its own run. Anva authorizes an
external reviewer against every immutable source boundary without expanding the sealed artifact
scope. A claim binds the task and append-only attempt to the authenticated actor and exact
repository credential; the caller-supplied claimant is only an audited display/provider label.
Submit and identical-result replay reject actor or credential switching, including a second token
for the same service identity. Revoked and expired credentials fail closed.

The evaluator emits observations, never readiness. Server precedence is:

1. stale exact input -> `STALE`;
2. engine failure -> `FAILED`;
3. deterministic failure, blocking policy/evidence gap, or supported blocking finding ->
   `BLOCKED`;
4. nonblocking concern or partial/limited evaluator coverage -> `READY_WITH_WARNINGS`;
5. otherwise -> `READY_FOR_HUMAN_REVIEW`.

An immutable Markdown/escaped-HTML report exposes readiness, blockers, review focus, exact versions,
and limitations. It says only that it supports focused human review and never grants merge or
deployment approval. Post-merge learning creates `KnowledgeProposal` records only; no proposal is
accepted or applied by this path.

## Consequences

Manual diff provenance remains an operator attestation, and changed code is not runtime-tested by
this engine. Deterministic CI/evidence must arrive through the exact existing evidence boundary.
Large or unsupported diffs fail closed rather than silently truncating. Re-evaluation stores
history and may increase database usage; production retention quotas remain future work.

## Security and privacy

PR/diff/evaluator text is hostile retained data. It is bounded and secret-scanned before
persistence, separated from evaluator instructions, never interpolated into shell commands, and
HTML-escaped. PostgreSQL composite tenant foreign keys and immutable update/delete triggers protect
all revision, chunk, occurrence, decision, evaluator-attempt, readiness, report, and proposal-link
history. Database triggers also prevent changes to the run initiator and a live task's claim
identity; each attempt snapshots the claim identity and is append-only.
