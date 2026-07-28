# ADR-022: Deterministic intent, policy, and evidence

## Context

Assurance cannot be replayed if work intent, policy selection, exception authority, or evidence
floats to a current mutable value. A lower-scope policy must not silently replace an
organization control, and prose must not be promoted to evidence.

## Decision

Work items and policies are stable mutable pointers to append-only, content-hashed revisions.
Requirements, exclusions, assumptions, criteria, decisions, approvals, summaries, policy
bindings, controls, evaluations, overrides, manifests, evidence, retention events, and criterion
mappings are version-bound history. PostgreSQL composite foreign keys enforce tenant ownership;
critical history has update/delete rejection triggers.

Policy evaluation accepts exact policy-version IDs and an explicit timezone-aware reference time.
Its canonical input includes the engine version, tenant/repository/PR/full commit, exact work
revision/hash, exact policy/binding/hash tuples, active override IDs, normalized POSIX paths,
entities, target branch, and simulation mode. The canonical output excludes generated IDs and
timestamps.

Binding dimensions are ANDed; alternatives within a dimension are ORed. `*` and `?` never cross
`/`; `**` may. All matching controls accumulate from organization through product/system,
repository, and path. Blocking wins over advisory. Policy syntax cannot remove a control. Only a
separately authorized immutable override can suppress its exact source control, and it is pinned
to the policy version, repository, PR, full commit, actor authority path, reason, and optional
expiry.

Evidence ingestion accepts a closed, bounded manifest only. It stores the validated manifest as
an immutable artifact and materializes immutable metadata records. It never fetches a URL, opens
an artifact path, unpacks data, imports code, or executes the submitted command. Criterion mapping
uses only passed, retained evidence for the exact work revision, PR, commit, evidence type, and
reference time; otherwise it emits an explicit gap. Mapping rows persist their engine version and
canonical input hash. Approval-required requirements force manual-approval evidence on every
linked criterion. A `WorkSummary` is context and can never satisfy a criterion.

## Alternatives considered

- Mutable requirements or policies: rejected because historical replay becomes ambiguous.
- Most-specific-policy-wins: rejected because it lets a narrow scope silently weaken mandatory
  controls.
- Implicit current time/current policy lookup: rejected because identical caller input can produce
  different results.
- Fetching or executing referenced evidence: rejected for this slice because it crosses a new
  hostile artifact boundary.

## Consequences

Callers must normalize intent, provide exact versions, full commits, and explicit reference time.
New work/policy revisions require new approvals and evaluations. Outputs are more verbose because
they retain match and source explanations.

## Security impact

Central authorization precedes governed lookup/idempotency. Simulations and evidence mapping
require assurance-execution authority in addition to read access; overrides require the exact
evaluation scope. Inputs are size/schema/path/secret checked. Overrides cannot float across
version, repository, PR, commit, or expiry. Composite tenant constraints and immutable triggers
provide database defense in depth.

## Privacy impact

Manifest metadata, commands, URLs, limitations, and approval reasons are retained as governed
history. Secret-bearing fields or values are rejected rather than redacted into persistence.
Artifact bytes are not collected by this slice.

## Operational impact

Operators use repository bearer tokens through `ANVA_TOKEN`, regenerate contracts after catalog
changes, and treat evidence retention changes as append-only events. Storage growth is bounded by
manifest limits but production quotas and deletion workflows remain follow-up work.
The repository still uses one pre-beta `1.0` schema-version constant across contracts; independent
per-contract version negotiation must be introduced before any contract has external stability.

## Revisit conditions

Revisit when PullRequestRecord/diff history, product/team/entity-scoped approval authority,
signed evidence uploads, binary verification, cross-scope intersection materialization, or
cross-commit evidence reuse is implemented.
