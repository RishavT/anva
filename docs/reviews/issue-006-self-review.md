# Issue #6 self-review: Deterministic intent, policy, and evidence

## Scope

This slice implements versioned work intent, deterministic additive policy calculation,
authority-pinned overrides, immutable manifest-only evidence ingestion, and criterion
evidence/gaps through model, migration, service, API, CLI, contract, and documentation layers.

## Acceptance-to-evidence matrix

| Acceptance requirement | Implementation evidence | Verification |
| --- | --- | --- |
| Same versioned inputs produce same outputs | Canonical input/output hashes, exact version IDs, explicit reference time, engine version, stable sorting | Repeat evaluation returns the same row and hashes |
| Stale/wrong commit/prose cannot satisfy | Exact manifest/evidence/mapping commit and work revision; `WorkSummary` is a separate context model | Summary-only and different-commit mappings are gaps |
| Lower scope cannot silently weaken | All matching controls accumulate; policy syntax has no removal operation; an override suppresses only its exact source control | Lower advisory cannot reduce blocking; exact override and revocation are tested |
| Every criterion has evidence or gap | Mapping emits a replayable row for every required evidence type and enforces approval-required criteria | Exact multi-type evidence satisfies; missing/stale/revoked emits named gap |
| Hostile manifests fail safely | Closed 64 KiB contract, bounded fields/counts/depth, POSIX path and HTTPS URL checks, recursive secret rejection | Unit/contract security cases |
| Authorization, revocation, audit | Dedicated actions/roles, execution authority for history-producing calculations, scope/repository checks, exact override/approval authority, audit/outbox in mutation transaction | Role matrix, denied mutation, revocation, and integration suites |
| Immutable tenant-safe history | Composite tenant FKs, current-pointer checks, semantic binding triggers, update/delete rejection | Forced graft and update tests |
| API/CLI/contracts/docs | Work/policy/evidence routes and commands, generated schema/OpenAPI/examples, ADR/runbook/threat model | Contract drift and CLI tests |

## Self-review findings fixed

1. The initial evaluation design could have selected implicit current policy/time. Exact policy
   version IDs and explicit `reference_time` are now mandatory canonical inputs.
2. Initial evidence retention was a mutable field. It is now append-only retention history.
3. Initial statement normalization sorted authored requirements. Position is now preserved and
   constrained within every work revision.
4. Evidence metadata initially lacked an immutable copy of the submitted manifest. It now reuses
   the content-hashed immutable artifact boundary.
5. The first migration command resolved the image `/app` copy and could not write the mounted
   workspace. It was rerun explicitly against `/workspace/src`; no partial file remained.
6. Review found that read-only policy/evidence actions could create immutable calculations.
   Simulations and mappings now also require scoped assurance-execution authority.
7. Criterion mapping originally treated required evidence types as alternatives and omitted
   replay inputs on gap rows. It now emits one row per type with PR/time/engine/input hash.

## Limitations

MVP-006 does not claim GitHub issue ingestion, historical PR diff simulation, signed/binary
evidence verification, URL/artifact fetching, archive scanning, automated assurance execution,
cross-commit reuse, generalized multi-scope materialized intersection, product/team/entity
delegated approval, UI, or MCP transport. Producer status/hash remain attested metadata. These
limits are explicit in ADR-022, the runbook, and threat model.

## Verification

The isolated Compose gate completed with formatting, lint, full mypy, migration drift, generated
contract validation, 187 passing tests, one intentionally skipped external-corpus test, and the
required 85% combined coverage. The production Compose topology migrated successfully; API, MCP,
worker, PostgreSQL, and object storage became healthy, and both readiness endpoints returned
`ready`. Hosted GitHub Actions results are recorded in the linked pull request.
