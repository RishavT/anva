# Runbook: Versioned intent, policy, and evidence

## Prepare

Use a repository-scoped token with the required `work.*`, `policy.*`, or `evidence.*` action.
Supply it only through `ANVA_TOKEN`. JSON files must be regular, non-symlink files no larger than
64 KiB.

```bash
export ANVA_TOKEN='<repository token>'
docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva work import --repository-id <repository-uuid> --file /fixtures/work.json
docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva policy import --repository-id <repository-uuid> --file /fixtures/policy.json
docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva policy simulate --repository-id <repository-uuid> --inputs /fixtures/simulation.json
docker compose --profile tools run --rm -e ANVA_TOKEN cli \
  anva evidence submit --repository-id <repository-uuid> \
  --pull-request-number 42 --manifest /fixtures/evidence.json
```

Work revisions and policy versions start at 1 and increase sequentially. Reusing a version with
different normalized content fails. A new work revision does not inherit an older approval.

## Simulation inputs

Always provide exact policy-version UUIDs, a full lowercase 40-character commit, PR number,
timezone-aware `reference_time`, normalized repository-relative changed paths, affected entity
ID/type objects, target branch, and optional exact work-item-revision UUID. Repeat the same values
to reproduce the same input/output hashes.

A lower policy can add controls or raise severity but cannot remove a source control. Create an
override only through the authorized policy override endpoint; it suppresses only the exact
policy-version control and can be withdrawn append-only. Rerun with a reference time after the
override or revocation.

## Evidence submission

The repository ID and PR number in the route must equal the manifest. The token, manifest
organization/repository/access scope, optional work revision, and evidence approval must all agree.
Test/build/lint/typecheck/migration/scan evidence requires a command. Visual evidence requires a
scenario; logs/traces require an environment. Manual evidence requires an exact unexpired
authority approval. A requirement marked `requires_approval` must link to criteria that explicitly
require `MANUAL_APPROVAL`; a requirement-target approval can satisfy only those linked criteria.

Artifact references are metadata-only relative POSIX paths. Source URLs must be HTTPS without
userinfo or secret query parameters. Anva does not fetch, open, unpack, or run either field.

Criterion mapping produces one immutable `SATISFIED` mapping or explicit `GAP` for every required
evidence type of every exact criterion. Each row records PR, commit, reference time, engine
version, and canonical input hash. `STALE_EVIDENCE_ONLY` means matching evidence of that type
exists only on another commit.

## Recovery

- `invalid_request`: validate against checked-in schemas; check body size, full commit, timestamp,
  path normalization, URL, and secret-bearing fields.
- `resource_not_found`: verify active token/action, tenant, repository, scope, exact revision, and
  approval authority. Foreign and missing resources intentionally share this response.
- version/idempotency conflict: allocate the next revision/version or restore the original bytes;
  exact canonical request replays return the existing immutable resource.
- unexpected policy output: compare input hash components and matched-binding explanations; never
  edit immutable rows.

## Current limitations

There is no GitHub network issue importer, PullRequestRecord/diff history, binary upload,
signature verification, artifact fetch, archive scanner, automatic assurance orchestration,
cross-commit reuse, fine-grained product/team/entity approval delegation, UI, or MCP transport.
