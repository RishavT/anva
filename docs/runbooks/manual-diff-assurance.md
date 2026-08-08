# Runbook: Independent manual-diff assurance

## Ingest and start

Use an `assurance.execute` and `artifact.create` capable repository token only through
`ANVA_TOKEN`. Metadata/result JSON must be regular non-symlink files up to 64 KiB. The diff must be
a newline-terminated regular UTF-8 non-symlink file up to 1,000,000 bytes.

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva assurance ingest \
  --repository-id <repository-uuid> --pull-request-number 42 \
  --metadata /fixtures/pr.json --diff /fixtures/pr.diff

docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva assurance start \
  --pull-request-revision-id <revision-uuid> --inputs /fixtures/assurance-inputs.json
```

The start input must contain exact active policy-version UUIDs, timezone-aware `reference_time`,
and deterministic checks with code/status/blocking/summary/exact evidence UUIDs. Optional work
revision, evaluator/prompt versions, and a SHA-256 delivery key are pinned into the run. An
unchanged canonical replay returns the existing run/task; a changed exact input retains and stales
the previous current result.

## Manual evaluator

Claim into a fresh, context-limited review process with a separate `assurance.review` principal.
The initiating actor cannot claim its own run. Anva rechecks the reviewer against every sealed
source boundary, then persists the authenticated actor and exact repository credential on the task
and append-only attempt. `--claimant` is only an audited provider/display label; it is not identity.

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva evaluator claim \
  --repository-id <repository-uuid> --claimant review-agent-7
```

Give the reviewer only the returned `request` object. Do not mount the repository, Docker socket,
database credentials, or application environment. The reviewer must return the checked-in
`evaluator-result` contract and cite only supplied diff coordinates or authorized context citation
IDs.

Place the one-time claim token in `ANVA_EVALUATOR_CLAIM_TOKEN`, not a command argument:

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN -e ANVA_EVALUATOR_CLAIM_TOKEN cli anva evaluator submit \
  <task-uuid> --result /fixtures/evaluator-result.json
```

Submit with the same still-active `ANVA_TOKEN` credential that performed the claim. A token for the
same service identity is not interchangeable: rotation, revocation, expiry, or switching to another
credential requires the lease to expire and a new claim attempt. Exact identical-result replay is
available only to that bound actor and credential. The claim-time provider/display label remains
immutable audit metadata and is not required—or consulted—when submitting.

## Inspect and recover

```bash
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva assurance status <run-uuid>
docker compose --profile tools run --rm \
  -e ANVA_TOKEN cli anva assurance report <run-uuid>
```

- `invalid_request`: validate schema, full SHAs, hunk counts, line endings, paths, size, citation
  coordinates, and secret patterns.
- lease conflict: discard the old token and claim again after expiry if attempts remain.
- stale: ingest/evaluate the current exact PR revision; never publish the historical result as
  current.
- blocked: resolve deterministic checks, policy approvals, or exact evidence gaps first. An
  evaluator resubmission cannot clear them.
- post-merge: create cited proposals only against the completed exact merged revision. Review them
  through the normal knowledge workflow; this path never accepts them.

The report is a review aid, not merge or deployment approval. It does not prove runtime safety,
capacity, rollout success, or absence of defects.
