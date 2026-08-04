# Developer guide

Develop and validate Anva through Docker Compose. Host Python and service
installations are not the project development contract.

## Local workflow

From the repository root:

```sh
docker compose up -d --wait
docker compose --profile test run --rm --build test
```

Use only checked-in Compose overlays for their documented purpose. A local test
result is development feedback, not release evidence unless its exact commit,
command, environment, output, and artifact are captured by the release process.

## Change expectations

- Enforce organization scope and permissions in every web, API, MCP, worker, and
  administrative path; add negative cross-organization tests.
- Keep migrations explicit and test supported upgrade and rollback boundaries.
  Rehearse reversal only in a guarded disposable restored database clone; never reverse
  the live development or deployment database.
- Avoid secrets, source text, prompts, and unbounded identifiers in logs or
  metric labels.
- Treat client-supplied forwarding headers as untrusted unless received from an
  explicitly trusted proxy.
- Update the relevant feature threat model, user/operator documentation,
  compatibility statement, and requirements/evidence mapping when behavior
  changes.
- Separate data-preserving shutdown, access revocation, retention expiry, hard
  deletion, and backup destruction in naming and implementation.
- Do not expose a caller-controlled clock on lifecycle HTTP endpoints. Retention
  must enforce explicit expiry and the organization minimum and keep operational
  cleanup tenant-scoped; destructive decommission remains recent-human-session
  and CSRF only.

## Release discipline

Do not mark the release checklist complete based on an implementation diff. The
release lane must independently capture tests, scans, artifact digest and
checksum, install/demo, migration, backup/restore, adversarial acceptance, and
fresh-agent usability evidence. Start from the
[release checklist](../releases/release-checklist.md) and
[evidence index](../evidence/issue-013/README.md).

The release runner must reject tracked/untracked worktree input and image/source
revision mismatch, rebuild and verify skills, and run both the source
vulnerability/secret/misconfiguration gate and the image gate with only the
reviewed, unexpired exception file. Operator-owned secret, backup, release, and
tool-cache paths excluded from the distributable source report require their own
custody and review; exclusion is not a safety claim.

Remove only exact task Compose projects, images, and cache directories after
tests. Do not use engine-wide pruning on a shared host. The observed MVP-013
task footprint remained below 5 GB, but no Docker quota enforces that ceiling.

Host-side MCP/skill installation and removal are separate integration concerns.
The Compose-owned CLI safely installs rendered Codex/Claude skills into an
explicit mounted destination and generates environment-reference-only MCP
configuration. No automated host uninstaller is provided, and sealed fresh-agent
Codex/Claude acceptance remains deferred; follow the [developer skills
runbook](../runbooks/developer-skills.md).
