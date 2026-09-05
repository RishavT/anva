# Issue 126 self-review

Review target: `feature/126-release-docs-reconciliation`, based on
`1446d4dcea8c89ef09d0e2b43bfb8ddc36d50caa`.

## Acceptance mapping

- Published identity: `v0.1.6.md`, current readiness, the release checklist,
  MVP summary, and requirements matrix record source
  `e89b06aed8207cc32eee0eeebde4a2731f0c0203`, image digest
  `sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`,
  12 public assets, release run `33781714974`, operator signoff run
  `33910747236`, and the final operator-ledger identity.
- Immutable/fix-forward boundary: active release records distinguish published
  v0.1.6 bytes from post-release `main` and consistently select the next patch,
  v0.1.7, without creating a tag, candidate, approval, artifact, or publication
  claim for it.
- Current status: README, readiness, compatibility, checklist, ownership,
  install guidance, MVP summary, and requirements mapping no longer describe
  v0.1.6 or gates #43/#44 as pending.
- Historical and deferred scope: aborted v0.1.1 through v0.1.4 evidence is
  retained, v0.1.5 remains the rollback predecessor, and issues #37 through
  #40 and #49 remain explicit post-MVP boundaries. The independent
  `anva-test#18` defect remains open and is not converted into product evidence.
- Manifest semantics: release guidance explains that
  `generated_unpublished` describes schema-v2 manifest bytes at build time and
  is not a retrospective claim about the live Release. No schema or workflow
  value was rewritten.
- Regression coverage: `test_release_documentation.py` requires exact release
  and operator identities, the v0.1.7 boundary, and build-stage status
  semantics, and rejects the previously authoritative stale phrases across the
  release records, operator guide/drill, retention runbook, and product threat
  model.
- Exact risk facts: the downloaded, checksummed public v0.1.6 assets prove 14
  unique CVEs across 18 HIGH-or-CRITICAL image package tuples, with approval
  through 2026-10-03, and three MEDIUM plus eight LOW Django source findings.
  Active documentation now distinguishes these sets. Release ownership links
  the immutable v0.1.6 decision asset and identifies the tracked v0.1.0
  exception as historical only.

## Validation

- `docker compose -p anva-issue126 --profile test run --rm ... pytest ...`:
  148 release/documentation tests passed.
- Ruff format and lint checks passed for the changed test module in the same
  Compose test container.
- After the independent review correction, the expanded documentation module
  passed all 15 tests together with repository-wide Ruff format and lint in
  project `anva-issue126-correction`.
- `git diff --check` passed.
- Exact project Compose resources are removed after validation.

## Security and scope review

The diff changes Markdown records and their consistency tests only. It changes
no runtime, release workflow, version metadata, credentials, immutable tags,
images, artifacts, decisions, approvals, or attestations. No secret or private
operator evidence is introduced.

## Known limitation

The live v0.1.6 GitHub Release body was generated from the immutable source and
still contains its pre-publication wording. This branch does not mutate that
public external record: issue #126 requires a separately reviewed and
authorized metadata or fix-forward release action. The source record therefore
describes both the authoritative publication evidence and this remaining
metadata limitation without pretending that these documentation bytes belong
to v0.1.6.
