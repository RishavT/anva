# Issue 29 accepted evidence upload verification

This index records local candidate evidence for
`RishavT/anva#29` (MVP-015). It is not a release or publication attestation. The
implementation candidate is the commit containing this document; its exact
commit SHA, independent security-review verdict, push, and pull request belong
in the external review/PR record after the source is frozen.

## Candidate boundary

- Starting source commit: `5868f84a408866e41610e8b62318eeb306f30329`
- Implementation branch: `feat/issue-29-evidence-upload`
- External corpus source: read-only `RishavT/anva-test` commit
  `48209b315f47acc8ec99a4c0cacda26e6488df62`
- External corpus worktree: clean before and after fixture inspection
- GitHub Actions, tag, release, merge, registry publication, and production
  deployment: not performed

The candidate adds short-lived actor/credential/tenant/repository/scope/PR/
commit-bound upload authorization; a bounded non-executing JSON/ZIP/TAR
inspector; conditional S3-compatible storage with HEAD and bounded GET
verification; immutable blob binding; cleanup recovery; and exact byte deletion
during retention/decommission. The
[threat model](../../security/evidence-upload-threat-model.md) and
[runbook](../../runbooks/evidence-upload.md) state the boundary and residual
risks.

## TST-007 artifact provenance

Six raw upload files were copied byte-for-byte from the sealed
`.anva/adversarial-evidence/artifacts/` inventory in the read-only external
repository. Their hashes are pinned before the production inspector receives
the bytes.

| Scenario | Expected boundary result | SHA-256 |
| --- | --- | --- |
| Drift malformed JSON | reject | `7b3199a0944001af205a2bd932d500b18cfebebc376b362eb19ea1f55c4fbe3c` |
| Elder oversized JSON | reject | `bc63913f2a32c1b8b4578a2acfbd3ddbce30f20c3f103782c1f2c663bd214c9f` |
| Flint schema-invalid JSON | reject | `e70d12d49a52e9aab07320fde80b190b1980e66bc4bda394b8f2fe6f3c81e7d1` |
| Glass traversal/executable ZIP | reject | `d0c89e82046b3f61ec3793382e68f1f17b8f4187cb994f6e008db8a50b3c2d50` |
| Harbor secret-pattern JSON | reject without disclosure | `8c84957062b97c350f9df7806ea9f8b36e025140d97fde71988e5e147292a797` |
| Linden structurally safe ZIP | raw head mismatch rejects; explicitly adapted in-memory copy accepts | `19f81a35213a2c613e2c42c363e15a0d65115a1db083ff1d43821a4c502eb979` |

The upstream Linden file intentionally uses a synthetic 64-character
`head_sha`, while Anva authorizes a full 40-character Git commit. The test first
proves the raw file fails that binding. It then changes an in-memory copy to the
authorized head and recomputes the results hash; the adapted bytes have a
different digest. No byte-for-byte upstream acceptance is claimed.

## Recorded local results

All development and tests ran in exact task-scoped Docker/Compose resources with
PostgreSQL and MinIO. The broad and browser source mounts were read-only; their
mutable performance/screenshot output used disposable overlays.

| Gate | Recorded result |
| --- | --- |
| Formatting/lint/type | Ruff format checked 194 files; Ruff lint returned zero findings; mypy checked 169 source files with zero errors. |
| Migration/generated contracts | `makemigrations --check --dry-run` reported no changes; 30 generated artifacts verified. |
| Focused upload suites | Unit/contract/security and PostgreSQL integration lanes passed, including API issue/PUT/replay, concurrent consumption, revoke, disconnect, storage failure, foreign precondition conflict, finalization cleanup, recovery, secret/log canaries, immutable blob linking, retention, and decommission behavior. The final post-documentation contract/security lane passed 46 tests in 0.82 seconds. |
| TST-007/parser | 15 focused cases passed, covering the six pinned artifacts and the hostile JSON/ZIP/TAR boundary matrix. |
| Live object storage | Real MinIO conditional PUT, ownership metadata, HEAD, bounded GET digest, accepted database blob, ownership-checked DELETE, missing-object behavior, and preserved `DELETED` metadata passed. |
| Broad/coverage | `pytest -m 'not browser'`: 846 passed, one expected live-MCP-profile skip, two browser tests deselected, zero failures, in 319.52 seconds. Total line/branch coverage met the 85% gate: 16,887 statements, 1,974 missed, 4,698 branches, and 1,036 partial branches. |
| Browser regression | Two Chromium journeys passed, 847 tests deselected, zero failures, in 107.06 seconds. |
| Source immutability | The committed issue-012 browser/database performance files retained SHA-256 `d55b55dabbbef10ca5b32fc0211a509da5c7d729337ecdeda7499f41ef572ea5` and `f2161dbda6302d72ec79735357e7d05a9d28b6ca64f2fc8b7964e5f465418b7e`. |

The broad-suite skip is expected because the live MCP test requires its separate
Compose profile and is unrelated to this upload boundary. The only warning was
the existing Starlette/httpx test-client deprecation warning.

## Resource and cleanup record

The browser-image build reached an estimated task peak of approximately
4.94 GB, below the 5,000,000,000-byte hard working limit. Immediately after the
image loaded, only the dedicated `issue29-evidence-builder` cache was pruned,
reclaiming approximately 2.891 GB and reducing the task footprint to about
2.05 GB. No engine-wide prune or unrelated/shared-image deletion was used.

Disposable browser screenshot and performance overlays were removed after the
green run. Final removal of the exact task browser/test images, PostgreSQL,
MinIO, network, volume, builder, and remaining builder cache is required after
review/PR work no longer needs test reruns.

## Open gates

- freeze a clean implementation commit;
- obtain an independent fresh security review of that exact commit, with no
  reviewer edits;
- remediate and re-review any finding against a new exact commit;
- push and open the focused pull request only after approval; and
- keep issue 29 open until the approved change is merged.

These open gates intentionally prevent this local candidate record from being
presented as an approved, merged, published, deployed, or independently audited
release.
