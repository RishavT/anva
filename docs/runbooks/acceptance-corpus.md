# Public acceptance corpus isolation

This runbook prepares the public input boundary for external acceptance. It does not run a private
grader, reveal held controls, launch native coding agents, or by itself satisfy the final release
gate.

## Bundle contract

The input directory contains exactly:

- `acceptance-corpus.json`, whose raw bytes are pinned by the operator; and
- manifest-listed, singly linked regular files beneath `payload/`.

The version `1.0` manifest is a closed public contract. It records only corpus identity, generation
time, source commit, explicit paths, byte sizes, SHA-256 digests, and declared count/size/depth
limits. It must not contain expected outcomes, grader rules, canaries, or oracle metadata. The
adapter rejects absolute, traversal, backslash, drive-prefixed, NUL, duplicate, unsorted, forbidden
control, symlink, hardlink, special, unlisted, over-limit, missing, size-mismatched, or hash-mismatched
input.

Commit the manifest and its SHA-256 before launching a host. Do not compute or select the pin from
an untrusted runtime argument after the run has begun.

## Canonicalize and verify

Use a fresh acceptance Compose project and an absolute path to the public export:

```sh
export ACCEPTANCE_PUBLIC_DIR=/absolute/path/to/candidate/input
export ANVA_ACCEPTANCE_MANIFEST_SHA256=<independently-recorded-raw-manifest-sha256>
ANVA_ACCEPTANCE_INPUT_DIR="$ACCEPTANCE_PUBLIC_DIR" \
  make acceptance-canonicalize

# Copy these two identities from the successful adapter result into the operator evidence record.
export ANVA_ACCEPTANCE_SOURCE_FINGERPRINT=<recorded-source-fingerprint>
export ANVA_ACCEPTANCE_CANONICAL_MANIFEST_SHA256=<recorded-canonical-manifest-sha256>
make acceptance-verify
```

The verification target requires all three exported identities. Make checks that none is omitted,
and Compose passes them as explicit CLI arguments to the read-only runner. Preserve the values in
operator-controlled evidence before verification; do not recompute or accept replacements from the
canonical volume. A self-consistent replacement of its payload and control manifest is rejected
when it does not match those preserved identities.

`acceptance-adapter` has a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, bounded tmpfs, and `network_mode: none`. It alone receives the raw bind mount.
Its container is additionally limited to 256 MiB memory, no swap above that limit, and 64 PIDs.
It defaults to the image's unprivileged UID/GID `10001:10001`, which owns Docker's image-seeded
named-volume root. For a closed external run, create every protected bind directory with mode
`0700` and its secret file with mode `0600`, then export both IDs of that owner before running any
acceptance target:

```console
export ANVA_ACCEPTANCE_UID="$(id -u protected-owner)"
export ANVA_ACCEPTANCE_GID="$(id -g protected-owner)"
```

Both variables must be supplied together and must be positive numeric IDs. The preflight rejects a
partial, zero, or malformed identity before Compose starts a container. The adapter, API, and all
four product phases run with this identity, including ownership of their private `/app/run` tmpfs;
do not weaken the protected directories or secret to accommodate a mismatched container identity.
The image seeds the otherwise-empty task-owned canonical volume root with sticky
world-write permissions so that the selected non-root identity can publish into a fresh volume
without gaining access to any host path or another user's entries. The adapter then
seals copied files and directories read-only for the product services.
It refuses a non-empty canonical volume. API, worker, MCP, CLI, and the acceptance runner receive
only `/app/acceptance/canonical` read-only, and the supported filesystem connector is restricted to
its `payload/` child.

The adapter emits a deterministic `source_fingerprint` over corpus identity, source commit, and the
sorted file inventory. It also writes `canonical-manifest.json` outside the connector root and
reports that file's SHA-256. Preserve those identities with the later public `acceptance-result`
document. That result must include a checksummed `knowledge_retrieval_results` artifact; its
contents remain public run output, not grading truth.

## Declare a least-privilege case scope

Every scenario supplied with `--case` (including the case mounted by the acceptance Compose
profile) must validate against
[`contracts/json-schema/v1/acceptance-case.schema.json`](../../contracts/json-schema/v1/acceptance-case.schema.json).
Start from the public shape in
[`contracts/examples/v1/acceptance-case.json`](../../contracts/examples/v1/acceptance-case.json),
then replace every scenario-specific value rather than deleting scope fields.

The closed `organization.bootstrap_scope` object explicitly requests one repository, one human
membership with the least-privilege `VIEWER` role, and exactly two named service identities. The
initiator has only the actions needed by the acceptance journey (`artifact.create`, `artifact.view`,
`assurance.execute`, `canvas.view`, `evidence.submit`, `evidence.view`, `knowledge.view`,
`mcp.context`, `policy.manage`, `policy.view`, `search.query`, `source.sync`, `source.view`, and
`work.manage`) on that repository. The independent reviewer has only `assurance.review` on the
same repository. The access scope names every requested membership, repository, and service
identity; it never uses an `all_*` binding.

Keys, role codes, action values, repository grants, and access-scope references are closed and
cross-validated. Omitted fields, unknown or extra actions, duplicate keys/actions, dangling
references, unbound requested records, an over-privileged reviewer, or an undeclared principal
fail before bootstrap. Changing a role, grant, repository, or principal changes the canonical case
hash and therefore cannot adopt an earlier run's state or handoff.

Only invocation without `--case` uses the original flat, broad local-bootstrap fixture for corpus
v1 compatibility. That legacy shape is constructed internally; it is not accepted as a new public
case and must not be copied into a scenario bundle.

## Run the product acceptance phases

Pre-create private host directories with mode `0700`, and preserve the exact product commit plus
all three corpus pins outside the runner.

### Generate the launch manifest

The launch manifest is a required numeric-version-`1` public contract. Its closed schema is
[`contracts/json-schema/v1/launch-manifest.schema.json`](../../contracts/json-schema/v1/launch-manifest.schema.json)
and its shape is illustrated by
[`contracts/examples/v1/launch-manifest.json`](../../contracts/examples/v1/launch-manifest.json).
It binds the exact product commit, build input, installed package, Docker image ID/reference,
required service inventory, and SHA-256 identities of the security-relevant resolved Compose
model. The resolved-model identity includes the fixed `postgres`, `minio`, `minio-init`, and
`migrate` dependency closure actually started for `api`, `worker`, and `mcp`, while the public
service inventory remains the established exact seven product/phase services. It intentionally
contains neither environment values, secret material, host paths, nor the resolved model itself.

Use the supported generator; a raw `docker compose config` document is not a launch manifest.
The host output path is required by every Make phase and must be absolute. On a clean start,
`make acceptance-start` invokes `make acceptance-launch-manifest` automatically. The explicit
target is available for preflight or evidence collection:

```sh
export ANVA_REVISION=<exact-40-character-product-commit>
export ANVA_BUILD_INPUT_SHA256=<exact-64-character-build-input-sha256>
export ANVA_IMAGE_SHA256=<docker-image-id-without-the-sha256-prefix>
export ANVA_ACCEPTANCE_LAUNCH_MANIFEST=/protected/path/launch-manifest.json
export ANVA_ACCEPTANCE_STATE_DIR=/private/path/state

make acceptance-launch-manifest
```

The target resolves the acceptance Compose model, inspects the pinned local image, and runs the
generator from that exact image with no network, a read-only root, no capabilities, no privilege
escalation, and the invoking non-root host identity. Generator inputs live only in a mode-`0700`
temporary directory beneath the state directory and are removed. Before emitting deterministic
JSON it verifies the exact seven product/phase services, their fixed four-service dependency
closure, image identities, internal-only network topology, non-root acceptance phases, read-only
roots, dropped capabilities, PID/memory ceilings, and every allowed bind's exact target/write mode
and `create_host_path: false` setting. A
missing or changed service/image/runtime/bind fails closed with a stable reason code.

The generated file is mode `0444`. If the output already exists as a regular read-only file, the
target preserves it so an existing valid v1 run can resume with the original byte hash; the
in-container preflight still validates its schema and exact pins. Move an obsolete manifest aside
before intentionally generating a replacement. Symlinked or writable existing files are rejected.

For direct CLI use, `--launch-manifest` is optional only because it defaults to the supported
in-container path `/acceptance/launch/manifest.json`. The host-side Make variable
`ANVA_ACCEPTANCE_LAUNCH_MANIFEST` is required because Compose must bind an explicit protected file
to that default path. Omitting the CLI option never disables validation and there is no downgrade
or bypass mode.

`acceptance-start` bootstraps a distinct initiator and
least-privilege reviewer, syncs the canonical source, exercises search/context through real MCP,
queries Canvas through HTTP, imports work and policy, uploads verified evidence bytes, evaluates
the case's exact pull request, and, when declared, proves that its independently numbered newer
head makes the earlier run stale. The no-case compatibility fixture retains its original PR 817/818
journey. The runner then stops at `AWAITING_EXTERNAL_REVIEW`.

```sh
export ANVA_REVISION=<exact-40-character-product-commit>
export ANVA_BUILD_INPUT_SHA256=<exact-64-character-build-input-sha256>
export ANVA_IMAGE_SHA256=<docker-image-id-without-the-sha256-prefix>
export ANVA_ACCEPTANCE_LAUNCH_MANIFEST=/protected/path/launch-manifest.json
export ANVA_ACCEPTANCE_STATE_DIR=/private/path/state
export ANVA_ACCEPTANCE_CREDENTIAL_DIR=/private/path/credentials
export ANVA_ACCEPTANCE_HANDOFF_DIR=/private/path/handoff
export ANVA_ACCEPTANCE_REVIEW_RESULT_DIR=/private/path/reviewer
export ANVA_ACCEPTANCE_RESULTS_DIR=/private/path/results

make acceptance-start
```

The one-time credential file is mode `0600`; the resume record contains only allowlisted opaque
UUIDs and hashes. With a supplied case, the bootstrap token belongs to the declared initiator and
the reviewer token belongs to the declared reviewer; the runner does not synthesize or select any
other principal. The public bootstrap response is explicitly marked `SCOPED` or `LEGACY`; a
`SCOPED` response is invalid unless it includes the distinct reviewer service-identity ID,
reviewer token-record ID, one-time reviewer token, and reviewer expiry. The two non-secret IDs are
bound into scoped assurance start, restart state, review handoff, and sealed provenance so a
different actor or credential cannot adopt the task. Raw tokens remain only in the private
one-time credential/handoff flow and never enter resume state or sealed results. Load each
credential into its named environment variable without printing it.
Use the reviewer credential only for the two reviewer phases:

```sh
export ANVA_ACCEPTANCE_REVIEWER_TOKEN=<reviewer-credential>
make acceptance-review-request
```

Give the resulting mode-`0600` handoff to an independent evaluator. That evaluator receives only
the public request, writes a public `evaluator-result` version `1.0` document to
`$ANVA_ACCEPTANCE_REVIEW_RESULT_DIR/result.json`, and must not receive the initiator credential,
raw corpus, private oracle, or grader. Submit from a fresh process:

```sh
make acceptance-review-submit
unset ANVA_ACCEPTANCE_REVIEWER_TOKEN
export ANVA_ACCEPTANCE_TOKEN=<initiator-credential>
make acceptance-finalize
```

Submission authenticates the distinct reviewer and consumes the claim handoff. Finalization
requires a completed, non-stale assurance run for the exact current head, retrieves the final
public API/MCP views, and atomically publishes a read-only result directory containing JSONL,
JSON, `acceptance-result.json`, and `SHA256SUMS`. Verify the checksums before copying results out.
Each phase is a separate hardened Compose service with a read-only root, all capabilities dropped,
no privilege escalation, bounded memory/PIDs/tmpfs/logs, and only the phase-specific mounts.
No phase receives the Docker socket, raw corpus, private scorer, oracle, or grader.

The first run precommits a reference instant after the bounded ingestion window, persists its hash,
and reuses it on every retry. A new run may precommit a different instant and therefore receives a
different UUIDv5 run namespace. Re-run a stopped phase with the same state, exact pins, product
commit, and appropriate credential; never edit the resume record or copy credentials into it.
When `start` stops while the state is `PREPARING`, it reconciles the persisted source and sync
identities before doing more work. A completed sync is observed through its documented read
boundary and is not recreated. The same unexpired initiator credential can therefore resume the
run without duplicating the source or sync.

On a safe `start` rejection, inspect
`$ANVA_ACCEPTANCE_STATE_DIR/operator-diagnostic.json`. This private, mode-`0600` record contains
only the run ID, a stable stage, a stable reason code, and (when applicable) an HTTP status. It does
not retain response bodies, exception text, URLs, headers, or credentials. In particular,
`authorization_rejected`, `sync_timeout`, and `semantic_assertion_failed` distinguish the common
operator actions while the command's public output remains deliberately non-oracular. Treat the
file as the most recent start failure; copy it to operator-owned evidence before retrying if the
failure record must be retained.

Launch rejection occurs before a resume record exists, but it now writes the same private
diagnostic with stage `launch_manifest_preflight`, run ID `unavailable`, and an allowlisted reason.
`launch_manifest_missing` means run `make acceptance-launch-manifest`;
`launch_manifest_permissions` means replace a symlink/special file or remove write permission;
`launch_manifest_malformed` and `launch_manifest_schema` mean generate a fresh schema-valid file;
the `*_mismatch` reasons name the stale product/build/package/image/service identity that must be
rebuilt or regenerated. No exception text, manifest content, Compose content, host path, token, or
secret is copied into the diagnostic or generic command response.

## Fail closed and clean up

Any rejection, including a write or durability failure after a temporary file is created, removes
tracked output and leaves the canonical root empty. If cleanup itself cannot be proven, discard the
entire ephemeral volume. Do not weaken operator ceilings to make a rejected bundle pass. Re-export
the public bundle, independently inspect its inventory, and pin the new raw manifest bytes.

After sealing the public result and copying required evidence out of the ephemeral project, remove
only its scoped resources:

```sh
make acceptance-down
```

This removes the `anva-acceptance` project's containers, network, and canonical volume. Never use
an engine-wide prune for this workflow.
