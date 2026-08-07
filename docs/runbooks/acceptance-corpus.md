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
It uses UID 0 without Linux capabilities only to initialize Docker's root-owned fresh named-volume
root, then seals copied files and directories read-only for the non-root product services.
It refuses a non-empty canonical volume. API, worker, MCP, CLI, and the acceptance runner receive
only `/app/acceptance/canonical` read-only, and the supported filesystem connector is restricted to
its `payload/` child.

The adapter emits a deterministic `source_fingerprint` over corpus identity, source commit, and the
sorted file inventory. It also writes `canonical-manifest.json` outside the connector root and
reports that file's SHA-256. Preserve those identities with the later public `acceptance-result`
document. That result must include a checksummed `knowledge_retrieval_results` artifact; its
contents remain public run output, not grading truth.

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
