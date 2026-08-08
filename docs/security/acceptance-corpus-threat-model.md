# Threat model: oracle-isolated acceptance corpus

## Trust boundaries

The operator-pinned public manifest is untrusted input. Its listed payload bytes are also untrusted
and must remain inert. The canonical volume remains untrusted until its raw-manifest hash, source
fingerprint, and canonical-manifest hash match identities preserved outside that volume. It is not
evidence of correctness. Private oracle, canary, host-scoring, and grader material belongs to a
separate disconnected control boundary and is never an Anva input.

The raw bind mount crosses only into `acceptance-adapter`. The adapter has no network and no product
credentials. Product services and the runner cross a different boundary through a read-only named
volume and never receive the raw mount. The filesystem connector begins at the canonical `payload/`
directory so the generated control manifest is not ingested.

Product acceptance is split across four mutually constrained runner processes. The start process
may receive the bootstrap/initiator credential and write the private resume/credential locations;
the claim and submit processes receive only reviewer authentication plus the handoff/result mounts;
the finalizer receives initiator authentication plus the result mount. The external evaluator is a
separate trust boundary and receives the public review request, not product credentials or private
scoring material. The disconnected private scorer is not part of this Compose topology.

## Security invariants

| Threat | Fail-closed control |
| --- | --- |
| Operator runs a substituted manifest | Compare the SHA-256 of exact raw manifest bytes with a required 64-character lowercase pin before parsing |
| A self-consistent canonical volume is substituted | Require and compare operator-preserved raw-manifest, source-fingerprint, and canonical-manifest SHA-256 identities; the volume cannot supply its own trust anchor |
| Traversal or platform path ambiguity | Require sorted unique POSIX-relative `payload/` paths; reject absolute, dot, dot-dot, empty, backslash, drive, NUL, oversized, and over-depth paths |
| Oracle or grader enters a public bundle | Reject forbidden control path components and filenames; reject every unlisted file or directory |
| Symlink, hardlink, device, FIFO, or socket escapes the inventory | Walk with `lstat`; require singly linked regular files; open every component with `O_NOFOLLOW` |
| Input changes between validation and copy | Revalidate descriptor identity and metadata around each bounded read, then compare exact size and SHA-256 |
| Resource exhaustion | Stream raw and canonical directory scans; enforce hard inventory bounds, closed-schema maxima, stricter operator ceilings, 256 MiB/no-extra-swap memory, 64 PIDs, and bounded tmpfs |
| Partial output is consumed | Require a fresh empty destination; publish same-directory temporary files only after write and fsync; remove tracked temporary/final entries on any failure; fsync the parent and write the canonical manifest last |
| Product reads raw or control metadata | Only the adapter has the raw mount; product/runner mounts are canonical and read-only; connector root is `payload/` |
| Adapter exfiltrates input | `network_mode: none`, no credentials, read-only root, dropped capabilities, `no-new-privileges`, and bounded tmpfs |
| Results smuggle private grading truth into Anva | The public result schema permits only run identity/status and checksummed public artifacts; private grading occurs elsewhere |
| Capability-less root cannot clean an image-seeded volume | Adapter runs as the fixed unprivileged image owner `10001:10001`; Compose and Dockerfile identity are tested together; chmod/unlink cleanup remains fail-closed |
| Runner bypasses a supported boundary | Runner imports no product model/service and uses only documented HTTP plus the official Streamable HTTP MCP client |
| Initiator evaluates its own change | Bootstrap optionally emits a distinct service identity with only `ASSURANCE_REVIEW`; reviewer claim/submit run in separate services without the initiator credential |
| A review targets a substituted run or head | Handoff and external result must match the precommitted run/task/request/organization/head; a newer head forces `STALE` and cannot finalize |
| Resume state becomes a credential cache | Closed state stores only allowlisted UUIDs and 40/64-character hashes in a mode-`0600` file under a private directory; one-time credentials and claim material use separate mode-`0600` handoffs |
| One-time upload secret is lost on restart | Replay discloses only an opaque authorization ID; runner derives a fresh bounded idempotency key and never persists an upload token |
| Partial or substituted output is published | Write a private sibling tree, validate the public result contract, hash every artifact, fsync, chmod read-only, and atomically rename; reject an existing destination or any private marker |
| Runner gains host control | Phase services have no Docker socket, raw corpus, oracle, or grader mount; root filesystem is read-only, capabilities are dropped, and memory/PID/tmpfs/log growth is bounded |

## Residual and deferred risk

An operator with Docker or host filesystem authority can replace mounts, images, or environment
values and must be handled by independent evidence capture. The Compose foundation does not itself
prove a private exporter correctly excluded every sensitive byte, execute Codex/Claude or another
native coding host, measure human timing, or grade outputs with private controls. Those gates require
independent bundle commitments, resolved Compose/image identities, cross-surface canary scans,
disconnected grading, and fresh reviewers. A host administrator can still inspect process memory or
private handoff files; operator access to those locations remains a privileged trust assumption.
