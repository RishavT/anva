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

## Residual and deferred risk

An operator with Docker or host filesystem authority can replace mounts, images, or environment
values and must be handled by independent evidence capture. The Compose foundation does not itself
prove a private exporter correctly excluded every sensitive byte, does not execute sealed native
agents, and does not grade outputs. Those gates require independent bundle commitments, resolved
Compose/image identities, cross-surface canary scans, disconnected grading, and fresh reviewers.
The adapter uses UID 0 solely because Docker initializes a fresh named-volume root with root
ownership. All Linux capabilities are dropped, privilege escalation is disabled, the root
filesystem is read-only, and only the canonical volume is writable; a rootless-volume provisioning
mechanism would reduce this residual privilege further.
