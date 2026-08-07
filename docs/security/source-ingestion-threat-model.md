# Threat model: Source ingestion and provenance

## Assets and trust boundaries

Protected assets are organizational source bytes, paths and metadata, access snapshots, assertions,
chunks, relationship edges, tenant boundaries, worker availability, credentials, and audit/outbox
history. A mounted corpus crosses into the connector as fully untrusted data. The API crosses the
authorization boundary before connection, synchronization, inspection, resync, or revocation.
Workers cross a PostgreSQL lease boundary and must revalidate the source and access snapshot after
claiming work.

No source file is imported, executed, rendered as a template, used to select a handler, or sent to a
model. Connector/parser/extractor registries are code-owned allowlists.

## Threats and controls

| Threat | Control | Verification |
| --- | --- | --- |
| Path traversal or symlink race | Absolute allowlisted roots; root rejects symlinks; `openat`/`O_NOFOLLOW` on every component; regular files only | Hostile path, root/file symlink, and special-file tests |
| Held-control or oracle ingestion during acceptance | A network-disabled adapter is the only raw-mount consumer; it verifies an operator-pinned public manifest and copies an exact allowlist into an ephemeral canonical volume | Contract, hostile inventory, connector, and resolved-Compose tests |
| Source mutation | Connector exposes discover/fetch only; Compose corpus mount is `:ro` | Mount read-only flag plus before/after SHA-256 fingerprints |
| Oversized or deeply nested input | File, entry, page, path, line, YAML token, node, scalar, and depth limits; unsafe discovery entries are isolated from siblings | Boundary, bomb, and partial hostile-path tests |
| YAML alias bomb or unsafe tags | Anchors/aliases rejected during token scan; safe YAML 1.2 loader | Alias and GitHub workflow tests |
| SSRF or local-file inclusion | OpenAPI remote and `file://` references are rejected; parsers make no network calls | Remote-reference test |
| Prompt injection | All text remains inert; only syntax-level deterministic claims are enabled | Adversarial Markdown produces no commands or claims |
| Customer-code execution | Migrations and source code are parsed as text; no import, subprocess, eval, or sandbox invocation | Migration/parser tests and code review |
| Cross-tenant grafting | Composite `(organization_id, id)` foreign keys on provenance, chunks, visibility, and edges | Forced PostgreSQL constraint tests |
| Visibility widening | Scope comes from immutable observation snapshot; assertions/edges are scope-versioned; retrieval requires active/current derivation state | ACL-only re-observation, parser-upgrade, revocation, and retrieval tests |
| Stale queued authority | Authorization precedes idempotency; workers revalidate after fetch/parse; source locks serialize writes/publication with revocation; terminal runs cannot reopen | Viewer-existing-run, queued/claimed, and mid-fetch revocation tests |
| Corrupted history or forged identity | Immutable history triggers plus PostgreSQL SHA-256 recomputation for raw bytes, normalized JSON, extraction claims, and chunks | Direct bulk update/delete and four forged-digest insert tests |
| Malformed-item denial of service | Per-item transaction/failure record; remaining items continue; run becomes partial | Mixed good/bad corpus test |
| Handler injection | Payload can select only an exact registered job kind, never a Python symbol | Registry and worker tests |

## Residual risk and operations

The filesystem connector has no external credential. Remote connectors require reviewed secret
storage, egress restrictions, pagination/backoff, and provider-specific permission snapshots.
Raw bytes currently reside in PostgreSQL and therefore follow database backup/retention policy.
Acceptance input is a public-only export, not a repository checkout. The private exporter, held
controls, and grader remain outside Anva's mounts and network. Production mounts must be read-only,
minimal, and separate by trust boundary.

On suspected source compromise, revoke the source immediately, preserve the correlation/run/job
IDs and secret-safe failures, and follow the source ingestion runbook. Do not delete immutable
history during investigation.
