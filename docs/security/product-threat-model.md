# Product threat model

This umbrella model records the security assumptions, verified controls, and
residual risks for published v0.1.6. It complements feature-specific models
under this directory; evidence is bounded to the exact published release and
does not turn deployment-owned controls into product guarantees.

Related models include [foundation](foundation-threat-model.md),
[tenancy and authorization](tenancy-authorization-threat-model.md),
[source ingestion](source-ingestion-threat-model.md),
[MCP](mcp-gateway-threat-model.md), [developer skills](developer-skills-threat-model.md),
[evidence manifests](evidence-manifest-threat-model.md), and
[product UI](product-ui-threat-model.md). Their individual scope and evidence
status still apply.

## Scope and assets

In scope are the web/API and MCP entry points, background workers, PostgreSQL,
object storage, release images and Compose configuration, backups,
telemetry, administrative operations, and host-side client integration.

Assets include source content and derived knowledge, provenance/evidence,
organization membership and authorization state, credentials and signing keys,
audit history, retention state, backups, release artifacts, and service
availability.

## Actors and trust boundaries

Actors include organization users, administrators, service identities, MCP
clients, unauthenticated network clients, infrastructure operators, release
publishers, and a compromised or malicious tenant. The model does not assume
that every authenticated actor is trustworthy.

Primary boundaries are:

1. client or reverse proxy to Anva entry points;
2. web/API/MCP processes to database, cache, and object storage;
3. one organization to another within shared services;
4. worker jobs to queued tenant-scoped work;
5. operator environment to backups, secrets, and administrative endpoints; and
6. source repository and CI to registry artifacts and deployment hosts.

TLS termination, proxy identity, secret delivery, backup custody, and host MCP
configuration may sit outside the Compose project and remain operator-owned.

## Important data flows

- A caller authenticates, selects an organization-scoped resource, and reads or
  mutates data through web/API/MCP paths.
- Ingestion reads source material, stores objects and metadata, and creates
  provenance/evidence used by later answers.
- Workers consume queued jobs and update tenant-scoped state.
- Operators scrape health/metrics and correlate logs and trace context.
- Privileged actors run retention, decommission, migration, backup, and restore
  workflows.
- CI builds images and release metadata that operators later deploy.

## Threats, expected controls, and open evidence

| Threat | Expected control | MVP-013 status / residual risk |
|---|---|---|
| Cross-organization object access or identifier substitution | Organization-scoped querysets and authorization at every entry point and worker | The release authorization matrix covers API, search, Canvas, MCP, artifacts, source and credential revocation; deployment identity configuration remains operator-owned. |
| Privilege escalation through membership, scope, token, or service identity | Central permission checks, least privilege, lifecycle revocation, audited administration | Decommission revokes these objects and the synthetic permission-leak response completed; restored credentials still require operator review. |
| Credential theft, replay, or leakage | Short exposure, secure storage, redaction, rotation/revocation, TLS | Canary scans and the synthetic rotation/revocation exercise passed; deployment secret delivery remains operator-owned. |
| Unauthenticated or abusive load | Pre-auth and actor-scoped rate limits with safe proxy attribution | PostgreSQL process-shared limits and stable responses passed; deployment-sized capacity and abuse testing remain post-MVP work. |
| Source-content or prompt injection influencing generated output | Preserve source boundaries/provenance; treat retrieved content as untrusted; apply authorization before retrieval | Five hostile source classes remained inert across two tenants. Product users still must not interpret an answer as authorization or deployment approval. |
| Tenant data in logs or metric labels | Structured allowlisted telemetry and restricted telemetry access | Bounded canary review passed; metrics fail closed without a token and require HTTPS in production. Persistent telemetry pipeline controls remain post-MVP issue #39. |
| Proxy-header spoofing or cleartext operational access | Exact immediate-peer proxy IP allowlist, HTTPS redirect, secure cookies, protected metrics | Forwarded client/protocol headers are accepted only from exact configured IPs; deployment TLS termination and proxy isolation remain operator-owned. |
| Object-store substitution or database/object inconsistency | Authenticated storage access, checksummed paired generations, atomic active pointer, quiesced writers, failure-safe restore | Paired backup/restore and synthetic interruption/resume passed against Compose-managed MinIO; external object-store, external-writer and deployment-sized recovery remain issue #38. |
| Destructive retention/decommission mistakes | Server-owned time, two eligibility conditions, tenant-scoped cleanup, setup-authenticated human session, CSRF, two exact confirmations, audit evidence | Isolation and synthetic interruption/retry passed. Decommission remains unavailable after the 15-minute setup-authenticated session because no reauthentication flow exists; neither workflow claims legal erasure. |
| Supply-chain artifact tampering | Clean source, exact OCI revision, rebuilt skills, scans, SBOM, immutable version-and-digest references, signed provenance | Run `33781714974` published and verified v0.1.6 at source `e89b06aed8207cc32eee0eeebde4a2731f0c0203` and image `sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`. Its release asset records the approved 14-unique-CVE/18-high-or-critical-tuple risk decision through 2026-10-03; the tracked v0.1.0 exception is historical only. |
| Rollback to vulnerable or schema-incompatible software | Compatibility declaration, controlled migrations in a disposable restored database clone, paired backups, digest-pinned rollback | Reversal/forward passed in a guarded restored clone; v0.1.5 is the exact digest-pinned predecessor only where the declared schema boundary permits rollback. |
| Denial of service through expensive queries, queues, or storage exhaustion | Limits, timeouts, bounded work, health signals, capacity alerts and runbooks | Process metrics and basic limits are candidates; thresholds, dashboards, queue/storage capacity proof are missing. |
| Compromised operator or backup environment | Separation of duties, least privilege, encrypted backup, audit trails, key separation | Primarily deployment-owned; no claim of enforced separation or backup encryption is made. |

## Security invariants for release acceptance

- Every data and administrative path enforces organization isolation server-side.
- Authentication never substitutes for explicit authorization.
- Revocation applies consistently to web, API, MCP, workers, and restored data.
- Observability helps correlation without becoming a content or credential leak.
- A release artifact is traceable to reviewed source and identified by immutable
  digest; a mutable tag alone is insufficient.
- Retention, decommission, uninstall, backup expiry, and legal erasure are named
  distinctly and tested according to their actual semantics.
- Failures in dependencies, migrations, and administrative workflows fail safely
  and are operator-visible.

## Required review and evidence

Before closing MVP-013, link feature threat models, automated authorization and
abuse tests, dependency/container/secret scan reports, SBOM/provenance, a manual
sensitive-data review, install/upgrade/rollback/restore drills, and adversarial
acceptance results from the [requirements/evidence matrix](../releases/requirements-evidence-matrix.md).
Unresolved high-severity findings require remediation or an explicit, owned risk
decision; this document itself is not that decision.
