# Product threat model

This umbrella model records the security assumptions and unresolved risks for
the MVP-013 release candidate. It complements feature-specific models under
this directory; it does not declare those controls effective or the release
production-ready.

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
| Cross-organization object access or identifier substitution | Organization-scoped querysets and authorization at every entry point and worker | Candidate controls exist; complete negative-path evidence is pending. |
| Privilege escalation through membership, scope, token, or service identity | Central permission checks, least privilege, lifecycle revocation, audited administration | Candidate decommission revokes these objects; race and restoration behavior remain unverified. |
| Credential theft, replay, or leakage | Short exposure, secure storage, redaction, rotation/revocation, TLS | Deployment secret delivery and rotation procedures are not demonstrated by MVP-013 docs alone. |
| Unauthenticated or abusive load | Pre-auth and actor-scoped rate limits with safe proxy attribution | PostgreSQL fixed-window limits and stable responses have focused coverage; deployed multi-process capacity and abuse exercises remain open. |
| Source-content or prompt injection influencing generated output | Preserve source boundaries/provenance; treat retrieved content as untrusted; apply authorization before retrieval | Product users must not interpret an answer as an authorization or deployment approval. Adversarial evaluation remains release evidence. |
| Tenant data in logs or metric labels | Structured allowlisted telemetry and restricted telemetry access | Metrics fail closed without a token and require HTTPS in production. Application access logs are disabled while structured request and server-error output is retained in bounded Compose logs. Manual sensitive-data review and operational pipeline controls remain pending. |
| Proxy-header spoofing or cleartext operational access | Exact immediate-peer proxy IP allowlist, HTTPS redirect, secure cookies, protected metrics | Forwarded client/protocol headers are accepted only from exact configured IPs; deployment TLS termination and proxy isolation remain operator-owned. |
| Object-store substitution or database/object inconsistency | Authenticated storage access, checksummed paired generations, atomic active pointer, quiesced writers, failure-safe restore | Current worktree drills passed atomic generation/pointer preservation, failed-restore stop, and successful paired restore/resume against Compose-managed MinIO. Exact-commit revalidation is pending; external object-store backup, external writers, and transaction-level consistency are not covered. |
| Destructive retention/decommission mistakes | Server-owned time, two eligibility conditions, tenant-scoped cleanup, setup-authenticated human session, CSRF, two exact confirmations, audit evidence | Retention requires both explicit expiry and the organization minimum and cleans only that tenant's rate buckets. Bearer/CLI decommission is rejected. The only authentication timestamp currently comes from one-time setup, and no post-setup reauthentication flow exists, so decommission cannot run after 15 minutes. Neither workflow physically erases governed content; interruption and recovery evidence remain open. |
| Supply-chain artifact tampering | Clean source, exact OCI revision, rebuilt skills, scans, SBOM, immutable version-and-digest references, signed provenance | Run `33596661334` published and verified `v0.1.0` at source `d919...` and image digest `sha256:29af...`, including the approved exact 13-CVE/16-tuple no-fix baseline through 2026-09-25 and standard/custom attestations. Metadata repair #74 changes no product bytes, risk, tag, or image. |
| Rollback to vulnerable or schema-incompatible software | Compatibility declaration, controlled migrations in a disposable restored database clone, paired backups, digest-pinned rollback | The current worktree rehearsal passed reversal/forward in a guarded disposable clone, removed its resources, and left the live database at head. Exact-commit revalidation, older-application compatibility, and published digest rollback remain open. |
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
