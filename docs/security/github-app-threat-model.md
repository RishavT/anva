# Threat model: GitHub App adapter

## Assets and trust boundaries

Protected assets are tenant/repository mapping, webhook secrets, the App private key, short-lived
installation tokens, exact pull-request and commit identity, assurance history, outbound write
intent, and audit history. Webhook bodies, pull-request text and diffs, fork metadata, provider
responses, human comments, and network failures are hostile. The API, core worker, GitHub worker,
PostgreSQL, and GitHub are separate trust boundaries.

## Threats and controls

| Threat | Control | Verification |
| --- | --- | --- |
| Forged webhook | HMAC-SHA256 over exact raw bytes; constant-time comparison; parsing and tenant lookup occur only after verification | Signature-order unit/integration tests |
| Replay or delivery-ID collision | Globally unique canonical delivery UUID plus checksum/event/installation comparison in a transaction | Replay, collision, and concurrent-delivery tests |
| Webhook tenant-routing spoof | After operator-assisted setup, tenant derives only from a prebound installation and repository derives only from its numeric prebound mapping; unmapped events receive a non-oracular acknowledgement | Cross-tenant database and unmapped-event tests |
| Spoofed setup callback | MVP App is private and has no setup/callback URL; deployment operator independently verifies installation/account/repository IDs in GitHub before using the admin binding API | Manifest contract and runbook review |
| Malicious/oversized JSON | 1 MiB body limit; duplicate-key, depth, node, string, event/action and normalized-field bounds | Hostile webhook parser tests |
| Stale event regresses a PR | Pull-request events fetch current provider truth; core revision identity deduplicates identical current input | Out-of-order delivery test |
| Fork receives credentials or executes code | Credentials stay in the dedicated server worker; tokens are base-repository scoped; diff is read and stored but never executed; no workflow/artifact dispatch | Fork boundary and no-network/no-execution tests |
| Prompt injection | PR prose/diff remains untrusted data in the existing evaluator envelope and never becomes worker instructions | Existing manual-assurance injection suite |
| Human spoofs Anva marker | Comment adoption requires both exact marker prefix and configured App-bot author | Fake/live-client adoption tests |
| Duplicate or ambiguous write | Frozen payload hash/idempotency key, one current projection, row lease, append-only attempts, same-App adoption after ambiguous response | Idempotency, ambiguity, and concurrent-claim tests |
| Stale/revoked write escapes | Dispatch rechecks current publication, PR head, run/report, repository, installation, service identity, and revocation while locked before client construction | New-head and revocation-without-network tests |
| Credential leaks to another process/log | Compose mounts the private key only in `github-worker`; webhook secrets only in API; token/key formats and configured secrets are redacted | Compose isolation and logging tests |
| Provider redirects/SSRF | Live origin is fixed to `https://api.github.com`; repository paths come from validated stored bindings; redirects are not accepted as configurable origins | Live-client validation tests |
| Provider outage or rate limit | Safe error codes only, bounded timeouts/responses, persisted retry schedule and maximum attempts | Rate-limit and retry tests |
| Cross-tenant database graft | Composite `(organization_id, id)` foreign keys cover every GitHub relation | PostgreSQL constraint test |
| Historical rewrite | Delivery, observations, and attempts have application and PostgreSQL immutability guards; write-intent content is frozen | Direct database immutability tests |

## Incident response

Disable the GitHub worker, revoke the App installation or repository binding, and rotate the
webhook secret and App key independently. Preserve delivery UUIDs, processing IDs, write-intent
IDs, attempt history, request IDs, and audit events. Do not copy response bodies or credentials
into tickets. Re-deliver verified events only after mapping and credentials are restored; stale
head checks still apply.

## Residual risks and limitations

- Live GitHub testing is not part of the deterministic MVP gate; behavior is verified through the
  client contract and fake.
- Public/self-service installation is not supported. The binding API is not cryptographic proof of
  GitHub-account ownership; exposing it without the documented operator verification could permit
  an authorized Anva admin to misbind another installation. A future flow must verify the installer
  with a GitHub user access token as described in
  [GitHub's setup URL guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).
- Public GitHub is the only supported API origin.
- Check/comment adoption examines at most 100 current provider results and fails closed on
  ambiguity.
- GitHub webhook authenticity proves GitHub delivery, not truth of user-authored PR prose or code.
- The adapter reads a diff server-side but does not execute code or fetch workflow artifacts.
- Operational retention and deletion schedules remain deployment policy.
