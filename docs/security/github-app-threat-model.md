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
| Concurrent stale provider read regresses a PR | A transaction-scoped PostgreSQL advisory lock serializes each binding/PR refresh; the diff must be bracketed by identical full provider snapshots; a final mismatch rolls back all local effects and retries | Delayed-head, synchronized-duplicate, bracket-change, and final-rollback tests |
| Suspension leaves access or work active | Suspension locks the installation/bindings, deactivates the principal, grants, bindings and repository context, cancels derived work/writes, and marks later deliveries ignored; every credential-bearing provider read/write holds locked authority, so suspension either wins before network or waits for that authorized transaction to drain | Suspension lifecycle, blocked-fetch/diff, and outbound-drain tests |
| Delayed lifecycle delivery overwrites newer state | Under the installation lock, suspend/unsuspend processing first rejects any older delivery superseded by a later accepted suspend, unsuspend, or delete delivery, including retries of a previously failed old delivery | Delayed and failed-retry lifecycle ordering tests |
| Webhook lifecycle action disagrees with GitHub | Suspend/unsuspend is reconciled against the fixed numeric installation's current provider state using an App-JWT-only GET; disagreement is durably `IGNORED` as `provider_lifecycle_state_mismatch` without authority mutation | Provider-state mismatch tests in both directions |
| Lifecycle lookup failure causes unsafe mutation | Network/provider errors and malformed, oversized, wrong-installation, or invalid timestamp responses fail closed before authority mutation and enter bounded durable retry/failure handling; no installation token is minted | Provider-error and live-client hostile-response tests |
| Unsuspension silently resumes stale work | Only a provider-confirmed installation unsuspend event restores the active principal, eligible non-revoked bindings/repositories, and the reviewed grants; cancelled work/credentials are not restored, and durable suspension audit time prevents an unmaterialized pre-suspension completed run from being published later | Suspension/unsuspend lifecycle and pre-suspension completed-run tests |
| Fork receives credentials or executes code | Credentials stay in the dedicated server worker; tokens are base-repository scoped; diff is read and stored but never executed; no workflow/artifact dispatch | Fork boundary and no-network/no-execution tests |
| Prompt injection | PR prose/diff remains untrusted data in the existing evaluator envelope and never becomes worker instructions | Existing manual-assurance injection suite |
| Human spoofs Anva marker | Comment adoption requires both exact marker prefix and configured App-bot author | Fake/live-client adoption tests |
| Duplicate or ambiguous write | Frozen payload hash/idempotency key, one current projection, row lease, append-only attempts, same-App adoption after ambiguous response | Idempotency, ambiguity, and concurrent-claim tests |
| Stale/revoked write escapes | Dispatch rechecks current publication, PR head, run/report, repository, installation, service identity, and revocation while locked before client construction | New-head and revocation-without-network tests |
| Credential leaks to another process/log | Compose mounts the private key only in `github-worker`; webhook secrets only in API; token/key formats and configured secrets are redacted | Compose isolation and logging tests |
| Provider redirects leak a bearer token | Live origin is fixed to `https://api.github.com`; repository paths come from validated stored bindings; the credential-bearing opener rejects every redirect, including same-origin redirects | Cross-origin and same-origin redirect tests |
| Malformed or unsafe token response | Installation tokens must match bounded `ghs_` syntax and have a timezone-aware expiry 30 seconds to 65 minutes in the future; oversized/malformed responses fail with safe codes | Token syntax, expiry, response-size, and malformed-response tests |
| Provider outage or rate limit | Safe error codes only, bounded timeouts/responses, persisted retry schedule and maximum attempts | Rate-limit and retry tests |
| Cross-tenant database graft | Composite `(organization_id, id)` foreign keys cover every GitHub relation | PostgreSQL constraint test |
| Historical rewrite | Delivery, observations, and attempts have application and PostgreSQL immutability guards; write-intent content is frozen | Direct database immutability tests |

## Incident response

Disable the GitHub worker, revoke the App installation or repository binding, and rotate the
webhook secret and App key independently. Preserve delivery UUIDs, processing IDs, write-intent
IDs, attempt history, request IDs, and audit events. Do not copy response bodies or credentials
into tickets. Re-deliver verified events only after mapping and credentials are restored; stale
head checks still apply.

For a temporary GitHub suspension, wait for the suspension event to finish: it is the drain point
for any provider read or write transaction that had already acquired authority. After a verified
unsuspend event, reconnect sources, issue fresh repository credentials, and deliberately redeliver
or restart only the work that should run; cancelled work and unmaterialized pre-suspension
completed runs are not replayed automatically.

If lifecycle processing fails or is ignored, preserve its delivery/processing identifiers and
inspect the safe reason code. Confirm current installation state directly in GitHub before
redelivery. Do not manually flip Anva authority state or mint an installation token to diagnose a
suspended installation; reconciliation uses the App JWT in the isolated worker.

## Residual risks and limitations

- Live GitHub testing is not part of the deterministic MVP gate; behavior is verified through the
  client contract and fake.
- Public/self-service installation is not supported. The binding API is not cryptographic proof of
  GitHub-account ownership; exposing it without the documented operator verification could permit
  an authorized Anva admin to misbind another installation. A future flow must verify the installer
  with a GitHub user access token as described in
  [GitHub's setup URL guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).
- Public GitHub is the only supported API origin.
- Suspend/unsuspend convergence depends on the public GitHub installation endpoint. Outages or
  malformed responses delay local lifecycle mutation while preserving the prior state and durable
  retry evidence.
- Synchronization fails transiently if provider state does not stabilize within three bracket
  attempts. This preserves current-head integrity at the cost of delayed ingestion during rapid
  force-push or metadata churn.
- Check/comment adoption examines at most 100 current provider results and fails closed on
  ambiguity.
- GitHub webhook authenticity proves GitHub delivery, not truth of user-authored PR prose or code.
- The adapter reads a diff server-side but does not execute code or fetch workflow artifacts.
- Operational retention and deletion schedules remain deployment policy.
