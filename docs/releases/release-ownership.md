# MVP release ownership and escalation

This record names the accountable human for the self-hosted Anva MVP release.
The separately enforced vulnerability-risk decision is recorded in
`docs/security/vulnerability-exceptions.json`; this record does not claim a
completed operator exercise. The technical `v0.1.0` publication is complete.

## Organization and owner

- Organization: AI Soft Work (`https://aisoftwork.com`; website may not yet be live)
- Owner: Rishav Thakker
- Primary release and incident contact: `rishav@aisoftwork.com`
- Alternate contact: `i@rishavthakker.com`

For the MVP, Rishav Thakker is the named:

- release owner;
- security incident owner and vulnerability adjudicator;
- application owner;
- platform and operations/on-call owner.

## Escalation path

Operational and security events escalate directly to the primary contact, with
the alternate contact used when the primary channel is unavailable. The owner
is responsible for release stop/go decisions, incident coordination, operator
communications, and selecting additional responders as the organization grows.

Do not put credentials, customer content, vulnerability exploit material, or
private incident data into email subjects or public issue comments. Preserve
timestamps, correlation identifiers, affected release identities, decisions,
and outcomes in the deployment-owned incident record.

## Separately enforced actions

Naming an owner does not perform or prove the operator exercises required by
issue #44. Rishav Thakker separately approved the exact v0.1.0 residual no-fix
risk set on 2026-08-26 through 2026-09-25. Run `33596661334` generated the
digest-bound acceptance for source `d919...` and image `sha256:29af...`. Drift,
a recorded fix, or expiry still fails closed.

This ownership was supplied directly by Rishav Thakker on 2026-08-26 together
with authorization to release the product. GitHub Releases, GHCR, and
GitHub-native keyless attestations were used for the completed technical
publication under issue #42. That automation does not perform the #44 exercise.
