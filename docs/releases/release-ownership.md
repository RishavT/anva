# MVP release ownership and escalation

This record names the accountable human for the self-hosted Anva MVP release.
The separately enforced vulnerability-risk decision is recorded in
`docs/security/vulnerability-exceptions.json`. The published v0.1.6 operator
exercise is recorded separately below.

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

## Separately enforced actions and completed exercise

Naming an owner alone did not perform the operator exercises required by issue
#44. Those exercises later completed against published v0.1.6 source
`e89b06aed8207cc32eee0eeebde4a2731f0c0203` and image
`ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`.
Protected signoff run `33910747236` records exact `release` approval by
`RishavT`; the final evidence records required decisions and zero-resource
cleanup. Issue #44 is complete.

Rishav Thakker separately approved the v0.1.6 digest-bound residual risk in
protected release run `33781714974`. Drift, a recorded fix, control change, or
expiry still fails closed; older release approvals are historical only.

This ownership was supplied directly by Rishav Thakker on 2026-08-26 together
with authorization to release the product. GitHub Releases, GHCR, and
GitHub-native keyless attestations provide the technical publication record;
the separately approved operator anchor provides the human exercise record.
