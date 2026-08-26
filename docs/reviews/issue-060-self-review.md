# Issue 60 self-review: exact-image vulnerability risk acceptance

## Decision and boundaries

Rishav Thakker, acting for AI Soft Work as release, security, application, and
platform owner, explicitly approved a 30-day exception on 2026-08-26. It expires
on 2026-09-25. The decision is temporary risk acceptance, not a claim that any
finding is fixed or not affected.

The committed authorization intentionally does not contain a source commit or
image digest: either value would change when committed or embedded into the
image and create a self-reference loop. After GHCR returns the immutable digest,
the release environment generates `vulnerability-risk-acceptance.json` from the
exact image scan, then regenerates the manifest and checksums before attesting
every artifact.

## Exact accepted baseline

The final reviewed scan contains 13 CVE identifiers and 16 HIGH/CRITICAL package
tuples. Every tuple has no scanner-recorded fixed version. The checked-in record
retains the per-CVE severity, package set, rationale, reachable residual risk,
and compensating runtime controls. The generated artifact additionally retains
the installed version, scanner status, fixed-version field, scan SHA-256, v0.1.0
version, source commit, GHCR digest and digest-qualified reference.

## Abuse and bypass review

- Future-dated, expired, or over-30-day approvals fail before waiver generation.
- Approval identity and all four accountable roles are exact, not caller input.
- Removed, added, repackaged, or severity-changed tuples fail exact comparison.
- Any scanner-recorded fixed version fails instead of being waived.
- The generated artifact accepts only the exact `ghcr.io/rishavt/anva@sha256:…`
  reference and matching digest, preventing tag, registry, or digest replay.
- Version/source/digest/scan identity is generated at release time. Changing the
  artifact afterward invalidates the manifest checksum and attestation.
- GitHub's protected `release` environment remains the human publication control.
  No credential, signature key, or approver-controlled string enters the image.
- Expiry uses UTC calendar dates. The gate is valid through 2026-09-25 UTC and
  fails beginning 2026-09-26 UTC.

## Verification

Focused release policy/workflow tests cover exact identity, tuple inventory,
dates, no-fix state, fixed-version rejection, output determinism, checksum
inclusion, workflow ordering and attestation. Ruff and mypy cover the changed
Python surface. The release workflow performs the authoritative fresh scan and
digest binding; this document does not claim a digest before publication.
