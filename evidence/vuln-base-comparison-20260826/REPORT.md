# Runtime base-image vulnerability remediation comparison

## Decision

Replace the digest-pinned Bookworm runtime base with the digest-pinned Trixie
base and explicitly install Debian's fixed OpenSSL packages. This is a narrow
release-closure remediation, not a general dependency refresh.

The comparison used unchanged Anva source commit
`9250545ceaf661aa37caabdfdd259d5caf2aa2f0` and Trivy `0.64.1` pinned at
`sha256:a8ca29078522f30393bdb34225e4c0994d38f37083be81a42da3a2a7e1488e9e`.
The vulnerability database was freshly downloaded on 2026-08-26 UTC.

## Exact inputs and outputs

- Prior release candidate:
  `sha256:93993b0682a2f81807ec17e303f1707e43f663595ff047ccdacabd92897751b3`.
- Trixie base:
  `python:3.12-slim-trixie@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17`.
- Patched comparison image:
  `sha256:66b227103046f2f7f67022cbf2e2e7fd99467b98c575d46f90c3f6442a247f27`.
  This is a local comparison image, not a published or final release artifact.
- Unpatched-Trixie scan SHA-256:
  `00f03c10db530ed24435307004d4dca34abc0a4af3193923c1130cfda4feb726`.
- Patched-Trixie scan SHA-256:
  `a1f4177ba0d7924db86032f240d395a2140845169c37631c32d34a2044721e6c`.

## Scan comparison

| Candidate | Total tuples | Critical | High | Medium | Low | Unknown | Fixable high/critical |
|---|---:|---:|---:|---:|---:|---:|---:|
| Bookworm final candidate | 236 | 5 | 31 | 83 | 107 | 10 | 0 |
| Digest-pinned Trixie, before OpenSSL update | 168 | 3 | 16 | 56 | 69 | 24 | 3 |
| Digest-pinned Trixie plus fixed OpenSSL | 138 | 3 | 13 | 53 | 66 | 3 | 0 |

The proposed image therefore removes 20 of 36 high/critical tuples (55.6%),
including two critical tuples, and removes 98 of 236 total tuples (41.5%). It
introduces no new high/critical vulnerability ID relative to the prior image.

The patched scan contains neither `CVE-2026-14456` nor `CVE-2026-53613`.
It also removes the prior `CVE-2026-53615`, `CVE-2023-45853`, and
`CVE-2025-7458` findings. Package proof from the comparison image records:

- `libssl3t64`, `openssl`, and `openssl-provider-legacy` at
  `3.5.7-1~deb13u2`;
- `mount` and `util-linux` at `2.41.5-0+deb13u1`;
- `libsqlite3-0` at `3.46.1-7+deb13u1`;
- `perl-base` at `5.40.1-6`.

Debian's security tracker identifies `3.5.7-1~deb13u2` as the fixed Trixie
OpenSSL version for `CVE-2026-14456` and `2.41.5-0+deb13u1` as the fixed
Trixie util-linux version for `CVE-2026-53613`. It still marks Bookworm's
versions as vulnerable, so a Bookworm false-positive VEX was rejected.

## Runtime and regression observations

The hardened comparison container ran as UID/GID 10001 with a read-only root,
all capabilities dropped, no-new-privileges, and no network. Python reported
OpenSSL 3.5.7 and SQLite 3.46.1. `/etc/fstab` contained only the base-system
unconfigured marker. Setuid executables remain present, including `mount`, so
supported deployment hardening remains required even though the fixed package
eliminates the reported util-linux CVE.

The exact test image built successfully. Ruff passed. The container-only unit
run produced 646 passes, one expected skip, and 26 failures: 23 required source
tree files deliberately absent from the image, while the remaining three match
the already documented environment-sensitive Host-policy and token-pepper
tests. This is useful compatibility evidence but is not a substitute for the
normal source-mounted regression matrix. A final commit-bound image must be
built and receive the existing release regression gates before publication.

## Residual findings and invalidation

The patched scan retains 16 high/critical tuples across 13 IDs, all with no
scanner-recorded fixed version. The fresh SQLite findings `CVE-2026-11822` and
`CVE-2026-11824` remain present and require explicit disposition; neither is
silently covered by the older 14-ID exception document.

This comparison does not renew vulnerability exceptions and does not approve
residual risk. Any change to the base digest, apt package versions, source
commit, lockfile, runtime configuration, architecture, or scanner database
requires a fresh exact-image scan and disposition review.
