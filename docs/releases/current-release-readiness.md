# Current v0.1.0 release readiness

Anva `v0.1.0` is technically published and verified. This audit distinguishes
that completed publication from the still-open human-owned acceptance gates.

## Authoritative public identities

| Identity | Value |
| --- | --- |
| Tag and product source | `v0.1.0` -> `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac` |
| Immutable image | `ghcr.io/rishavt/anva@sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d` |
| Release workflow | [successful run 33596661334](https://github.com/RishavT/anva/actions/runs/33596661334) |
| GitHub Release | [Anva 0.1.0](https://github.com/RishavT/anva/releases/tag/v0.1.0), 13 public assets |

Run `33596661334` completed build, scan/risk binding, GHCR publication,
standard and custom attestations, GitHub Release creation, download/checksum
verification, digest pull, fresh install, migrations, readiness, and demo
lifecycle. The exact 13-CVE/16-package-tuple no-fix decision is bound to this
source and digest through 2026-09-25; drift, a recorded fix, or expiry invalidates it.

## Remaining gates

| Gate | Current disposition |
| --- | --- |
| [#43](https://github.com/RishavT/anva/issues/43) | Open. Aggregate the exact-current broad, browser, 31-case, prompt-injection, and independent-review evidence. Publication does not close it. |
| [#44](https://github.com/RishavT/anva/issues/44) | Open. Named ownership exists, but the timestamped human operator exercise and deployment TLS/proxy evidence do not. Workflow lifecycle automation is not a substitute. |
| [#13](https://github.com/RishavT/anva/issues/13) | Open pending honest reconciliation of applicable gates, including #43/#44. |

Publication issue #42 and its technical descendants are complete. Historical
local seal identities remain evidence history, not the current public release
identity. Post-MVP deferrals #37-#40 and #49 remain unchanged.

## Metadata correction

The initial public release body and metadata assets retained obsolete candidate
claims that publication had not happened. [#74](https://github.com/RishavT/anva/issues/74)
repairs only the Release body and the closed three-file metadata set
(`RELEASE_NOTES.md`, `release-manifest.json`, and `SHA256SUMS`) through the
reviewed, protected `release` environment. It leaves the other ten assets,
product tag/source, image/runtime, risk decision, and old attestations unchanged.
The repair must not execute until its pull request is reviewed and merged.
