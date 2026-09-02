# Current v0.1.1 release readiness

Anva `v0.1.1` is in release preparation. No tag, candidate image, risk
approval, protected-environment approval, or GitHub Release is claimed here.

The preparation baseline is `3bea51afbfb0e3128cd600b107ff661cc85fa438`.
It contains the supported decommission retry from #73/PR #76 and the synthetic
operator drill harness from #80/PR #81. The final candidate identity is the
full reviewed `main` commit supplied to the release dispatch and must equal the
commit resolved from the existing `v0.1.1` tag.

## Blocking gates

| Gate | Current disposition |
| --- | --- |
| Candidate identity | Pending reviewed merge and exact tag-to-commit binding. |
| Candidate build and scan | Pending two clean builds and a fresh run-owned Trivy database against the exact image. |
| Residual risk | Pending an attested proposal followed by an explicit RishavT decision through personal protected-environment approval for the exact source, digest, report, tuple set, runtime controls, and expiry. GitHub's exact-run approval record and proposal SHA must bind the generated decision. The v0.1.0 decision is invalid here. |
| Publication | Pending separate tag creation and protected `release` environment approval. |
| Human acceptance #44 | Still separate. Harness success cannot approve or finalize it. |

The workflow remains fail closed until these gates are satisfied. Publication
must produce checksums, SPDX/CycloneDX SBOMs, standard GitHub provenance,
supplemental source predicates, immutable GHCR identity, and a clean install and
demo verification from the downloaded assets.

## Historical v0.1.0 identity

The published v0.1.0 tag remains bound to
`d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac` and image digest
`sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d`.
Its metadata-repair workflow and risk decision are immutable historical
evidence and are not retargeted to v0.1.1.
