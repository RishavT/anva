# Current v0.1.2 release readiness

Anva `v0.1.2` is in release preparation. No tag, candidate image, risk
approval, protected-environment approval, or GitHub Release is claimed here.

The preparation baseline is `0302bda3e3bfb57383c2d554ba87a71aef4824d5`.
It contains the supported decommission retry, the synthetic operator drill
harness, hardened release evidence, and the deterministic container build
machinery from #91. The final candidate identity will be the full reviewed
`main` commit supplied to the release dispatch and must equal the commit
resolved from a newly created immutable `v0.1.2` tag.

## Blocking gates

| Gate | Current disposition |
| --- | --- |
| Candidate identity | Pending reviewed merge and exact tag-to-commit binding. |
| Candidate build and scan | Pending a fresh deterministic double-build and scan from the reviewed v0.1.2 source. The v0.1.1 runs `33691370693` and `33698109859` exposed differing digests from the same source and were cancelled with zero approvals and no publication. #91 corrected the build machinery after the immutable v0.1.1 tag, so it is included only through this fix-forward candidate. |
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
evidence and are not retargeted to v0.1.2.

## Historical v0.1.1 identity

The immutable v0.1.1 tag remains bound to
`d813c9b75923285761cfc3ec1105e63ca98aea0e`. It is an aborted, unpublished
record: no GHCR image or GitHub Release exists for v0.1.1, and its cancelled
proposals cannot authorize or supply v0.1.2.
