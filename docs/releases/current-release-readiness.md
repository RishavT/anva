# Current v0.1.3 release readiness

Anva `v0.1.3` is in release preparation. No tag, candidate image, risk
approval, protected-environment approval, or GitHub Release is claimed here.

The preparation baseline is `30c87a65f86b8bfc50244acb62f3bc0c1baa2af7`.
It contains the supported decommission retry, the synthetic operator drill
harness, hardened release evidence, deterministic container construction from
#91, and the single-byte OCI lineage from #96. The final candidate identity will be the full reviewed
`main` commit supplied to the release dispatch and must equal the commit
resolved from a newly created immutable `v0.1.3` tag.

## Blocking gates

| Gate | Current disposition |
| --- | --- |
| Candidate identity | Pending reviewed merge and exact tag-to-commit binding. |
| Candidate build and scan | Pending a fresh deterministic double-build and scan from the reviewed v0.1.3 source. The v0.1.1 runs `33691370693` and `33698109859` exposed build nondeterminism and were cancelled with zero approvals; #91 corrected that machinery after the immutable v0.1.1 tag. The v0.1.2 run `33703772407` received exactly one RishavT `Build and attest` environment approval, then failed exact-candidate binding because its protected rebuild diverged. It produced no generated or attested risk decision, received no publish/verify approval, and published nothing. #96 corrected the OCI lineage after the immutable v0.1.2 tag. Both fixes are included only through this fix-forward candidate. |
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
evidence and are not retargeted to v0.1.3.

## Historical v0.1.1 identity

The immutable v0.1.1 tag remains bound to
`d813c9b75923285761cfc3ec1105e63ca98aea0e`. It is an aborted, unpublished
record: no GHCR image or GitHub Release exists for v0.1.1, and its cancelled
proposals cannot authorize or supply v0.1.3.

## Historical v0.1.2 identity

The immutable v0.1.2 tag remains bound to
`53f58e6bc01b0b5ac8316f030ba17048285049b6`. It is aborted and unpublished.
Release run `33703772407` proposed candidate digest
`sha256:caf1e15ade5c65fe507c6ff019064b0c4165904e760535cf3c690033d7a0acd9`,
but its protected rebuild produced
`sha256:cfc7dfaf74c28f18f3fb0fc29eb09c6d7a5b23f7b88183c70deec7af79fafc49`.
The exact-candidate binding failed closed before publication. #96 landed after
that immutable tag and is included only by fixing forward to v0.1.3. Run
`33703772407` had exactly one RishavT `Build and attest` environment approval,
but no generated or attested risk decision, publish/verify approval, GHCR
image, or GitHub Release. No v0.1.2 evidence can authorize v0.1.3.
