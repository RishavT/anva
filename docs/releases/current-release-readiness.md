# Current v0.1.4 release readiness

Anva `v0.1.4` is in release preparation. No tag, candidate image, risk
approval, protected-environment approval, or GitHub Release is claimed here.

The preparation baseline is `c3203aead34111ed9d2ba5b66b7a92fa4ecd9687`.
It contains the supported decommission retry, the synthetic operator drill
harness, hardened release evidence, deterministic container construction from
#91, the single-byte OCI lineage from #96, and the protected decision
verification binding from #101. The final candidate identity will be the full
reviewed `main` commit supplied to the release dispatch and must equal the
commit resolved from a newly created immutable `v0.1.4` tag.

## Blocking gates

| Gate | Current disposition |
| --- | --- |
| Candidate identity | Pending reviewed merge and exact tag-to-commit binding. |
| Candidate build and scan | Pending a fresh deterministic double-build and scan from reviewed v0.1.4 source. The aborted v0.1.1, v0.1.2, and v0.1.3 runs are historical only. #91, #96, and #101 landed after their respective immutable failed tags and are included only through fix-forward candidates. |
| Residual risk | Pending a fresh attested proposal followed by an explicit RishavT decision through personal protected-environment approval for the exact source, digest, report, tuple set, runtime controls, and expiry. GitHub's exact-run approval record and proposal SHA must bind the generated decision. No prior decision or approval can be replayed. |
| Publication | Pending a separate protected `release` environment approval after the build and attest job succeeds. |
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
evidence and are not retargeted to v0.1.4.

## Historical v0.1.1 identity

The immutable v0.1.1 tag remains bound to
`d813c9b75923285761cfc3ec1105e63ca98aea0e`. It is an aborted, unpublished
record. Runs `33691370693` and `33698109859` exposed build nondeterminism and
were cancelled with zero approvals. No v0.1.1 GHCR image or GitHub Release
exists, and its proposals cannot authorize or supply v0.1.4.

## Historical v0.1.2 identity

The immutable v0.1.2 tag remains bound to
`53f58e6bc01b0b5ac8316f030ba17048285049b6`. It is aborted and unpublished.
Run `33703772407` received exactly one RishavT `Build and attest` environment
approval, then failed exact-candidate binding when its protected rebuild
diverged. It produced no generated or attested risk decision, received no
publish/verify approval, and published no GHCR image or GitHub Release.

## Historical v0.1.3 identity

The immutable v0.1.3 tag remains bound to
`ae6310a942b96ca0173d66cd452b09ec218b0118`. Run `33713418248` received exactly
one RishavT `Build and attest` environment approval. The protected build reached
decision-attestation creation and upload, then failed closed during immediate
readback because the verification step lacked its image-digest environment
binding. It received zero Publish or Verify approvals. No v0.1.3 GHCR image or
GitHub Release exists. #101 landed after the immutable tag and is included only
by fixing forward to v0.1.4; no v0.1.3 evidence authorizes v0.1.4.
