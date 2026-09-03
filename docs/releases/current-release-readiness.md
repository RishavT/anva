# Current v0.1.5 release readiness

Anva `v0.1.5` is in release preparation. No tag, candidate image, risk
approval, protected-environment approval, or GitHub Release is claimed here.

The preparation baseline is `72b4af7318eb27797e8d957fa0b9de803206fed1`.
It contains deterministic construction from #91, single-byte OCI lineage from
#96, protected decision verification from #101, and the least-privilege Skopeo
auth-file identity fix from #106. The final candidate identity will be the full
reviewed `main` commit supplied to release dispatch and must equal the commit
resolved from a newly created immutable `v0.1.5` tag.

## Blocking gates

| Gate | Current disposition |
| --- | --- |
| Candidate identity | Pending reviewed merge and exact tag-to-commit binding. |
| Candidate build and scan | Pending a fresh deterministic double-build and scan from reviewed v0.1.5 source. The aborted v0.1.1 through v0.1.4 runs are historical only; #91, #96, #101, and #106 are included only through fix-forward candidates. |
| Residual risk | Pending a fresh attested proposal followed by an explicit RishavT decision through personal protected-environment approval for the exact source, digest, report, tuple set, runtime controls, and expiry. GitHub's exact-run approval record and proposal SHA must bind the generated decision. No prior decision or approval can be replayed. |
| Publication | Pending a separate protected `release` environment approval after the build and attest job succeeds. |
| Human acceptance #44 | Still separate. Harness success cannot approve or finalize it. |

The workflow remains fail closed until these gates are satisfied. Publication
must produce checksums, SPDX/CycloneDX SBOMs, standard GitHub provenance,
supplemental source predicates, immutable GHCR identity, and clean install and
demo verification from downloaded assets.

## Historical v0.1.0 identity

The published v0.1.0 tag remains bound to
`d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac` and image digest
`sha256:29af794b9fda21e75461866437dd4853db54b54072252d0df9aa2eed77807c2d`.
Its metadata-repair workflow and risk decision are immutable historical
evidence and are not retargeted to v0.1.5.

## Historical v0.1.1 identity

The immutable v0.1.1 tag remains bound to
`d813c9b75923285761cfc3ec1105e63ca98aea0e`. It is aborted and unpublished.
Runs `33691370693` and `33698109859` exposed build nondeterminism and were
cancelled with zero approvals. No v0.1.1 GHCR image or GitHub Release exists.

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
readback because the verification step lacked its image-digest binding. It
received zero Publish or Verify approvals. No v0.1.3 GHCR image or GitHub
Release exists.

## Historical v0.1.4 identity

The immutable v0.1.4 tag remains bound to
`098e7727d4c307a8bbf25c05c36b0d27e25b4274`. Run `33718942806` received exactly
one RishavT `Build and attest` environment approval, explicitly excluding
Publish and Verify. The protected build reproduced the exact candidate,
generated and attested the risk decision, and passed immediate attestation
readback. Its first Skopeo registry copy then failed because the dropped-
capability container could not read the runner-owned mode-0600 auth bind. It
received zero Publish or Verify approvals. No v0.1.4 GHCR image or GitHub
Release exists. #106 landed after the immutable tag and is included only by
fixing forward to v0.1.5; no v0.1.4 approval or decision authorizes v0.1.5.
