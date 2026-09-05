# Current release readiness

## Published v0.1.6

Anva `v0.1.6` is published and immutable:

- tag/source: `v0.1.6` / `e89b06aed8207cc32eee0eeebde4a2731f0c0203`;
- image: `ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`;
- protected release run: [33781714974](https://github.com/RishavT/anva/actions/runs/33781714974);
- the exact published risk set received an explicit RishavT decision before
  protected publication;
- 12 public assets with checksum closure, SBOMs, scans, risk decision, standard
  provenance, and supplemental source attestations;
- protected operator signoff: [33910747236](https://github.com/RishavT/anva/actions/runs/33910747236),
  with issue #44 completed and exact drill resources removed.

The separately generated schema-v2 manifest retains
`publication_status=generated_unpublished` because that field describes the
build-stage bytes before registry or Release mutation. It is not the current
publication status. The hosted release, digest, attestations, and successful
post-publication verification are authoritative for publication.

## Current main and v0.1.7 preparation

Current source contains post-v0.1.6 fixes and documentation. None changes the
immutable v0.1.6 tag, image, artifacts, risk decision, or operator ledger.
`v0.1.7` is the next patch/fix-forward version. It is **not published** and has
no candidate tag, image, decision, approval, or Release until a separately
reviewed preparation reaches the protected workflow.

| Gate | v0.1.6 evidence | v0.1.7 disposition |
| --- | --- | --- |
| Candidate identity | Exact `e89b06a` tag/source verified | Pending a future reviewed source and immutable tag |
| Build and scan | Deterministic build, scan and SBOM jobs succeeded in `33781714974` | Must be generated afresh |
| Residual risk | Exact digest-bound RishavT decision published and attested | Must not replay v0.1.6 approval |
| Publication | Protected publication and verification succeeded | Pending a future protected release run |
| Operator acceptance | Drill/signoff `33910747236` completed | Reuse is forbidden if a future release changes the applicable boundary |

## Historical release sequence

- `v0.1.0` is published at source `d919a2ca8fee32cbd2c0746ca8fcf3fed83920ac`.
- `v0.1.1` (`d813c9b75923285761cfc3ec1105e63ca98aea0e`) was aborted
  after runs `33691370693` and `33698109859`; both were cancelled with zero
  approvals and no release.
- `v0.1.2` (`53f58e6bc01b0b5ac8316f030ba17048285049b6`) received
  exactly one RishavT `Build and attest` environment approval in
  `33703772407`, then failed exact-candidate binding. It produced no generated
  or attested risk decision and received no publish/verify approval.
- `v0.1.3` (`ae6310a942b96ca0173d66cd452b09ec218b0118`) received
  exactly one RishavT `Build and attest` environment approval in
  `33713418248`, then failed decision-attestation readback. It received zero
  Publish or Verify approvals. No v0.1.3 GHCR image or GitHub Release exists.
- `v0.1.4` (`098e7727d4c307a8bbf25c05c36b0d27e25b4274`) received
  exactly one RishavT `Build and attest` environment approval in
  `33718942806`. It passed immediate attestation readback but failed the
  mode-0600 auth bind for registry copy. It received zero Publish or Verify
  approvals. No v0.1.4 GHCR image or GitHub Release exists.
- `v0.1.5` is the published rollback predecessor at source
  `491cdd7830a7f4d6af7140f6a4744f95c80c46a9` and digest
  `sha256:19488230c6f7900cda33bd11adc7f1ad824d23b77ee87fd65ac883cd0dacc725`.

## Deferred boundary

Issues #37–#40 remain legitimate post-MVP work for session re-entry, external
object-store recovery, durable observability, and managed deployment. Issue #49
retains a correctness-preserving performance follow-up and the unchanged 250 ms
p95 target. None is represented as completed by v0.1.6.
