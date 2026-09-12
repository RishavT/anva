# GitHub-native v0.1.7 preparation

The active release workflow now targets v0.1.7. Preparation does not create a tag,
dispatch the workflow, approve a gate, or publish an artifact. Track preparation
and pre-publication evidence in the [candidate checklist](v0.1.7-checklist.md)
against one reviewed candidate. The workflow and post-publication checks complete
the remaining publication items.

Use the immutable identity, two-build reproducibility, fresh scan/proposal,
protected approval, attestation, publication and verification sequence described
in the [historical v0.1.6 procedure](github-native-release.md), with the new tag
and candidate commit. Do not reuse historical artifacts, decisions or approvals.
The workflow still rejects mismatched source/tag/version identities and refuses
to overwrite an existing release.

After the separately reviewed candidate tag exists, the intended dispatch is:

```sh
ANVA_SOURCE_COMMIT=<reviewed-full-40-character-commit>
gh workflow run release.yml --repo rishavt/anva --ref main \
  -f tag=v0.1.7 -f source_commit="$ANVA_SOURCE_COMMIT" \
  -f risk_expires_on=YYYY-MM-DD
```

Generate and review a fresh exact-candidate proposal and disposition. The prior
digest-bound v0.1.6 risk approval cannot authorize these new bytes. The protected
workflow's existing owner and approval checks remain in force.

Until publication is independently verified, consumer install guidance continues
to point at published v0.1.6. The v0.1.7 rollback predecessor is its verified image
`ghcr.io/rishavt/anva@sha256:916ea866ac290af35b5e97a6bd875fb365b832cb171284cf701a128b5ea524fb`;
establish schema compatibility or use paired restore. Never overwrite old releases.
