# GitHub App permissions review

Reviewed: 2026-07-30

The checked-in manifest at `deploy/github/app-manifest.yaml` is the maximum permission set approved
for MVP-008. The live token request narrows every token to one numeric repository ID and the same
explicit operation permissions; GitHub supplies the mandatory read-only metadata permission
implicitly.

| Permission | Level | Required use |
| --- | --- | --- |
| metadata | read | GitHub-required repository/App metadata |
| contents | read | Read the exact pull-request diff and commit-backed repository metadata |
| pull requests | read | Read current pull-request identity, head/base commits, state, and fork metadata |
| checks | write | Find, create, and update the Anva Check for the evaluated head |
| issues | write | Find, create, and update only the Anva-marked pull-request comment |
| actions | read | Observe bounded workflow-run metadata and evidence links |

The implementation does not request administration, members, organization administration,
deployments, environments, secrets, workflows write, or contents write. `pull_requests: write` is
accepted from an already-installed App snapshot for compatibility, but the checked-in manifest and
minted repository token request only `read`.

Any new event or provider operation requires updating this review, the manifest, token-mint
allowlist, setup validation, threat model, and tests before deployment. In particular, branch
protection management and organization-member discovery are not approved.

References: [GitHub App manifest parameters](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)
and [permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).
