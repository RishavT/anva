# GitHub Actions trust boundary

## Pull requests and forks

Pull-request workflows execute untrusted repository content. They receive only
the read-only `GITHUB_TOKEN`, do not persist checkout credentials, do not use
release secrets, do not publish packages, and must not use `pull_request_target`
to execute fork-controlled code. Fork pull requests require maintainer review
under repository settings. Workflow actions are pinned to immutable commit SHAs.

## Default token policy

Set repository Actions permissions to read-only by default. Individual jobs may
elevate only the permission needed for that job. CI requires `contents: read`.
No CI job receives package, attestation, identity-token, or content-write access.

## Release environment

The `release` environment is the only boundary allowed to publish Anva. Protect
it with Rishav Thakker as required reviewer, prevent self-review when another
reviewer becomes available, restrict deployment branches/tags to protected
`v*` tags, and keep environment secrets empty for the GitHub-native keyless
flow. The build job receives narrowly scoped `packages: write`,
`attestations: write`, and `id-token: write`; publication receives only
`contents: write`; verification is read-only.

Branch protection should require CI, prevent force pushes and deletion, require
review for workflow changes, and require conversation resolution. GitHub-hosted
OIDC and artifact attestations avoid a long-lived signing key. A release tag must
identify a commit reachable from protected `main`.
