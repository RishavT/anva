# Contributing to Anva

Thank you for your interest in Anva. This is a source-available proprietary
project, not an open-source project. Opening an issue or pull request does not
grant rights under the Anva license.

## Issues and pull requests

- Search existing issues before opening a focused report.
- Do not submit secrets, personal data, customer data, private repository
  content, raw agent transcripts, or host-environment captures.
- Discuss substantial changes in an issue before investing in implementation.
- Keep changes scoped, add tests, and update relevant documentation.
- Use synthetic fixtures only; clearly label fake credentials and domains.
- Sign commits with an identity you are authorized to publish.

By submitting a contribution, you represent that you have the right to submit
it and grant AI Soft Work a perpetual, worldwide, irrevocable, royalty-free
license to use, reproduce, modify, distribute, sublicense, and commercialize the
contribution as part of Anva. AI Soft Work is not obligated to accept it.

## Local verification

Development and tests run through Docker Compose. Start with:

```console
docker compose config --quiet
make ci
```

Before submitting, scan the tracked tree with the repository's exact Gitleaks
allowlist:

```console
gitleaks dir . --redact --no-banner
```

Security reports belong in the private process described in `SECURITY.md`, not
in a public pull request.
