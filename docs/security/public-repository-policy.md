# Public repository content policy

The public Anva repository contains only material needed to understand, build,
test, review, and install the product under the proprietary `LICENSE`.

## Allowed tracked content

- Product source, migrations, templates, static assets, and vendored assets with
  their license notices.
- Public contracts, host-neutral skills, deployment examples, and documentation.
- Deterministic tests using synthetic identities, domains, credentials, and data.
- Curated screenshots and compact, sanitized evidence summaries that disclose no
  private prompts, hidden graders, host paths, credentials, or customer content.
- CI/release automation and machine-readable security policy.

## Content that must not be tracked

- Credentials, cookies, private keys, signing material, or live access tokens.
- Customer or private-repository data and personal data not approved for public
  attribution.
- Raw agent transcripts, hidden evaluators, grader/oracle material, unredacted
  stdout/stderr, environment dumps, or absolute operator paths.
- Generated worktrees, caches, release output, scan databases, database backups,
  or bulk local evidence directories.

The narrow `.gitleaksignore` contains exact fingerprints for intentional
synthetic secret-handling tests. New or moved findings fail closed and require
human classification. A path-level or generic regex suppression is prohibited.

Before changing repository visibility, scan both the current tracked tree and
all refs, execute the approved history plan, re-scan a fresh clone, and review
GitHub issues, Actions logs/artifacts, releases, packages, caches, and forks as
separate disclosure surfaces.
