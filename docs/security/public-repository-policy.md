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

The owner explicitly chose to retain existing Git history without rewriting or
re-attributing it. That preserves classified historical synthetic evaluator
fixtures, public package metadata, and operator-local paths. The all-ref review
found no potentially real credential, but that result is not a waiver for a new
secret or prohibited current-tree content.

Before changing repository visibility, minimize hosted refs to the reviewed
set, scan every retained ref, scan a fresh clone and its exported public tree,
and review GitHub issues, Actions logs/artifacts, releases, packages, caches,
and forks as separate disclosure surfaces. The machine-readable inventory and
non-destructive keep/delete proposal are in
[`history-rewrite-plan.json`](history-rewrite-plan.json); despite its retained
filename, it records the explicit **no-rewrite** decision. Gitleaks remains a
fail-closed gate with only exact-fingerprint exceptions.
