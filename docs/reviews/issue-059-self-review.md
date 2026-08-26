# Issue 59 self-review: public repository readiness

## Scope and result

This change prepares the current tracked tree for an intentional public release
without changing GitHub visibility, settings, refs, tags, or releases. It adds
the proprietary legal/support boundary, removes operator-local evidence, pins
CI actions, and makes the remaining secret-scan exceptions exact and auditable.

## Secret classification

Gitleaks scanned 131 reachable commits and reported 31 findings before the
allowlist. They are repeated historical instances of 16 current-tree findings:

- 10 deliberately synthetic secret-handling fixtures or canaries;
- 4 public Debian base-image GPG metadata strings in generated scanner output;
- 1 opaque, non-secret Anva access-scope identifier in generated evidence; and
- 1 explicitly synthetic hidden-evaluation marker.

No potentially real credential was found, so this review does not request
credential rotation. Values are intentionally omitted. Exact fingerprints—not
path-wide or rule-wide suppressions—are recorded in `.gitleaksignore`. After
removing generated evidence, the staged public tree retains only the 10
synthetic test findings. A moved, edited, or new finding fails closed.

## Content and privacy review

The removed directories contained raw host stdout/stderr, executable and
worktree paths, environment captures, hidden grader/oracle material, raw agent
transcripts, or bulk generated vulnerability evidence. They are not required to
build, test, understand, or install Anva. Sanitized product reviews, public
contracts, curated screenshots, and threat models remain tracked.

`.gitignore` now excludes local worktrees and generated evidence, and the public
content policy prohibits private/customer data and raw evaluator artifacts.
The current tracked tree contains no operator-specific absolute path.

## Supply-chain and contribution review

- `LICENSE` remains consistent with `pyproject.toml` and deliberately grants no
  open-source license.
- `NOTICE` identifies direct third-party components and makes the exact release
  SBOM authoritative for transitive inventory.
- Security disclosure, support, and contribution terms name AI Soft Work and
  the approved contact addresses.
- Every workflow action is pinned to an immutable 40-character commit SHA.
- CI is read-only and does not persist checkout credentials. The documented
  fork threat model separates untrusted PR execution from the protected,
  approval-gated, keyless release environment.

## Verification

- Staged-tree Gitleaks scan: zero unallowlisted findings.
- All-history Gitleaks scan: 131 commits, zero unallowlisted findings.
- Docker policy and release tests: 26 passed.
- Docker Actionlint 1.7.7: passed with no findings.
- Docker Compose configuration and `git diff --check`: passed.

## Explicitly unresolved destructive/external work

`docs/security/history-rewrite-plan.json` inventories the exact affected path
groups and commits, current ref scope, proposed AI Soft Work re-attribution, and
required fresh-clone verification. It is a plan only. Before visibility changes,
a human must explicitly authorize the write freeze, mirror-clone rewrite,
coordinated force-push, invalidation of stale hosted artifacts/caches, and fork
coordination. GitHub branch protection, default token permissions, release
environment reviewers, and visibility must also be configured and independently
verified through GitHub settings.
