# Issue 61 self-review: public history and ref reconciliation

## Decisions preserved

Rishav Thakker, acting for AI Soft Work, explicitly chose not to rewrite or
re-attribute repository history. This change records that decision without
claiming historical objects were removed. The accepted residual exposure is
limited to classified synthetic evaluator fixtures, public operating-system
metadata, and old operator-local paths. The prior all-history review found no
potentially real credential, so no credential rotation is indicated.

This is not a secret-policy exception. Credentials, customer/private data,
signing material, and newly detected or moved secrets remain prohibited. The
narrow Gitleaks file continues to allow only exact fingerprints; all-ref and
fresh-clone/export scans remain mandatory before visibility changes.

## Remote inventory

The read-only inventory was taken while the GitHub repository was private.
Remote `main` was `184b2c7f526293d2c46f666ac47d7bad050fa1f4`, there were
13 additional branches and no tags. Each additional branch belongs to a merged
pull request. Their tips are not Git ancestors of current local `main` because
the pull requests used non-fast-forward integration; exact divergence counts
and PR associations are retained in the machine-readable record.

The proposal keeps only `refs/heads/main` and deletes the 13 already-merged
development branches before public visibility. It archives nothing. This lane
does not delete, archive, rewrite, force-push, tag, publish, or change settings.

## Vulnerability language

Tracked release guidance now consistently recognizes the owner-approved exact
13-CVE/16-HIGH-or-CRITICAL-tuple no-fix decision, valid from 2026-08-26 through
2026-09-25 UTC. The checked-in authorization cannot name a not-yet-published
digest. The release workflow must freshly reproduce the exact tuple set and
generate a source-, version-, scan-, and immutable-GHCR-digest-bound acceptance
artifact. Tuple drift, a scanner-recorded fix, changed controls, identity
mismatch, or expiry continues to fail closed.

## Review checklist

- No product, runtime, API, schema, dependency, or secret-gate behavior changed.
- The inventory includes every remote branch and tag observed after fetch.
- Every non-main remote branch has a merged PR association and an explicit
  proposed action; no proposal was executed.
- Current policy states the no-rewrite decision and residual exposure plainly.
- Vulnerability approval and generated digest-bound acceptance are not
  conflated.
- Validation evidence is recorded on issue #61 and in its closing comment.
