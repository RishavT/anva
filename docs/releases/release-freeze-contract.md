# Install-ready MVP release-freeze contract

This contract fixes the remaining boundary for the install-ready, self-hosted
MVP. It narrows release work; it does not replace the product requirements,
erase historical evidence, or turn a local result into a publication claim.

## Frozen scope

Feature behavior, public API and MCP contracts, UI journeys, data models and
migrations, and the external acceptance-harness protocol are frozen. New
features, generalized deployment modes, new evaluator orchestration, additional
case-state machinery, and cosmetic redesign are not release work.

## Allowed release-closure exceptions

Only these changes may enter the release candidate:

1. A correctness or security fix required by a failed fixed gate below.
2. Dependency or vulnerability remediation and time-bounded exception review.
3. Exact-candidate test, evidence, manifest, checksum, SBOM, provenance, tag,
   package, image, and installation corrections.
4. Documentation corrections that make claims match observed release behavior.

Every exception must name the failed gate, stay at the smallest practical
scope, and rerun only the affected lane plus its direct dependants. Anything
else is a post-MVP issue.

## Fixed acceptance evidence

The candidate is releasable only when one clean commit, tree, and immutable
image/package identity has:

- the Compose-owned product check, browser, security, migration, backup/restore,
  and lifecycle gates required by the release checklist;
- a fresh install from the artifacts that will actually be published, followed
  by representative UI, API, MCP, worker, upgrade/rollback, and uninstall checks;
- current vulnerability dispositions, release-wide secret-canary scanning,
  tenant/revocation isolation evidence, and the applicable security and
  operations reviews;
- deterministic import and replay of all 31 committed public acceptance cases,
  proving complete inventory, stable bindings, and clean public-result reading;
- one representative context-free manual assurance review, performed by an
  independent reviewer identity over the messy knowledge corpus, with the
  private oracle/grader excluded from product and reviewer context; and
- a signed or provenance-attested tag, registry/package digests, checksums, and
  a publication record bound to that same candidate.

The 31 cases provide breadth for corpus/import/replay behavior. They do **not**
require 31 separate human or native-agent review sessions. The representative
manual review provides the qualitative, context-free reviewer check; it does
not substitute for deterministic product, security, installation, or 31-case
replay evidence.

## Stop and retest rules

Stop changing a lane after one canonical run supplies the evidence above. Do
not repeat a successful case to improve presentation, accumulate roots, or add
confidence without a new risk. After a scoped fix, rerun the failed lane and
directly affected dependants; rerun the full gate only when candidate identity,
shared contracts, dependencies, migrations, authorization, packaging, or the
runtime image changed.

Retain one indexed canonical evidence root per candidate under the applicable
evidence policy. Superseded scratch roots are not additional acceptance
evidence. A failure may authorize a narrow release-closure exception; it does
not reopen feature, API, UI, data, or harness scope.
