# MVP-011 formal-review remediation evidence

This directory is deliberately separate from `../screenshots`. The nine original PR screenshots
remain byte-for-byte unchanged; remediation browser runs write only here.

## Fail-before proof

The isolated Compose project `anva-i11-remediate` reproduced the formal review findings before
implementation:

- focused reviewer suite: 8 failed, 2 passed;
- the valid sealed-scope permission PoC independently failed because `/app` serialized
  `CANARY-HIDDEN-SOURCE` and `CANARY-HIDDEN-ERROR`;
- exact correction retry created two proposal scopes;
- a missing configured MCP DNS name still rendered a compatible local-service claim;
- the 0014-to-0015 upgrade created zero product settings and profiles;
- semantic navigation, Compose forwarding, humanized labels, and wheel-runtime assertions failed.

## Pass-after proof

- focused product, migration, diagnostic, static, and smoke suite: 36 passed;
- stale correction: zero proposals, proposal scopes, audit events, and outbox events;
- concurrent exact correction retry: one canonical proposal and one set of side effects;
- strict formatting and Ruff: passed;
- strict mypy: passed across 141 source files;
- model-state drift: no changes detected;
- generated contracts: 24 artifacts and their examples verified;
- full coverage suite: 624 passed, 3 expected skips, 85% coverage;
- browser journey: passed in Chromium 150 at desktop, at 390px with script execution disabled,
  at 320px, and at an effective 320px layout under 200% browser zoom;
- production Compose: migrations completed and API, MCP, PostgreSQL, and MinIO were healthy;
- installed runtime: UID 10001, no `/app/src`, non-editable wheel import from `site-packages`,
  collected static assets, and compiled bytecode.

`SHA256SUMS` records the remediation screenshots. The CI result is recorded in the PR discussion
after the pushed commit is available.

## Final re-review follow-up

The final review at commit `54d7c0b4f893640d62a0a0f7cad310fbb187a39f` identified two
additional authorization-state gaps. The isolated Compose project `anva-i11-finalfix` captured
three fail-before regressions: an inaccessible GitHub binding affected product status, the source
revocation onboarding branch was unreachable, and the binding status API exposed an inaccessible
same-tenant binding.

The follow-up gates passed after centralizing active GitHub binding reads behind the actor's
authorized access-scope boundary and adding an identity-free source-health aggregate for authorized
revoked sources:

- exact fail-before/pass-after regression set: 3 failed, then 3 passed;
- affected product, GitHub, and architecture suites: 44 passed;
- database and migration upgrade suites: 2 passed;
- formatting, Ruff, strict mypy across 142 source files, model drift, 24 generated contracts,
  skill distribution, and Compose validation: passed;
- full coverage suite: 626 passed, 3 expected skips, 85% coverage;
- dedicated Chromium 150 journey: passed at desktop, 320px, and 200% browser zoom.

The eleven remediation screenshot hashes below were regenerated and verified. The original
`../screenshots` evidence set remains unchanged.
