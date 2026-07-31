# Issue 011 self-review

## Scope and outcome

MVP-011 adds the complete server-rendered product surface requested by issue
11: one-time organization setup, onboarding, attention home, Explorer and
entity detail, source health, knowledge review, repository profile, work and
policy views, assurance list/detail/timeline, developer-skill diagnostics, and
privileged audit search. It stays inside the Python/Django modular monolith and
adds no Node runtime, frontend compiler, client router, or coding-agent UI.

The interactive relationship Canvas remains MVP-012. This release provides the
semantic one-hop relationship table/list seam and never renders hidden node
details into the page.

## Design rationale

The visual system is a restrained “night map”: warm near-black surfaces,
off-white strategic serif headings, compact sans-serif operational copy,
monospaced exact identities, signal-lime navigation/attention, and
teal/amber/coral state accents. Lines, nodes, and small geometric marks connect
the interface to organizational knowledge without imitating a generic admin
dashboard. Status always includes text and a symbol; color is redundant.

The 240-pixel desktop rail keeps the operating model stable across every page.
Below 760 pixels it becomes a keyboard-operable overlay with a visible menu
control. Content grids collapse, tables scroll inside labelled regions, exact
hashes wrap, and 390-pixel browser evidence has no horizontal document
overflow. CSS includes visible `:focus-visible`, reduced-motion, forced-colors,
and print behavior. The two small JavaScript enhancements only toggle mobile
navigation and focus validation summaries; navigation and forms remain useful
without JavaScript.

The home page prioritizes decisions rather than activity. Assurance similarly
leads with current readiness, exact head/evaluated commits, blockers, and the
human-review boundary before checks, findings, evidence, versions, limitations,
and timeline.

## Architecture and authorization

- Thin views adapt HTTP to `ProductUIFacade`; templates perform no ORM query.
- Every list starts from currently visible repositories and authorizes
  source/access-scope rows before returning records or counts.
- Details use tenant-safe lookups and stable unavailable errors.
- Audit has a separate `audit.view` action restricted to organization
  administrators and security reviewers.
- Corrections use the existing governed proposal service and add an explicit
  organization/repository/access-scope/assertion binding. Generic unscoped
  proposals never appear in the review queue.
- Profile confirmation, assertion decisions, source sync/revocation, and
  correction submission use existing domain authorization, audit, revision,
  and invalidation paths.

Human sessions contain only user and organization UUIDs. Each request
re-resolves the active user, active membership, and database role into a
`USER` actor. Service bearer headers cannot enter this boundary. CSRF protects
forms; cookies and browser headers are hardened. A forged form actor/role is
ignored and a viewer cannot review knowledge.

The correction integration test exposed one audit-path defect during review:
the generic proposal creator initially received the raw `web-session:` path,
which the audit secret guard correctly rejected. The facade now records the
fresh `knowledge.propose` authorization decision path.

## Verification evidence

- Migration: fresh apply succeeded; `0015 → 0014` rollback succeeded; reapply
  to `0015` succeeded; the full graph then reported no work.
- Static gates: all 155 files formatted, Ruff clean, mypy clean across 136
  files, no migration drift, 24 contract artifacts verified, and skill
  distributions reported no drift.
- Focused product/security/accessibility/application-shell gate: 16/16 pass.
- Full ordinary test image: 604 passed, 3 expected skips in 163.64 seconds;
  total branch coverage is 85%. The skips are the unmounted external corpus,
  the separate Chromium stage, and the optional live MCP Compose profile.
- The subsequent composite-tenant migration hardening has an additional
  passing cross-tenant graft regression; the complete product integration file
  is 11/11.
- Browser image: one 30-second end-to-end Selenium journey passes setup,
  search, entity/provenance, review decision, blocked assurance, diagnostics,
  safe error, keyboard focus, and 390-pixel navigation.
- Browser accessibility/quality: Chrome accessibility-tree inspection finds
  no unnamed visible link or button; the final run has no unexpected severe
  console entry and no horizontal document overflow. Static tests cover
  semantic landmarks, skip links, labels, reduced motion, forced colors,
  status text, and secret-free progressive enhancement.
- Screenshots: nine PNGs under
  `docs/evidence/issue-011/screenshots` cover all required browser states and
  total approximately 2.0 MB.
- Production target: the project wheel and `anva` console script are installed,
  bytecode and static assets are collected, the runtime user is
  `uid=10001(anva)`, and Django's deployment check exits successfully. TLS
  redirect and HSTS remain an ingress decision, so the check reports their
  standard warnings.
- Compose resources during the gate: isolated PostgreSQL and MinIO remained
  healthy and used approximately 297 MiB combined. Runtime, test, and isolated
  browser images are approximately 355 MB, 603 MB, and 1.29 GB respectively,
  including shared layers.

## Security and privacy review

- No plaintext bootstrap secret, token, cookie, credential ID, environment
  variable value, or source payload is stored in the session, JavaScript,
  screenshot evidence, or UI diagnostics.
- Setup retry values omit the secret; logout flushes the session; membership
  deactivation is effective on the next request.
- CSP denies bases, objects, framing, external forms/scripts/styles, and
  non-same-origin connections. Frame denial, content-sniffing denial,
  same-origin opener/referrer policy, and browser capability denial add
  defense in depth.
- Cross-tenant entity deep links and unauthorized viewer mutations return the
  same safe 404 without leaking content or applying changes.
- Stale mutations return 409 and leave governed state unchanged.
- Assurance makes no merge, deploy, safety, or code-execution claim.

## Current limitations

- Setup is a one-time local entry mechanism. Password, SSO, OAuth, and GitHub
  login are not implemented or claimed; operator-assisted re-entry remains
  required after logout/expiry.
- GitHub App installation and source authorization remain operator workflows.
  The onboarding UI reports stored completion only.
- Anva does not execute customer code. Tests and evidence appear only when
  externally supplied or produced through existing governed services.
- The browser stage currently uses Debian Chromium/ChromeDriver; additional
  engine-specific visual regression infrastructure is future work.
- Distributed rate limiting, CSP reporting, session-device management, and TLS
  enforcement are deployment/ingress or follow-up concerns.
- Canvas visualization and graph editing remain explicitly outside MVP-011.

## Conclusion

The result meets the issue's semantic HTML, attention-first assurance,
keyboard/accessibility, server-authorization, Selenium, design-evidence, and
Compose requirements while preserving the established knowledge, proposal,
and assurance authority boundaries.
