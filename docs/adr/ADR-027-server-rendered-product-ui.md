# ADR-027: Server-rendered product UI and human sessions

- Status: Accepted
- Date: 2026-07-31
- Owners: Product Engineering and Security

## Context

Anva needs a complete operating surface for setup, knowledge, sources, review,
work, policy, assurance, skills, and audit. The existing product boundary
forbids a separate Node application, and the existing repository bearer token
is a service credential with an exact repository/action boundary. Treating that
token as a browser identity would collapse human role, organization membership,
CSRF, revocation, and audit semantics.

## Decision

Build the product as semantic Django templates, CSS, and small progressive
enhancements. Views are thin HTTP adapters over `ProductUIFacade`; templates do
not query tenant models. The facade authorizes repository and access-scope
visibility before returning list rows, counts, details, or mutation targets.

The one-time local bootstrap establishes a Django session containing only
opaque `User.id` and `Organization.id`. Every request re-resolves an active
user, membership, and database role into an `ActorContext` with actor type
`USER`. Browser forms use same-site, HTTP-only session/CSRF cookies and Django
CSRF protection. Repository access tokens and `Authorization` headers cannot
establish human sessions.

Setup is the only current session-entry mechanism. After logout or expiry, the
access page truthfully reports that operator-assisted re-entry is required; no
password, OAuth, SSO, or GitHub sign-in is claimed.

The main product is an attention queue. Explorer and entity pages show
freshness, uncertainty, provenance, and an accessible one-hop relationship
list. The interactive Canvas remains MVP-012. Knowledge changes use existing
governed transitions; corrections create explicit repository/scope-bound
proposals. Assurance leads with exact commits, currentness, blockers, evidence,
and limitations and never claims merge, deploy, or safety authority.

## Consequences

- No Node runtime, client router, browser token store, or parallel domain API is
  introduced.
- Permission filtering is centralized and testable before presentation.
- Useful navigation and forms continue to work without JavaScript.
- A future approved authenticator can establish the same minimal session
  without changing authorization or product facades.
- Audit is a distinct privileged action; ordinary viewers do not receive audit
  contents.
- Browser compatibility adds an isolated Selenium/Chromium test image, not a
  production dependency.

## Rejected alternatives

- Service bearer token in a browser session: loses human authority semantics
  and creates token-exfiltration risk.
- Client-rendered SPA: duplicates the Python domain boundary and adds an
  unnecessary runtime/build system.
- Template-owned ORM queries: makes authorization ordering difficult to prove.
- Fabricated GitHub/OAuth login: claims an authenticator that does not exist.
- Pulling Canvas into this release: weakens the issue boundary and accessible
  list-first seam.
