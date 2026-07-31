# Product UI threat model

## Scope and assets

This covers setup, Django human sessions, every `/app` page and form, static
assets, safe error states, and the product facade. Protected assets are tenant
knowledge and counts, provenance, source configuration, repository profiles,
work/policy/assurance records, audit history, human authority, session state,
and bootstrap/service credentials.

## Trust boundaries

- Browsers, request fields, query strings, identifiers, referrers, and source
  text are untrusted.
- The session stores user and organization identifiers only.
- Active membership, active user, and database role are resolved per request.
- `ProductUIFacade` is the presentation data boundary; templates are not an
  authorization boundary.
- Existing domain services remain authoritative for governed transitions,
  proposals, ingestion, assurance, and retrieval.

## Threats and controls

### Service credential used as a human

The UI ignores bearer headers for sign-in. Sessions never store credential IDs,
tokens, roles, or permitted actions. Actors are always freshly constructed as
`USER`; deactivated memberships invalidate the next request.

### CSRF and session theft

Django CSRF middleware protects every POST. Session and CSRF cookies are
HTTP-only and same-site; production cookies are secure. Session keys rotate at
bootstrap and flush at logout. Sessions expire after twelve hours and refresh
only while used.

### Tenant, repository, source, or scope probing

Tenant lookups include organization ownership. Facade lists first establish
visible repositories and then authorize each row's source/access scope before
presentation. Foreign, missing, revoked, and unauthorized records share a
stable 404 without object detail. Generic unscoped proposals are excluded.

### Form authority forgery and stale updates

Actor, role, organization, and authorization fields in forms are ignored.
Writes use the session actor and existing authorization services. Revision
fields enforce optimistic concurrency and return a stable 409 without applying
stale changes. Corrections remain source-linked, scope-bound proposals.

### Secret disclosure

Bootstrap secrets are password inputs, are never copied into safe retry values,
and never enter the session. Skill diagnostics render compatibility metadata
only and contain no token input or browser storage. JavaScript uses no
`localStorage`, `sessionStorage`, cookies, authorization headers, or network
calls.

### XSS, framing, and browser capability abuse

Django template escaping remains enabled. No source text is marked safe. A
restrictive CSP allows only same-origin scripts/styles/forms/connections,
denies objects, bases, and framing, and permits data images only. Frame denial,
content sniffing denial, same-origin opener isolation, a same-origin referrer
policy, and camera/microphone/geolocation denial add defense in depth.

### Misleading readiness or unavailable integrations

Assurance always displays exact head/evaluated commits, currentness, blockers,
evidence, and limitations. It explicitly disclaims merge/deploy/safety
authority. GitHub binding, source indexing, skill use, and assurance onboarding
steps derive from stored observations and remain visibly incomplete when
unavailable.

## Residual risks

- Setup is a local one-time authenticator, not a general re-entry system.
- Distributed rate limiting, enterprise SSO, CSP reporting, and session device
  management remain ingress or follow-up work.
- Human administrators with broad organization roles can see all scopes
  granted by that role; least-privilege role assignment remains operational.
- The visual relationship Canvas remains out of scope; this release provides
  the accessible list seam only.

## Verification

- Integration: session redaction, active membership re-resolution, bearer
  rejection, CSRF rejection, forged viewer mutation, stale revisions, foreign
  tenant deep links, stable errors, headers, and cookie attributes.
- Static accessibility: landmarks, labels, skip links, focus visibility,
  reduced motion, forced colors, status text, and no secret-capable JavaScript.
- Browser: setup/search/review/assurance/skills/error/mobile flow, console gate,
  Chrome accessibility tree names, keyboard focus, and horizontal overflow.
