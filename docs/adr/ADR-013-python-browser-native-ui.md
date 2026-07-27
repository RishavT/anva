# ADR-013: Python core with browser-native UI

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

Anva needs a polished, accessible management interface without adding a second application
runtime and package ecosystem before interactive canvas requirements are validated.

## Decision

Python 3.12 and Django are the core application runtime. The initial UI uses Django
templates, semantic HTML, CSS, and browser-native JavaScript. There is no frontend package
manager, transpiler, bundler, or build pipeline.

JavaScript modules or focused browser libraries may be introduced only through a later ADR
when a concrete interaction requires them. No server or developer workflow may require a
host JavaScript runtime.

## Consequences

- A fresh clone requires only Docker and Compose.
- UI delivery remains simple, cacheable, and accessible.
- Complex canvas behavior will require a deliberate architecture decision later.
- Browser support must target standards implemented by the supported evergreen browsers.

## Alternatives considered

- Separate single-page application: deferred because the foundation has no validated canvas
  interaction to justify its operational cost.
- Go backend: not selected because Django's application, ORM, migrations, admin primitives,
  and Python model ecosystem better fit the approved implementation plan.

## Security and privacy

Removing a frontend supply chain reduces foundation attack surface. Server-side
authorization remains mandatory; hidden or absent controls must never be treated as
authorization.
