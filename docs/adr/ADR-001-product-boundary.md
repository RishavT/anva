# ADR-001: Anva product boundary

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

Anva connects organizational intent, decisions, requirements, systems, and code so that
people and AI can begin changes with relevant context. The product plan deliberately avoids
building another hosted coding-agent harness.

## Decision

Anva consists of:

1. A permission-aware organizational knowledge system and management canvas.
2. Portable skills that let developers use their existing supported coding agents.
3. Server-owned pull-request assurance at the CI boundary.

The foundation may establish API, background worker, MCP, and CLI process boundaries, but
it must not introduce a coding-agent runtime, general workflow engine, graph database,
customer-code sandbox, or a claim that code is production-ready without stored evidence.

## Alternatives considered

- Hosted coding-agent harness: rejected because it expands scope and competes with developer
  tools customers already use.
- General orchestration platform: rejected because it weakens the organizational-context
  focus.

## Consequences

- Agent execution remains the customer's choice.
- Trustworthy knowledge, authorization, provenance, and evidence remain Anva's core.
- The MCP process exists before its protocol so deployment topology can stabilize, but its
  protocol route explicitly reports that it is not implemented.

## Security impact

The boundary avoids executing customer code. Later knowledge and assurance features must
enforce tenant scope inside domain operations. Introducing customer-code execution would
create a new trust boundary and requires a separate sandbox decision.

## Privacy impact

No customer content is ingested by this foundation. Later knowledge features must minimize
content sent to external systems, preserve provenance and access scope, and implement
tenant-level retention, correction, and deletion.

## Operational impact

API, worker, MCP, and CLI processes share one image and dependency lock. Operators must not
treat process health as evidence that MCP, knowledge, or assurance behavior exists. The MCP
protocol route remains an explicit `501 Not Implemented` until its milestone is complete.

## Revisit conditions

Revisit if a validated pilot cannot work through existing coding agents and CI, if Anva is
asked to execute customer code, or if the product boundary changes to hosted orchestration.
Any change requires a new ADR and threat model before implementation.
