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

## Consequences

- Agent execution remains the customer's choice.
- Trustworthy knowledge, authorization, provenance, and evidence remain Anva's core.
- The MCP process exists before its protocol so deployment topology can stabilize, but its
  protocol route explicitly reports that it is not implemented.

## Alternatives considered

- Hosted coding-agent harness: rejected because it expands scope and competes with developer
  tools customers already use.
- General orchestration platform: rejected because it weakens the organizational-context
  focus.

## Security and privacy

The boundary avoids executing customer code. Later knowledge and assurance features must
enforce tenant scope in domain operations and preserve provenance, retention, and deletion.
