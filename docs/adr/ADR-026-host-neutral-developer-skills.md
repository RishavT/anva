# ADR-026: Host-neutral developer skills

- Status: Accepted
- Date: 2026-07-30
- Owners: Developer Experience and Security

## Context

Codex and Claude Code must guide the same Anva-backed prepare, build,
preflight, and learn workflows without a proprietary coding harness. Their
skill discovery, plugin manifests, invocation controls, and MCP setup differ.
Customer endpoints and credentials cannot be embedded in reusable packages.

MVP-009 already provides the authoritative versioned `dispatch_tool` MCP
facade, exact-repository bearer authorization, permission-safe context packets,
read-only discovery, and review-only proposals. A skill-specific ORM or HTTP
client would duplicate and weaken those controls.

## Decision

Maintain one versioned portable source under `packages/anva-skills`:

- `manifest.yaml` declares skill, MCP-contract, packet-schema, and tested-host
  versions;
- `workflows/*.yaml` declare phase, canonical tools, ordered steps, stops,
  degraded behavior, and outputs;
- `shared/` owns provenance, unavailable-state, evidence, and output schemas.

Generate thin adapters deterministically:

- Codex repository skills at `.agents/skills`, an installable
  `.codex-plugin/plugin.json` package, `agents/openai.yaml`, and repository
  marketplace metadata;
- Claude Code repository skills at `.claude/skills`, an installable
  `.claude-plugin/plugin.json` package, and marketplace metadata.

Host-only frontmatter and tool-name presentation are allowlisted differences.
Normalized workflow content must remain equal. `anva-learn` is explicit-only in
both hosts.

Keep remote MCP registration outside immutable plugin archives because no
single organization-neutral Anva endpoint exists. The Python installer copies
skills into an explicit destination and provides secret-free handoffs:

- Codex: `codex mcp add anva --url ... --bearer-token-env-var ANVA_TOKEN`;
- Claude Code: project `.mcp.json` with `${ANVA_MCP_URL}` and
  `Bearer ${ANVA_TOKEN}` references.

Packages contain no hooks, executables, Node metadata, tokens, endpoints, or
customer facts. Deterministic gzip/tar metadata and `SHA256SUMS` make releases
reproducible and inspectable.

All organizational reads and proposals use canonical MCP tools. The
unauthenticated `/diagnostics` route is the only client-side HTTP exception.
There is no `/capabilities` fallback and no direct ORM coupling.

## Host documentation verification

Revalidated on 2026-07-30 against current official documentation:

- [OpenAI build skills](https://developers.openai.com/plugins/build/skills)
- [OpenAI package plugins](https://developers.openai.com/plugins/build/plugins)
- [OpenAI Codex MCP](https://developers.openai.com/codex/mcp)
- [Anthropic Claude Code skills](https://code.claude.com/docs/en/slash-commands)
- [Anthropic plugins reference](https://code.claude.com/docs/en/plugins-reference)
- [Anthropic plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
- [Anthropic Claude Code MCP](https://code.claude.com/docs/en/mcp)

Local format validation targets Codex `0.145.0` and Claude Code `2.1.220`.
These are tested versions, not invented minimum supported versions. Unknown
host versions are reported `UNVERIFIED`.

## Consequences

- Both hosts retrieve the same authorized packet through one server boundary.
- Provider packaging can evolve without changing Anva domain invariants.
- Installers do not execute host CLIs, trust plugin hooks, or receive token
  values as arguments.
- Local preflight remains advisory and independent server assurance remains
  outside the skill.
- OAuth is not claimed: MVP-009 currently supports exact-repository bearer
  credentials. OAuth handoff remains follow-up scope.

## Rejected alternatives

- Byte-identical host packages: hides real metadata and invocation differences.
- Package a fixed MCP endpoint: leaks deployment policy and breaks portability.
- Bundle a local MCP proxy or coding harness: creates another authority path.
- Direct API/ORM fallback: bypasses the canonical facade and safe revocation.
- Automatic knowledge writes: violates explicit intent and human review.
