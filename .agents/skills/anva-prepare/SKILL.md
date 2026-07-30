---
name: anva-prepare
description: Prepare an implementation task with live, permission-filtered Anva context.
  Use when starting an issue, clarifying requirements, defining acceptance criteria,
  or planning verification; do not use it to claim approval or authoritative assurance.
---

# Anva Prepare

Use portable skill version `1.0.0` with Anva MCP contract `1` for phase `PREPARE`. Keep the existing coding agent in control; Anva supplies bounded context and review-only proposals.

<!-- anva-workflow-fingerprint: 249fb8a5cb19b32f7735df31e348d0150b58ba4aba130d879262bc52180152b3 -->

## Record invocation context

Make the skill version, host and host version, MCP contract version, repository, context-packet identifier and schema version, and workflow phase discoverable in the result. Label an unknown host version `UNVERIFIED`; do not invent compatibility.

## Follow the workflow

1. Resolve the exact credential-bound repository before looking up any task.
2. Resolve the work item by its opaque identifier or external key.
3. Request one minimum relevant PREPARE context packet for the stated task.
4. Use packet citations and assertion explanations for every material organizational claim.
5. Separate confirmed facts, requirements, assumptions, conflicts, and limitations.
6. Return acceptance criteria plus implementation and verification plans within approved scope.

## Use only these Anva tools

- `anva.resolve_repository` (read)
- `anva.resolve_work_item` (read)
- `anva.get_context_packet` (read)
- `anva.get_requirements` (read)
- `anva.get_repository_profile` (read)
- `anva.get_policy_bundle` (read)
- `anva.explain_assertion` (read)
- `anva.get_source_excerpt` (read)

Call `anva.resolve_repository`, then `anva.resolve_work_item`, then `anva.get_context_packet` when those tools are listed. Use detail tools only as needed. Never use a direct Anva HTTP or database fallback.

## Stop at these boundaries

- The organization or repository cannot be resolved.
- The task has a material unresolved knowledge conflict.
- A blocking requirement or policy remains ambiguous.

## Degrade safely

- Label organizational alignment UNVERIFIED and make no Anva-derived claim.
- Offer a local-only draft only after the user explicitly accepts degraded work.
- List unavailable authentication, repository, contract, and provenance as limitations.

## Return the structured result

Follow `references/output.schema.json` and include these visible sections:

- `Problem`
- `Confirmed requirements`
- `Out of scope`
- `Assumptions`
- `Conflicts`
- `Acceptance criteria`
- `Affected systems and owners`
- `Relevant decisions and policies`
- `Implementation plan`
- `Verification plan`
- `Unresolved questions`
- `Limitations`
- `Anva sources`

Every material fact, requirement, policy, owner, decision, or finding must carry normalized provenance. If URL, locator, content hash, or observation time is missing, move the item to limitations instead of citing an internal UUID.

<!-- ANVA HOST ADAPTER START -->
Select the matching canonical tools from the configured `anva` MCP server; Codex may display a host-qualified tool name. Require host approval for every proposal tool. If the server is not configured, stop and use the documented `codex mcp add` handoff.
<!-- ANVA HOST ADAPTER END -->

## Read supporting rules as needed

- Before any Anva tool call, read [boundary.md](references/boundary.md).
- Before rendering material claims, read [provenance.md](references/provenance.md).
- On any unavailable or denied state, read [safe-unavailable.md](references/safe-unavailable.md).
