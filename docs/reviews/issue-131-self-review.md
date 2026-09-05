# Issue 131 self-review

## Scope and cause

Issue #128 added server-derived change facets to persisted context packet requests and
items. The v1 MCP output contract stayed closed but did not declare those additions, so
the official `anva.get_context_packet` Streamable HTTP response failed its own output
validator. The broad-corpus reproduction reached the public `dispatch_tool` boundary
and failed first at `packet.request`, then exposed the complete set of affected item
payload fields.

## Producer-to-contract inventory

| Producer | Newly emitted shape | Contract treatment |
| --- | --- | --- |
| request | `retrieval_facets[]` with label, query, anchors, required and coverage flags | Optional closed objects; 1–8 facets, bounded strings, 0–16 unique anchors, required facets require an anchor |
| every item | `retrieval_facets[]`, `required_context_facets[]` | Optional unique label arrays; 8 retrieval labels and up to 9 required labels because conflicts add the synthetic `conflict` facet |
| source excerpt | facet label, zero-based position, match mode | Optional typed fields; position 0–7 and two explicit match modes |
| conflict | left/right assertion value and review/staleness state | Optional closed sides using the existing public assertion-value schema and explicit state enums |

The exact property-set parameterization covers assertion, legacy decision reference,
relationship, source, and conflict payload variants. All objects remain closed; no
`additionalProperties` relaxation was introduced.

## Compatibility and security review

- All added contract properties are optional, so prior valid v1 packets remain valid.
- The public example exercises the new fields and all generated MCP/acceptance artifacts
  are regenerated from the authoritative Python contract.
- Arbitrary nested assertion values in conflict sides are converted on a deep copy to
  the existing bounded canonical public representation, matching top-level assertions.
- Secret/private-control scanning still runs before normalization, and persisted
  artifacts are not mutated.
- Authorization, retrieval, selection, packet byte/item/token/citation bounds, and ACL
  queries are unchanged.
- Empty, duplicate, oversized, malformed, and unknown facet metadata is rejected.

## Verification

- Docker Compose Ruff formatting and lint: passed.
- Focused MCP/schema/normalization plus full 107-document broad-corpus integration:
  31 passed.
- Contract generation wrote all 33 artifacts successfully with example validation.
- Broad unit/contract selection: 872 passed and 3 environment-dependent skips. Four
  release-Makefile tests initially failed because the sustainable reused image lacked
  `/usr/bin/make`; rerunning exactly those four with the existing current test-target
  image passed 4/4.

Independent review and hosted CI remain required before merge.
