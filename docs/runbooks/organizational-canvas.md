# Runbook: Organizational Canvas

## Open and operate

Start the normal Compose topology, bootstrap an organization, connect at least
one authorized source, and complete an ingestion sync. Open **Canvas** in the
product navigation or visit `/app/canvas`.

- Select one or more visible repository boundaries, then filter by entity type,
  owner, status, risk, freshness, search text, and semantic layer.
- Choose a saved Strategy, Product-system, Initiative, Risk-policy,
  Change-history, or Custom view. A saved view is re-evaluated against current
  permissions and source state.
- Select a node to inspect ownership, provenance, freshness, conflicts, and
  bounded permitted relationships, decisions/policies, risks/incidents, active
  work/recent pull requests, history, reviewers, annotations, and contextual
  actions. A section-level bounded-context notice means additional permitted
  items were omitted; it never reveals their count or identity.
- Use **Fit**, zoom, pan, minimap, arrow keys, or drag nodes. **Save layout**
  appends a new presentation revision; it does not change canonical knowledge.
- Use **Focus here** or **Expand one hop** for progressive disclosure. The focus
  root and expansion depth are server-authorized and reflected in the URL.
- Set **As of** to bound entity creation and assertion/relationship observation
  time. Identity fields still reflect the current authorized entity row; this
  is not a full historical identity snapshot.
- Use **Why are these connected?** for one deterministic permitted path of at
  most six hops.
- Enter **Draw proposal**, choose a typed relationship, then drag from one node
  to another (or select the endpoints by keyboard). Review the resulting form's
  endpoints and current revisions; submission creates a governed proposal only.
- Ask a scoped organizational question from a selected node. Results use only
  its permitted one-hop context and bounded authorized Explorer search. The
  no-JavaScript Explorer form preserves the same selected-entity boundary.
- Add annotations to the current layout, then save a new revision to persist
  them. An annotation never changes canonical knowledge.
- A share links to the exact current revision but requires the recipient's
  current Anva authorization. An owner or current manager can revoke an active
  share; revocation is immediate and keeps audit history.

Without JavaScript, use the **Permitted nodes** and **Relationships** tables,
semantic GET form, path form, proposal form, and scoped Explorer question form.
The tables are also the keyboard/accessibility equivalent of the map.

## Operational limits

One projection accepts at most 100 repositories and returns at most 300 nodes,
600 relationships, and 750 KiB of UTF-8 JSON. Semantic focus depth is four;
path depth is six. A response that hits a limit reports truncation. Narrow the
repository boundary, entity types, owner, risk, freshness, layers, or focus root
before treating a bounded view as exhaustive.

Inspector detail separately caps relationships at 50 and each contextual
subgroup at 20. Active work excludes the documented inactive statuses before
ranking, while recent pull requests retain descending observation-time order.
Saved-view listing returns at most 300 currently authorized candidates; an
inaccessible or malformed legacy saved view is omitted before that cap and does
not crowd out a later visible view.

## Verification

Run the ordinary gates in the isolated test profile:

```bash
docker compose -p anva-canvas --profile test run --rm test ruff check .
docker compose -p anva-canvas --profile test run --rm test mypy src tests
docker compose -p anva-canvas --profile test run --rm test pytest
docker compose -p anva-canvas --profile test run --rm test pytest -q \
  tests/integration/test_canvas_integration.py::test_committed_canvas_performance_summaries_recompute_from_serialized_samples
```

Run the separate Chromium evidence stage:

```bash
docker compose -p anva-canvas --profile test --profile browser run --rm browser-test \
  pytest -q tests/browser/test_canvas_browser.py
```

The browser test regenerates PNG evidence under
`docs/evidence/issue-012/screenshots`. Review the images before publishing them;
never attach tokens, cookies, environment values, customer source payloads, or
unredacted console/network captures.

Verify vendored artifacts:

```bash
sha256sum src/anva/static/anva/vendor/dagre-2.0.0/*
```

The expected JavaScript digest is
`e073937ba0b6918fd3bba7d50a61d525b18e9dabf6ed8b208abbc0eed11be1ee`.
The optional upstream `sourceMappingURL` trailer is intentionally removed so
the production static manifest does not require a development-only source map.

## Troubleshooting

- Stable unavailable response: the view/entity/share is missing, foreign,
  revoked, expired, or outside current permissions. The response deliberately
  does not distinguish those cases.
- Share revocation `409`: reload the exact saved revision before retrying; a
  newer Canvas revision won the optimistic-concurrency check.
- Empty view: confirm successful source ingestion and repository/scope access,
  then broaden typed filters. An empty result is not evidence that hidden data
  exists or does not exist.
- Missing saved view in the selector: confirm that its current revision still
  contains well-formed semantic JSON and that every relational and semantic
  repository, scope/source, and root boundary remains currently authorized.
- Truncated view: reduce repositories or filters/focus before investigation.
- Truncated inspector section: treat only the rendered items as known. Do not
  translate a bounded empty section into “none exists”; narrow the repository
  boundary or inspect a more specific semantic view.
- Truncated selection-scoped evidence: the permitted one-hop edge, assertion,
  or source-lineage budget was reached. Narrow the repository or question; do
  not treat omitted excerpts as proof of absence.
- `409` while saving: another revision won. Reload the view and reapply the
  presentation edit.
- Proposal revision conflict: reload source and target details before proposing
  again; canonical state was not changed.
- Read-only deployment: browsing, table fallback, detail, and path remain
  available while save/share/proposal controls are unavailable.
- Poor dense-graph layout: use focus depth and semantic layers, or save pinned
  positions. Do not infer meaning from geometric proximity alone.
