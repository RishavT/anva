# Issue 146 self-review: public acceptance launch contract

## Outcome

The acceptance workflow now publishes a closed numeric-v1 JSON Schema and example for the
launch manifest and provides a deterministic `anva acceptance launch-manifest` generator. The
supported Make workflow resolves Compose, inspects the exact pinned image, runs that generator
inside the same image under a networkless/read-only/capability-free container, and installs the
secret-free output read-only before any product acceptance phase starts.

An immutable valid v1 manifest is preserved for resume compatibility. A missing, malformed,
mutable, stale, or mismatched manifest still fails before bootstrap, but now records an allowlisted
stage and reason in the private mode-`0600` operator diagnostic while retaining the generic public
CLI rejection.

## Contract and security review

- The manifest binds the product commit, build input, installed package, Docker engine image ID,
  image reference, exact seven-service inventory, and per-service security-relevant configuration
  hashes. Every object is closed and every identity is format-bounded.
- The generator rejects missing services, mixed images, published product ports, non-internal
  acceptance networks, root acceptance phases, writable roots, missing capability/privilege
  controls, incorrect resource ceilings, unsafe bind creation, writable protected mounts, and
  Docker socket exposure.
- Environment values and host bind sources are excluded from the hashed public model. Only sorted
  environment key names and redacted bind roles participate, so changing a private canary does not
  change the output and neither the canary nor its host path appears in the bytes.
- Generator inputs use a private temporary directory beneath the operator's protected state path.
  Cleanup and replacement target only exact task paths; no global Docker cleanup is used.
- The CLI default remains the supported in-container manifest path. Make requires the explicit
  host path because Compose must create a protected read-only bind; omission never disables
  preflight validation.

## Compatibility review

- The established numeric schema version `1` and manifest field shape remain accepted.
- Contract validation now reads the version constant from each schema, retaining string `"1.0"`
  behavior for all existing contracts while supporting this established numeric-v1 contract.
- The existing public CLI failure body remains generic. Only the private diagnostic gains the
  stable `launch_manifest_preflight` stage and allowlisted reason code.
- No database model, migration, HTTP request, MCP request, or authorization behavior changes.

## Verification

- Exact host-resolved Make generation produced mode-`0444` output twice with identical SHA-256;
  the generated manifest contained exactly seven services and passed in-container preflight.
- A missing manifest produced generic public output, no resume state, and a private mode-`0600`
  `launch_manifest_missing` diagnostic. The generated manifest advanced past preflight.
- The documented Compose/Make flow then completed real bootstrap, API, worker, and official MCP
  client operations through `AWAITING_EXTERNAL_REVIEW`; scoped services and volumes were removed.
- Focused launch/Compose/contract tests passed (42 plus the later 24-test tamper/count rerun).
- Runner boundary, resume, and permission integrations passed 28 tests with one expected
  Docker-in-container skip.
- The unit marker passed 1,150 tests with five expected Docker-CLI-unavailable skips. The combined
  integration/contract/smoke gate passed 326 tests before exposing one stale artifact-count
  assertion; after changing 33 to 35, the exact failed contract and focused launch set passed.
- Ruff passed across `src` and `tests`; strict mypy passed across 211 source files; all 35 generated
  contract artifacts verified; `git diff --check` passed.

Independent exact-head review and hosted CI remain required before merge.
