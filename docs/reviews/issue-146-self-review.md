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

## Independent-review remediation

The first exact-head reviewer blocked the change after proving that an `api` service with
privileged/Docker-socket access and an acceptance phase with an added writable oracle bind could
still generate a manifest. The generator now uses closed service-field allowlists and exact
per-service mount inventories across all seven services. Unknown privilege, capability, device,
network, or mount fields fail closed; expected binds have exact target/type/write-mode rules; the
canonical volume and API bootstrap secret are exact; Docker-socket sources are forbidden.

The same review found that `PermissionError` during manifest metadata inspection escaped the
provenance boundary. Every metadata `OSError` is now converted to a path-free stable permissions
reason, allowing the runner to write its private pre-state diagnostic and retaining generic public
CLI output. Regression tests reproduce both reviewer findings.

A second exact-head review then identified Docker's acceptance of leading-zero root UID strings
and the missing `api`/`worker`/`mcp` dependency closure. Numeric image users now reject every
all-zero UID spelling. The generator requires the exact dependency graph and conditions, pinned
dependency images, closed runtime fields, backend networks, and mount inventories for `postgres`,
`minio`, `minio-init`, and `migrate`; their redacted identities participate in
`resolved_compose_sha256`. The established seven-service public field shape and prior valid v1
manifests remain compatible.

A third exact-head review reproduced Docker's signed-zero UID forms (`+0`, `-0`, and their
`UID:GID` variants), which the leading-zero check did not cover. The next review then showed that
an unmapped bare numeric UID inherits GID 0 and that named users and groups cannot be proven
non-root from image metadata alone. The runtime image now declares exact numeric default identity
`10001:10001`; `worker`, `mcp`, and `migrate` also declare that pair explicitly. The generator
requires the exact image default and an explicit in-range positive numeric `UID:GID` on every
launched product service, rejecting bare IDs, names, zero groups, signed-zero, out-of-range,
whitespace, non-string, and malformed forms. Absolute Compose build contexts remain outside the
runtime identity hash because the launch uses the already digest-pinned image.

A further exact-head review demonstrated that the original immutable-file fast path could reuse a
manifest after the current resolved Compose identity changed. The Make target now always generates
a private current candidate, compares an existing read-only manifest byte-for-byte, reuses only an
exact match, and rejects drift without overwriting the protected artifact. New artifacts still use
a securely created same-directory temporary file and atomic no-replace publication. The host
identity preflight also enforces
Docker's inclusive upper UID/GID bound of `2147483647` before any container launch.

The next exact-head review found that signal handlers cleaned temporary inputs but continued the
recipe, and that only the start phase refreshed the current candidate. Cleanup is now idempotent
and status-preserving, with HUP, INT, and TERM terminating as 129, 130, and 143. Start, review
request, review submission, and finalization all depend on the generator/comparison target before
launching their phase service, so configuration drift cannot cross a resume boundary.

## Verification

- Exact host-resolved Make generation produced mode-`0444` output twice with identical SHA-256;
  the generated manifest contained exactly seven services and passed in-container preflight.
- A missing manifest produced generic public output, no resume state, and a private mode-`0600`
  `launch_manifest_missing` diagnostic. The generated manifest advanced past preflight.
- The documented Compose/Make flow then completed real bootstrap, API, worker, and official MCP
  client operations through `AWAITING_EXTERNAL_REVIEW`; scoped services and volumes were removed.
- Final-remediation launch/Compose/contract/runner tests passed 112 checks with four expected
  Docker-CLI-unavailable skips; both the base and optional-case real resolved Compose models passed
  the tightened generator.
- Executable Make regressions passed creation, exact reuse, drift preservation, and fail-closed
  HUP/INT/TERM cleanup; dry-runs resolved the current candidate before every product phase.
- Runner boundary, resume, and permission integrations passed 28 tests with one expected
  Docker-in-container skip.
- The final-remediation unit marker passed 1,201 tests with five expected Docker-CLI-unavailable
  skips. The combined
  integration/contract/smoke gate passed 326 tests before exposing one stale artifact-count
  assertion; after changing 33 to 35, the exact failed contract and focused launch set passed.
- Ruff passed across `src` and `tests`; strict mypy passed across 211 source files; all 35 generated
  contract artifacts verified; `git diff --check` passed.

Independent exact-head review and hosted CI remain required before merge.
