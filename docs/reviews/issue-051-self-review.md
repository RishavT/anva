# Issue 51 self-review: demo scope discovery

## Change reviewed

The installed `anva demo` CLI response now includes `access_scope_id`, taken directly from the
`BootstrapResult` returned by the same atomic bootstrap transaction that creates the organization,
repository, service identity, token, and access scope. The README and source-ingestion runbook
describe how a fresh user uses the returned repository/scope identifiers without retaining the
one-time token.

## Security and compatibility review

- **Tenant isolation:** the value is not selected from an organization-wide query or inferred from
  another record. It is the exact scope created in the authenticated local-bootstrap transaction.
  No list endpoint, cross-tenant search surface, or authorization bypass was added.
- **Principal binding:** contract coverage proves the returned scope, repository, and service
  identity belong to the same organization and that the bootstrap scope authorizes repositories
  and service identities in that tenant.
- **Secret handling:** the additional value is a non-secret UUID. Existing one-time token behavior,
  response keys, no-logging Compose configuration, and guidance not to redirect the response are
  unchanged.
- **Backward compatibility:** the JSON response only gains an additive key. Existing consumers can
  continue reading all prior keys; source commands and API contracts are unchanged.
- **Failure behavior:** already-bootstrapped and conflicting-installation responses are unchanged.
  The discovery promise applies to the successful fresh response where the usable token is issued.

## Verification

- Docker: 34 existing CLI unit tests plus the new integration/contract test passed.
- Docker: Ruff passed for the changed Python sources.
- Fresh wheel-installed Compose journey used only public installed interfaces. `anva demo` returned
  a repository ID and access-scope ID; those exact values authorized `anva source connect` against
  the read-only `RishavT/anva-test` mount. Sync inspection reached `PARTIALLY_COMPLETED` after
  discovering 619 files, with 23 safely isolated failures from the deliberately messy corpus.
- No database lookup or private acceptance-harness state was used by the fresh journey.

Detailed redacted evidence is in `evidence/issue-51-scope-discovery/REPORT.md`.
