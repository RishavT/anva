# Current install-ready MVP release readiness

This is a documentation-only audit of candidate input
`a954fd458b72aec8d3c5c622b6ea263342e6f58c`. It classifies existing evidence
under the [release-freeze contract](release-freeze-contract.md). It is not new
execution evidence and does not change historical results.

## Proven documentation and static artifacts

- Installation, upgrade, rollback, preserve-data uninstall, and destructive
  clean uninstall are covered by the
  [lifecycle runbook](../runbooks/install-upgrade-uninstall.md).
- Paired database/object backup, verification, clean-project restore, failure
  handling, and post-restore identity checks are covered by the
  [backup runbook](../runbooks/backup-and-restore.md).
- Metrics authentication, proxy trust, rate-limit triage, and current
  process-local limitations are covered by the
  [observability runbook](../runbooks/observability-and-rate-limits.md).
- Historical Chromium screenshots and browser/performance records remain
  indexed under `docs/evidence/issue-011` and `docs/evidence/issue-012`. They
  demonstrate implemented UI behavior at their recorded identities; they are
  not browser evidence for the current candidate.
- Release packaging, manifest, checksum, SBOM, and scan commands exist. Their
  historical outputs remain valid only for the commits and image IDs they name.

These documents are sufficient instructions for execution. An unchecked
release-checklist item must not be checked merely because its command or
historical artifact exists.

## Release blockers

| Blocker | Required evidence | Tracking |
| --- | --- | --- |
| Immutable publication and install | Authoritative version, provenance-attested tag, registry/package digests, and fresh published-artifact lifecycle exercise | [#42](https://github.com/RishavT/anva/issues/42) |
| Exact-candidate product/security/UI gate | Current Compose product suites, browser/UI artifacts, tenant/revocation and security gates, 31-case deterministic replay, and one representative independent manual review | [#43](https://github.com/RishavT/anva/issues/43) |
| Vulnerability closure | Exact-current SBOM/source/image scans proving the `sqlparse` findings are removed, plus current disposition of every remaining finding and exception | [#41](https://github.com/RishavT/anva/issues/41) and [#43](https://github.com/RishavT/anva/issues/43) |
| Essential operational ownership | Deployment-owned release, security-incident, and operations/on-call contacts plus exercised essential incident runbooks | [#44](https://github.com/RishavT/anva/issues/44) |
| MVP umbrella review | Reconcile every applicable unchecked checklist item and explicitly accept only freeze-contract deferrals | [#13](https://github.com/RishavT/anva/issues/13) |

The metrics release gate is limited to the implemented surface: authenticated
scrape, trusted-proxy behavior, usable exported series, and a recorded triage
exercise. Provisioned dashboards, persistent aggregation, distributed tracing,
and managed alert delivery are not implemented MVP claims.

## Post-MVP

- Supported human login/recovery after logout or expiry: [#37](https://github.com/RishavT/anva/issues/37).
- External object-store and deployment-sized recovery: [#38](https://github.com/RishavT/anva/issues/38).
- Persistent observability, dashboards, managed alerts, and distributed tracing: [#39](https://github.com/RishavT/anva/issues/39).
- Managed deployment, remote identity, penetration testing, quotas, support,
  billing, and status operations: [#40](https://github.com/RishavT/anva/issues/40).

These issues do not block the self-hosted install-ready MVP unless their scope
is separately moved into the fixed release contract.

## Completion rule

Close a blocker only from evidence bound to the selected clean candidate and
published artifact identities. When a closure change alters candidate identity,
apply the freeze contract's scoped retest rule. Do not rerun an already passing
lane or create another evidence root unless a changed dependency, contract,
migration, authorization boundary, package, or runtime image makes it relevant.
