# Issue 124 self-review: writable Sigstore cache for the drill finalizer

## Root cause

The finalizer mounts the host GitHub CLI into a read-only container, but the
service did not give the CLI a writable home or cache. Once a narrow GitHub
configuration was mounted correctly, `gh attestation verify` failed while
initializing its Sigstore verifier because its default cache location was on
the read-only image filesystem.

## Fix

`drill-finalizer` now points `HOME` and `XDG_CACHE_HOME` at separate paths
under its existing `/tmp` tmpfs. No additional mount, capability, network, or
host path is introduced. The root filesystem remains read-only, the process
remains nonroot with all capabilities dropped and `no-new-privileges`, and the
service remains limited to the finalizer egress network and existing read-only
inputs.

## Verification

- Raw and fully resolved Compose contracts assert both writable-cache paths
  and preserve the finalizer's isolation properties.
- The focused Docker test passed all executable assertions; its nested Docker
  configuration case is intentionally skipped inside the test container.
- A separate host-side resolved Compose assertion passed.
- The exact published v0.1.6 finalizer image, under this overlay and without
  ad-hoc environment overrides, successfully verified both the standard SLSA
  provenance and custom operator-drill predicate for the protected-owner
  anchor that exposed the defect.
- The completed operator ledger was not mounted writable or modified during
  the exact-container regression.
