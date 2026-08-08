# TST-007 upload fixtures

These six files are byte-for-byte copies of the deterministic upload artifacts
in `RishavT/anva-test`'s `.anva/adversarial-evidence/artifacts/` corpus. The
unit test pins every SHA-256 before passing the bytes to Anva's production
upload inspector.

The upstream corpus uses synthetic 64-character `head_sha` values, while Anva
authorizes exact 40-character Git commit IDs. The five rejection fixtures are
tested without modification. The safe Linden fixture is first shown to fail
the incompatible raw head binding and is then explicitly re-sealed in memory
with a 40-character head and a recomputed results hash. That adapted success is
not described as byte-for-byte acceptance of the upstream artifact.
