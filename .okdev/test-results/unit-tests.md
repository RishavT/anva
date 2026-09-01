# Unit test results

- Full suite: 1,058 collected; 1,052 passed; 1 failed; 5 skipped.
- Focused added tests: 19 passed.
- Coverage: 85% total; 19,667 statements with 2,256 missed; 5,740 branches with 1,310 partial.

## Added coverage

- `tests/unit/test_acceptance_client.py`: serialisation, invalid inputs, HTTP and transport failures, and bounded invalid responses.
- `tests/unit/test_skill_packages.py`: deterministic host archives, metadata normalization, symlink/checksum rejection.
- `tests/unit/test_ingestion_parser_outputs.py`: textual and structured parsers plus explicit mechanical claims.

## Remaining failure

`tests/integration/test_canvas_integration.py:1043` failed only under the full coverage-instrumented run: the frozen `< 1.0s` performance assertion measured 1.052s. The exact test passed in isolation (`1 passed in 70.89s`). No production behavior or #49 threshold was changed.
