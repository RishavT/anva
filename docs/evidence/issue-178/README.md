# Issue 178: Canvas path-navigation wait

Base: `d84432b62b5c7d1390c1b186c0b54e67350fb088`.
Issue: https://github.com/RishavT/anva/issues/178
Recorded failing CI: https://github.com/RishavT/anva/actions/runs/34687918141

The recorded failure queried the submitted form after navigation using Selenium's
`staleness_of`. Chromium returned inspector error -32000, "Node with given id
does not belong to the document", rather than Selenium's stale-element exception.
The replacement never probes that detached form. It requires the fresh URL's
exact submitted source and target IDs, the existing canvas interactive marker,
and at least two path-result steps. Both existing trace checks remain in place.

## Focused verification

`focused-tests.log` records the final Docker run. It selects the 11 new predicate
cases and the two existing navigation-wait regressions, followed by Ruff checks.
The tests cover old/wrong query pages, wrong routes, incomplete readiness/results,
successful readiness, stale/missing-element races, and propagation of generic
WebDriver errors including the original inspector message on a fresh lookup.

Execution used the already-cached Anva canonical runtime image
`anva-lifecycle-canonical:0.1.7` (engine ID prefix `b51f9ef8fbe9`), read-only source
mount and root filesystem, 1 CPU / 768 MiB / 128 PID limits, and a 350 MiB tmpfs.
Ephemeral test dependencies: pytest 8.4.1, pytest-django 4.11.1, Selenium 4.34.2,
Ruff 0.12.9. Dependency transitive versions are recorded in the log; this focused
run is not a claim of full locked-dependency CI equivalence.

Command inside the container, after installing those packages into `/tmp/testdeps`:

```sh
python -m pytest -o cache_dir=/tmp/pytest-cache tests/browser/test_canvas_browser.py \
  -k 'path_wait or interactive_wait_predicate or navigation_wait' -vv
/tmp/testdeps/bin/ruff check --no-cache tests/browser/test_canvas_browser.py
/tmp/testdeps/bin/ruff format --check --no-cache tests/browser/test_canvas_browser.py
```

Initial bridge-network DNS failed; an owned-container retry used host networking.
The first focused test run passed, but lint could not execute from a noexec tmpfs.
The first lint-only retry found loop-variable capture; the final revision uses
`functools.partial` to bind submitted IDs. The final logged run includes both
tests and lint on that revision. Containers use `--rm`; no image build, dependency
service, persistent Docker volume, daemon configuration, or production ref changed.

## Self-review and limits

- Changes are test-only; no broad ignored WebDriver exceptions or retry wrapper.
- Wrong/old trace results cannot satisfy the predicate just because rows exist.
- Missing/stale fresh-document lookups remain bounded by the existing WebDriverWait.
- No product code, release tag, or immutable candidate artifact was modified.
- Full Chromium flow has **not** been rerun locally. Upstream dependency availability
  and a green exact-head browser CI run remain separate gates; unit mocks alone
  do not prove the original browser failure is resolved end to end.
- Independent review is required before merge.
