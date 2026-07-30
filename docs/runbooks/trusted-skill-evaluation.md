# Trusted skill evaluation

Deterministic package and fixture tests are safety checks, not evidence that a
native coding-agent host followed a skill. Fresh-agent semantic evaluations are
separate evidence and must be labeled with the actual evaluator host. A
trusted live-model release evaluation is claimable only when the two-stage gate
below produces a passing `grade-record.json`.

The gate deliberately has three commands. `prepare` and `run` do not accept an
oracle or grader argument. They create a new read-only input workspace
containing only the selected packaged skill, raw task, synthetic MCP
transcript, the canonical schema derived from that packaged skill, and a
provider-compatible generation schema derived from the canonical schema. The
workspace does not contain the repository worktree, prior outputs, ambient MCP
configuration, oracle, or grader. Provider restrictions therefore cannot
weaken post-seal validation: `grade` uses the canonical schema. The native host
output is captured and hashed before `grade` can read the separately held
oracle and grader.

```console
python scripts/trusted_skill_eval.py prepare \
  --host codex \
  --workflow anva-prepare \
  --package-root packages/anva-skills \
  --task tests/skill_evals/public/forward-prepare-task.txt \
  --transcript tests/skill_evals/public/synthetic-mcp-transcript.json \
  --evidence-directory /new/evidence/codex \
  --commit-sha "$EXACT_COMMIT_SHA"

python scripts/trusted_skill_eval.py run \
  --evidence-directory /new/evidence/codex

python scripts/trusted_skill_eval.py grade \
  --evidence-directory /new/evidence/codex \
  --oracle /separately-held/oracle.json \
  --grader /separately-held/grader.json
```

The run uses the installed native Codex or Claude executable. It may use the
CLI's existing authenticated session, but the gate never reads, copies, or
records credentials and removes token/key/secret environment variables.
Codex runs ephemerally with user configuration/rules ignored, a filesystem
profile that denies root and temporary-directory reads outside its read-only
input workspace, and model-command network access disabled. Claude runs in
safe mode with no model tools, no session persistence, no setting sources, and
an empty strict MCP configuration.

If the executable, authentication, or a schema-shaped result is unavailable,
the run record is `NOT_RUN`; it is not provider evidence. A passing grade
records hashes for every input, the packaged input artifact, isolation
manifest, raw host streams, structured output, oracle, grader, and gate code,
plus the exact commit, host/version, schema result, score, timestamps, and
GitHub Actions run identity when available. Preserve the complete evidence
directory as an immutable exact-SHA CI artifact.
