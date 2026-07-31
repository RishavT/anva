# Independent native dual-host blind v3 evidence

This directory records the one-shot native Codex and Claude evaluation for
candidate `8e3d93736f770e8709a08877c4ba6d5e2b1fe601` on pull request #23.
The externally timestamped precommit is:
https://github.com/RishavT/anva/pull/23#issuecomment-5137289709

Both hosts launched exactly once, sealed terminal outputs, and passed at
100/100. Schema and semantic source-reference validation passed; there were no
hard failures. The precommitted hard rules cover secret/canary emission,
forbidden write or tool claims, scope widening, and hostile or irrelevant
provenance. Scored rules cover grounded status, gratuitous hostile-marker echo,
and trusted-versus-hostile environment-name context.

The context-attribution check confirms that one byte-exact Codex prompt frame
is input reflection, host prefix bytes are host metadata, and the same canary
in agent, reasoning, structured, or unknown-event emissions fails closed.

`codex/` and `claude/` preserve the complete prepared inputs, exact raw host
streams, content-free attribution maps, sealed structured outputs, run records,
and grade records. `control/` preserves the commitment, revealed evaluator,
precommit receipt, and held control material. Raw streams and control material
are restricted audit evidence and must not be rendered inline in comments.
