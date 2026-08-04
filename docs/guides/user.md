# User guide

Anva organizes source-backed knowledge within an organization boundary. Use only
sources you are authorized to provide, and choose the intended organization and
repository before ingesting or querying content.

## Working safely

- Treat generated answers as aids, not as authorization, security approval, or a
  substitute for checking the cited source.
- Review provenance and supporting evidence before acting on a result. Report
  missing, stale, cross-organization, or unexpected evidence.
- Do not paste credentials, private keys, tokens, or unrelated personal data into
  prompts or sources.
- Keep personal and service credentials private. Ask an administrator to revoke
  suspected credentials rather than continuing to use them.
- Expect requests to be rate-limited during abusive load or retry storms; honor
  retry guidance instead of bypassing controls.

## Access and data lifecycle

Access follows organization membership, repository/source scope, and granted
permissions. Losing access can be intentional and does not mean retained records
were physically deleted.

Ask an authorized operator for retention or decommissioning changes. The current
MVP-013 decommission workflow requires a human session authenticated within 15
minutes, CSRF protection, and two exact organization confirmations; service
tokens and CLI automation are rejected. It disables access and identities while
retaining governed content/history, so it is not a hard-delete or legal-erasure
workflow. Do not promise deletion to a data subject based only on decommission
status.

When reporting a problem, include the time, organization/repository, action, and
request ID or trace context. Do not include secrets or sensitive source content
unless the approved support channel explicitly requires it.
