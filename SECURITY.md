# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include secrets,
customer data, exploit details, or private logs in GitHub issues.

Email `rishav@aisoftwork.com` with a concise description, affected version or
commit, reproduction conditions, and impact. You may use
`i@rishavthakker.com` if the primary address is unavailable. AI Soft Work will
acknowledge receipt as soon as practical, coordinate validation and remediation,
and agree on disclosure timing with the reporter.

Do not access data that is not yours, degrade a service, persist after proving
the issue, or publish details before a coordinated fix is available.

## Supported versions

Until a stable support policy is announced, only the most recent published Anva
release is eligible for security fixes. Unreleased commits are not supported
products. Exact release artifacts and their attestations are published on the
repository's Releases page.

## Secrets accidentally committed

Revoke or rotate the credential first. Removing it from the current tree is not
sufficient because Git history, forks, caches, logs, and downloaded artifacts may
retain it. Contact the security address before rewriting history.
