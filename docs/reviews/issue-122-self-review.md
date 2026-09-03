# Issue 122 self-review: drill decommission operator runtime contract

## Root cause

`drill-decommission-operator` is defined only in the drill overlay. It does not
inherit the similarly named production service's application environment or
security mapping. Its rendered configuration therefore omitted the production
object-storage settings, used a mismatched database password default, and ran
as the image-default UID, which could not read the host-owned mode-0600
operator credential.

## Fix and security boundary

- The helper receives the same production application and object-storage
  values as the drill runtime, including the unique drill secrets.
- The database default now matches the drill PostgreSQL credentials.
- The Make target passes the invoking host UID/GID, preserving the credential's
  mode-0600 host permissions instead of making it broadly readable.
- The container explicitly retains a read-only root, dropped capabilities,
  `no-new-privileges`, and a narrow temporary filesystem.
- It remains on only the internal backend network, publishes no ports, mounts
  only the named credential secret, and runs the exact immutable drill image.

## Verification

Raw and fully rendered Compose regressions cover the runtime user, production
environment, object-storage values, database URL, security controls, internal
network, absent ports/volumes, and narrow secret target. A separate rendered
configuration check also exercised a non-default UID/GID. No live operator
project was inspected, restarted, or mutated; configuration rendering used a
distinct disposable project name and created no Compose resources.
