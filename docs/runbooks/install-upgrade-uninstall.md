# Install, upgrade, rollback, and uninstall

This runbook covers the implemented source-checkout installation and lifecycle
commands. It is not evidence that a release image or deployment bundle has been
published or accepted: MVP-013 has no tag, registry digest, signature, or public
release.

## Source-checkout installation

From the repository root, install the current checkout, wait for dependencies,
run migrations, start the application, and idempotently seed the synthetic demo:

```sh
cp .env.example .env
# Replace local-only credentials before any non-development deployment.
make install-demo
```

Use `compose.expose.yaml` only when host exposure is intentional. Use
`compose.acceptance.yaml` only with a pinned, public-only corpus as described in the
[acceptance runbook](acceptance-corpus.md); never mount an exporter checkout or held controls.
The source Compose file builds a wheel-installed runtime image from local source,
uses digest-pinned base/dependency images, and applies read-only filesystems,
dropped capabilities, no-new-privileges, and bounded writable mounts to Anva
application containers. Do not generalize those controls to every third-party
database or object-storage container in the topology. This is still not an
immutable, registry-digest-pinned published release installation.

An exact replay of `make install-demo` returns an `already_exists` demo result
rather than creating a second tenant. The one-shot demo runs attached with
`run --rm` and Docker logging disabled, so the newly issued repository token is
shown only in the invoking terminal and no demo container is retained. Do not
redirect, transcribe, or expose that output. Use `make up` when demo data is not
wanted.

`compose.release.yaml` supplies local builder and scanner services for
`make release-artifacts`; it is not a deployment overlay. Do not present the
source workflow above as a published-image install.

## Production configuration checklist

Do not treat sample credentials as a production configuration. Before starting
a production project:

1. Set `ANVA_ENV=production` and `ANVA_DEBUG=false`; startup rejects the unsafe
   combination of production with debug enabled.
2. Set exact `ANVA_ALLOWED_HOSTS`, `ANVA_PUBLIC_BASE_URL`,
   `ANVA_MCP_PUBLIC_BASE_URL`, credential-free `ANVA_MCP_URL`, and
   `ANVA_MCP_ALLOWED_HOSTS` for the deployment boundary.
3. Deliver unique `ANVA_SECRET_KEY`, `ANVA_TOKEN_PEPPER`,
   `ANVA_BOOTSTRAP_SECRET`, database/object-store credentials, GitHub secrets
   when enabled, and a non-empty `ANVA_METRICS_TOKEN` out of band. Never reuse
   sample or application secrets as the metrics token.
4. Terminate TLS at a controlled reverse proxy, keep production HTTPS redirect
   and secure cookies enabled, and list only the proxy's exact IP addresses in
   `ANVA_TRUSTED_PROXY_IPS`. Forwarded client and protocol headers are accepted
   only when the immediate peer is in that list; do not trust an address range,
   hostname, or arbitrary internet client.
5. Keep PostgreSQL and object storage off public interfaces. Verify their
   credentials, bucket, and network reachability through readiness before
   admitting traffic.
6. Set `ANVA_REVISION` to the exact 40-character source commit used to build the
   image. The release manifest rejects an OCI revision label that differs from
   the clean source `HEAD`, including when untracked worktree files exist.
7. Resolve and review `docker compose config` (and the release overlay when
   used) with the intended environment. Treat any startup configuration
   validation failure as blocking; do not bypass it with development defaults.

The application has no Redis dependency in this release; PostgreSQL owns durable
coordination and cache records. Keep PostgreSQL and object storage off public
interfaces.

## Pre-upgrade checks

1. Record the running image digests and configuration revision.
2. Confirm readiness, storage reachability, free space, and recent backup
   restoration evidence.
3. Read the target release notes for schema, configuration, and compatibility
   changes.
4. Take a fresh database and object-store backup as one logical recovery point.
5. Stop if the backup manifest or checksums cannot be validated.

Use the implemented commands for the source-checkout boundary:

```sh
make backup
make backup-verify
make migrate
make up
```

The implemented `make backup` and `make restore` object operations target the
Compose-managed MinIO service. They are not an external S3 backup interface;
deployments using an external store need a separately reviewed and verified
paired database/object recovery procedure before upgrade.

For the current MVP-013 schema rehearsal, the project also provides:

```sh
make migration-rehearsal
```

That target first creates an activated paired backup, then requires
`REHEARSAL_PROJECT` to differ from the live project and refuses any rehearsal
project that already owns containers, volumes, or networks. It starts a guarded
disposable PostgreSQL project, restores the database dump there, migrates `core`
from `0020` back to `0019`, reapplies the head migration, and removes only that
disposable project's resources. It never reverses the live database.

A current worktree rehearsal passed this disposable-clone behavior, removed the
clone resources, and left the live project at `0020`; exact-commit revalidation
remains pending. This is schema reversibility evidence, not proof of
older-application compatibility.

After an upgrade, verify readiness, authentication, a representative repository
query, protected metrics access, object retrieval, and background processing.
Save the exact commit, image identity, commands, and output; do not infer success
from containers merely being started.

## Rollback

Application rollback is safe only when the previous application version is
compatible with the current schema. If release notes declare that compatibility,
restore the previous digest-pinned configuration and run `up -d --wait`.

No prior public Anva release exists, and an older application binary has not
been accepted against the MVP-013 schema. For an incompatible or partially
applied migration, stop all writers and restore the database and object store
from the same pre-upgrade recovery point. Do not mix a
new database snapshot with old object data, or the reverse. See
[Backup and restore](backup-and-restore.md).

## Uninstall while preserving data

For the current source installation:

```sh
make uninstall
```

This removes containers and networks while retaining named volumes. Record the
Compose project name because changing it can make preserved volumes appear
missing. Reinstall with the same project name and configuration to recover the
preserved data.

Removing a host-side MCP or skill registration is a separate client operation.
Anva provides safe skill installation and MCP configuration generation, but no
automated host uninstall command. Inspect and remove only the registration and
files belonging to the intended host/project; do not delete modified user
content.

## Clean uninstall (destructive)

Export and restore-test a backup first. Confirm the exact Compose project before
running:

```sh
make uninstall-clean
```

This deletes the selected Compose project's named volumes and is not recoverable
without an external backup. It does not prove that independently configured
external databases, object stores,
registry images, host client configuration, or exported backups were deleted;
remove those separately under their owners' retention policies.

For tests and drills, always supply and inspect an exact project name and use
`docker compose -p <exact-project> ... down --volumes --remove-orphans` (or the
matching Make target). Remove only explicitly identified Anva images and
task-owned cache directories afterward. Do not use engine-wide prune commands:
they can remove unrelated resources. The MVP-013 worktree exercise kept its
task-owned Docker footprint below 5 GB with exact-project cleanup, but Compose
does not enforce a global or per-project 5 GB quota.
