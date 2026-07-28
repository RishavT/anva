# ADR-012: Evidence and assurance artifact identity

- Status: Accepted
- Date: 2026-07-28
- Owners: Anva engineering

## Context

Context packets, evidence manifests, and assurance reports must remain tied to the exact
content and commit evaluated. Mutable artifacts could make a historical result cite evidence
that did not exist at evaluation time.

## Decision

Governed artifacts are canonical-JSON content addressed with SHA-256, tenant owned, schema
versioned, and immutable after insertion in both the ORM and PostgreSQL. Identical content,
kind, and tenant deduplicate idempotently. Assurance completion requires evaluated and report
commits to equal the run head commit.

## Alternatives considered

Random identifiers without hashes were rejected because they cannot prove content identity.
Mutable rows were rejected because they invalidate historical reports. Hashing non-canonical
JSON was rejected because key ordering would create unstable identities.

## Consequences

Any content change creates a new artifact. Producers must use supported JSON Schema versions
and retain limitations explicitly. Large object-storage artifacts introduced later must use
the same digest and metadata identity as their database manifest.

## Security impact

Hashes detect replacement but are not signatures. Artifact access still requires tenant
authorization and storage encryption. Canonical serialization rejects non-JSON numeric values.

## Privacy impact

Immutability can conflict with deletion obligations. Payloads must minimize personal data and
prefer stable source references over copied source content.

## Operational impact

Database triggers reject updates and deletes, including bulk ORM operations. Recovery and
retention procedures must preserve hash identity.

## Revisit conditions

Revisit when large artifacts move to object storage, signatures are required, or retention
needs cryptographic erasure.
