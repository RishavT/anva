"""Tenant-explicit PostgreSQL models and critical database invariants."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, ClassVar

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVectorField
from django.db import models
from django.db.models import F, Q
from django.utils import timezone
from pgvector.django import HnswIndex, VectorField


def canonical_payload_bytes(payload: object) -> bytes:
    """Serialize JSON deterministically for stable content identities."""
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()


def content_hash(payload: object) -> str:
    """Return a lowercase SHA-256 digest for a JSON-compatible payload."""
    return hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()


class ArtifactImmutableError(ValueError):
    """An immutable artifact was changed after creation."""


class UUIDModel(models.Model):
    """Opaque UUID identity for externally addressable records."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class TimeStampedModel(UUIDModel):
    """UTC creation and modification timestamps."""

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Organization(TimeStampedModel):
    """Root tenant record."""

    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=300)

    def __str__(self) -> str:
        return self.slug


class User(TimeStampedModel):
    """A human identity that may belong to multiple organizations."""

    email = models.EmailField(max_length=320, unique=True)
    display_name = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)


class TenantOwnedModel(TimeStampedModel):
    """Base for rows whose organization ownership must remain explicit."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)

    class Meta:
        abstract = True


class RevisionedTenantModel(TenantOwnedModel):
    """Governed tenant record with optimistic-concurrency revision."""

    revision = models.PositiveBigIntegerField(default=1)

    class Meta:
        abstract = True
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="%(app_label)s_%(class)s_revision_gte_1",
            )
        ]


class SourceConnection(RevisionedTenantModel):
    """A tenant-owned external source connection."""

    class State(models.TextChoices):
        DRAFT = "DRAFT"
        AUTHORIZING = "AUTHORIZING"
        ACTIVE = "ACTIVE"
        DEGRADED = "DEGRADED"
        REVOKED = "REVOKED"
        DISABLED = "DISABLED"
        FAILED = "FAILED"

    class ConnectorKind(models.TextChoices):
        FILESYSTEM = "FILESYSTEM"

    external_key = models.CharField(max_length=300)
    display_name = models.CharField(max_length=300, blank=True)
    connector_kind = models.CharField(
        max_length=32,
        choices=ConnectorKind,
        default=ConnectorKind.FILESYSTEM,
    )
    configuration = models.JSONField(default=dict)
    repository = models.ForeignKey(
        "Repository",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    access_scope = models.ForeignKey(
        "AccessScope",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    state = models.CharField(max_length=20, choices=State, default=State.DRAFT)
    last_successful_sync_at = models.DateTimeField(null=True, blank=True)
    last_error_code = models.CharField(max_length=100, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "external_key"],
                name="core_source_connection_org_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_connection_org_id_unique",
            ),
        ]


class SyncRun(RevisionedTenantModel):
    """One authoritative source synchronization state machine."""

    class State(models.TextChoices):
        REQUESTED = "REQUESTED"
        DISCOVERING = "DISCOVERING"
        FETCHING = "FETCHING"
        PARSING = "PARSING"
        INDEXING = "INDEXING"
        EXTRACTING = "EXTRACTING"
        RESOLVING = "RESOLVING"
        PUBLISHING = "PUBLISHING"
        COMPLETED = "COMPLETED"
        PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
        FAILED = "FAILED"
        CANCELLED = "CANCELLED"

    class ScanMode(models.TextChoices):
        FULL = "FULL"
        INCREMENTAL = "INCREMENTAL"

    source_connection = models.ForeignKey(SourceConnection, on_delete=models.PROTECT)
    access_snapshot = models.ForeignKey(
        "AccessSnapshot",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    scan_mode = models.CharField(max_length=16, choices=ScanMode, default=ScanMode.FULL)
    state = models.CharField(max_length=24, choices=State, default=State.REQUESTED)
    failure_code = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    discovered_count = models.PositiveIntegerField(default=0)
    processed_count = models.PositiveIntegerField(default=0)
    failed_count = models.PositiveIntegerField(default=0)
    tombstoned_count = models.PositiveIntegerField(default=0)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "source_connection", "state"],
                name="core_sync_org_conn_state_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_sync_run_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "source_connection"],
                condition=Q(
                    state__in=[
                        "REQUESTED",
                        "DISCOVERING",
                        "FETCHING",
                        "PARSING",
                        "INDEXING",
                        "EXTRACTING",
                        "RESOLVING",
                        "PUBLISHING",
                    ]
                ),
                name="core_sync_one_active_per_connection",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state__in=[
                            "COMPLETED",
                            "PARTIALLY_COMPLETED",
                            "FAILED",
                            "CANCELLED",
                        ],
                        completed_at__isnull=False,
                    )
                    | Q(
                        state__in=[
                            "REQUESTED",
                            "DISCOVERING",
                            "FETCHING",
                            "PARSING",
                            "INDEXING",
                            "EXTRACTING",
                            "RESOLVING",
                            "PUBLISHING",
                        ],
                        completed_at__isnull=True,
                    )
                ),
                name="core_sync_terminal_completion_coherent",
            ),
        ]


class SourceContainer(TenantOwnedModel):
    """Stable connector-neutral container discovered beneath one connection."""

    source_connection = models.ForeignKey(SourceConnection, on_delete=models.PROTECT)
    external_id = models.CharField(max_length=500)
    name = models.CharField(max_length=300)
    canonical_url = models.CharField(max_length=1_000)
    is_active = models.BooleanField(default=True)
    first_observed_at = models.DateTimeField(default=timezone.now)
    last_observed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "source_connection", "external_id"],
                name="core_source_container_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_container_org_id_unique",
            ),
        ]


class SourceDocument(TenantOwnedModel):
    """Stable logical document whose immutable content revisions retain history."""

    class Kind(models.TextChoices):
        MARKDOWN = "MARKDOWN"
        YAML = "YAML"
        JSON = "JSON"
        TEXT = "TEXT"
        CODEOWNERS = "CODEOWNERS"
        MANIFEST = "MANIFEST"
        MIGRATION = "MIGRATION"
        WORKFLOW = "WORKFLOW"
        OPENAPI = "OPENAPI"

    class State(models.TextChoices):
        PRESENT = "PRESENT"
        TOMBSTONED = "TOMBSTONED"

    source_container = models.ForeignKey(SourceContainer, on_delete=models.PROTECT)
    external_id = models.CharField(max_length=1_000)
    relative_path = models.CharField(max_length=1_000)
    canonical_url = models.CharField(max_length=1_500)
    document_kind = models.CharField(max_length=32, choices=Kind)
    media_type = models.CharField(max_length=200)
    state = models.CharField(max_length=16, choices=State, default=State.PRESENT)
    current_revision = models.ForeignKey(
        "SourceRevision",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )
    last_seen_run = models.ForeignKey(
        SyncRun,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="seen_documents",
    )
    first_observed_at = models.DateTimeField(default=timezone.now)
    last_observed_at = models.DateTimeField(default=timezone.now)
    tombstoned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "source_container", "state"],
                name="core_src_doc_cont_state_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "source_container", "external_id"],
                name="core_source_document_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_document_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state="PRESENT", tombstoned_at__isnull=True)
                    | Q(state="TOMBSTONED", tombstoned_at__isnull=False)
                ),
                name="core_source_document_tombstone_coherent",
            ),
        ]


class SourceContentArtifact(UUIDModel):
    """Tenant-isolated immutable bytes, deliberately separated from visibility."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    content_hash = models.CharField(max_length=64, editable=False)
    byte_size = models.PositiveIntegerField()
    media_type = models.CharField(max_length=200)
    content = models.BinaryField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "content_hash"],
                name="core_source_content_org_hash_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_content_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_source_content_hash_sha256",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Compute byte identity at creation and reject ORM updates."""
        digest = hashlib.sha256(bytes(self.content)).hexdigest()
        if not self._state.adding:
            raise ArtifactImmutableError("Source content artifacts cannot be updated")
        if self.content_hash and self.content_hash != digest:
            raise ArtifactImmutableError("Source content hash does not match bytes")
        if self.byte_size != len(self.content):
            raise ArtifactImmutableError("Source content byte_size does not match bytes")
        self.content_hash = digest
        super().save(*args, **kwargs)


class SourceRevision(UUIDModel):
    """Immutable content identity for a logical document."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    source_document = models.ForeignKey(SourceDocument, on_delete=models.PROTECT)
    content_artifact = models.ForeignKey(SourceContentArtifact, on_delete=models.PROTECT)
    content_hash = models.CharField(max_length=64)
    canonical_url = models.CharField(max_length=1_500)
    source_modified_at = models.DateTimeField(null=True, blank=True)
    observed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "source_document", "content_hash"],
                name="core_source_revision_document_hash_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_revision_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_source_revision_hash_sha256",
            ),
        ]


class SourceObservation(UUIDModel):
    """One scan-time observation, preserving A→B→A without duplicating revisions."""

    class Status(models.TextChoices):
        PRESENT = "PRESENT"
        TOMBSTONED = "TOMBSTONED"
        FAILED = "FAILED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    sync_run = models.ForeignKey(SyncRun, on_delete=models.PROTECT)
    source_document = models.ForeignKey(SourceDocument, on_delete=models.PROTECT)
    source_revision = models.ForeignKey(
        SourceRevision,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    access_snapshot = models.ForeignKey("AccessSnapshot", on_delete=models.PROTECT)
    status = models.CharField(max_length=16, choices=Status)
    observed_at = models.DateTimeField(default=timezone.now)
    error_code = models.CharField(max_length=100, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "sync_run", "source_document"],
                name="core_source_observation_run_document_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_observation_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(status="PRESENT", source_revision__isnull=False, error_code="")
                    | Q(status="TOMBSTONED", source_revision__isnull=True, error_code="")
                    | Q(status="FAILED", source_revision__isnull=True)
                ),
                name="core_source_observation_status_coherent",
            ),
        ]


class ParsedSource(UUIDModel):
    """Immutable parser-version-specific normalized output."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    source_revision = models.ForeignKey(SourceRevision, on_delete=models.PROTECT)
    parser_name = models.CharField(max_length=100)
    parser_version = models.CharField(max_length=50)
    document_kind = models.CharField(max_length=32, choices=SourceDocument.Kind)
    normalized = models.JSONField()
    output_hash = models.CharField(max_length=64)
    duration_ms = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "source_revision",
                    "parser_name",
                    "parser_version",
                ],
                name="core_parsed_source_version_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_parsed_source_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(output_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_parsed_source_hash_sha256",
            ),
        ]


class SourceLocation(UUIDModel):
    """Normalized address inside one observed parser derivation."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    parsed_source = models.ForeignKey(ParsedSource, on_delete=models.PROTECT)
    source_observation = models.ForeignKey(SourceObservation, on_delete=models.PROTECT)
    pointer = models.CharField(max_length=1_000)
    start_line = models.PositiveIntegerField(null=True, blank=True)
    end_line = models.PositiveIntegerField(null=True, blank=True)
    excerpt_hash = models.CharField(max_length=64)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "parsed_source",
                    "source_observation",
                    "pointer",
                ],
                name="core_source_location_pointer_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_location_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(excerpt_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_source_location_hash_sha256",
            ),
            models.CheckConstraint(
                condition=(
                    Q(start_line__isnull=True, end_line__isnull=True)
                    | Q(
                        start_line__isnull=False,
                        end_line__isnull=False,
                        end_line__gte=F("start_line"),
                    )
                ),
                name="core_source_location_lines_coherent",
            ),
        ]


class ExtractionResult(UUIDModel):
    """Immutable extractor-version-specific claims over one parser output."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    parsed_source = models.ForeignKey(ParsedSource, on_delete=models.PROTECT)
    extractor_name = models.CharField(max_length=100)
    extractor_version = models.CharField(max_length=50)
    claims = models.JSONField()
    output_hash = models.CharField(max_length=64)
    duration_ms = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "parsed_source",
                    "extractor_name",
                    "extractor_version",
                ],
                name="core_extraction_result_version_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_extraction_result_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(output_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_extraction_result_hash_sha256",
            ),
        ]


class SourceChunk(UUIDModel):
    """Immutable parser-derived retrieval unit, separate from visibility state."""

    objects: ClassVar[models.Manager[SourceChunk]] = models.Manager()
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    parsed_source = models.ForeignKey(ParsedSource, on_delete=models.PROTECT)
    chunk_index = models.PositiveIntegerField()
    pointer = models.CharField(max_length=1_000)
    text = models.TextField()
    content_hash = models.CharField(max_length=64, editable=False)
    char_count = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "parsed_source", "chunk_index"],
                name="core_source_chunk_index_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_source_chunk_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_source_chunk_hash_sha256",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Compute identity at creation and reject ORM updates."""
        digest = hashlib.sha256(self.text.encode()).hexdigest()
        if not self._state.adding:
            raise ArtifactImmutableError("Source chunks cannot be updated")
        if self.content_hash and self.content_hash != digest:
            raise ArtifactImmutableError("Source chunk hash does not match text")
        if self.char_count != len(self.text):
            raise ArtifactImmutableError("Source chunk char_count does not match text")
        self.content_hash = digest
        super().save(*args, **kwargs)


class SourceChunkSearchIndex(UUIDModel):
    """Immutable versioned full-text and vector index for one source chunk."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    source_chunk = models.ForeignKey(SourceChunk, on_delete=models.PROTECT)
    index_version = models.CharField(max_length=50)
    embedding_provider = models.CharField(max_length=100)
    embedding_version = models.CharField(max_length=50)
    indexed_text_hash = models.CharField(max_length=64)
    search_vector = SearchVectorField()
    embedding = VectorField(dimensions=32)
    indexed_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            GinIndex(fields=["search_vector"], name="core_chunk_search_fts_gin"),
            HnswIndex(
                fields=["embedding"],
                name="core_chunk_embedding_hnsw",
                m=16,
                ef_construction=64,
                opclasses=["vector_cosine_ops"],
            ),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "source_chunk",
                    "index_version",
                    "embedding_version",
                ],
                name="core_chunk_search_version_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_chunk_search_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(indexed_text_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_chunk_search_hash_sha256",
            ),
        ]


class SourceChunkVisibility(UUIDModel):
    """Observation-specific index visibility for an immutable source chunk."""

    class State(models.TextChoices):
        AVAILABLE = "AVAILABLE"
        SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
        REVOKED = "REVOKED"
        EXCLUDED = "EXCLUDED"

    objects: ClassVar[models.Manager[SourceChunkVisibility]] = models.Manager()
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    source_chunk = models.ForeignKey(SourceChunk, on_delete=models.PROTECT)
    source_location = models.ForeignKey(SourceLocation, on_delete=models.PROTECT)
    source_observation = models.ForeignKey(SourceObservation, on_delete=models.PROTECT)
    access_snapshot = models.ForeignKey("AccessSnapshot", on_delete=models.PROTECT)
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    state = models.CharField(max_length=24, choices=State, default=State.AVAILABLE)
    observed_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "access_scope", "state"],
                name="core_chunk_vis_scope_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "source_chunk", "source_observation"],
                name="core_chunk_visibility_observation_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_chunk_visibility_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state="AVAILABLE", revoked_at__isnull=True)
                    | Q(
                        state__in=["SOURCE_UNAVAILABLE", "REVOKED", "EXCLUDED"],
                        revoked_at__isnull=False,
                    )
                ),
                name="core_chunk_visibility_state_coherent",
            ),
        ]


class SyncCursor(RevisionedTenantModel):
    """Versioned opaque incremental cursor owned by one connection."""

    source_connection = models.ForeignKey(SourceConnection, on_delete=models.PROTECT)
    cursor_key = models.CharField(max_length=100)
    cursor_value = models.JSONField()

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "source_connection", "cursor_key"],
                name="core_sync_cursor_connection_key_unique",
            ),
        ]


class IngestionFailure(TenantOwnedModel):
    """Secret-safe per-item failure that does not poison the containing sync."""

    sync_run = models.ForeignKey(SyncRun, on_delete=models.PROTECT)
    source_document = models.ForeignKey(
        SourceDocument,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    stage = models.CharField(max_length=50)
    item_key = models.CharField(max_length=1_000)
    error_code = models.CharField(max_length=100)
    safe_message = models.CharField(max_length=500)
    is_transient = models.BooleanField(default=False)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "sync_run", "stage"],
                name="core_ing_fail_run_stage_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "sync_run",
                    "stage",
                    "item_key",
                    "error_code",
                ],
                name="core_ingestion_failure_item_unique",
            )
        ]


class IngestionStageResult(TenantOwnedModel):
    """Observable idempotent stage result with explicit implementation versions."""

    class Status(models.TextChoices):
        RUNNING = "RUNNING"
        SUCCEEDED = "SUCCEEDED"
        PARTIAL = "PARTIAL"
        FAILED = "FAILED"

    sync_run = models.ForeignKey(SyncRun, on_delete=models.PROTECT)
    background_job = models.ForeignKey(
        "BackgroundJob",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    stage = models.CharField(max_length=50)
    input_version = models.CharField(max_length=100)
    implementation_version = models.CharField(max_length=100)
    output_version = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=16, choices=Status)
    duration_ms = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=100, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "sync_run",
                    "stage",
                    "implementation_version",
                ],
                name="core_ingestion_stage_run_version_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(status="RUNNING", completed_at__isnull=True)
                    | Q(
                        status__in=["SUCCEEDED", "PARTIAL", "FAILED"],
                        completed_at__isnull=False,
                    )
                ),
                name="core_ingestion_stage_completion_coherent",
            ),
        ]


class KnowledgeAssertion(RevisionedTenantModel):
    """Current governed assertion state with provenance-preserving content."""

    class ReviewState(models.TextChoices):
        UNREVIEWED = "UNREVIEWED"
        AUTO_ACCEPTED = "AUTO_ACCEPTED"
        HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
        DISPUTED = "DISPUTED"
        REJECTED = "REJECTED"
        SUPERSEDED = "SUPERSEDED"
        STALE = "STALE"

    class ExtractionClass(models.TextChoices):
        MECHANICAL = "MECHANICAL"
        INTERPRETIVE = "INTERPRETIVE"
        HUMAN = "HUMAN"

    class StalenessState(models.TextChoices):
        FRESH = "FRESH"
        AGING = "AGING"
        STALE = "STALE"
        CONTRADICTED = "CONTRADICTED"
        SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"

    subject_key = models.CharField(max_length=500)
    predicate = models.CharField(max_length=200)
    value = models.JSONField()
    is_inferred = models.BooleanField(default=False)
    extraction_class = models.CharField(
        max_length=20,
        choices=ExtractionClass,
        default=ExtractionClass.HUMAN,
    )
    extraction_method = models.CharField(max_length=200, default="human")
    confidence = models.FloatField(default=1.0)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    observed_at = models.DateTimeField(default=timezone.now)
    staleness_state = models.CharField(
        max_length=24,
        choices=StalenessState,
        default=StalenessState.FRESH,
    )
    provenance = models.JSONField(default=list)
    review_state = models.CharField(
        max_length=24,
        choices=ReviewState,
        default=ReviewState.UNREVIEWED,
    )
    access_scope = models.ForeignKey(
        "AccessScope",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "subject_key", "predicate"],
                name="core_assert_subject_pred_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assertion_org_id_unique",
            ),
            models.CheckConstraint(
                condition=~Q(provenance=[]),
                name="core_assertion_provenance_not_empty",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0.0, confidence__lte=1.0),
                name="core_assertion_confidence_range",
            ),
            models.CheckConstraint(
                condition=Q(valid_until__isnull=True) | Q(valid_until__gt=F("valid_from")),
                name="core_assertion_validity_coherent",
            ),
        ]


class AssertionProvenance(TenantOwnedModel):
    """Normalized source lineage for one assertion."""

    assertion = models.ForeignKey(KnowledgeAssertion, on_delete=models.PROTECT)
    source_location = models.ForeignKey(SourceLocation, on_delete=models.PROTECT)
    source_observation = models.ForeignKey(SourceObservation, on_delete=models.PROTECT)
    access_snapshot = models.ForeignKey("AccessSnapshot", on_delete=models.PROTECT)
    extraction_class = models.CharField(
        max_length=20,
        choices=KnowledgeAssertion.ExtractionClass,
    )
    extraction_method = models.CharField(max_length=200)
    confidence = models.FloatField()
    is_inferred = models.BooleanField(default=False)
    observed_at = models.DateTimeField()

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "assertion", "source_location"],
                name="core_assertion_provenance_location_unique",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0.0, confidence__lte=1.0),
                name="core_assertion_provenance_confidence_range",
            ),
        ]


class AssertionValidityInterval(UUIDModel):
    """Immutable-open, one-way-close temporal occurrence of a claim in a document."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assertion = models.ForeignKey(KnowledgeAssertion, on_delete=models.PROTECT)
    source_document = models.ForeignKey(SourceDocument, on_delete=models.PROTECT)
    source_observation = models.ForeignKey(SourceObservation, on_delete=models.PROTECT)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True)
    observed_from = models.DateTimeField()
    observed_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "assertion", "source_document"],
                condition=Q(valid_until__isnull=True),
                name="core_assertion_one_active_document_interval",
            ),
            models.CheckConstraint(
                condition=(
                    Q(valid_until__isnull=True, observed_until__isnull=True)
                    | Q(
                        valid_until__isnull=False,
                        observed_until__isnull=False,
                        valid_until__gt=F("valid_from"),
                        observed_until__gte=F("observed_from"),
                    )
                ),
                name="core_assertion_interval_coherent",
            ),
        ]


class AssertionRevision(UUIDModel):
    """Immutable reconstruction record for a governed assertion revision."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assertion = models.ForeignKey(KnowledgeAssertion, on_delete=models.PROTECT)
    revision = models.PositiveBigIntegerField()
    snapshot = models.JSONField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "assertion", "revision"],
                name="core_assertion_revision_unique",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="core_assertion_revision_gte_1",
            ),
        ]


class AssertionReview(UUIDModel):
    """Explicit human/service review decision history."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assertion = models.ForeignKey(KnowledgeAssertion, on_delete=models.PROTECT)
    actor_type = models.CharField(max_length=50)
    actor_id = models.CharField(max_length=200)
    from_state = models.CharField(max_length=24)
    to_state = models.CharField(max_length=24)
    assertion_revision = models.PositiveBigIntegerField()
    reason = models.CharField(max_length=500, blank=True)
    reviewed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "assertion", "assertion_revision"],
                name="core_assertion_review_revision_unique",
            )
        ]


class AssertionConflict(TenantOwnedModel):
    """Both sides of a contradictory active claim, retained for review."""

    class Status(models.TextChoices):
        OPEN = "OPEN"
        RESOLVED = "RESOLVED"

    left_assertion = models.ForeignKey(
        KnowledgeAssertion,
        on_delete=models.PROTECT,
        related_name="left_conflicts",
    )
    right_assertion = models.ForeignKey(
        KnowledgeAssertion,
        on_delete=models.PROTECT,
        related_name="right_conflicts",
    )
    predicate = models.CharField(max_length=200)
    status = models.CharField(max_length=16, choices=Status, default=Status.OPEN)
    detected_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assertion_conflict_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "left_assertion", "right_assertion"],
                name="core_assertion_conflict_pair_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(status="OPEN", resolved_at__isnull=True)
                    | Q(status="RESOLVED", resolved_at__isnull=False)
                ),
                name="core_assertion_conflict_resolution_coherent",
            ),
            models.CheckConstraint(
                condition=~Q(left_assertion=F("right_assertion")),
                name="core_assertion_conflict_distinct",
            ),
        ]


class KnowledgeEntity(RevisionedTenantModel):
    """Common explicit entity identity without a table per future noun."""

    class EntityType(models.TextChoices):
        TEAM = "TEAM"
        REPOSITORY = "REPOSITORY"
        SERVICE = "SERVICE"
        COMPONENT = "COMPONENT"
        API = "API"
        DATA_ASSET = "DATA_ASSET"
        DECISION = "DECISION"
        POLICY = "POLICY"
        REQUIREMENT = "REQUIREMENT"
        UNKNOWN = "UNKNOWN"

    entity_type = models.CharField(max_length=32, choices=EntityType)
    canonical_key = models.CharField(max_length=500)
    display_name = models.CharField(max_length=500)
    attributes = models.JSONField(default=dict)
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    is_active = models.BooleanField(default=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "entity_type", "canonical_key"],
                name="core_knowledge_entity_canonical_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_knowledge_entity_org_id_unique",
            ),
        ]


class EntityAlias(TenantOwnedModel):
    """Normalized alias used without silently merging ambiguous entities."""

    entity = models.ForeignKey(KnowledgeEntity, on_delete=models.PROTECT)
    normalized_alias = models.CharField(max_length=500)
    source_location = models.ForeignKey(SourceLocation, on_delete=models.PROTECT)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "entity", "normalized_alias"],
                name="core_entity_alias_unique",
            )
        ]


class EntityResolution(UUIDModel):
    """Immutable outcome of alias-aware entity matching."""

    class Outcome(models.TextChoices):
        MATCHED = "MATCHED"
        CREATED = "CREATED"
        AMBIGUOUS = "AMBIGUOUS"
        CONFLICT = "CONFLICT"
        IGNORED = "IGNORED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    source_location = models.ForeignKey(SourceLocation, on_delete=models.PROTECT)
    candidate_key = models.CharField(max_length=500)
    outcome = models.CharField(max_length=16, choices=Outcome)
    entity = models.ForeignKey(
        KnowledgeEntity,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    candidate_ids = models.JSONField(default=list)
    resolver_version = models.CharField(max_length=50)
    resolved_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "source_location",
                    "candidate_key",
                    "resolver_version",
                ],
                name="core_entity_resolution_input_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_entity_resolution_org_id_unique",
            ),
        ]


class KnowledgeRelationship(UUIDModel):
    """Normalized, provenance-bearing edge committed for graph consumers."""

    class RelationshipType(models.TextChoices):
        OWNED_BY = "OWNED_BY"
        MAINTAINED_BY = "MAINTAINED_BY"
        DEPENDS_ON = "DEPENDS_ON"

    class ReviewState(models.TextChoices):
        UNREVIEWED = "UNREVIEWED"
        AMBIGUOUS = "AMBIGUOUS"
        CONFIRMED = "CONFIRMED"
        REJECTED = "REJECTED"

    objects: ClassVar[models.Manager[KnowledgeRelationship]] = models.Manager()
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    relationship_type = models.CharField(max_length=32, choices=RelationshipType)
    source_entity = models.ForeignKey(
        KnowledgeEntity,
        on_delete=models.PROTECT,
        related_name="outgoing_relationships",
    )
    target_entity = models.ForeignKey(
        KnowledgeEntity,
        on_delete=models.PROTECT,
        related_name="incoming_relationships",
    )
    source_entity_type = models.CharField(max_length=32, choices=KnowledgeEntity.EntityType)
    target_entity_type = models.CharField(max_length=32, choices=KnowledgeEntity.EntityType)
    assertion = models.ForeignKey(KnowledgeAssertion, on_delete=models.PROTECT)
    source_location = models.ForeignKey(SourceLocation, on_delete=models.PROTECT)
    source_observation = models.ForeignKey(SourceObservation, on_delete=models.PROTECT)
    access_snapshot = models.ForeignKey("AccessSnapshot", on_delete=models.PROTECT)
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    extraction_class = models.CharField(
        max_length=20,
        choices=KnowledgeAssertion.ExtractionClass,
    )
    confidence = models.FloatField()
    observed_at = models.DateTimeField()
    review_state = models.CharField(
        max_length=24,
        choices=ReviewState,
        default=ReviewState.UNREVIEWED,
    )

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "access_scope", "relationship_type"],
                name="core_rel_scope_type_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "assertion",
                    "source_entity",
                    "target_entity",
                    "relationship_type",
                ],
                name="core_relationship_assertion_edge_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_relationship_org_id_unique",
            ),
            models.CheckConstraint(
                condition=~Q(source_entity=F("target_entity")),
                name="core_relationship_distinct_endpoints",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0.0, confidence__lte=1.0),
                name="core_relationship_confidence_range",
            ),
        ]


class ImmutableArtifact(UUIDModel):
    """Content-addressed context or assurance artifact that cannot be updated."""

    class Kind(models.TextChoices):
        CONTEXT_PACKET = "CONTEXT_PACKET"
        DIFF_ARTIFACT = "DIFF_ARTIFACT"
        EVIDENCE_MANIFEST = "EVIDENCE_MANIFEST"
        EVALUATOR_REQUEST = "EVALUATOR_REQUEST"
        EVALUATOR_RESULT = "EVALUATOR_RESULT"
        ASSURANCE_REPORT = "ASSURANCE_REPORT"
        RENDERED_EXTERNAL_CONTENT = "RENDERED_EXTERNAL_CONTENT"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(
        "AccessScope",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    kind = models.CharField(max_length=32, choices=Kind)
    schema_name = models.CharField(max_length=100)
    schema_version = models.CharField(max_length=20)
    revision = models.PositiveBigIntegerField(default=1)
    payload = models.JSONField()
    content_hash = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="core_artifact_revision_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_artifact_hash_sha256",
            ),
            models.UniqueConstraint(
                fields=["organization", "kind", "content_hash"],
                name="core_artifact_org_kind_hash_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_artifact_org_id_unique",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Compute identity at creation and reject ORM updates."""
        digest = content_hash(self.payload)
        if not self._state.adding:
            raise ArtifactImmutableError("Immutable artifacts cannot be updated")
        if self.content_hash and self.content_hash != digest:
            raise ArtifactImmutableError("Artifact content_hash does not match canonical payload")
        self.content_hash = digest
        super().save(*args, **kwargs)


class RetrievalWatermark(RevisionedTenantModel):
    """Repository retrieval generation used to invalidate packet cache keys."""

    repository = models.ForeignKey("Repository", on_delete=models.PROTECT)
    value = models.PositiveBigIntegerField(default=1)
    reason = models.CharField(max_length=100, default="INITIAL")

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "repository"],
                name="core_retrieval_watermark_repo_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_retrieval_watermark_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(value__gte=1),
                name="core_retrieval_watermark_value_gte_1",
            ),
        ]


class ContextPacketRecord(UUIDModel):
    """Immutable reconstructable retrieval result and cache identity."""

    class Phase(models.TextChoices):
        PREPARE = "PREPARE"
        BUILD = "BUILD"
        PREFLIGHT = "PREFLIGHT"
        ASSURANCE = "ASSURANCE"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    artifact = models.OneToOneField(ImmutableArtifact, on_delete=models.PROTECT)
    repository = models.ForeignKey("Repository", on_delete=models.PROTECT)
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    phase = models.CharField(max_length=16, choices=Phase)
    normalized_request = models.JSONField()
    request_hash = models.CharField(max_length=64)
    authorization_hash = models.CharField(max_length=64)
    selection_hash = models.CharField(max_length=64)
    retrieval_watermark = models.PositiveBigIntegerField()
    retrieval_algorithm_version = models.CharField(max_length=50)
    index_version = models.CharField(max_length=50)
    embedding_version = models.CharField(max_length=50)
    budget_max_items = models.PositiveIntegerField()
    budget_max_tokens = models.PositiveIntegerField()
    budget_max_bytes = models.PositiveIntegerField()
    budget_max_citations = models.PositiveIntegerField()
    selected_items = models.PositiveIntegerField()
    selected_tokens = models.PositiveIntegerField()
    selected_bytes = models.PositiveIntegerField()
    selected_citations = models.PositiveIntegerField()
    limitations = models.JSONField(default=list)
    cache_key = models.CharField(max_length=64)
    generated_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "repository", "cache_key"],
                name="core_packet_cache_lookup_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "cache_key"],
                name="core_context_packet_cache_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_context_packet_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(request_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_context_packet_request_sha256",
            ),
            models.CheckConstraint(
                condition=Q(authorization_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_context_packet_auth_sha256",
            ),
            models.CheckConstraint(
                condition=Q(selection_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_context_packet_selection_sha256",
            ),
            models.CheckConstraint(
                condition=Q(cache_key__regex=r"^[a-f0-9]{64}$"),
                name="core_context_packet_cache_sha256",
            ),
            models.CheckConstraint(
                condition=(
                    Q(selected_items__lte=F("budget_max_items"))
                    & Q(selected_tokens__lte=F("budget_max_tokens"))
                    & Q(selected_bytes__lte=F("budget_max_bytes"))
                    & Q(selected_citations__lte=F("budget_max_citations"))
                ),
                name="core_context_packet_budget_coherent",
            ),
        ]


class ContextPacketItem(UUIDModel):
    """Immutable ordered material selected into one context packet."""

    class Kind(models.TextChoices):
        POLICY = "POLICY"
        RELATIONSHIP = "RELATIONSHIP"
        ASSERTION = "ASSERTION"
        SOURCE_EXCERPT = "SOURCE_EXCERPT"
        DECISION = "DECISION"
        INCIDENT = "INCIDENT"
        CONFLICT = "CONFLICT"

    class Freshness(models.TextChoices):
        CURRENT = "CURRENT"
        STALE = "STALE"
        UNKNOWN = "UNKNOWN"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    context_packet = models.ForeignKey(ContextPacketRecord, on_delete=models.PROTECT)
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    kind = models.CharField(max_length=24, choices=Kind)
    item_key = models.CharField(max_length=500)
    source_assertion = models.ForeignKey(
        KnowledgeAssertion,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    source_relationship = models.ForeignKey(
        KnowledgeRelationship,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    source_chunk = models.ForeignKey(
        SourceChunk,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    source_conflict = models.ForeignKey(
        AssertionConflict,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    summary = models.TextField()
    freshness = models.CharField(max_length=16, choices=Freshness)
    is_inferred = models.BooleanField(default=False)
    selection_reason = models.CharField(max_length=500)
    rank_score = models.FloatField()
    token_count = models.PositiveIntegerField()
    byte_count = models.PositiveIntegerField()
    payload = models.JSONField()
    content_hash = models.CharField(max_length=64, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "context_packet", "position"],
                name="core_context_packet_item_position_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "context_packet", "item_key"],
                name="core_context_packet_item_key_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_context_packet_item_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_context_packet_item_sha256",
            ),
            models.CheckConstraint(
                condition=Q(rank_score__gte=0.0),
                name="core_context_packet_item_score_gte_0",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        digest = content_hash(self.payload)
        if not self._state.adding:
            raise ArtifactImmutableError("Context packet items cannot be updated")
        if self.content_hash and self.content_hash != digest:
            raise ArtifactImmutableError("Context packet item hash does not match payload")
        self.content_hash = digest
        super().save(*args, **kwargs)


class ContextPacketCitation(UUIDModel):
    """Immutable normalized citation for one selected packet item."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    context_packet = models.ForeignKey(ContextPacketRecord, on_delete=models.PROTECT)
    context_item = models.ForeignKey(ContextPacketItem, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    source_location = models.ForeignKey(
        SourceLocation,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    source_observation = models.ForeignKey(
        SourceObservation,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    access_snapshot = models.ForeignKey(
        "AccessSnapshot",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    canonical_url = models.CharField(max_length=1_500)
    locator = models.CharField(max_length=1_000)
    source_content_hash = models.CharField(max_length=64)
    observed_at = models.DateTimeField()

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "context_packet", "context_item", "position"],
                name="core_context_packet_citation_position_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_context_packet_citation_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(source_content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_context_packet_citation_sha256",
            ),
        ]


class ContextPacketInvalidation(UUIDModel):
    """Append-only reason that a historical packet cannot be reused."""

    class Reason(models.TextChoices):
        INGESTION = "INGESTION"
        CORRECTION = "CORRECTION"
        REVOCATION = "REVOCATION"
        SCOPE_CHANGE = "SCOPE_CHANGE"
        MANUAL = "MANUAL"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    context_packet = models.ForeignKey(ContextPacketRecord, on_delete=models.PROTECT)
    repository = models.ForeignKey("Repository", on_delete=models.PROTECT)
    reason = models.CharField(max_length=24, choices=Reason)
    watermark = models.PositiveBigIntegerField()
    details = models.JSONField(default=dict)
    invalidated_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "context_packet", "watermark", "reason"],
                name="core_context_packet_invalidation_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_context_packet_inval_org_id_unique",
            ),
        ]


class PullRequest(RevisionedTenantModel):
    """Current pointer for a repository pull request ingested without code execution."""

    class State(models.TextChoices):
        OPEN = "OPEN"
        MERGED = "MERGED"
        CLOSED = "CLOSED"

    repository = models.ForeignKey("Repository", on_delete=models.PROTECT)
    number = models.PositiveIntegerField()
    state = models.CharField(max_length=16, choices=State, default=State.OPEN)
    current_head_commit = models.CharField(max_length=40)
    current_revision_number = models.PositiveBigIntegerField(default=1)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "repository", "number"],
                name="core_pull_request_repo_number_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_pull_request_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(current_head_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_pull_request_head_commit_sha",
            ),
            models.CheckConstraint(
                condition=Q(number__gte=1, current_revision_number__gte=1),
                name="core_pull_request_numbers_gte_1",
            ),
        ]


class PullRequestRevision(UUIDModel):
    """Immutable manual pull-request snapshot and exact diff identity."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    pull_request = models.ForeignKey(PullRequest, on_delete=models.PROTECT)
    revision = models.PositiveBigIntegerField()
    base_commit = models.CharField(max_length=40)
    head_commit = models.CharField(max_length=40)
    title = models.CharField(max_length=1_000)
    description = models.TextField(blank=True)
    target_branch = models.CharField(max_length=300)
    is_draft = models.BooleanField(default=False)
    state = models.CharField(max_length=16, choices=PullRequest.State)
    diff_artifact = models.ForeignKey(ImmutableArtifact, on_delete=models.PROTECT)
    diff_hash = models.CharField(max_length=64)
    input_hash = models.CharField(max_length=64)
    changed_paths = models.JSONField(default=list)
    classification_summary = models.JSONField(default=dict)
    limitations = models.JSONField(default=list)
    ingested_by_type = models.CharField(max_length=20)
    ingested_by_id = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_pr_revision_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "pull_request", "revision"],
                name="core_pr_revision_number_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "pull_request", "input_hash"],
                name="core_pr_revision_input_unique",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="core_pr_revision_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(base_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_pr_revision_base_sha",
            ),
            models.CheckConstraint(
                condition=Q(head_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_pr_revision_head_sha",
            ),
            models.CheckConstraint(
                condition=Q(diff_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_pr_revision_diff_sha",
            ),
            models.CheckConstraint(
                condition=Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_pr_revision_input_sha",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ArtifactImmutableError("Pull request revisions cannot be updated")
        super().save(*args, **kwargs)


class DiffChunk(UUIDModel):
    """Immutable bounded hunk supplied to an evaluator as untrusted text."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    pull_request_revision = models.ForeignKey(PullRequestRevision, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    path = models.CharField(max_length=1_000)
    classification = models.CharField(max_length=40)
    old_start = models.PositiveIntegerField()
    old_count = models.PositiveIntegerField()
    new_start = models.PositiveIntegerField()
    new_count = models.PositiveIntegerField()
    text = models.TextField()
    content_hash = models.CharField(max_length=64)
    char_count = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "pull_request_revision", "position"],
                name="core_diff_chunk_position_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_diff_chunk_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(position__gte=1),
                name="core_diff_chunk_position_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_diff_chunk_hash_sha",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        digest = hashlib.sha256(self.text.encode()).hexdigest()
        if not self._state.adding:
            raise ArtifactImmutableError("Diff chunks cannot be updated")
        if self.content_hash and self.content_hash != digest:
            raise ArtifactImmutableError("Diff chunk hash does not match text")
        if self.char_count != len(self.text):
            raise ArtifactImmutableError("Diff chunk char_count does not match text")
        self.content_hash = digest
        super().save(*args, **kwargs)


class AssuranceRun(RevisionedTenantModel):
    """Commit-pinned pull-request assurance state machine."""

    class State(models.TextChoices):
        REQUESTED = "REQUESTED"
        DEBOUNCING = "DEBOUNCING"
        FETCHING_PULL_REQUEST = "FETCHING_PULL_REQUEST"
        COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
        EVALUATING_POLICY = "EVALUATING_POLICY"
        BUILDING_CONTEXT = "BUILDING_CONTEXT"
        MODEL_REVIEW = "MODEL_REVIEW"
        MAPPING_EVIDENCE = "MAPPING_EVIDENCE"
        RENDERING_REPORT = "RENDERING_REPORT"
        PUBLISHING = "PUBLISHING"
        COMPLETED = "COMPLETED"
        STALE = "STALE"
        FAILED = "FAILED"
        CANCELLED = "CANCELLED"

    repository_external_id = models.CharField(max_length=300)
    pull_request_number = models.PositiveIntegerField()
    head_commit = models.CharField(max_length=64)
    evaluated_commit = models.CharField(max_length=64, blank=True)
    report_commit = models.CharField(max_length=64, blank=True)
    policy_version = models.PositiveBigIntegerField()
    context_artifact = models.ForeignKey(
        ImmutableArtifact,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="legacy_assurance_runs",
    )
    repository = models.ForeignKey(
        "Repository",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="assurance_runs",
    )
    pull_request_revision = models.ForeignKey(
        PullRequestRevision,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    work_item_revision = models.ForeignKey(
        "WorkItemRevision",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    diff_artifact = models.ForeignKey(
        ImmutableArtifact,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="diff_assurance_runs",
    )
    context_packet = models.ForeignKey(
        ContextPacketRecord,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    policy_evaluation = models.ForeignKey(
        "PolicyEvaluation",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    trigger_key = models.CharField(max_length=64, blank=True)
    input_hash = models.CharField(max_length=64, blank=True)
    requirements_hash = models.CharField(max_length=64, blank=True)
    policy_bundle_hash = models.CharField(max_length=64, blank=True)
    evidence_bundle_hash = models.CharField(max_length=64, blank=True)
    evaluator_version = models.CharField(max_length=100, blank=True)
    prompt_version = models.CharField(max_length=100, blank=True)
    limitations = models.JSONField(default=list)
    readiness = models.CharField(
        max_length=32,
        choices=[
            ("BLOCKED", "BLOCKED"),
            ("READY_WITH_WARNINGS", "READY_WITH_WARNINGS"),
            ("READY_FOR_HUMAN_REVIEW", "READY_FOR_HUMAN_REVIEW"),
            ("STALE", "STALE"),
            ("FAILED", "FAILED"),
        ],
        blank=True,
    )
    failure_code = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=32, choices=State, default=State.REQUESTED)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "repository_external_id", "pull_request_number"],
                name="core_assurance_pr_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assurance_run_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "repository_external_id",
                    "pull_request_number",
                    "head_commit",
                    "input_hash",
                ],
                name="core_assurance_one_head_summary",
            ),
            models.CheckConstraint(
                condition=Q(head_commit__regex=r"^[a-f0-9]{7,64}$"),
                name="core_assurance_head_commit_format",
            ),
            models.CheckConstraint(
                condition=Q(policy_version__gte=1),
                name="core_assurance_policy_version_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(input_hash="") | Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_assurance_input_hash_sha",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(state="COMPLETED")
                    | (
                        Q(evaluated_commit=F("head_commit"))
                        & Q(report_commit=F("head_commit"))
                        & Q(completed_at__isnull=False)
                    )
                ),
                name="core_assurance_completed_commit_match",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state__in=["COMPLETED", "STALE", "FAILED", "CANCELLED"],
                        completed_at__isnull=False,
                    )
                    | Q(
                        state__in=[
                            "REQUESTED",
                            "DEBOUNCING",
                            "FETCHING_PULL_REQUEST",
                            "COLLECTING_EVIDENCE",
                            "EVALUATING_POLICY",
                            "BUILDING_CONTEXT",
                            "MODEL_REVIEW",
                            "MAPPING_EVIDENCE",
                            "RENDERING_REPORT",
                            "PUBLISHING",
                        ],
                        completed_at__isnull=True,
                    )
                ),
                name="core_assurance_terminal_time_coherent",
            ),
        ]


class AssuranceCheck(UUIDModel):
    """Immutable deterministic check result for an exact assurance run."""

    class Status(models.TextChoices):
        PASSED = "PASSED"
        FAILED = "FAILED"
        NOT_AVAILABLE = "NOT_AVAILABLE"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assurance_run = models.ForeignKey(AssuranceRun, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    code = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=Status)
    blocking = models.BooleanField(default=True)
    summary = models.CharField(max_length=2_000)
    evidence_ids = models.JSONField(default=list)
    input_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "assurance_run", "position"],
                name="core_assurance_check_position_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "assurance_run", "code"],
                name="core_assurance_check_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assurance_check_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_assurance_check_input_sha",
            ),
        ]


class EvaluatorTask(RevisionedTenantModel):
    """Provider-neutral, claim/submit queue item containing a sealed review request."""

    class State(models.TextChoices):
        PENDING = "PENDING"
        CLAIMED = "CLAIMED"
        SUBMITTED = "SUBMITTED"
        FAILED = "FAILED"
        CANCELLED = "CANCELLED"

    assurance_run = models.OneToOneField(AssuranceRun, on_delete=models.PROTECT)
    repository = models.ForeignKey("Repository", on_delete=models.PROTECT)
    request_artifact = models.ForeignKey(
        ImmutableArtifact,
        on_delete=models.PROTECT,
        related_name="evaluator_request_tasks",
    )
    result_artifact = models.ForeignKey(
        ImmutableArtifact,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="evaluator_result_tasks",
    )
    state = models.CharField(max_length=16, choices=State, default=State.PENDING)
    claimant = models.CharField(max_length=200, blank=True)
    claim_token_hash = models.CharField(max_length=64, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    attempt_count = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)
    submitted_at = models.DateTimeField(null=True, blank=True)
    failure_code = models.CharField(max_length=100, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "repository", "state", "created_at"],
                name="core_evaluator_task_claim_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_evaluator_task_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(attempt_count__lte=F("max_attempts")),
                name="core_evaluator_attempt_bound",
            ),
        ]


class EvaluatorAttempt(UUIDModel):
    """Append-only evaluator claim or submission attempt history."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    evaluator_task = models.ForeignKey(EvaluatorTask, on_delete=models.PROTECT)
    attempt = models.PositiveIntegerField()
    claimant = models.CharField(max_length=200)
    event = models.CharField(max_length=24)
    request_hash = models.CharField(max_length=64)
    result_hash = models.CharField(max_length=64, blank=True)
    usage = models.JSONField(default=dict)
    safe_error_code = models.CharField(max_length=100, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "evaluator_task", "attempt", "event"],
                name="core_evaluator_attempt_event_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_evaluator_attempt_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(attempt__gte=1),
                name="core_evaluator_attempt_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(request_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_evaluator_attempt_request_sha",
            ),
        ]


class Finding(RevisionedTenantModel):
    """Stable finding identity with an explicit lifecycle across run occurrences."""

    class Kind(models.TextChoices):
        DETERMINISTIC = "DETERMINISTIC"
        POLICY = "POLICY"
        EVIDENCE = "EVIDENCE"
        MODEL = "MODEL"

    class Severity(models.TextChoices):
        BLOCKING = "BLOCKING"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        ADVISORY = "ADVISORY"

    class Confidence(models.TextChoices):
        PROVEN = "PROVEN"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"

    class State(models.TextChoices):
        OPEN = "OPEN"
        DISMISSED = "DISMISSED"
        RISK_ACCEPTED = "RISK_ACCEPTED"
        RESOLVED = "RESOLVED"
        OBSOLETE = "OBSOLETE"

    pull_request = models.ForeignKey(PullRequest, on_delete=models.PROTECT)
    first_run = models.ForeignKey(
        AssuranceRun,
        on_delete=models.PROTECT,
        related_name="first_findings",
    )
    latest_run = models.ForeignKey(
        AssuranceRun,
        on_delete=models.PROTECT,
        related_name="latest_findings",
    )
    fingerprint = models.CharField(max_length=64)
    code = models.CharField(max_length=100)
    kind = models.CharField(max_length=24, choices=Kind)
    severity = models.CharField(max_length=16, choices=Severity)
    confidence = models.CharField(max_length=16, choices=Confidence)
    title = models.CharField(max_length=300)
    explanation = models.TextField()
    path = models.CharField(max_length=1_000, blank=True)
    line = models.PositiveIntegerField(null=True, blank=True)
    citations = models.JSONField(default=list)
    evidence_ids = models.JSONField(default=list)
    criterion_codes = models.JSONField(default=list)
    uncertainty = models.CharField(max_length=2_000)
    suggested_resolution = models.CharField(max_length=2_000)
    state = models.CharField(max_length=20, choices=State, default=State.OPEN)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "pull_request", "state", "severity"],
                name="core_finding_pr_state_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "pull_request", "fingerprint"],
                name="core_finding_fingerprint_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_finding_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(fingerprint__regex=r"^[a-f0-9]{64}$"),
                name="core_finding_fingerprint_sha",
            ),
        ]


class FindingOccurrence(UUIDModel):
    """Immutable observation of one stable finding in one exact run."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    finding = models.ForeignKey(Finding, on_delete=models.PROTECT)
    assurance_run = models.ForeignKey(AssuranceRun, on_delete=models.PROTECT)
    payload = models.JSONField()
    payload_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "finding", "assurance_run"],
                name="core_finding_occurrence_run_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_finding_occurrence_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_finding_occurrence_sha",
            ),
        ]


class FindingDecision(UUIDModel):
    """Append-only authorized lifecycle decision for a finding."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    finding = models.ForeignKey(Finding, on_delete=models.PROTECT)
    from_state = models.CharField(max_length=20)
    to_state = models.CharField(max_length=20)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    authority_path = models.CharField(max_length=1_000)
    reason = models.CharField(max_length=2_000)
    decided_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_finding_decision_org_id_unique",
            )
        ]


class ReadinessDecision(UUIDModel):
    """Immutable precedence result for one exact assurance run."""

    class Status(models.TextChoices):
        BLOCKED = "BLOCKED"
        READY_WITH_WARNINGS = "READY_WITH_WARNINGS"
        READY_FOR_HUMAN_REVIEW = "READY_FOR_HUMAN_REVIEW"
        STALE = "STALE"
        FAILED = "FAILED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assurance_run = models.OneToOneField(AssuranceRun, on_delete=models.PROTECT)
    status = models.CharField(max_length=32, choices=Status)
    reason_codes = models.JSONField(default=list)
    input_hash = models.CharField(max_length=64)
    decided_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_readiness_decision_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_readiness_input_sha",
            ),
            models.CheckConstraint(
                condition=Q(
                    status__in=[
                        "BLOCKED",
                        "READY_WITH_WARNINGS",
                        "READY_FOR_HUMAN_REVIEW",
                        "STALE",
                        "FAILED",
                    ]
                ),
                name="core_readiness_status_valid",
            ),
        ]


class AssuranceReport(UUIDModel):
    """Immutable deterministic Markdown and escaped HTML summary."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assurance_run = models.OneToOneField(AssuranceRun, on_delete=models.PROTECT)
    artifact = models.OneToOneField(ImmutableArtifact, on_delete=models.PROTECT)
    markdown = models.TextField()
    html = models.TextField()
    content_hash = models.CharField(max_length=64)
    renderer_version = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assurance_report_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_assurance_report_sha",
            ),
        ]


class AssuranceKnowledgeProposal(UUIDModel):
    """Post-merge proposal link; never an automatic knowledge mutation."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    assurance_run = models.ForeignKey(AssuranceRun, on_delete=models.PROTECT)
    knowledge_proposal = models.OneToOneField("KnowledgeProposal", on_delete=models.PROTECT)
    classification = models.CharField(max_length=20)
    confidence = models.CharField(max_length=16)
    input_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "assurance_run", "input_hash"],
                name="core_assurance_proposal_input_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assurance_proposal_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_assurance_proposal_sha",
            ),
        ]


class KnowledgeProposal(RevisionedTenantModel):
    """A proposed knowledge mutation requiring validation and review."""

    class State(models.TextChoices):
        PROPOSED = "PROPOSED"
        VALIDATING = "VALIDATING"
        AWAITING_REVIEW = "AWAITING_REVIEW"
        ACCEPTED = "ACCEPTED"
        REJECTED = "REJECTED"
        SUPERSEDED = "SUPERSEDED"
        FAILED = "FAILED"

    summary = models.TextField()
    proposed_changes = models.JSONField()
    anva_sources = models.JSONField()
    state = models.CharField(max_length=24, choices=State, default=State.PROPOSED)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_knowledge_proposal_org_id_unique",
            ),
            models.CheckConstraint(
                condition=~Q(anva_sources=[]),
                name="core_proposal_sources_not_empty",
            ),
            models.CheckConstraint(
                condition=~Q(proposed_changes=[]),
                name="core_proposal_changes_not_empty",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state__in=["ACCEPTED", "REJECTED", "SUPERSEDED", "FAILED"],
                        decided_at__isnull=False,
                    )
                    | Q(
                        state__in=["PROPOSED", "VALIDATING", "AWAITING_REVIEW"],
                        decided_at__isnull=True,
                    )
                ),
                name="core_proposal_decision_time_coherent",
            ),
        ]


class KnowledgeProposalScope(UUIDModel):
    """Explicit repository and visibility binding for a review-only proposal."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    knowledge_proposal = models.OneToOneField(KnowledgeProposal, on_delete=models.PROTECT)
    repository = models.ForeignKey("Repository", on_delete=models.PROTECT)
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    assertion = models.ForeignKey(
        KnowledgeAssertion,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_proposal_scope_org_id_unique",
            )
        ]


class GitHubInstallation(RevisionedTenantModel):
    """Tenant mapping for one GitHub App installation; credentials are never stored."""

    class State(models.TextChoices):
        ACTIVE = "ACTIVE"
        SUSPENDED = "SUSPENDED"
        REVOKED = "REVOKED"

    external_id = models.PositiveBigIntegerField()
    account_id = models.PositiveBigIntegerField()
    account_login = models.CharField(max_length=300)
    account_type = models.CharField(max_length=32)
    repository_selection = models.CharField(max_length=16)
    permissions = models.JSONField(default=dict)
    service_identity = models.OneToOneField(
        "ServiceIdentity",
        on_delete=models.PROTECT,
        related_name="github_installation",
    )
    state = models.CharField(max_length=16, choices=State, default=State.ACTIVE)
    suspended_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["external_id", "state"], name="core_gh_install_ext_state_idx")
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["external_id"],
                name="core_gh_install_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_install_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state="REVOKED", revoked_at__isnull=False)
                    | Q(
                        state__in=["ACTIVE", "SUSPENDED"],
                        revoked_at__isnull=True,
                    )
                ),
                name="core_gh_install_revoked_time",
            ),
        ]


class GitHubRepositoryBinding(RevisionedTenantModel):
    """Explicit installation-to-Anva repository and assurance configuration."""

    installation = models.ForeignKey(GitHubInstallation, on_delete=models.PROTECT)
    repository = models.OneToOneField(
        "Repository",
        on_delete=models.PROTECT,
        related_name="github_binding",
    )
    access_scope = models.ForeignKey("AccessScope", on_delete=models.PROTECT)
    external_repository_id = models.PositiveBigIntegerField()
    full_name = models.CharField(max_length=600)
    default_branch = models.CharField(max_length=300)
    is_private = models.BooleanField(default=True)
    is_archived = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    auto_assurance = models.BooleanField(default=True)
    policy_version_ids = models.JSONField(default=list)
    work_item_revision = models.ForeignKey(
        "WorkItemRevision",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["installation", "external_repository_id", "is_active"],
                name="core_gh_repo_install_state_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["installation", "external_repository_id"],
                name="core_gh_repo_install_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_repo_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(Q(is_active=True, revoked_at__isnull=True) | Q(is_active=False)),
                name="core_gh_repo_active_not_revoked",
            ),
        ]


class GitHubWebhookDelivery(UUIDModel):
    """Immutable, verified, bounded event envelope keyed by GitHub delivery ID."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    installation = models.ForeignKey(GitHubInstallation, on_delete=models.PROTECT)
    repository_binding = models.ForeignKey(
        GitHubRepositoryBinding,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    delivery_id = models.UUIDField()
    event_type = models.CharField(max_length=64)
    action = models.CharField(max_length=64)
    payload_checksum = models.CharField(max_length=64)
    normalized_payload = models.JSONField()
    received_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "installation", "received_at"],
                name="core_gh_delivery_install_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["delivery_id"],
                name="core_gh_delivery_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_delivery_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(payload_checksum__regex=r"^[a-f0-9]{64}$"),
                name="core_gh_delivery_sha256",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ArtifactImmutableError("GitHub webhook deliveries cannot be updated")
        super().save(*args, **kwargs)


class GitHubEventProcessing(RevisionedTenantModel):
    """Mutable processing projection separated from the immutable delivery."""

    class State(models.TextChoices):
        PENDING = "PENDING"
        PROCESSING = "PROCESSING"
        PROCESSED = "PROCESSED"
        IGNORED = "IGNORED"
        FAILED = "FAILED"

    delivery = models.OneToOneField(GitHubWebhookDelivery, on_delete=models.PROTECT)
    state = models.CharField(max_length=16, choices=State, default=State.PENDING)
    attempt_count = models.PositiveIntegerField(default=0)
    result_identifiers = models.JSONField(default=dict)
    last_error_code = models.CharField(max_length=100, blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_processing_org_id_unique",
            ),
        ]


class GitHubCheckObservation(UUIDModel):
    """Immutable exact-commit observation of a Check, suite, or workflow."""

    class Kind(models.TextChoices):
        CHECK_RUN = "CHECK_RUN"
        CHECK_SUITE = "CHECK_SUITE"
        WORKFLOW_RUN = "WORKFLOW_RUN"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository_binding = models.ForeignKey(GitHubRepositoryBinding, on_delete=models.PROTECT)
    delivery = models.ForeignKey(GitHubWebhookDelivery, on_delete=models.PROTECT)
    kind = models.CharField(max_length=20, choices=Kind)
    external_id = models.PositiveBigIntegerField()
    name = models.CharField(max_length=300)
    head_commit = models.CharField(max_length=40)
    status = models.CharField(max_length=32)
    conclusion = models.CharField(max_length=32, blank=True)
    details_url = models.URLField(max_length=2_000, blank=True)
    pull_request_numbers = models.JSONField(default=list)
    payload_hash = models.CharField(max_length=64)
    observed_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["repository_binding", "head_commit", "observed_at"],
                name="core_gh_check_head_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "repository_binding",
                    "kind",
                    "external_id",
                    "payload_hash",
                ],
                name="core_gh_check_observation_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_check_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(head_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_gh_check_head_sha",
            ),
            models.CheckConstraint(
                condition=Q(payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_gh_check_payload_sha",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ArtifactImmutableError("GitHub Check observations cannot be updated")
        super().save(*args, **kwargs)


class GitHubPullRequestObservation(UUIDModel):
    """Provider metadata for one immutable core pull-request revision."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository_binding = models.ForeignKey(GitHubRepositoryBinding, on_delete=models.PROTECT)
    delivery = models.ForeignKey(GitHubWebhookDelivery, on_delete=models.PROTECT)
    pull_request_revision = models.OneToOneField(PullRequestRevision, on_delete=models.PROTECT)
    external_pull_request_id = models.PositiveBigIntegerField()
    head_repository_id = models.PositiveBigIntegerField()
    head_ref = models.CharField(max_length=300)
    is_fork = models.BooleanField(default=False)
    payload_hash = models.CharField(max_length=64)
    observed_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_pr_observation_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_gh_pr_observation_sha",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ArtifactImmutableError("GitHub pull-request observations cannot be updated")
        super().save(*args, **kwargs)


class GitHubPublication(RevisionedTenantModel):
    """Single current external projection for one PR and publication kind."""

    class Kind(models.TextChoices):
        CHECK = "CHECK"
        COMMENT = "COMMENT"

    repository_binding = models.ForeignKey(GitHubRepositoryBinding, on_delete=models.PROTECT)
    pull_request = models.ForeignKey(PullRequest, on_delete=models.PROTECT)
    assurance_run = models.ForeignKey(AssuranceRun, on_delete=models.PROTECT)
    kind = models.CharField(max_length=16, choices=Kind)
    head_commit = models.CharField(max_length=40)
    is_current = models.BooleanField(default=True)
    external_id = models.CharField(max_length=100, blank=True)
    external_url = models.URLField(max_length=2_000, blank=True)
    last_payload_hash = models.CharField(max_length=64, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["repository_binding", "pull_request", "kind", "head_commit"],
                name="core_gh_publication_head_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "repository_binding", "pull_request", "kind"],
                condition=Q(is_current=True),
                name="core_gh_publication_one_current",
            ),
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "repository_binding",
                    "pull_request",
                    "kind",
                    "head_commit",
                ],
                name="core_gh_publication_head_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_publication_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(head_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_gh_publication_head_sha",
            ),
            models.CheckConstraint(
                condition=Q(last_payload_hash="") | Q(last_payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_gh_publication_payload_sha",
            ),
        ]


class GitHubWriteIntent(UUIDModel):
    """Immutable rendered write plus mutable retry state, backed by the outbox."""

    class State(models.TextChoices):
        PENDING = "PENDING"
        RUNNING = "RUNNING"
        RETRY = "RETRY"
        SUCCEEDED = "SUCCEEDED"
        FAILED = "FAILED"
        CANCELLED = "CANCELLED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    publication = models.ForeignKey(GitHubPublication, on_delete=models.PROTECT)
    assurance_run = models.ForeignKey(AssuranceRun, on_delete=models.PROTECT)
    head_commit = models.CharField(max_length=40)
    rendered_payload = models.JSONField()
    payload_hash = models.CharField(max_length=64)
    idempotency_key = models.CharField(max_length=200)
    state = models.CharField(max_length=16, choices=State, default=State.PENDING)
    attempt_count = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=8)
    available_at = models.DateTimeField(default=timezone.now)
    lease_owner = models.CharField(max_length=200, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    last_error_code = models.CharField(max_length=100, blank=True)
    external_id = models.CharField(max_length=100, blank=True)
    external_url = models.URLField(max_length=2_000, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["state", "available_at", "created_at"],
                name="core_gh_write_dispatch_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_write_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"],
                name="core_gh_write_idempotency_unique",
            ),
            models.CheckConstraint(
                condition=Q(head_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_gh_write_head_sha",
            ),
            models.CheckConstraint(
                condition=Q(payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_gh_write_payload_sha",
            ),
            models.CheckConstraint(
                condition=Q(attempt_count__lte=F("max_attempts")),
                name="core_gh_write_attempt_bound",
            ),
        ]


class GitHubWriteAttempt(UUIDModel):
    """Append-only, secret-free history for one outbound GitHub attempt."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    write_intent = models.ForeignKey(GitHubWriteIntent, on_delete=models.PROTECT)
    attempt = models.PositiveIntegerField()
    outcome = models.CharField(max_length=24)
    safe_error_code = models.CharField(max_length=100, blank=True)
    external_id = models.CharField(max_length=100, blank=True)
    response_metadata = models.JSONField(default=dict)
    occurred_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "write_intent", "attempt"],
                name="core_gh_write_attempt_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_gh_write_attempt_org_id_unique",
            ),
        ]


class BackgroundJob(TenantOwnedModel):
    """PostgreSQL job row claimed using row locks and expiring leases."""

    class State(models.TextChoices):
        PENDING = "PENDING"
        RUNNING = "RUNNING"
        SUCCEEDED = "SUCCEEDED"
        FAILED = "FAILED"
        CANCELLED = "CANCELLED"

    kind = models.CharField(max_length=100)
    payload = models.JSONField()
    state = models.CharField(max_length=16, choices=State, default=State.PENDING)
    priority = models.SmallIntegerField(default=0)
    available_at = models.DateTimeField(default=timezone.now)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=3)
    lease_owner = models.CharField(max_length=200, null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    idempotency_key = models.CharField(max_length=200)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["state", "available_at", "-priority", "created_at"],
                name="core_job_claim_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_background_job_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"],
                name="core_job_org_idempotency_unique",
            ),
            models.CheckConstraint(
                condition=Q(max_attempts__gte=1),
                name="core_job_max_attempts_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(attempt_count__lte=F("max_attempts")),
                name="core_job_attempt_within_max",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        state="RUNNING",
                        lease_owner__isnull=False,
                        lease_expires_at__isnull=False,
                    )
                    | (
                        ~Q(state="RUNNING")
                        & Q(lease_owner__isnull=True)
                        & Q(lease_expires_at__isnull=True)
                    )
                ),
                name="core_job_lease_state_coherent",
            ),
        ]


class AuditEvent(UUIDModel):
    """Immutable record of one authorized state mutation."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    actor_type = models.CharField(max_length=50)
    actor_id = models.CharField(max_length=200)
    action = models.CharField(max_length=200)
    target_type = models.CharField(max_length=100)
    target_id = models.UUIDField()
    from_state = models.CharField(max_length=50)
    to_state = models.CharField(max_length=50)
    authorization_path = models.CharField(max_length=500)
    request_id = models.UUIDField()
    source_ip_hash = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "target_type", "target_id", "created_at"],
                name="core_audit_target_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "request_id",
                    "target_type",
                    "target_id",
                    "from_state",
                    "to_state",
                ],
                name="core_audit_request_transition_unique",
            )
        ]


class OutboxEvent(UUIDModel):
    """Transactional handoff for externally visible side effects."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    aggregate_type = models.CharField(max_length=100)
    aggregate_id = models.UUIDField()
    event_type = models.CharField(max_length=200)
    payload = models.JSONField()
    idempotency_key = models.CharField(max_length=300)
    available_at = models.DateTimeField(default=timezone.now)
    attempt_count = models.PositiveIntegerField(default=0)
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["published_at", "available_at", "created_at"],
                name="core_outbox_dispatch_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"],
                name="core_outbox_org_idempotency_unique",
            )
        ]


class Role(TenantOwnedModel):
    """Organization-owned role using one of Anva's stable role codes."""

    class Code(models.TextChoices):
        ORG_ADMIN = "ORG_ADMIN"
        KNOWLEDGE_ADMIN = "KNOWLEDGE_ADMIN"
        TECHNICAL_OWNER = "TECHNICAL_OWNER"
        PRODUCT_OWNER = "PRODUCT_OWNER"
        DEVELOPER = "DEVELOPER"
        REVIEWER = "REVIEWER"
        SECURITY_REVIEWER = "SECURITY_REVIEWER"
        VIEWER = "VIEWER"

    code = models.CharField(max_length=32, choices=Code)
    name = models.CharField(max_length=100)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "code"],
                name="core_role_org_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_role_org_id_unique",
            ),
        ]


class Membership(RevisionedTenantModel):
    """A human user's role-bearing membership in one organization."""

    user = models.ForeignKey(User, on_delete=models.PROTECT)
    role = models.ForeignKey(Role, on_delete=models.PROTECT)
    is_active = models.BooleanField(default=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "user"],
                name="core_membership_org_user_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_membership_org_id_unique",
            ),
        ]


class Team(TenantOwnedModel):
    """A tenant-owned team used in approval and access scopes."""

    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=100)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "slug"],
                name="core_team_org_slug_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_team_org_id_unique",
            ),
        ]


class TeamMembership(TenantOwnedModel):
    """A same-tenant membership assigned to a team."""

    team = models.ForeignKey(Team, on_delete=models.CASCADE)
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "team", "membership"],
                name="core_team_membership_unique",
            )
        ]


class ServiceIdentity(RevisionedTenantModel):
    """A non-human principal with an explicit issuer and audience."""

    name = models.CharField(max_length=200)
    issuer = models.CharField(max_length=200)
    audience = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "name"],
                name="core_service_identity_org_name_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_service_identity_org_id_unique",
            ),
        ]


class ExternalIdentity(TimeStampedModel):
    """A provider identity linked to one human user."""

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    provider = models.CharField(max_length=50)
    subject = models.CharField(max_length=300)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["provider", "subject"],
                name="core_external_identity_unique",
            )
        ]


class Repository(TenantOwnedModel):
    """A tenant-owned repository authorization boundary."""

    external_id = models.CharField(max_length=300)
    name = models.CharField(max_length=300)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "external_id"],
                name="core_repository_org_external_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_repository_org_id_unique",
            ),
        ]


class OrganizationProductSettings(UUIDModel):
    """Durable product choices captured during organization setup."""

    class ModelProcessing(models.TextChoices):
        DISABLED = "DISABLED"
        REDACTED_ONLY = "REDACTED_ONLY"
        ALLOWED = "ALLOWED"

    class SkillDistribution(models.TextChoices):
        SELF_SERVICE = "SELF_SERVICE"
        MANAGED = "MANAGED"

    class AssuranceMode(models.TextChoices):
        OBSERVE = "OBSERVE"
        EVIDENCE = "EVIDENCE"

    organization = models.OneToOneField(Organization, on_delete=models.PROTECT)
    retention_days = models.PositiveIntegerField(default=365)
    model_processing = models.CharField(
        max_length=24,
        choices=ModelProcessing,
        default=ModelProcessing.REDACTED_ONLY,
    )
    skill_distribution = models.CharField(
        max_length=24,
        choices=SkillDistribution,
        default=SkillDistribution.SELF_SERVICE,
    )
    assurance_mode = models.CharField(
        max_length=24,
        choices=AssuranceMode,
        default=AssuranceMode.OBSERVE,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(retention_days__gte=1, retention_days__lte=3650),
                name="core_product_settings_retention_range",
            )
        ]


class RepositoryProfile(RevisionedTenantModel):
    """Governed repository profile proposed during onboarding and human-confirmed."""

    class Status(models.TextChoices):
        DRAFT = "DRAFT"
        PROPOSED = "PROPOSED"
        CONFIRMED = "CONFIRMED"

    repository = models.OneToOneField(Repository, on_delete=models.PROTECT)
    purpose = models.TextField(blank=True)
    owning_team = models.CharField(max_length=300, blank=True)
    products = models.JSONField(default=list)
    systems = models.JSONField(default=list)
    runtime = models.JSONField(default=list)
    setup_commands = models.JSONField(default=list)
    required_checks = models.JSONField(default=list)
    sensitive_paths = models.JSONField(default=list)
    unsupported_or_ambiguous = models.JSONField(default=list)
    source_references = models.JSONField(default=list)
    status = models.CharField(max_length=16, choices=Status, default=Status.DRAFT)
    confirmed_by_type = models.CharField(max_length=20, blank=True)
    confirmed_by_id = models.CharField(max_length=200, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_repository_profile_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        status="CONFIRMED",
                        confirmed_at__isnull=False,
                        confirmed_by_type__gt="",
                        confirmed_by_id__gt="",
                    )
                    | (
                        ~Q(status="CONFIRMED")
                        & Q(
                            confirmed_at__isnull=True,
                            confirmed_by_type="",
                            confirmed_by_id="",
                        )
                    )
                ),
                name="core_repository_profile_confirmation_coherent",
            ),
        ]


class AccessScope(RevisionedTenantModel):
    """A reusable visibility boundary over principals, repositories, and sources."""

    name = models.CharField(max_length=200)
    all_memberships = models.BooleanField(default=False)
    all_service_identities = models.BooleanField(default=False)
    all_repositories = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_derived = models.BooleanField(default=False)
    boundary_sealed_at = models.DateTimeField(null=True, blank=True)
    derived_from = models.ManyToManyField(
        "self",
        symmetrical=False,
        blank=True,
        related_name="derived_scopes",
    )

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_access_scope_org_id_unique",
            ),
            models.CheckConstraint(
                condition=(
                    Q(is_derived=False, boundary_sealed_at__isnull=True)
                    | Q(is_derived=True, boundary_sealed_at__isnull=False)
                ),
                name="core_access_scope_derived_seal_coherent",
            ),
        ]


class AccessScopeMembership(TenantOwnedModel):
    """A human principal included in an access scope."""

    access_scope = models.ForeignKey(AccessScope, on_delete=models.CASCADE)
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["access_scope", "membership"],
                name="core_scope_membership_unique",
            )
        ]


class AccessScopeServiceIdentity(TenantOwnedModel):
    """A service principal included in an access scope."""

    access_scope = models.ForeignKey(AccessScope, on_delete=models.CASCADE)
    service_identity = models.ForeignKey(ServiceIdentity, on_delete=models.CASCADE)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["access_scope", "service_identity"],
                name="core_scope_service_unique",
            )
        ]


class AccessScopeRepository(TenantOwnedModel):
    """A repository included in an access scope."""

    access_scope = models.ForeignKey(AccessScope, on_delete=models.CASCADE)
    repository = models.ForeignKey(Repository, on_delete=models.CASCADE)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["access_scope", "repository"],
                name="core_scope_repository_unique",
            )
        ]


class AccessScopeSource(TenantOwnedModel):
    """A source connection contributing to an access scope."""

    access_scope = models.ForeignKey(AccessScope, on_delete=models.CASCADE)
    source_connection = models.ForeignKey(SourceConnection, on_delete=models.CASCADE)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["access_scope", "source_connection"],
                name="core_scope_source_unique",
            )
        ]


class AccessSnapshot(UUIDModel):
    """A content-addressed record of a source permission boundary at one instant."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    source_connection = models.ForeignKey(SourceConnection, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    scope_revision = models.PositiveBigIntegerField()
    payload = models.JSONField()
    content_hash = models.CharField(max_length=64, editable=False)
    captured_at = models.DateTimeField(default=timezone.now, editable=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(scope_revision__gte=1),
                name="core_access_snapshot_revision_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_access_snapshot_hash_sha256",
            ),
            models.UniqueConstraint(
                fields=["organization", "source_connection", "content_hash"],
                name="core_access_snapshot_identity_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_access_snapshot_org_id_unique",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        digest = content_hash(self.payload)
        if self.content_hash and self.content_hash != digest:
            raise ValueError("Access snapshot hash does not match canonical payload")
        self.content_hash = digest
        super().save(*args, **kwargs)


class AccessGrant(TenantOwnedModel):
    """One action grant for exactly one human or service principal."""

    membership = models.ForeignKey(
        Membership,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    service_identity = models.ForeignKey(
        ServiceIdentity,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    repository = models.ForeignKey(
        Repository,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    source_connection = models.ForeignKey(
        SourceConnection,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=100)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=(
                    Q(membership__isnull=False, service_identity__isnull=True)
                    | Q(membership__isnull=True, service_identity__isnull=False)
                ),
                name="core_access_grant_one_principal",
            ),
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "membership",
                    "service_identity",
                    "repository",
                    "source_connection",
                    "action",
                ],
                nulls_distinct=False,
                name="core_access_grant_principal_unique",
            ),
        ]


class RepositoryAccessToken(UUIDModel):
    """A repository-scoped bearer credential stored only as a keyed hash."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    service_identity = models.ForeignKey(ServiceIdentity, on_delete=models.PROTECT)
    token_hash = models.CharField(max_length=64, editable=False)
    allowed_actions = models.JSONField()
    issuer = models.CharField(max_length=200)
    audience = models.CharField(max_length=200)
    issued_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    rotated_from = models.OneToOneField(
        "self",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="rotated_to",
    )

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(
                condition=Q(token_hash__regex=r"^[a-f0-9]{64}$"),  # noqa: S106
                name="core_repository_token_hash_sha256",
            ),
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("issued_at")),
                name="core_repository_token_expiry_after_issue",
            ),
            models.CheckConstraint(
                condition=~Q(allowed_actions=[]),
                name="core_repository_token_actions_not_empty",
            ),
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_repository_token_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "repository", "id"],
                name="core_repository_token_org_repo_id_unique",
            ),
            models.UniqueConstraint(
                fields=["token_hash"],
                name="core_repository_token_hash_unique",
            ),
        ]


class WorkItem(RevisionedTenantModel):
    """Current pointer for versioned, repository-scoped delivery intent."""

    class WorkType(models.TextChoices):
        FEATURE = "FEATURE"
        BUG = "BUG"
        SECURITY = "SECURITY"
        MIGRATION = "MIGRATION"
        OPERATIONS = "OPERATIONS"
        OTHER = "OTHER"

    class Status(models.TextChoices):
        DRAFT = "DRAFT"
        READY = "READY"
        APPROVED = "APPROVED"
        CLOSED = "CLOSED"

    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    external_key = models.CharField(max_length=300, null=True, blank=True)
    title = models.CharField(max_length=500)
    work_type = models.CharField(max_length=24, choices=WorkType)
    status = models.CharField(max_length=24, choices=Status, default=Status.DRAFT)
    current_content_hash = models.CharField(max_length=64)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_work_item_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "repository", "external_key"],
                condition=Q(external_key__isnull=False),
                name="core_work_item_external_unique",
            ),
            models.CheckConstraint(
                condition=Q(current_content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_work_item_hash_sha256",
            ),
        ]


class WorkItemRevision(UUIDModel):
    """Immutable normalized snapshot of one complete work-item version."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item = models.ForeignKey(WorkItem, on_delete=models.PROTECT)
    revision = models.PositiveBigIntegerField()
    title = models.CharField(max_length=500)
    work_type = models.CharField(max_length=24, choices=WorkItem.WorkType)
    status = models.CharField(max_length=24, choices=WorkItem.Status)
    summary = models.TextField(blank=True)
    origin = models.CharField(max_length=100)
    source_references = models.JSONField(default=list)
    normalized_payload = models.JSONField()
    content_hash = models.CharField(max_length=64)
    created_by_type = models.CharField(max_length=20)
    created_by_id = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_work_revision_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item", "revision"],
                name="core_work_revision_number_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item", "content_hash"],
                name="core_work_revision_hash_unique",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="core_work_revision_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_work_revision_hash_sha256",
            ),
        ]


class Requirement(UUIDModel):
    """Immutable confirmed requirement in one exact work-item revision."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    code = models.CharField(max_length=64)
    normalized_text = models.TextField()
    origin = models.CharField(max_length=100)
    owner = models.CharField(max_length=300, blank=True)
    status = models.CharField(max_length=24)
    source_references = models.JSONField(default=list)
    related_entity_ids = models.JSONField(default=list)
    requires_approval = models.BooleanField(default=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_requirement_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "code"],
                name="core_requirement_revision_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "position"],
                name="core_requirement_revision_position_unique",
            ),
        ]


class NonRequirement(UUIDModel):
    """Immutable explicit exclusion from one work-item revision."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    code = models.CharField(max_length=64)
    normalized_text = models.TextField()
    rationale = models.TextField(blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_non_requirement_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "code"],
                name="core_non_requirement_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "position"],
                name="core_non_requirement_position_unique",
            ),
        ]


class Assumption(UUIDModel):
    """Immutable explicitly labeled assumption in one work-item revision."""

    class Status(models.TextChoices):
        OPEN = "OPEN"
        VALIDATED = "VALIDATED"
        INVALIDATED = "INVALIDATED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    code = models.CharField(max_length=64)
    normalized_text = models.TextField()
    status = models.CharField(max_length=16, choices=Status, default=Status.OPEN)
    validation_reference = models.CharField(max_length=1_000, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_assumption_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "code"],
                name="core_assumption_revision_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "position"],
                name="core_assumption_revision_position_unique",
            ),
        ]


class AcceptanceCriterion(UUIDModel):
    """Immutable, version-bound outcome that must map to evidence or a gap."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    requirement = models.ForeignKey(
        Requirement,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    code = models.CharField(max_length=64)
    normalized_text = models.TextField()
    required_evidence_types = models.JSONField(default=list)
    manual_approval_allowed = models.BooleanField(default=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_criterion_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "code"],
                name="core_criterion_revision_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "position"],
                name="core_criterion_revision_position_unique",
            ),
        ]


class Decision(UUIDModel):
    """Immutable plan or product decision attached to one intent revision."""

    class Status(models.TextChoices):
        PROPOSED = "PROPOSED"
        ACCEPTED = "ACCEPTED"
        REJECTED = "REJECTED"
        SUPERSEDED = "SUPERSEDED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    position = models.PositiveIntegerField()
    code = models.CharField(max_length=64)
    title = models.CharField(max_length=500)
    outcome = models.TextField()
    rationale = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_decision_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "code"],
                name="core_decision_revision_code_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "position"],
                name="core_decision_revision_position_unique",
            ),
        ]


class Approval(UUIDModel):
    """Append-only authority decision over exact versioned intent."""

    class Status(models.TextChoices):
        APPROVED = "APPROVED"
        REJECTED = "REJECTED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    target_kind = models.CharField(max_length=40)
    target_key = models.CharField(max_length=200)
    status = models.CharField(max_length=16, choices=Status)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    authority_action = models.CharField(max_length=100)
    reason = models.CharField(max_length=2_000)
    idempotency_key = models.CharField(max_length=64)
    decided_at = models.DateTimeField(default=timezone.now, editable=False)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_approval_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"],
                name="core_approval_idempotency_unique",
            ),
            models.CheckConstraint(
                condition=Q(idempotency_key__regex=r"^[a-f0-9]{64}$"),
                name="core_approval_key_sha256",
            ),
        ]


class ApprovalRevocation(UUIDModel):
    """Append-only withdrawal of one exact approval."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    approval = models.OneToOneField(Approval, on_delete=models.PROTECT)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    authority_path = models.CharField(max_length=1_000)
    reason = models.CharField(max_length=2_000)
    revoked_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_approval_revocation_org_id_unique",
            )
        ]


class WorkSummary(UUIDModel):
    """Immutable structured summary that is context, never deterministic evidence."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(WorkItemRevision, on_delete=models.PROTECT)
    summary_type = models.CharField(max_length=40)
    structured_data = models.JSONField()
    content_hash = models.CharField(max_length=64)
    producer = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_work_summary_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "work_item_revision", "content_hash"],
                name="core_work_summary_hash_unique",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_work_summary_hash_sha256",
            ),
        ]


class Policy(RevisionedTenantModel):
    """Current pointer for one governed, versioned deterministic policy."""

    class Status(models.TextChoices):
        DRAFT = "DRAFT"
        ACTIVE = "ACTIVE"
        DISABLED = "DISABLED"

    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    name = models.CharField(max_length=300)
    owner = models.CharField(max_length=300)
    status = models.CharField(max_length=16, choices=Status)
    current_content_hash = models.CharField(max_length=64)

    class Meta(RevisionedTenantModel.Meta):
        constraints: ClassVar[list[models.BaseConstraint]] = [
            *RevisionedTenantModel.Meta.constraints,
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_org_id_unique",
            ),
            models.CheckConstraint(
                condition=Q(current_content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_policy_hash_sha256",
            ),
        ]


class PolicyVersion(UUIDModel):
    """Immutable validated policy definition used by every evaluation."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    policy = models.ForeignKey(Policy, on_delete=models.PROTECT)
    version = models.PositiveBigIntegerField()
    schema_version = models.CharField(max_length=20)
    definition = models.JSONField()
    content_hash = models.CharField(max_length=64)
    effective_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by_type = models.CharField(max_length=20)
    created_by_id = models.CharField(max_length=200)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_version_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "policy", "version"],
                name="core_policy_version_number_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "policy", "content_hash"],
                name="core_policy_version_hash_unique",
            ),
            models.CheckConstraint(
                condition=Q(version__gte=1),
                name="core_policy_version_gte_1",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_policy_version_hash_sha256",
            ),
        ]


class PolicyBinding(UUIDModel):
    """Immutable matcher dimensions for one exact policy version."""

    class ScopeLevel(models.TextChoices):
        ORGANIZATION = "ORGANIZATION"
        PRODUCT = "PRODUCT"
        SYSTEM = "SYSTEM"
        REPOSITORY = "REPOSITORY"
        PATH = "PATH"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    policy_version = models.OneToOneField(PolicyVersion, on_delete=models.PROTECT)
    scope_level = models.CharField(max_length=20, choices=ScopeLevel)
    mandatory = models.BooleanField(default=False)
    repository_ids = models.JSONField(default=list)
    entity_ids = models.JSONField(default=list)
    entity_types = models.JSONField(default=list)
    path_patterns = models.JSONField(default=list)
    work_item_types = models.JSONField(default=list)
    target_branches = models.JSONField(default=list)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_binding_org_id_unique",
            )
        ]


class PolicyRequirement(UUIDModel):
    """Immutable normalized requirement emitted by one policy version."""

    class Enforcement(models.TextChoices):
        BLOCKING = "BLOCKING"
        ADVISORY = "ADVISORY"

    class CheckType(models.TextChoices):
        DETERMINISTIC = "DETERMINISTIC"
        EVIDENCE = "EVIDENCE"
        MODEL_REVIEW = "MODEL_REVIEW"
        MANUAL_APPROVAL = "MANUAL_APPROVAL"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    policy_version = models.ForeignKey(PolicyVersion, on_delete=models.PROTECT)
    code = models.CharField(max_length=64)
    description = models.TextField()
    enforcement = models.CharField(max_length=16, choices=Enforcement)
    check_type = models.CharField(max_length=24, choices=CheckType)
    required_evidence = models.JSONField(default=list)
    required_reviewers = models.JSONField(default=list)
    required_approval = models.BooleanField(default=False)
    report_sections = models.JSONField(default=list)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_requirement_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "policy_version", "code"],
                name="core_policy_requirement_code_unique",
            ),
        ]


class PolicyEvaluation(UUIDModel):
    """Content-addressed immutable result for exact versioned policy inputs."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(
        WorkItemRevision,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    pull_request_number = models.PositiveIntegerField()
    commit_sha = models.CharField(max_length=40)
    reference_time = models.DateTimeField()
    is_simulation = models.BooleanField(default=False)
    input_payload = models.JSONField()
    input_hash = models.CharField(max_length=64)
    output_payload = models.JSONField()
    output_hash = models.CharField(max_length=64)
    evaluated_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_evaluation_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "input_hash"],
                name="core_policy_evaluation_input_unique",
            ),
            models.CheckConstraint(
                condition=Q(commit_sha__regex=r"^[a-f0-9]{40}$"),
                name="core_policy_evaluation_commit_sha",
            ),
            models.CheckConstraint(
                condition=Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_policy_evaluation_input_sha",
            ),
            models.CheckConstraint(
                condition=Q(output_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_policy_evaluation_output_sha",
            ),
        ]


class PolicyOverride(UUIDModel):
    """Append-only authority-checked exception for an exact evaluation input."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    policy_evaluation = models.ForeignKey(PolicyEvaluation, on_delete=models.PROTECT)
    policy_version = models.ForeignKey(PolicyVersion, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    pull_request_number = models.PositiveIntegerField()
    requirement_code = models.CharField(max_length=64)
    commit_sha = models.CharField(max_length=40)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    authority_path = models.CharField(max_length=1_000)
    reason = models.CharField(max_length=2_000)
    idempotency_key = models.CharField(max_length=64)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_override_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "idempotency_key"],
                name="core_policy_override_key_unique",
            ),
            models.CheckConstraint(
                condition=Q(commit_sha__regex=r"^[a-f0-9]{40}$"),
                name="core_policy_override_commit_sha",
            ),
            models.CheckConstraint(
                condition=Q(idempotency_key__regex=r"^[a-f0-9]{64}$"),
                name="core_policy_override_key_sha",
            ),
        ]


class PolicyOverrideRevocation(UUIDModel):
    """Append-only withdrawal of one exact policy override."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    policy_override = models.OneToOneField(PolicyOverride, on_delete=models.PROTECT)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    authority_path = models.CharField(max_length=1_000)
    reason = models.CharField(max_length=2_000)
    revoked_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_policy_override_revoke_org_id_unique",
            )
        ]


class EvidenceManifest(UUIDModel):
    """Immutable schema-validated submission envelope; payloads are never executed."""

    class ProducerMode(models.TextChoices):
        MANUAL = "MANUAL"
        CI = "CI"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    artifact = models.OneToOneField(ImmutableArtifact, on_delete=models.PROTECT)
    work_item_revision = models.ForeignKey(
        WorkItemRevision,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    pull_request_number = models.PositiveIntegerField()
    commit_sha = models.CharField(max_length=40)
    schema_version = models.CharField(max_length=20)
    producer = models.CharField(max_length=200)
    producer_version = models.CharField(max_length=100)
    producer_mode = models.CharField(max_length=16, choices=ProducerMode)
    payload_hash = models.CharField(max_length=64)
    payload_size = models.PositiveIntegerField()
    received_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_evidence_manifest_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "repository", "payload_hash"],
                name="core_evidence_manifest_hash_unique",
            ),
            models.CheckConstraint(
                condition=Q(commit_sha__regex=r"^[a-f0-9]{40}$"),
                name="core_evidence_manifest_commit_sha",
            ),
            models.CheckConstraint(
                condition=Q(payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_evidence_manifest_payload_sha",
            ),
        ]


class Evidence(UUIDModel):
    """Immutable commit-bound deterministic status or approved manual evidence."""

    class Kind(models.TextChoices):
        CHECK_STATUS = "CHECK_STATUS"
        TEST_RESULT = "TEST_RESULT"
        BUILD_RESULT = "BUILD_RESULT"
        TYPECHECK_RESULT = "TYPECHECK_RESULT"
        LINT_RESULT = "LINT_RESULT"
        SCREENSHOT = "SCREENSHOT"
        VIDEO = "VIDEO"
        CONSOLE_LOG = "CONSOLE_LOG"
        NETWORK_TRACE = "NETWORK_TRACE"
        API_ASSERTION = "API_ASSERTION"
        STATIC_ANALYSIS = "STATIC_ANALYSIS"
        SECURITY_SCAN = "SECURITY_SCAN"
        DEPENDENCY_SCAN = "DEPENDENCY_SCAN"
        MIGRATION_RESULT = "MIGRATION_RESULT"
        PERFORMANCE_RESULT = "PERFORMANCE_RESULT"
        ACCESSIBILITY_RESULT = "ACCESSIBILITY_RESULT"
        MANUAL_APPROVAL = "MANUAL_APPROVAL"
        SOURCE_REFERENCE = "SOURCE_REFERENCE"
        DIFF_REFERENCE = "DIFF_REFERENCE"

    class Status(models.TextChoices):
        PASSED = "PASSED"
        FAILED = "FAILED"
        UNKNOWN = "UNKNOWN"

    class RetentionState(models.TextChoices):
        ACTIVE = "ACTIVE"
        EXPIRED = "EXPIRED"
        DELETED = "DELETED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    manifest = models.ForeignKey(EvidenceManifest, on_delete=models.PROTECT)
    approval = models.ForeignKey(Approval, on_delete=models.PROTECT, null=True, blank=True)
    commit_sha = models.CharField(max_length=40)
    kind = models.CharField(max_length=32, choices=Kind)
    name = models.CharField(max_length=300)
    producer = models.CharField(max_length=200)
    producer_version = models.CharField(max_length=100)
    command = models.CharField(max_length=2_000, blank=True)
    status = models.CharField(max_length=16, choices=Status)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField()
    artifact_reference = models.CharField(max_length=2_000, blank=True)
    source_url = models.URLField(max_length=2_000, blank=True)
    content_hash = models.CharField(max_length=64)
    limitations = models.JSONField(default=list)
    criterion_codes = models.JSONField(default=list)
    retention_class = models.CharField(max_length=100)
    retention_expires_at = models.DateTimeField(null=True, blank=True)
    environment = models.CharField(max_length=200, blank=True)
    scenario = models.CharField(max_length=500, blank=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_evidence_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "manifest", "content_hash", "kind", "name"],
                name="core_evidence_manifest_identity_unique",
            ),
            models.CheckConstraint(
                condition=Q(commit_sha__regex=r"^[a-f0-9]{40}$"),
                name="core_evidence_commit_sha",
            ),
            models.CheckConstraint(
                condition=Q(content_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_evidence_hash_sha256",
            ),
            models.CheckConstraint(
                condition=Q(started_at__isnull=True) | Q(completed_at__gte=F("started_at")),
                name="core_evidence_time_coherent",
            ),
            models.CheckConstraint(
                condition=(
                    Q(kind="MANUAL_APPROVAL", approval__isnull=False)
                    | (~Q(kind="MANUAL_APPROVAL") & Q(approval__isnull=True))
                ),
                name="core_evidence_manual_approval_coherent",
            ),
        ]


class CriterionEvidence(UUIDModel):
    """Immutable deterministic mapping or explicit gap for one criterion version."""

    class Classification(models.TextChoices):
        DIRECT = "DIRECT"
        INDIRECT = "INDIRECT"
        GAP = "GAP"

    class Assessment(models.TextChoices):
        SATISFIED = "SATISFIED"
        GAP = "GAP"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    criterion = models.ForeignKey(AcceptanceCriterion, on_delete=models.PROTECT)
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT, null=True, blank=True)
    target_commit = models.CharField(max_length=40)
    pull_request_number = models.PositiveIntegerField()
    reference_time = models.DateTimeField()
    required_evidence_type = models.CharField(max_length=32)
    engine_version = models.CharField(max_length=64)
    input_hash = models.CharField(max_length=64)
    classification = models.CharField(max_length=16, choices=Classification)
    assessment = models.CharField(max_length=16, choices=Assessment)
    verifier_type = models.CharField(max_length=20)
    verifier_id = models.CharField(max_length=200)
    limitations = models.JSONField(default=list)
    confidence = models.FloatField()
    gap_code = models.CharField(max_length=64, blank=True)
    gap_description = models.CharField(max_length=2_000, blank=True)
    mapping_key = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_criterion_evidence_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "mapping_key"],
                name="core_criterion_evidence_key_unique",
            ),
            models.CheckConstraint(
                condition=Q(target_commit__regex=r"^[a-f0-9]{40}$"),
                name="core_criterion_evidence_commit_sha",
            ),
            models.CheckConstraint(
                condition=Q(mapping_key__regex=r"^[a-f0-9]{64}$"),
                name="core_criterion_evidence_key_sha",
            ),
            models.CheckConstraint(
                condition=Q(input_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_criterion_evidence_input_sha",
            ),
            models.CheckConstraint(
                condition=Q(pull_request_number__gte=1),
                name="core_criterion_evidence_pr_gte_1",
            ),
            models.CheckConstraint(
                condition=~Q(engine_version="") & ~Q(required_evidence_type=""),
                name="core_criterion_evidence_versions_present",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0.0, confidence__lte=1.0),
                name="core_criterion_evidence_confidence",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        assessment="SATISFIED",
                        evidence__isnull=False,
                        gap_code="",
                        gap_description="",
                    )
                    | (
                        Q(
                            assessment="GAP",
                            evidence__isnull=True,
                        )
                        & ~Q(gap_code="")
                        & ~Q(gap_description="")
                    )
                ),
                name="core_criterion_evidence_coherent",
            ),
        ]


class EvidenceRetentionEvent(UUIDModel):
    """Append-only availability history without mutating immutable evidence."""

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    evidence = models.ForeignKey(Evidence, on_delete=models.PROTECT)
    state = models.CharField(max_length=16, choices=Evidence.RetentionState)
    reason = models.CharField(max_length=1_000)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    occurred_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_evidence_retention_org_id_unique",
            )
        ]


class MCPToolInvocation(UUIDModel):
    """Content-free audit record for one authenticated MCP or parity HTTP call."""

    class Outcome(models.TextChoices):
        SUCCEEDED = "SUCCEEDED"
        FAILED = "FAILED"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    credential = models.ForeignKey(
        RepositoryAccessToken,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    transport = models.CharField(max_length=16)
    tool_name = models.CharField(max_length=100)
    required_action = models.CharField(max_length=100)
    arguments_hash = models.CharField(max_length=64)
    request_id = models.UUIDField()
    outcome = models.CharField(max_length=16, choices=Outcome)
    error_code = models.CharField(max_length=100, blank=True)
    target_id = models.UUIDField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(
                fields=["organization", "repository", "created_at"],
                name="core_mcp_audit_repo_idx",
            )
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_mcp_invocation_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "request_id"],
                name="core_mcp_invocation_request_unique",
            ),
            models.CheckConstraint(
                condition=Q(arguments_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_mcp_invocation_args_sha256",
            ),
            models.CheckConstraint(
                condition=(
                    Q(outcome="SUCCEEDED", error_code="") | Q(outcome="FAILED", error_code__gt="")
                ),
                name="core_mcp_invocation_outcome_coherent",
            ),
        ]


class MCPProposalSubmission(UUIDModel):
    """Repository/scope-bound provenance for a review-only MCP proposal."""

    class Kind(models.TextChoices):
        CORRECTION = "CORRECTION"
        RELATIONSHIP = "RELATIONSHIP"
        DECISION = "DECISION"
        WORK_SUMMARY = "WORK_SUMMARY"
        PREFLIGHT_SUMMARY = "PREFLIGHT_SUMMARY"

    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    repository = models.ForeignKey(Repository, on_delete=models.PROTECT)
    access_scope = models.ForeignKey(AccessScope, on_delete=models.PROTECT)
    knowledge_proposal = models.OneToOneField(KnowledgeProposal, on_delete=models.PROTECT)
    credential = models.ForeignKey(
        RepositoryAccessToken,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    proposal_kind = models.CharField(max_length=32, choices=Kind)
    actor_type = models.CharField(max_length=20)
    actor_id = models.CharField(max_length=200)
    payload_hash = models.CharField(max_length=64)
    idempotency_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["organization", "id"],
                name="core_mcp_submission_org_id_unique",
            ),
            models.UniqueConstraint(
                fields=["organization", "repository", "idempotency_hash"],
                name="core_mcp_submission_idempotent_unique",
            ),
            models.CheckConstraint(
                condition=Q(payload_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_mcp_submission_payload_sha256",
            ),
            models.CheckConstraint(
                condition=Q(idempotency_hash__regex=r"^[a-f0-9]{64}$"),
                name="core_mcp_submission_key_sha256",
            ),
        ]
