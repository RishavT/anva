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
        EVIDENCE_MANIFEST = "EVIDENCE_MANIFEST"
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
    )
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
                fields=[
                    "organization",
                    "repository_external_id",
                    "pull_request_number",
                    "head_commit",
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
                    "repository",
                    "source_connection",
                    "action",
                ],
                nulls_distinct=False,
                name="core_access_grant_membership_unique",
            ),
            models.UniqueConstraint(
                fields=[
                    "organization",
                    "service_identity",
                    "repository",
                    "source_connection",
                    "action",
                ],
                nulls_distinct=False,
                name="core_access_grant_service_unique",
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
                fields=["token_hash"],
                name="core_repository_token_hash_unique",
            ),
        ]
