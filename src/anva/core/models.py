"""Tenant-explicit PostgreSQL models and critical database invariants."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, ClassVar

from django.db import models
from django.db.models import F, Q
from django.utils import timezone


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

    external_key = models.CharField(max_length=300)
    state = models.CharField(max_length=20, choices=State, default=State.DRAFT)

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

    source_connection = models.ForeignKey(SourceConnection, on_delete=models.PROTECT)
    state = models.CharField(max_length=24, choices=State, default=State.REQUESTED)
    failure_code = models.CharField(max_length=100, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

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

    subject_key = models.CharField(max_length=500)
    predicate = models.CharField(max_length=200)
    value = models.JSONField()
    is_inferred = models.BooleanField(default=False)
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
            models.CheckConstraint(
                condition=~Q(provenance=[]),
                name="core_assertion_provenance_not_empty",
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
