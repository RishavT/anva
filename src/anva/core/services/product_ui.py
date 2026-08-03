"""Permission-first facade for the server-rendered Anva product.

Templates receive bounded, presentation-safe dictionaries from this module. Views do not query
tenant models directly, and every repository/scope detail is authorized before related rows are
loaded or counted.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import cast

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q, QuerySet
from django.utils import timezone

from anva.core.exceptions import DomainOperationError, ResourceNotFoundError
from anva.core.models import (
    AcceptanceCriterion,
    AssertionConflict,
    AssertionRevision,
    AssuranceCheck,
    AssuranceReport,
    AssuranceRun,
    AuditEvent,
    CanvasShare,
    CanvasView,
    CanvasViewRevision,
    ContextPacketRecord,
    CriterionEvidence,
    Decision,
    Evidence,
    EvidenceManifest,
    Finding,
    ImmutableArtifact,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeProposalScope,
    KnowledgeRelationship,
    Membership,
    NonRequirement,
    Organization,
    OrganizationProductSettings,
    Policy,
    PolicyBinding,
    PolicyEvaluation,
    PolicyOverride,
    PolicyRequirement,
    PolicyVersion,
    Repository,
    RepositoryProfile,
    Requirement,
    SourceConnection,
    SyncRun,
    WorkItem,
    WorkItemRevision,
    content_hash,
)
from anva.core.services.authorization import (
    Action,
    authorize_action,
    authorized_access_scope_ids,
    get_tenant_record,
    get_tenant_record_for_update,
)
from anva.core.services.bootstrap import BootstrapResult, bootstrap_local_organization
from anva.core.services.canvas import (
    DEFAULT_LAYERS,
    RELATIONSHIP_ENDPOINTS,
    CanvasQuery,
    canvas_entity_detail,
    canvas_path,
    canvas_projection,
    canvas_selection_scope,
    create_canvas_share,
    create_canvas_view,
    list_canvas_views,
    propose_canvas_relationship,
    resolve_canvas_share,
    revoke_canvas_share,
    save_canvas_revision,
)
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import authorized_assertion_citations
from anva.core.services.creation import submit_knowledge_proposal
from anva.core.services.events import record_transition
from anva.core.services.github_bindings import authorized_active_github_bindings
from anva.core.services.graph import traverse_graph
from anva.core.services.ingestion import request_ingestion_sync
from anva.core.services.retrieval import (
    authorized_assertions,
    authorized_entities,
    get_authorized_entity,
)
from anva.core.services.scopes import revoke_source_connection
from anva.core.services.search import search_chunks
from anva.core.services.secured_operations import review_assertion
from anva.integrations.mcp_diagnostics import probe_mcp_diagnostics

PAGE_LIMIT = 100
SEARCH_LIMIT = 30
IDENTITY_ONLY_PROFILE_LIMITATION = (
    "Profile backfill preserved repository identity only; ownership, purpose, runtime, "
    "checks, and sensitive paths require human confirmation."
)


def _short(value: object, length: int = 12) -> str:
    return str(value)[:length]


def _json_summary(value: object) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return rendered if len(rendered) <= 500 else f"{rendered[:497]}…"


def _state_tone(value: str) -> str:
    normalized = value.upper()
    if normalized in {
        "ACTIVE",
        "COMPLETED",
        "PASSED",
        "CONFIRMED",
        "HUMAN_CONFIRMED",
        "READY_FOR_HUMAN_REVIEW",
        "AVAILABLE",
        "FRESH",
        "SUCCEEDED",
    }:
        return "positive"
    if normalized in {
        "FAILED",
        "BLOCKED",
        "REJECTED",
        "REVOKED",
        "DISABLED",
        "CONTRADICTED",
    }:
        return "critical"
    if normalized in {
        "STALE",
        "DEGRADED",
        "AGING",
        "READY_WITH_WARNINGS",
        "OPEN",
        "UNREVIEWED",
    }:
        return "warning"
    return "neutral"


def _status(value: str, *, label: str | None = None) -> dict[str, str]:
    return {
        "value": value,
        "label": label or value.replace("_", " ").title(),
        "tone": _state_tone(value),
    }


def _profile_defaults(repository: Repository) -> dict[str, object]:
    return {
        "status": RepositoryProfile.Status.DRAFT,
        "unsupported_or_ambiguous": [IDENTITY_ONLY_PROFILE_LIMITATION],
        "source_references": [
            {
                "external_id": repository.external_id,
                "kind": "repository_identity",
                "name": repository.name,
            }
        ],
    }


@dataclass(frozen=True, slots=True)
class SetupInput:
    organization_slug: str
    organization_name: str
    admin_email: str
    admin_display_name: str
    repository_external_id: str
    repository_name: str
    retention_days: int
    model_processing: str
    skill_distribution: str
    assurance_mode: str


@dataclass(frozen=True, slots=True)
class SourceHealthAggregate:
    """Identity-free source health totals for onboarding."""

    visible_count: int
    successfully_indexed_count: int
    revoked_count: int


def _validate_setup(data: SetupInput) -> None:
    if not 1 <= data.retention_days <= 3650:
        raise ValueError("Retention must be between 1 and 3650 days")
    if data.model_processing not in OrganizationProductSettings.ModelProcessing.values:
        raise ValueError("Model processing choice is invalid")
    if data.skill_distribution not in OrganizationProductSettings.SkillDistribution.values:
        raise ValueError("Skill distribution choice is invalid")
    if data.assurance_mode not in OrganizationProductSettings.AssuranceMode.values:
        raise ValueError("Assurance mode is invalid")


def bootstrap_product(*, supplied_secret: str, data: SetupInput) -> BootstrapResult:
    """Atomically bootstrap core tenancy and persist every accepted product choice."""
    _validate_setup(data)
    with transaction.atomic():
        result = bootstrap_local_organization(
            supplied_secret=supplied_secret,
            organization_slug=data.organization_slug,
            organization_name=data.organization_name,
            admin_email=data.admin_email,
            admin_display_name=data.admin_display_name,
            repository_external_id=data.repository_external_id,
            repository_name=data.repository_name,
        )
        OrganizationProductSettings.objects.create(
            organization=result.organization,
            retention_days=data.retention_days,
            model_processing=data.model_processing,
            skill_distribution=data.skill_distribution,
            assurance_mode=data.assurance_mode,
        )
        RepositoryProfile.objects.create(
            organization=result.organization,
            repository=result.repository,
            unsupported_or_ambiguous=[
                "Purpose, owner, commands, checks, and sensitive paths await technical-owner "
                "confirmation."
            ],
        )
        return result


def setup_available() -> bool:
    """Return whether the one-time bootstrap is still available."""
    return not Organization.objects.exists()


class ProductUIFacade:
    """Bounded product read/write surface for one already-authenticated human."""

    def __init__(self, actor: ActorContext) -> None:
        self.actor = actor
        authorize_action(actor=actor, action=Action.ORG_VIEW)

    def _repositories(self) -> list[Repository]:
        visible: list[Repository] = []
        candidates = Repository.objects.filter(
            organization_id=self.actor.organization_id,
            is_active=True,
        ).order_by("name", "id")[:PAGE_LIMIT]
        for repository in candidates:
            try:
                authorize_action(
                    actor=self.actor,
                    action=Action.REPOSITORY_VIEW,
                    repository_id=repository.id,
                )
            except ResourceNotFoundError:
                continue
            visible.append(repository)
        return visible

    def _repository(self, repository_id: uuid.UUID, *, action: Action) -> Repository:
        repository = get_tenant_record(
            queryset=Repository.objects.filter(is_active=True),
            record_id=repository_id,
            organization_id=self.actor.organization_id,
        )
        authorize_action(actor=self.actor, action=action, repository_id=repository.id)
        return repository

    def _visible_scope_ids(
        self,
        *,
        repository_id: uuid.UUID,
        action: Action,
        include_inactive: bool = False,
        include_revoked_sources: bool = False,
    ) -> set[uuid.UUID]:
        """Resolve scope visibility before any scoped product records are queried."""
        return authorized_access_scope_ids(
            actor=self.actor,
            action=action,
            repository_id=repository_id,
            include_inactive=include_inactive,
            include_revoked_sources=include_revoked_sources,
        )

    def _scoped_repository_boundary(
        self,
        *,
        repositories: list[Repository],
        action: Action,
        repository_field: str = "repository_id",
        scope_field: str = "access_scope_id",
        include_inactive_scopes: bool = False,
        include_revoked_scope_sources: bool = False,
    ) -> Q:
        boundary = Q(pk__in=[])
        for repository in repositories:
            scope_ids = self._visible_scope_ids(
                repository_id=repository.id,
                action=action,
                include_inactive=include_inactive_scopes,
                include_revoked_sources=include_revoked_scope_sources,
            )
            scope_boundary = Q(**{f"{scope_field}__in": scope_ids})
            if _authorized(self.actor, action, repository.id, None):
                scope_boundary |= Q(**{f"{scope_field}__isnull": True})
            boundary |= Q(**{repository_field: repository.id}) & scope_boundary
        return boundary

    def _scope_authorized_sources(
        self,
        repositories: list[Repository],
        *,
        include_revoked_scope_history: bool = False,
    ) -> QuerySet[SourceConnection]:
        boundary = self._scoped_repository_boundary(
            repositories=repositories,
            action=Action.SOURCE_VIEW,
            include_inactive_scopes=include_revoked_scope_history,
            include_revoked_scope_sources=include_revoked_scope_history,
        )
        return SourceConnection.objects.filter(
            organization_id=self.actor.organization_id,
        ).filter(boundary)

    def _visible_sources(
        self,
        repositories: list[Repository],
    ) -> QuerySet[SourceConnection]:
        return self._scope_authorized_sources(repositories).exclude(
            state=SourceConnection.State.REVOKED
        )

    def _source_health_aggregate(
        self,
        repositories: list[Repository],
    ) -> SourceHealthAggregate:
        visible = self._visible_sources(repositories).aggregate(
            visible_count=Count("id"),
            successfully_indexed_count=Count(
                "id",
                filter=Q(last_successful_sync_at__isnull=False),
            ),
        )
        revoked_count = (
            self._scope_authorized_sources(
                repositories,
                include_revoked_scope_history=True,
            )
            .filter(state=SourceConnection.State.REVOKED)
            .count()
        )
        return SourceHealthAggregate(
            visible_count=cast(int, visible["visible_count"]),
            successfully_indexed_count=cast(int, visible["successfully_indexed_count"]),
            revoked_count=revoked_count,
        )

    def _visible_packets(
        self,
        repositories: list[Repository],
    ) -> QuerySet[ContextPacketRecord]:
        return ContextPacketRecord.objects.filter(
            organization_id=self.actor.organization_id,
        ).filter(
            self._scoped_repository_boundary(
                repositories=repositories,
                action=Action.MCP_CONTEXT,
            )
        )

    def _visible_assurance_runs(
        self,
        repositories: list[Repository],
    ) -> QuerySet[AssuranceRun]:
        boundary = Q(pk__in=[])
        for repository in repositories:
            scope_ids = self._visible_scope_ids(
                repository_id=repository.id,
                action=Action.ASSURANCE_VIEW,
            )
            repository_match = Q(repository_id=repository.id) | Q(
                repository_external_id=repository.external_id
            )
            scoped_context = Q(context_packet__access_scope_id__in=scope_ids) | (
                Q(context_packet__isnull=True)
                & (
                    Q(context_artifact__isnull=True)
                    | Q(context_artifact__access_scope_id__isnull=True)
                    | Q(context_artifact__access_scope_id__in=scope_ids)
                )
            )
            boundary |= repository_match & scoped_context
        return AssuranceRun.objects.filter(
            organization_id=self.actor.organization_id,
        ).filter(boundary)

    def _visible_manifests(
        self,
        repositories: list[Repository],
    ) -> QuerySet[EvidenceManifest]:
        return EvidenceManifest.objects.filter(
            organization_id=self.actor.organization_id,
        ).filter(
            self._scoped_repository_boundary(
                repositories=repositories,
                action=Action.EVIDENCE_VIEW,
            )
        )

    def _visible_audit_events(
        self,
        repositories: list[Repository],
    ) -> QuerySet[AuditEvent]:
        source_ids = set(self._visible_sources(repositories).values_list("id", flat=True))
        sync_run_ids = set(
            SyncRun.objects.filter(
                organization_id=self.actor.organization_id,
                source_connection_id__in=source_ids,
            ).values_list("id", flat=True)
        )
        assertion_ids: set[uuid.UUID] = set()
        for repository in repositories:
            assertion_ids.update(
                authorized_assertions(
                    actor=self.actor,
                    repository_id=repository.id,
                    action=Action.KNOWLEDGE_VIEW,
                ).values_list("id", flat=True)
            )
        proposal_ids = set(
            KnowledgeProposalScope.objects.filter(
                organization_id=self.actor.organization_id,
            )
            .filter(
                self._scoped_repository_boundary(
                    repositories=repositories,
                    action=Action.KNOWLEDGE_VIEW,
                )
            )
            .values_list("knowledge_proposal_id", flat=True)
        )
        run_ids = set(self._visible_assurance_runs(repositories).values_list("id", flat=True))
        manifest_ids = set(self._visible_manifests(repositories).values_list("id", flat=True))
        work_ids = set(
            WorkItem.objects.filter(organization_id=self.actor.organization_id)
            .filter(
                self._scoped_repository_boundary(
                    repositories=repositories,
                    action=Action.WORK_VIEW,
                )
            )
            .values_list("id", flat=True)
        )
        visible_scope_ids: set[uuid.UUID] = set()
        for repository in repositories:
            visible_scope_ids.update(
                self._visible_scope_ids(
                    repository_id=repository.id,
                    action=Action.ARTIFACT_VIEW,
                )
            )
        artifact_ids = set(
            ImmutableArtifact.objects.filter(
                organization_id=self.actor.organization_id,
                access_scope_id__in=visible_scope_ids,
            ).values_list("id", flat=True)
        )
        visibility = (
            Q(target_type="organization", target_id=self.actor.organization_id)
            | Q(target_type="membership")
            | Q(target_type="repositoryprofile")
            | Q(target_type="repositoryaccesstoken")
            | Q(target_type="sourceconnection", target_id__in=source_ids)
            | Q(target_type="syncrun", target_id__in=sync_run_ids)
            | Q(target_type="accesssnapshot", target_id__in=source_ids)
            | Q(target_type="knowledgeassertion", target_id__in=assertion_ids)
            | Q(target_type="knowledgeproposal", target_id__in=proposal_ids)
            | Q(target_type="assurancerun", target_id__in=run_ids)
            | Q(target_type="evidencemanifest", target_id__in=manifest_ids)
            | Q(target_type="workitem", target_id__in=work_ids)
            | Q(target_type="immutable_artifact", target_id__in=artifact_ids)
            | Q(target_type="accessscope", target_id__in=visible_scope_ids)
        )
        return AuditEvent.objects.filter(
            organization_id=self.actor.organization_id,
        ).filter(visibility)

    def shell(self) -> dict[str, object]:
        organization = Organization.objects.get(id=self.actor.organization_id)
        repositories = self._repositories()
        membership = Membership.objects.select_related("user", "role").get(
            organization_id=self.actor.organization_id,
            user_id=self.actor.actor_id,
            is_active=True,
            user__is_active=True,
        )
        try:
            authorize_action(actor=self.actor, action=Action.AUDIT_VIEW)
        except ResourceNotFoundError:
            can_audit = False
        else:
            can_audit = True
        return {
            "organization": organization,
            "actor_name": membership.user.display_name,
            "actor_role": membership.role.name,
            "repositories": repositories,
            "read_only": settings.ANVA_WEB_READ_ONLY,
            "can_audit": can_audit,
        }

    def onboarding(self) -> dict[str, object]:
        repositories = self._repositories()
        repository_ids = [item.id for item in repositories]
        source_health = self._source_health_aggregate(repositories)
        profiles = {
            profile.repository_id: profile
            for profile in RepositoryProfile.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
        }
        settings_record, _created = OrganizationProductSettings.objects.get_or_create(
            organization_id=self.actor.organization_id,
            defaults={
                "retention_days": 365,
                "model_processing": OrganizationProductSettings.ModelProcessing.DISABLED,
                "skill_distribution": OrganizationProductSettings.SkillDistribution.SELF_SERVICE,
                "assurance_mode": OrganizationProductSettings.AssuranceMode.OBSERVE,
            },
        )
        latest_packet = self._visible_packets(repositories).order_by("-generated_at").first()
        latest_run = self._visible_assurance_runs(repositories).order_by("-created_at").first()
        binding_count = authorized_active_github_bindings(
            actor=self.actor,
            repository_ids=repository_ids,
        ).count()
        checks: list[dict[str, object]] = [
            {
                "name": "Organization settings",
                "state": "DONE" if settings_record else "NEEDS_ATTENTION",
                "detail": (
                    f"{settings_record.retention_days}-day retention · "
                    f"{settings_record.model_processing.replace('_', ' ').title()}"
                    if settings_record
                    else "Product settings have not been persisted."
                ),
                "href": "/app/onboarding#organization-settings",
            },
            {
                "name": "Repository connected",
                "state": "DONE" if repositories else "NEEDS_ATTENTION",
                "detail": f"{len(repositories)} visible repository boundary",
                "href": (
                    f"/app/repositories/{repositories[0].id}" if repositories else "/app/onboarding"
                ),
            },
            {
                "name": "GitHub App binding",
                "state": "DONE" if binding_count else "UNAVAILABLE",
                "detail": (
                    f"{binding_count} active installation binding"
                    if binding_count
                    else "Operator-assisted GitHub App installation is required."
                ),
                "href": "/app/onboarding#github-installation",
            },
            {
                "name": "Repository profile confirmed",
                "state": (
                    "DONE"
                    if any(
                        item.status == RepositoryProfile.Status.CONFIRMED
                        for item in profiles.values()
                    )
                    else "NEEDS_ATTENTION"
                ),
                "detail": "Purpose, owner, commands, checks, and sensitive paths require review.",
                "href": (
                    f"/app/repositories/{repositories[0].id}#profile"
                    if repositories
                    else "/app/onboarding"
                ),
            },
            {
                "name": "Sources indexed with provenance",
                "state": (
                    "DONE" if source_health.successfully_indexed_count else "NEEDS_ATTENTION"
                ),
                "detail": (
                    f"{source_health.visible_count} source "
                    f"connection{'s' if source_health.visible_count != 1 else ''}"
                ),
                "href": "/app/sources",
            },
            {
                "name": "Developer skill context request",
                "state": "DONE" if latest_packet else "NEEDS_ATTENTION",
                "detail": (
                    f"Last request {latest_packet.generated_at.isoformat()}"
                    if latest_packet
                    else "No successful context packet is visible."
                ),
                "href": "/app/skills",
            },
            {
                "name": "Test pull request assurance",
                "state": "DONE" if latest_run else "NEEDS_ATTENTION",
                "detail": (
                    f"Latest run {latest_run.state.replace('_', ' ').title()}"
                    if latest_run
                    else "No assurance run has been observed."
                ),
                "href": "/app/assurance",
            },
            {
                "name": "Source revocation exercise",
                "state": "DONE" if source_health.revoked_count else "NEEDS_ATTENTION",
                "detail": (
                    (
                        f"Revocation verified for {source_health.revoked_count} authorized "
                        f"source{'s' if source_health.revoked_count != 1 else ''}; reconnect or "
                        f"replace {'them' if source_health.revoked_count != 1 else 'it'} before "
                        "ingestion resumes."
                    )
                    if source_health.revoked_count
                    else (
                        "No authorized source revocation has been observed. "
                        "Revoke a test source to verify future retrieval is denied."
                    )
                ),
                "href": "/app/sources",
            },
        ]
        return {"checks": checks, "settings_record": settings_record}

    def home(self) -> dict[str, object]:
        repositories = self._repositories()
        sources = list(
            self._visible_sources(repositories)
            .filter(
                Q(state__in=[SourceConnection.State.DEGRADED, SourceConnection.State.FAILED])
                | Q(last_successful_sync_at__isnull=True)
            )
            .order_by("-updated_at")[:8]
        )
        runs = list(
            self._visible_assurance_runs(repositories)
            .filter(
                Q(readiness__in=["BLOCKED", "STALE", "FAILED"])
                | Q(state__in=[AssuranceRun.State.STALE, AssuranceRun.State.FAILED])
            )
            .order_by("-created_at")[:8]
        )
        review_items: list[KnowledgeAssertion] = []
        seen: set[uuid.UUID] = set()
        for repository in repositories:
            assertions = authorized_assertions(
                actor=self.actor,
                repository_id=repository.id,
                action=Action.KNOWLEDGE_VIEW,
            ).filter(
                Q(review_state=KnowledgeAssertion.ReviewState.UNREVIEWED)
                | Q(staleness_state__in=["STALE", "CONTRADICTED"])
            )[:8]
            for assertion in assertions:
                if assertion.id not in seen:
                    seen.add(assertion.id)
                    review_items.append(assertion)
        attention = [
            {
                "kind": "ASSURANCE",
                "title": f"PR #{run.pull_request_number} · {run.repository_external_id}",
                "detail": run.readiness or run.state,
                "status": _status(run.readiness or run.state),
                "href": f"/app/assurance/{run.id}",
                "time": run.created_at,
            }
            for run in runs
        ]
        attention.extend(
            {
                "kind": "KNOWLEDGE",
                "title": assertion.subject_key,
                "detail": assertion.predicate.replace("_", " "),
                "status": _status(
                    assertion.staleness_state
                    if assertion.staleness_state != KnowledgeAssertion.StalenessState.FRESH
                    else assertion.review_state
                ),
                "href": f"/app/review?focus={assertion.id}",
                "time": assertion.updated_at,
            }
            for assertion in review_items[:8]
        )
        attention.extend(
            {
                "kind": "SOURCE",
                "title": source.display_name or source.external_key,
                "detail": source.last_error_code or "Initial sync is still needed",
                "status": _status(source.state),
                "href": f"/app/sources/{source.id}",
                "time": source.updated_at,
            }
            for source in sources
        )
        attention.sort(key=lambda item: cast(datetime, item["time"]), reverse=True)
        latest_audit: list[AuditEvent] = []
        try:
            authorize_action(actor=self.actor, action=Action.AUDIT_VIEW)
            latest_audit = list(
                self._visible_audit_events(repositories).order_by("-created_at")[:6]
            )
        except ResourceNotFoundError:
            pass
        visible_sources = self._visible_sources(repositories)
        current_sources = visible_sources.filter(
            state=SourceConnection.State.ACTIVE,
            last_successful_sync_at__isnull=False,
        ).count()
        return {
            "attention": attention[:16],
            "repositories_count": len(repositories),
            "current_sources": current_sources,
            "source_total": visible_sources.count(),
            "latest_audit": latest_audit,
        }

    def explorer(
        self,
        *,
        repository_id: uuid.UUID | None,
        start_entity_id: uuid.UUID | None,
        query: str,
        entity_type: str,
        freshness: str,
    ) -> dict[str, object]:
        repositories = self._repositories()
        selected = (
            self._repository(repository_id, action=Action.KNOWLEDGE_VIEW)
            if repository_id
            else (repositories[0] if repositories else None)
        )
        if selected is None:
            return {
                "selected_repository": None,
                "entities": [],
                "source_results": [],
                "query": query,
                "entity_type": entity_type,
                "freshness": freshness,
                "start_entity": None,
                "selection_context": None,
            }
        selection_scope: dict[str, object] | None = None
        scoped_entity_ids: set[uuid.UUID] | None = None
        scoped_subject_keys: set[str] | None = None
        scoped_source_locations: tuple[uuid.UUID, ...] | None = None
        if start_entity_id is not None:
            selection_scope = canvas_selection_scope(
                actor=self.actor,
                entity_id=start_entity_id,
                repository_id=selected.id,
            )
            selection_context = cast(dict[str, object], selection_scope["selection_context"])
            scoped_entity_ids = {
                uuid.UUID(cast(str, item["id"]))
                for item in cast(list[dict[str, object]], selection_context["nodes"])
            }
            scoped_subject_keys = {
                cast(str, item["canonical_key"])
                for item in cast(list[dict[str, object]], selection_context["nodes"])
            }
            scoped_source_locations = cast(
                tuple[uuid.UUID, ...], selection_scope["source_location_ids"]
            )
        entities = authorized_entities(actor=self.actor, repository_id=selected.id)
        if scoped_entity_ids is not None:
            entities = entities.filter(id__in=scoped_entity_ids)
        if query:
            entities = entities.filter(
                Q(display_name__icontains=query) | Q(canonical_key__icontains=query)
            )
        if entity_type in KnowledgeEntity.EntityType.values:
            entities = entities.filter(entity_type=entity_type)
        entity_rows = list(entities.order_by("display_name", "id")[:SEARCH_LIMIT])
        source_results: list[object] = []
        if query:
            source_results = list(
                search_chunks(
                    actor=self.actor,
                    repository_id=selected.id,
                    query=query[:500],
                    limit=15,
                    source_location_ids=scoped_source_locations,
                ).results
            )
        assertions: list[KnowledgeAssertion] = []
        if freshness in KnowledgeAssertion.StalenessState.values:
            assertion_query = authorized_assertions(
                actor=self.actor,
                repository_id=selected.id,
                action=Action.KNOWLEDGE_VIEW,
            ).filter(staleness_state=freshness)
            if scoped_subject_keys is not None:
                assertion_query = assertion_query.filter(subject_key__in=scoped_subject_keys)
            assertions = list(assertion_query.order_by("-observed_at")[:SEARCH_LIMIT])
        return {
            "selected_repository": selected,
            "entities": entity_rows,
            "source_results": source_results,
            "freshness_assertions": assertions,
            "query": query,
            "entity_type": entity_type,
            "freshness": freshness,
            "start_entity": selection_scope["entity"] if selection_scope else None,
            "selection_context": (
                selection_scope["selection_context"] if selection_scope else None
            ),
            "entity_types": KnowledgeEntity.EntityType.choices,
            "freshness_states": KnowledgeAssertion.StalenessState.choices,
        }

    def entity(self, *, repository_id: uuid.UUID, entity_id: uuid.UUID) -> dict[str, object]:
        repository = self._repository(repository_id, action=Action.KNOWLEDGE_VIEW)
        entity = get_authorized_entity(
            actor=self.actor,
            repository_id=repository.id,
            entity_id=entity_id,
        )
        assertions = list(
            authorized_assertions(
                actor=self.actor,
                repository_id=repository.id,
                action=Action.KNOWLEDGE_VIEW,
            )
            .filter(subject_key=entity.canonical_key)
            .order_by("-observed_at")[:PAGE_LIMIT]
        )
        assertion_ids = [item.id for item in assertions]
        conflicts = list(
            AssertionConflict.objects.filter(
                organization_id=self.actor.organization_id,
            )
            .filter(
                Q(left_assertion_id__in=assertion_ids) | Q(right_assertion_id__in=assertion_ids)
            )
            .order_by("-detected_at")[:PAGE_LIMIT]
        )
        revisions = list(
            AssertionRevision.objects.filter(
                organization_id=self.actor.organization_id,
                assertion_id__in=assertion_ids,
            ).order_by("-created_at")[:PAGE_LIMIT]
        )
        citations: dict[uuid.UUID, tuple[dict[str, object], ...]] = {}
        for assertion in assertions:
            citations[assertion.id] = authorized_assertion_citations(
                actor=self.actor,
                repository_id=repository.id,
                assertion_id=assertion.id,
            )
        graph = traverse_graph(
            actor=self.actor,
            repository_id=repository.id,
            start_entity_id=entity.id,
            depth=1,
            edge_limit=100,
        )
        return {
            "repository": repository,
            "entity": entity,
            "assertions": [
                {
                    "record": assertion,
                    "value": _json_summary(assertion.value),
                    "status": _status(assertion.staleness_state),
                    "citations": citations[assertion.id],
                }
                for assertion in assertions
            ],
            "relationships": graph.edges,
            "conflicts": conflicts,
            "revisions": revisions,
        }

    def canvas(
        self,
        *,
        query: CanvasQuery,
        path_source_id: uuid.UUID | None = None,
        path_target_id: uuid.UUID | None = None,
    ) -> dict[str, object]:
        """Return a visual projection and the complete server-rendered equivalent."""
        graph = canvas_projection(actor=self.actor, query=query)
        labels = {
            cast(str, node["id"]): cast(str, node["label"])
            for node in cast(list[dict[str, object]], graph["nodes"])
        }
        relationship_rows = [
            {
                **edge,
                "source_label": labels[cast(str, edge["source"])],
                "target_label": labels[cast(str, edge["target"])],
            }
            for edge in cast(list[dict[str, object]], graph["edges"])
        ]
        path_result: dict[str, object] | None = None
        if path_source_id and path_target_id:
            path_result = canvas_path(
                actor=self.actor,
                source_id=path_source_id,
                target_id=path_target_id,
                repository_ids=query.repository_ids,
            )
        can_manage = not settings.ANVA_WEB_READ_ONLY
        can_propose = not settings.ANVA_WEB_READ_ONLY
        try:
            authorize_action(actor=self.actor, action=Action.CANVAS_MANAGE)
        except ResourceNotFoundError:
            can_manage = False
        try:
            authorize_action(actor=self.actor, action=Action.KNOWLEDGE_PROPOSE)
        except ResourceNotFoundError:
            can_propose = False
        return {
            "graph": graph,
            "resolved_query": cast(dict[str, object], graph["semantic_query"]),
            "resolved_repository_ids": tuple(
                uuid.UUID(str(repository["id"]))
                for repository in cast(list[dict[str, object]], graph["repositories"])
            ),
            "relationship_rows": relationship_rows,
            "saved_views": list_canvas_views(actor=self.actor),
            "entity_types": KnowledgeEntity.EntityType.choices,
            "relationship_types": [
                choice
                for choice in KnowledgeRelationship.RelationshipType.choices
                if choice[0] in RELATIONSHIP_ENDPOINTS
            ],
            "layers": DEFAULT_LAYERS,
            "query": query,
            "path": path_result,
            "can_manage": can_manage,
            "can_propose": can_propose,
            "read_only": settings.ANVA_WEB_READ_ONLY,
            "idempotency_key": str(uuid.uuid4()),
        }

    def canvas_detail(
        self,
        *,
        entity_id: uuid.UUID,
        repository_ids: tuple[uuid.UUID, ...] = (),
    ) -> dict[str, object]:
        return canvas_entity_detail(
            actor=self.actor,
            entity_id=entity_id,
            repository_ids=repository_ids,
        )

    def canvas_question(
        self,
        *,
        entity_id: uuid.UUID,
        repository_id: uuid.UUID,
        question: str,
    ) -> dict[str, object]:
        """Return cited retrieval scoped to one currently authorized Canvas selection."""
        question = question.strip()
        if not question or len(question) > 500:
            raise ValueError("Canvas question is outside its size budget")
        selection_scope = canvas_selection_scope(
            actor=self.actor,
            entity_id=entity_id,
            repository_id=repository_id,
        )
        response = search_chunks(
            actor=self.actor,
            repository_id=repository_id,
            query=question,
            limit=10,
            source_location_ids=cast(tuple[uuid.UUID, ...], selection_scope["source_location_ids"]),
        )
        return {
            "entity": selection_scope["entity"],
            "selection_context": selection_scope["selection_context"],
            "results": [result.as_dict() for result in response.results],
            "limitation": (
                "No authorized source excerpt matched this selection-scoped question."
                if not response.results
                else "Answers are limited to these authorized source excerpts."
            ),
        }

    def canvas_share_query(self, share_id: uuid.UUID) -> CanvasQuery:
        view, revision = resolve_canvas_share(actor=self.actor, share_id=share_id)
        return CanvasQuery(view_id=view.id, view_revision=revision.revision)

    def create_canvas(
        self,
        *,
        name: str,
        description: str,
        view_type: str,
        semantic_query: dict[str, object],
        repository_id: uuid.UUID | None,
        idempotency_key: str,
    ) -> tuple[CanvasView, bool]:
        if settings.ANVA_WEB_READ_ONLY:
            raise ResourceNotFoundError("Web mutations are disabled")
        return create_canvas_view(
            actor=self.actor,
            name=name,
            description=description,
            view_type=view_type,
            semantic_query=semantic_query,
            repository_id=repository_id,
            access_scope_id=None,
            idempotency_key=idempotency_key,
        )

    def save_canvas(
        self,
        *,
        view_id: uuid.UUID,
        expected_revision: int,
        semantic_query: dict[str, object],
        presentation: dict[str, list[dict[str, object]]],
        idempotency_key: str,
    ) -> tuple[CanvasViewRevision, bool]:
        if settings.ANVA_WEB_READ_ONLY:
            raise ResourceNotFoundError("Web mutations are disabled")
        return save_canvas_revision(
            actor=self.actor,
            view_id=view_id,
            expected_revision=expected_revision,
            semantic_query=semantic_query,
            placements=presentation["placements"],
            filters=presentation["filters"],
            layers=presentation["layers"],
            groups=presentation["groups"],
            annotations=presentation["annotations"],
            idempotency_key=idempotency_key,
        )

    def share_canvas(
        self,
        *,
        view_id: uuid.UUID,
        idempotency_key: str,
    ) -> tuple[CanvasShare, bool]:
        if settings.ANVA_WEB_READ_ONLY:
            raise ResourceNotFoundError("Web mutations are disabled")
        return create_canvas_share(
            actor=self.actor,
            view_id=view_id,
            idempotency_key=idempotency_key,
        )

    def revoke_canvas_share(
        self,
        *,
        share_id: uuid.UUID,
        expected_view_revision: int,
        idempotency_key: str,
    ) -> tuple[CanvasShare, bool]:
        if settings.ANVA_WEB_READ_ONLY:
            raise ResourceNotFoundError("Web mutations are disabled")
        return revoke_canvas_share(
            actor=self.actor,
            share_id=share_id,
            expected_view_revision=expected_view_revision,
            idempotency_key=idempotency_key,
        )

    def propose_canvas_relationship(
        self,
        *,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        relationship_type: str,
        repository_id: uuid.UUID,
        expected_source_revision: int,
        expected_target_revision: int,
        rationale: str,
        idempotency_key: str,
    ) -> tuple[KnowledgeProposal, bool]:
        if settings.ANVA_WEB_READ_ONLY:
            raise ResourceNotFoundError("Web mutations are disabled")
        return propose_canvas_relationship(
            actor=self.actor,
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
            repository_id=repository_id,
            expected_source_revision=expected_source_revision,
            expected_target_revision=expected_target_revision,
            rationale=rationale,
            idempotency_key=idempotency_key,
        )

    def sources(self) -> dict[str, object]:
        repositories = self._repositories()
        rows = list(
            self._visible_sources(repositories)
            .select_related("repository")
            .order_by("display_name", "external_key")[:PAGE_LIMIT]
        )
        return {"sources": [{"record": row, "status": _status(row.state)} for row in rows]}

    def source(self, source_id: uuid.UUID) -> dict[str, object]:
        repositories = self._repositories()
        source = get_tenant_record(
            queryset=self._visible_sources(repositories).select_related(
                "repository",
                "access_scope",
            ),
            record_id=source_id,
            organization_id=self.actor.organization_id,
        )
        if source.repository_id is None:
            raise ResourceNotFoundError("Governed record was not found")
        self._repository(source.repository_id, action=Action.SOURCE_VIEW)
        authorize_action(
            actor=self.actor,
            action=Action.SOURCE_VIEW,
            repository_id=source.repository_id,
            source_connection_id=source.id,
            access_scope_id=source.access_scope_id,
        )
        runs = list(
            SyncRun.objects.filter(
                organization_id=self.actor.organization_id,
                source_connection=source,
            ).order_by("-created_at")[:PAGE_LIMIT]
        )
        return {
            "source": source,
            "status": _status(source.state),
            "runs": runs,
            "can_sync": _authorized_source(
                self.actor,
                Action.SOURCE_SYNC,
                source.repository_id,
                source.id,
                source.access_scope_id,
            ),
            "can_revoke": _authorized_source(
                self.actor,
                Action.SOURCE_REVOKE,
                source.repository_id,
                source.id,
                source.access_scope_id,
            ),
        }

    def sync_source(self, *, source_id: uuid.UUID, scan_mode: str) -> SyncRun:
        if settings.ANVA_WEB_READ_ONLY:
            raise DomainOperationError("This web installation is read-only")
        source_data = self.source(source_id)
        source = cast(SourceConnection, source_data["source"])
        run, _created = request_ingestion_sync(
            actor=replace(self.actor, repository_id=source.repository_id),
            source_connection_id=source.id,
            scan_mode=scan_mode,
        )
        return run

    def revoke_source(
        self,
        *,
        source_id: uuid.UUID,
        expected_revision: int,
    ) -> SourceConnection:
        if settings.ANVA_WEB_READ_ONLY:
            raise DomainOperationError("This web installation is read-only")
        source_data = self.source(source_id)
        source = cast(SourceConnection, source_data["source"])
        return revoke_source_connection(
            actor=replace(self.actor, repository_id=source.repository_id),
            source_connection_id=source.id,
            expected_revision=expected_revision,
        )

    def review_queue(
        self,
        *,
        repository_id: uuid.UUID | None,
        queue: str,
    ) -> dict[str, object]:
        repositories = self._repositories()
        selected = (
            self._repository(repository_id, action=Action.KNOWLEDGE_VIEW)
            if repository_id
            else (repositories[0] if repositories else None)
        )
        if selected is None:
            return {"selected_repository": None, "assertions": [], "proposals": [], "queue": queue}
        assertions = authorized_assertions(
            actor=self.actor,
            repository_id=selected.id,
            action=Action.KNOWLEDGE_VIEW,
        )
        if queue == "conflicts":
            assertions = assertions.filter(
                Q(staleness_state=KnowledgeAssertion.StalenessState.CONTRADICTED)
                | Q(left_conflicts__status=AssertionConflict.Status.OPEN)
                | Q(right_conflicts__status=AssertionConflict.Status.OPEN)
            )
        elif queue == "stale":
            assertions = assertions.filter(
                staleness_state__in=[
                    KnowledgeAssertion.StalenessState.STALE,
                    KnowledgeAssertion.StalenessState.AGING,
                ]
            )
        else:
            assertions = assertions.filter(review_state=KnowledgeAssertion.ReviewState.UNREVIEWED)
        assertion_rows = list(assertions.distinct().order_by("-observed_at")[:PAGE_LIMIT])
        proposal_scopes = list(
            KnowledgeProposalScope.objects.filter(
                organization_id=self.actor.organization_id,
                repository=selected,
            )
            .filter(
                self._scoped_repository_boundary(
                    repositories=[selected],
                    action=Action.KNOWLEDGE_VIEW,
                )
            )
            .select_related("knowledge_proposal", "assertion")
            .order_by("-created_at")[:PAGE_LIMIT]
        )
        return {
            "selected_repository": selected,
            "assertions": [
                {
                    "record": row,
                    "value": _json_summary(row.value),
                    "status": _status(row.staleness_state),
                    "can_review": _authorized(
                        self.actor,
                        Action.KNOWLEDGE_REVIEW,
                        selected.id,
                        row.access_scope_id,
                    ),
                    "can_propose": _authorized(
                        self.actor,
                        Action.KNOWLEDGE_PROPOSE,
                        selected.id,
                        row.access_scope_id,
                    ),
                }
                for row in assertion_rows
            ],
            "proposals": proposal_scopes,
            "queue": queue,
        }

    def review_assertion(
        self,
        *,
        repository_id: uuid.UUID,
        assertion_id: uuid.UUID,
        decision: str,
        expected_revision: int,
        correction: str = "",
    ) -> KnowledgeAssertion | KnowledgeProposal:
        if settings.ANVA_WEB_READ_ONLY:
            raise DomainOperationError("This web installation is read-only")
        repository = self._repository(repository_id, action=Action.KNOWLEDGE_VIEW)
        mapping = {
            "CONFIRM": KnowledgeAssertion.ReviewState.HUMAN_CONFIRMED,
            "REJECT": KnowledgeAssertion.ReviewState.REJECTED,
            "MARK_STALE": KnowledgeAssertion.ReviewState.STALE,
        }
        if decision in mapping:
            return review_assertion(
                actor=self.actor,
                repository_id=repository.id,
                assertion_id=assertion_id,
                target_state=mapping[decision],
                expected_revision=expected_revision,
            )
        if decision != "CORRECT" or not correction.strip():
            raise ValueError("A supported decision and correction text are required")
        with transaction.atomic():
            assertion: KnowledgeAssertion = get_tenant_record_for_update(
                queryset=KnowledgeAssertion.objects.all(),
                record_id=assertion_id,
                organization_id=self.actor.organization_id,
            )
            if assertion.access_scope_id is None:
                raise ResourceNotFoundError("Governed record was not found")
            authorization = authorize_action(
                actor=self.actor,
                action=Action.KNOWLEDGE_PROPOSE,
                repository_id=repository.id,
                access_scope_id=assertion.access_scope_id,
            )
            if assertion.revision != expected_revision:
                raise DomainOperationError(
                    "The assertion changed; review the current version before deciding."
                )
            current_value_hash = content_hash(assertion.value)
            idempotency_key = content_hash(
                {
                    "actor_id": self.actor.actor_id,
                    "actor_type": self.actor.actor_type,
                    "assertion_id": str(assertion.id),
                    "expected_revision": expected_revision,
                    "operation": "CORRECT",
                    "organization_id": str(self.actor.organization_id),
                    "repository_id": str(repository.id),
                }
            )
            request_hash = content_hash(
                {
                    "correction": correction.strip(),
                    "current_value_hash": current_value_hash,
                    "idempotency_key": idempotency_key,
                }
            )
            existing = (
                KnowledgeProposalScope.objects.select_related("knowledge_proposal")
                .filter(
                    organization_id=self.actor.organization_id,
                    idempotency_key=idempotency_key,
                )
                .first()
            )
            if existing is not None:
                if existing.request_hash != request_hash:
                    raise DomainOperationError(
                        "The correction retry conflicts with the original request."
                    )
                return existing.knowledge_proposal
            citations = authorized_assertion_citations(
                actor=self.actor,
                repository_id=repository.id,
                assertion_id=assertion.id,
            )
            sources = [
                {
                    "type": "assertion",
                    "id": str(assertion.id),
                    "locator": citation.get("locator", ""),
                }
                for citation in citations
            ] or [{"type": "assertion", "id": str(assertion.id)}]
            proposal = submit_knowledge_proposal(
                actor=replace(self.actor, authorization_path=authorization.authorization_path),
                summary=f"Correction proposed for {assertion.subject_key}",
                proposed_changes=[
                    {
                        "operation": "CORRECT",
                        "assertion_id": str(assertion.id),
                        "current_value_hash": current_value_hash,
                        "proposed_value": correction.strip(),
                    }
                ],
                anva_sources=sources,
            )
            KnowledgeProposalScope.objects.create(
                organization_id=self.actor.organization_id,
                knowledge_proposal=proposal,
                repository=repository,
                access_scope_id=assertion.access_scope_id,
                assertion=assertion,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
            )
            return proposal

    def repository(self, repository_id: uuid.UUID) -> dict[str, object]:
        repository = self._repository(repository_id, action=Action.REPOSITORY_VIEW)
        profile, _created = RepositoryProfile.objects.get_or_create(
            organization_id=self.actor.organization_id,
            repository=repository,
            defaults=_profile_defaults(repository),
        )
        sources = list(
            self._visible_sources([repository]).order_by("display_name", "external_key")[
                :PAGE_LIMIT
            ]
        )
        policy_candidates = list(
            Policy.objects.filter(
                organization_id=self.actor.organization_id,
                policyversion__policybinding__repository_ids__contains=[str(repository.id)],
            )
            .distinct()
            .order_by("name")[:PAGE_LIMIT]
        )
        policies = [
            policy
            for policy in policy_candidates
            if _authorized(
                self.actor,
                Action.POLICY_VIEW,
                repository.id,
                policy.access_scope_id,
            )
        ]
        runs = list(self._visible_assurance_runs([repository]).order_by("-created_at")[:12])
        unresolved = list(
            authorized_assertions(
                actor=self.actor,
                repository_id=repository.id,
                action=Action.KNOWLEDGE_VIEW,
            )
            .filter(
                Q(review_state=KnowledgeAssertion.ReviewState.UNREVIEWED)
                | Q(staleness_state__in=["STALE", "CONTRADICTED"])
            )
            .order_by("-updated_at")[:12]
        )
        github_bound = authorized_active_github_bindings(
            actor=self.actor,
            repository_ids=[repository.id],
        ).exists()
        return {
            "repository": repository,
            "profile": profile,
            "sources": sources,
            "policies": policies,
            "runs": runs,
            "unresolved": unresolved,
            "github_bound": github_bound,
            "can_manage_profile": _authorized(
                self.actor,
                Action.WORK_MANAGE,
                repository.id,
                None,
            ),
        }

    def save_repository_profile(
        self,
        *,
        repository_id: uuid.UUID,
        expected_revision: int,
        purpose: str,
        owning_team: str,
        setup_commands: list[str],
        required_checks: list[str],
        sensitive_paths: list[str],
    ) -> RepositoryProfile:
        if settings.ANVA_WEB_READ_ONLY:
            raise DomainOperationError("This web installation is read-only")
        repository = self._repository(repository_id, action=Action.WORK_MANAGE)
        with transaction.atomic():
            fallback_profile, _created = RepositoryProfile.objects.get_or_create(
                organization_id=self.actor.organization_id,
                repository=repository,
                defaults=_profile_defaults(repository),
            )
            profile = get_tenant_record(
                queryset=RepositoryProfile.objects.select_for_update(),
                record_id=fallback_profile.id,
                organization_id=self.actor.organization_id,
            )
            if profile.revision != expected_revision:
                raise DomainOperationError(
                    "The repository profile changed; review the current version."
                )
            decision = authorize_action(
                actor=self.actor,
                action=Action.WORK_MANAGE,
                repository_id=repository.id,
            )
            from_state = profile.status
            profile.purpose = purpose.strip()
            profile.owning_team = owning_team.strip()
            profile.setup_commands = setup_commands
            profile.required_checks = required_checks
            profile.sensitive_paths = sensitive_paths
            profile.status = RepositoryProfile.Status.CONFIRMED
            profile.confirmed_by_type = self.actor.actor_type
            profile.confirmed_by_id = self.actor.actor_id
            profile.confirmed_at = timezone.now()
            profile.revision += 1
            profile.save()
            record_transition(
                organization=repository.organization,
                actor=ActorContext(
                    organization_id=self.actor.organization_id,
                    actor_type=self.actor.actor_type,
                    actor_id=self.actor.actor_id,
                    authorization_path=decision.authorization_path,
                    request_id=self.actor.request_id,
                    source_ip_hash=self.actor.source_ip_hash,
                ),
                target_type="repositoryprofile",
                target_id=profile.id,
                from_state=from_state,
                to_state=profile.status,
                revision=profile.revision,
                metadata={"repository_id": str(repository.id)},
            )
            return profile

    def work(self) -> dict[str, object]:
        repositories = self._repositories()
        repository_ids = [item.id for item in repositories]
        for repository in repositories:
            authorize_action(
                actor=self.actor,
                action=Action.WORK_VIEW,
                repository_id=repository.id,
            )
        candidates = list(
            WorkItem.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
            .select_related("repository")
            .order_by("-updated_at")[:PAGE_LIMIT]
        )
        items = [
            item
            for item in candidates
            if _authorized(
                self.actor,
                Action.WORK_VIEW,
                item.repository_id,
                item.access_scope_id,
            )
        ]
        return {"work_items": items}

    def work_detail(self, work_item_id: uuid.UUID) -> dict[str, object]:
        work_item = get_tenant_record(
            queryset=WorkItem.objects.select_related("repository", "access_scope"),
            record_id=work_item_id,
            organization_id=self.actor.organization_id,
        )
        self._repository(work_item.repository_id, action=Action.WORK_VIEW)
        authorize_action(
            actor=self.actor,
            action=Action.WORK_VIEW,
            repository_id=work_item.repository_id,
            access_scope_id=work_item.access_scope_id,
        )
        revision = WorkItemRevision.objects.filter(
            organization_id=self.actor.organization_id,
            work_item=work_item,
            revision=work_item.revision,
        ).first()
        if revision is None:
            raise ResourceNotFoundError("Governed record was not found")
        requirements = list(
            Requirement.objects.filter(
                organization_id=self.actor.organization_id,
                work_item_revision=revision,
            ).order_by("position")[:PAGE_LIMIT]
        )
        criteria = list(
            AcceptanceCriterion.objects.filter(
                organization_id=self.actor.organization_id,
                work_item_revision=revision,
            ).order_by("position")[:PAGE_LIMIT]
        )
        criterion_ids = [item.id for item in criteria]
        evidence_scope_ids = self._visible_scope_ids(
            repository_id=work_item.repository_id,
            action=Action.EVIDENCE_VIEW,
        )
        evidence = list(
            CriterionEvidence.objects.filter(
                organization_id=self.actor.organization_id,
                criterion_id__in=criterion_ids,
                access_scope_id__in=evidence_scope_ids,
            )
            .filter(
                Q(evidence__isnull=True)
                | Q(evidence__manifest__access_scope_id__in=evidence_scope_ids)
            )
            .select_related("evidence")
            .order_by("criterion_id", "-created_at")[:PAGE_LIMIT]
        )
        return {
            "work_item": work_item,
            "revision": revision,
            "requirements": requirements,
            "non_requirements": list(
                NonRequirement.objects.filter(
                    organization_id=self.actor.organization_id,
                    work_item_revision=revision,
                ).order_by("position")[:PAGE_LIMIT]
            ),
            "criteria": criteria,
            "evidence": evidence,
            "decisions": list(
                Decision.objects.filter(
                    organization_id=self.actor.organization_id,
                    work_item_revision=revision,
                ).order_by("-created_at")[:PAGE_LIMIT]
            ),
        }

    def policies(self) -> dict[str, object]:
        repositories = self._repositories()
        if not repositories:
            return {"policies": []}
        for repository in repositories:
            authorize_action(
                actor=self.actor,
                action=Action.POLICY_VIEW,
                repository_id=repository.id,
            )
        candidates = list(
            Policy.objects.filter(organization_id=self.actor.organization_id)
            .select_related("access_scope")
            .order_by("name")[:PAGE_LIMIT]
        )
        policies = [
            policy
            for policy in candidates
            if any(
                _authorized(
                    self.actor,
                    Action.POLICY_VIEW,
                    repository.id,
                    policy.access_scope_id,
                )
                for repository in repositories
            )
        ]
        return {"policies": policies}

    def policy(self, policy_id: uuid.UUID) -> dict[str, object]:
        policy = get_tenant_record(
            queryset=Policy.objects.select_related("access_scope"),
            record_id=policy_id,
            organization_id=self.actor.organization_id,
        )
        repositories = self._repositories()
        if not any(
            _authorized(
                self.actor,
                Action.POLICY_VIEW,
                repository.id,
                policy.access_scope_id,
            )
            for repository in repositories
        ):
            raise ResourceNotFoundError("Governed record was not found")
        versions = list(
            PolicyVersion.objects.filter(
                organization_id=self.actor.organization_id,
                policy=policy,
            ).order_by("-version")[:PAGE_LIMIT]
        )
        version_ids = [item.id for item in versions]
        return {
            "policy": policy,
            "versions": versions,
            "bindings": list(
                PolicyBinding.objects.filter(
                    organization_id=self.actor.organization_id,
                    policy_version_id__in=version_ids,
                )[:PAGE_LIMIT]
            ),
            "requirements": list(
                PolicyRequirement.objects.filter(
                    organization_id=self.actor.organization_id,
                    policy_version_id__in=version_ids,
                ).order_by("code")[:PAGE_LIMIT]
            ),
            "evaluations": list(
                PolicyEvaluation.objects.filter(
                    organization_id=self.actor.organization_id,
                )
                .filter(
                    output_payload__applied_policy_versions__contains=[
                        str(version_ids[0]) if version_ids else ""
                    ]
                )
                .order_by("-evaluated_at")[:20]
            )
            if version_ids
            else [],
            "overrides": list(
                PolicyOverride.objects.filter(
                    organization_id=self.actor.organization_id,
                    policy_version_id__in=version_ids,
                ).order_by("-created_at")[:PAGE_LIMIT]
            ),
        }

    def assurance(self) -> dict[str, object]:
        repositories = self._repositories()
        for repository in repositories:
            authorize_action(
                actor=self.actor,
                action=Action.ASSURANCE_VIEW,
                repository_id=repository.id,
            )
        runs = list(self._visible_assurance_runs(repositories).order_by("-created_at")[:PAGE_LIMIT])
        return {
            "runs": [{"record": run, "status": _status(run.readiness or run.state)} for run in runs]
        }

    def assurance_detail(self, run_id: uuid.UUID) -> dict[str, object]:
        repositories = self._repositories()
        run = get_tenant_record(
            queryset=self._visible_assurance_runs(repositories).select_related(
                "repository",
                "pull_request_revision",
                "work_item_revision",
                "policy_evaluation",
            ),
            record_id=run_id,
            organization_id=self.actor.organization_id,
        )
        repository = (
            run.repository
            or Repository.objects.filter(
                organization_id=self.actor.organization_id,
                external_id=run.repository_external_id,
                is_active=True,
            ).first()
        )
        if repository is None:
            raise ResourceNotFoundError("Governed record was not found")
        self._repository(repository.id, action=Action.ASSURANCE_VIEW)
        runs = list(
            self._visible_assurance_runs([repository])
            .filter(
                repository_external_id=run.repository_external_id,
                pull_request_number=run.pull_request_number,
            )
            .order_by("-created_at")[:PAGE_LIMIT]
        )
        checks = list(
            AssuranceCheck.objects.filter(
                organization_id=self.actor.organization_id,
                assurance_run=run,
            ).order_by("position")[:PAGE_LIMIT]
        )
        findings = list(
            Finding.objects.filter(
                organization_id=self.actor.organization_id,
                latest_run=run,
            ).order_by("severity", "title")[:PAGE_LIMIT]
        )
        evidence = list(
            Evidence.objects.filter(
                organization_id=self.actor.organization_id,
                manifest_id__in=self._visible_manifests([repository]).values("id"),
                commit_sha=run.head_commit,
            ).order_by("kind", "name")[:PAGE_LIMIT]
        )
        report = AssuranceReport.objects.filter(
            organization_id=self.actor.organization_id,
            assurance_run=run,
        ).first()
        current = (
            run.state != AssuranceRun.State.STALE
            and bool(run.evaluated_commit)
            and run.evaluated_commit == run.head_commit
            and (not run.report_commit or run.report_commit == run.head_commit)
        )
        blockers = [
            finding
            for finding in findings
            if finding.severity in {Finding.Severity.BLOCKING, Finding.Severity.HIGH}
            and finding.state == Finding.State.OPEN
        ]
        human_focus = [
            finding
            for finding in findings
            if finding.kind == Finding.Kind.MODEL
            or finding.severity in {Finding.Severity.HIGH, Finding.Severity.MEDIUM}
        ][:5]
        return {
            "run": run,
            "repository": repository,
            "status": _status(run.readiness or run.state),
            "is_current": current,
            "blockers": blockers,
            "human_focus": human_focus,
            "checks": checks,
            "findings": findings,
            "evidence": evidence,
            "report": report,
            "timeline": runs,
            "policy_evaluation": run.policy_evaluation,
            "limitations": run.limitations,
        }

    def skills(self) -> dict[str, object]:
        repositories = self._repositories()
        last_packet = self._visible_packets(repositories).order_by("-generated_at").first()
        diagnostic = probe_mcp_diagnostics()
        settings_record = OrganizationProductSettings.objects.filter(
            organization_id=self.actor.organization_id
        ).first()
        return {
            "diagnostic": diagnostic,
            "last_packet": last_packet,
            "settings_record": settings_record,
            "hosts": [
                {
                    "name": "Codex",
                    "package": "packages/anva-skills/generated/codex-plugin",
                    "version": "v1",
                },
                {
                    "name": "Claude Code",
                    "package": "packages/anva-skills/generated/claude-plugin",
                    "version": "v1",
                },
            ],
        }

    def audit(self, filters: dict[str, str]) -> dict[str, object]:
        authorize_action(actor=self.actor, action=Action.AUDIT_VIEW)
        events = self._visible_audit_events(self._repositories())
        if filters.get("actor"):
            events = events.filter(actor_id__icontains=filters["actor"][:200])
        if filters.get("action"):
            events = events.filter(action__icontains=filters["action"][:200])
        if filters.get("target"):
            events = events.filter(target_type__icontains=filters["target"][:100])
        if filters.get("request_id"):
            try:
                events = events.filter(request_id=uuid.UUID(filters["request_id"]))
            except ValueError:
                events = events.none()
        if filters.get("date_from"):
            try:
                start = datetime.fromisoformat(filters["date_from"])
                if timezone.is_naive(start):
                    start = timezone.make_aware(start)
                events = events.filter(created_at__gte=start)
            except ValueError:
                events = events.none()
        return {
            "events": list(events.order_by("-created_at")[:PAGE_LIMIT]),
            "filters": filters,
            "bounded": True,
        }


def _authorized(
    actor: ActorContext,
    action: Action,
    repository_id: uuid.UUID,
    access_scope_id: uuid.UUID | None,
) -> bool:
    try:
        authorize_action(
            actor=actor,
            action=action,
            repository_id=repository_id,
            access_scope_id=access_scope_id,
        )
    except ResourceNotFoundError:
        return False
    return True


def _authorized_source(
    actor: ActorContext,
    action: Action,
    repository_id: uuid.UUID,
    source_connection_id: uuid.UUID,
    access_scope_id: uuid.UUID | None,
    *,
    allow_revoked: bool = False,
) -> bool:
    try:
        authorize_action(
            actor=actor,
            action=action,
            repository_id=repository_id,
            source_connection_id=source_connection_id,
            access_scope_id=access_scope_id,
            allow_revoked_source=allow_revoked,
        )
    except ResourceNotFoundError:
        return False
    return True
