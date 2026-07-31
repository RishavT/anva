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
from django.db.models import Q
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
    ContextPacketRecord,
    CriterionEvidence,
    Decision,
    Evidence,
    Finding,
    GitHubInstallation,
    GitHubRepositoryBinding,
    KnowledgeAssertion,
    KnowledgeEntity,
    KnowledgeProposal,
    KnowledgeProposalScope,
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
    get_tenant_record,
)
from anva.core.services.bootstrap import BootstrapResult, bootstrap_local_organization
from anva.core.services.context import ActorContext
from anva.core.services.context_packets import authorized_assertion_citations
from anva.core.services.creation import submit_knowledge_proposal
from anva.core.services.events import record_transition
from anva.core.services.graph import traverse_graph
from anva.core.services.ingestion import request_ingestion_sync
from anva.core.services.mcp_gateway import diagnostics_payload
from anva.core.services.retrieval import (
    authorized_assertions,
    authorized_entities,
    get_authorized_entity,
)
from anva.core.services.scopes import revoke_source_connection
from anva.core.services.search import search_chunks
from anva.core.services.secured_operations import review_assertion

PAGE_LIMIT = 100
SEARCH_LIMIT = 30


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
        sources = list(
            SourceConnection.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            ).order_by("display_name", "id")[:PAGE_LIMIT]
        )
        profiles = {
            profile.repository_id: profile
            for profile in RepositoryProfile.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
        }
        settings_record = OrganizationProductSettings.objects.filter(
            organization_id=self.actor.organization_id
        ).first()
        latest_packet = (
            ContextPacketRecord.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
            .order_by("-generated_at")
            .first()
        )
        latest_run = (
            AssuranceRun.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
            .order_by("-created_at")
            .first()
        )
        binding_count = GitHubRepositoryBinding.objects.filter(
            organization_id=self.actor.organization_id,
            repository_id__in=repository_ids,
            is_active=True,
            revoked_at__isnull=True,
            installation__state=GitHubInstallation.State.ACTIVE,
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
                    "DONE"
                    if any(item.last_successful_sync_at for item in sources)
                    else "NEEDS_ATTENTION"
                ),
                "detail": f"{len(sources)} source connection{'s' if len(sources) != 1 else ''}",
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
                "state": (
                    "DONE"
                    if any(item.state == SourceConnection.State.REVOKED for item in sources)
                    else "NEEDS_ATTENTION"
                ),
                "detail": "Verify future retrieval no longer returns revoked content.",
                "href": "/app/sources",
            },
        ]
        return {"checks": checks, "settings_record": settings_record}

    def home(self) -> dict[str, object]:
        repositories = self._repositories()
        repository_ids = [item.id for item in repositories]
        external_ids = [item.external_id for item in repositories]
        sources = list(
            SourceConnection.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
            .filter(
                Q(state__in=[SourceConnection.State.DEGRADED, SourceConnection.State.FAILED])
                | Q(last_successful_sync_at__isnull=True)
            )
            .order_by("-updated_at")[:8]
        )
        runs = list(
            AssuranceRun.objects.filter(
                organization_id=self.actor.organization_id,
            )
            .filter(
                Q(repository_id__in=repository_ids) | Q(repository_external_id__in=external_ids)
            )
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
                AuditEvent.objects.filter(organization_id=self.actor.organization_id).order_by(
                    "-created_at"
                )[:6]
            )
        except ResourceNotFoundError:
            pass
        current_sources = SourceConnection.objects.filter(
            organization_id=self.actor.organization_id,
            repository_id__in=repository_ids,
            state=SourceConnection.State.ACTIVE,
            last_successful_sync_at__isnull=False,
        ).count()
        return {
            "attention": attention[:16],
            "repositories_count": len(repositories),
            "current_sources": current_sources,
            "source_total": SourceConnection.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            ).count(),
            "latest_audit": latest_audit,
        }

    def explorer(
        self,
        *,
        repository_id: uuid.UUID | None,
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
            }
        entities = authorized_entities(actor=self.actor, repository_id=selected.id)
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
                ).results
            )
        assertions: list[KnowledgeAssertion] = []
        if freshness in KnowledgeAssertion.StalenessState.values:
            assertions = list(
                authorized_assertions(
                    actor=self.actor,
                    repository_id=selected.id,
                    action=Action.KNOWLEDGE_VIEW,
                )
                .filter(staleness_state=freshness)
                .order_by("-observed_at")[:SEARCH_LIMIT]
            )
        return {
            "selected_repository": selected,
            "entities": entity_rows,
            "source_results": source_results,
            "freshness_assertions": assertions,
            "query": query,
            "entity_type": entity_type,
            "freshness": freshness,
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

    def sources(self) -> dict[str, object]:
        repositories = self._repositories()
        repository_ids = [item.id for item in repositories]
        candidates = list(
            SourceConnection.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
            .select_related("repository")
            .order_by("display_name", "external_key")[:PAGE_LIMIT]
        )
        rows = [
            row
            for row in candidates
            if row.repository_id is not None
            and _authorized_source(
                self.actor,
                Action.SOURCE_VIEW,
                row.repository_id,
                row.id,
                row.access_scope_id,
                allow_revoked=True,
            )
        ]
        return {"sources": [{"record": row, "status": _status(row.state)} for row in rows]}

    def source(self, source_id: uuid.UUID) -> dict[str, object]:
        source = get_tenant_record(
            queryset=SourceConnection.objects.select_related("repository", "access_scope"),
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
            allow_revoked_source=True,
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
                allow_revoked=True,
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
        proposal_candidates = list(
            KnowledgeProposalScope.objects.filter(
                organization_id=self.actor.organization_id,
                repository=selected,
            )
            .select_related("knowledge_proposal", "assertion")
            .order_by("-created_at")[:PAGE_LIMIT]
        )
        proposal_scopes = [
            scope
            for scope in proposal_candidates
            if _authorized(
                self.actor,
                Action.KNOWLEDGE_VIEW,
                selected.id,
                scope.access_scope_id,
            )
        ]
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
        assertion = (
            authorized_assertions(
                actor=self.actor,
                repository_id=repository.id,
                action=Action.KNOWLEDGE_PROPOSE,
            )
            .filter(id=assertion_id)
            .first()
        )
        if assertion is None or assertion.access_scope_id is None:
            raise ResourceNotFoundError("Governed record was not found")
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
        authorization = authorize_action(
            actor=self.actor,
            action=Action.KNOWLEDGE_PROPOSE,
            repository_id=repository.id,
            access_scope_id=assertion.access_scope_id,
        )
        with transaction.atomic():
            proposal = submit_knowledge_proposal(
                actor=replace(self.actor, authorization_path=authorization.authorization_path),
                summary=f"Correction proposed for {assertion.subject_key}",
                proposed_changes=[
                    {
                        "operation": "CORRECT",
                        "assertion_id": str(assertion.id),
                        "current_value_hash": content_hash(assertion.value),
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
            )
            return proposal

    def repository(self, repository_id: uuid.UUID) -> dict[str, object]:
        repository = self._repository(repository_id, action=Action.REPOSITORY_VIEW)
        profile = RepositoryProfile.objects.filter(
            organization_id=self.actor.organization_id,
            repository=repository,
        ).first()
        source_candidates = list(
            SourceConnection.objects.filter(
                organization_id=self.actor.organization_id,
                repository=repository,
            ).order_by("display_name", "external_key")[:PAGE_LIMIT]
        )
        sources = [
            source
            for source in source_candidates
            if _authorized_source(
                self.actor,
                Action.SOURCE_VIEW,
                repository.id,
                source.id,
                source.access_scope_id,
                allow_revoked=True,
            )
        ]
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
        runs = list(
            AssuranceRun.objects.filter(organization_id=self.actor.organization_id)
            .filter(Q(repository=repository) | Q(repository_external_id=repository.external_id))
            .order_by("-created_at")[:12]
        )
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
        binding = GitHubRepositoryBinding.objects.filter(
            organization_id=self.actor.organization_id,
            repository=repository,
        ).first()
        return {
            "repository": repository,
            "profile": profile,
            "sources": sources,
            "policies": policies,
            "runs": runs,
            "unresolved": unresolved,
            "github_binding": binding,
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
            profile = get_tenant_record(
                queryset=RepositoryProfile.objects.select_for_update(),
                record_id=RepositoryProfile.objects.get(repository=repository).id,
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
        evidence = list(
            CriterionEvidence.objects.filter(
                organization_id=self.actor.organization_id,
                criterion_id__in=criterion_ids,
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
        repository_ids = [item.id for item in repositories]
        external_ids = [item.external_id for item in repositories]
        for repository in repositories:
            authorize_action(
                actor=self.actor,
                action=Action.ASSURANCE_VIEW,
                repository_id=repository.id,
            )
        runs = list(
            AssuranceRun.objects.filter(organization_id=self.actor.organization_id)
            .filter(
                Q(repository_id__in=repository_ids) | Q(repository_external_id__in=external_ids)
            )
            .order_by("-created_at")[:PAGE_LIMIT]
        )
        return {
            "runs": [{"record": run, "status": _status(run.readiness or run.state)} for run in runs]
        }

    def assurance_detail(self, run_id: uuid.UUID) -> dict[str, object]:
        run = get_tenant_record(
            queryset=AssuranceRun.objects.select_related(
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
            AssuranceRun.objects.filter(
                organization_id=self.actor.organization_id,
                repository_external_id=run.repository_external_id,
                pull_request_number=run.pull_request_number,
            ).order_by("-created_at")[:PAGE_LIMIT]
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
                manifest__repository=repository,
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
        repository_ids = [item.id for item in repositories]
        last_packet = (
            ContextPacketRecord.objects.filter(
                organization_id=self.actor.organization_id,
                repository_id__in=repository_ids,
            )
            .order_by("-generated_at")
            .first()
        )
        diagnostic = diagnostics_payload()
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
        events = AuditEvent.objects.filter(organization_id=self.actor.organization_id)
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
