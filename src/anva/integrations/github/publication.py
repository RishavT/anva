"""Exact-head GitHub Check/comment rendering and durable outbox dispatch."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast

from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from anva.core.logging import redact_text
from anva.core.models import (
    AssuranceReport,
    AssuranceRun,
    Finding,
    GitHubInstallation,
    GitHubPublication,
    GitHubRepositoryBinding,
    GitHubWriteAttempt,
    GitHubWriteIntent,
    OutboxEvent,
    PullRequest,
    content_hash,
)
from anva.core.services.context import ActorContext
from anva.core.services.events import record_transition
from anva.integrations.github.client import (
    GitHubClient,
    GitHubClientError,
    GitHubWriteResult,
    RepositoryReference,
)

CHECK_NAME = "Anva / Assurance"
MAX_ANNOTATIONS = 50
MAX_SUMMARY_CHARS = 4_000
MAX_COMMENT_CHARS = 20_000
WRITE_LEASE_SECONDS = 120

READINESS_CONCLUSIONS = {
    "BLOCKED": "failure",
    "FAILED": "failure",
    "READY_WITH_WARNINGS": "neutral",
    "READY_FOR_HUMAN_REVIEW": "success",
}
SEVERITY_RANK: dict[str, int] = {
    Finding.Severity.BLOCKING: 0,
    Finding.Severity.HIGH: 1,
    Finding.Severity.MEDIUM: 2,
    Finding.Severity.LOW: 3,
    Finding.Severity.ADVISORY: 4,
}


@dataclass(frozen=True, slots=True)
class PublicationQueueResult:
    publications: tuple[GitHubPublication, ...]
    intents: tuple[GitHubWriteIntent, ...]
    created_count: int


def _report_url(run: AssuranceRun) -> str:
    base = str(settings.ANVA_PUBLIC_BASE_URL).rstrip("/")
    return f"{base}/api/v1/assurance-runs/{run.id}/report"


def _marker(pull_request: PullRequest, head_commit: str) -> tuple[str, str]:
    prefix = f"<!-- anva:pr={pull_request.id} report=assurance"
    return prefix, f"{prefix} commit={head_commit} -->"


def _current_findings(run: AssuranceRun) -> list[Finding]:
    return list(
        Finding.objects.filter(
            organization=run.organization,
            latest_run=run,
            state=Finding.State.OPEN,
        ).order_by("severity", "path", "line", "fingerprint")
    )


def _counts(findings: list[Finding]) -> tuple[int, int]:
    blocking = sum(
        finding.severity in {Finding.Severity.BLOCKING, Finding.Severity.HIGH}
        for finding in findings
    )
    warnings = len(findings) - blocking
    return blocking, warnings


def _annotations(run: AssuranceRun, findings: list[Finding]) -> list[dict[str, object]]:
    revision = run.pull_request_revision
    if revision is None:
        return []
    changed_paths = set(cast(list[str], revision.changed_paths))
    eligible = [
        finding
        for finding in findings
        if finding.path
        and finding.path in changed_paths
        and finding.line is not None
        and finding.line >= 1
        and finding.confidence in {Finding.Confidence.PROVEN, Finding.Confidence.HIGH}
    ]
    eligible.sort(
        key=lambda finding: (
            SEVERITY_RANK[finding.severity],
            finding.path,
            finding.line or 0,
            finding.fingerprint,
        )
    )
    annotations: list[dict[str, object]] = []
    for finding in eligible[:MAX_ANNOTATIONS]:
        message = redact_text(f"{finding.title}: {finding.explanation}")[:2_000]
        annotations.append(
            {
                "path": finding.path,
                "start_line": finding.line,
                "end_line": finding.line,
                "annotation_level": (
                    "failure"
                    if finding.severity in {Finding.Severity.BLOCKING, Finding.Severity.HIGH}
                    else "warning"
                ),
                "title": redact_text(finding.title)[:255],
                "message": message,
            }
        )
    return annotations


def render_publications(
    *,
    run: AssuranceRun,
    report: AssuranceReport,
    pull_request: PullRequest,
) -> dict[str, dict[str, object]]:
    """Render bounded provider payloads with an explicit evaluated commit."""
    if run.head_commit != run.evaluated_commit or run.head_commit != run.report_commit:
        raise ValueError("Assurance report is not pinned to its evaluated commit")
    findings = _current_findings(run)
    blocking, warnings = _counts(findings)
    report_url = _report_url(run)
    readiness = run.readiness
    if readiness not in READINESS_CONCLUSIONS:
        raise ValueError("Assurance readiness cannot be published")
    evaluated = run.head_commit
    short_sha = evaluated[:12]
    summary = redact_text(
        "\n".join(
            [
                f"Readiness: **{readiness.replace('_', ' ').title()}**",
                f"Evaluated commit: `{evaluated}`",
                f"Blocking findings: {blocking}",
                f"Warnings: {warnings}",
                "",
                "This is independent review-readiness evidence; it does not claim the "
                "change is safe to merge or deploy.",
            ]
        )
    )[:MAX_SUMMARY_CHARS]
    annotations = _annotations(run, findings)
    check_payload: dict[str, object] = {
        "status": "completed",
        "conclusion": READINESS_CONCLUSIONS[readiness],
        "completed_at": (run.completed_at or timezone.now()).isoformat(),
        "details_url": report_url,
        "output": {
            "title": f"Anva: {readiness.replace('_', ' ').title()} ({short_sha})"[:255],
            "summary": summary,
            "text": redact_text(report.markdown)[:20_000],
            "annotations": annotations,
        },
    }
    marker_prefix, marker = _marker(pull_request, evaluated)
    comment_body = redact_text(
        "\n".join(
            [
                marker,
                "## Anva assurance",
                "",
                summary,
                "",
                f"[Open the detailed Anva report]({report_url})",
            ]
        )
    )[:MAX_COMMENT_CHARS]
    return {
        GitHubPublication.Kind.CHECK: check_payload,
        GitHubPublication.Kind.COMMENT: {
            "marker_prefix": marker_prefix,
            "body": comment_body,
        },
    }


@transaction.atomic
def queue_assurance_publications(*, run_id: uuid.UUID) -> PublicationQueueResult:
    """Create one frozen outbox intent per current Check/comment projection."""
    run = (
        AssuranceRun.objects.select_for_update(of=("self",))
        .select_related(
            "organization",
            "repository__github_binding__installation__service_identity",
            "pull_request_revision__pull_request",
        )
        .get(id=run_id)
    )
    if (
        run.state != AssuranceRun.State.COMPLETED
        or run.repository is None
        or run.pull_request_revision is None
    ):
        return PublicationQueueResult((), (), 0)
    pull_request = run.pull_request_revision.pull_request
    binding = (
        GitHubRepositoryBinding.objects.select_for_update()
        .select_related("installation__service_identity", "repository")
        .filter(
            organization=run.organization,
            repository=run.repository,
            is_active=True,
            is_archived=False,
            installation__state=GitHubInstallation.State.ACTIVE,
            installation__service_identity__is_active=True,
            repository__is_active=True,
        )
        .first()
    )
    if (
        binding is None
        or pull_request.current_head_commit != run.head_commit
        or run.evaluated_commit != run.head_commit
        or run.report_commit != run.head_commit
    ):
        return PublicationQueueResult((), (), 0)
    newer_current = (
        AssuranceRun.objects.filter(
            organization=run.organization,
            repository=run.repository,
            pull_request_number=run.pull_request_number,
        )
        .exclude(
            state__in=[
                AssuranceRun.State.STALE,
                AssuranceRun.State.FAILED,
                AssuranceRun.State.CANCELLED,
            ]
        )
        .filter(Q(created_at__gt=run.created_at) | Q(created_at=run.created_at, id__gt=run.id))
        .exists()
    )
    if newer_current:
        return PublicationQueueResult((), (), 0)
    report = AssuranceReport.objects.filter(
        organization=run.organization,
        assurance_run=run,
    ).first()
    if report is None:
        return PublicationQueueResult((), (), 0)
    rendered = render_publications(run=run, report=report, pull_request=pull_request)
    actor = ActorContext(
        organization_id=run.organization_id,
        actor_type="SERVICE",
        actor_id=str(binding.installation.service_identity_id),
        authorization_path=f"github-installation:{binding.installation_id}",
        request_id=uuid.uuid4(),
    )
    publications: list[GitHubPublication] = []
    intents: list[GitHubWriteIntent] = []
    created_count = 0
    for kind in (GitHubPublication.Kind.CHECK, GitHubPublication.Kind.COMMENT):
        current_rows = list(
            GitHubPublication.objects.select_for_update().filter(
                organization=run.organization,
                repository_binding=binding,
                pull_request=pull_request,
                kind=kind,
                is_current=True,
            )
        )
        for current in current_rows:
            if current.head_commit != run.head_commit:
                current.is_current = False
                current.revision += 1
                current.save(update_fields=["is_current", "revision", "updated_at"])
                _cancel_pending_intents(current)
        publication = (
            GitHubPublication.objects.select_for_update()
            .filter(
                organization=run.organization,
                repository_binding=binding,
                pull_request=pull_request,
                kind=kind,
                head_commit=run.head_commit,
            )
            .first()
        )
        if publication is None:
            publication = GitHubPublication.objects.create(
                organization=run.organization,
                repository_binding=binding,
                pull_request=pull_request,
                assurance_run=run,
                kind=kind,
                head_commit=run.head_commit,
                is_current=True,
            )
        else:
            publication.assurance_run = run
            publication.is_current = True
            publication.revision += 1
            publication.save(
                update_fields=["assurance_run", "is_current", "revision", "updated_at"]
            )
        payload = rendered[kind]
        payload_hash = content_hash(payload)
        idempotency_key = f"github-write:{publication.id}:{payload_hash}"
        intent = GitHubWriteIntent.objects.filter(
            organization=run.organization,
            idempotency_key=idempotency_key,
        ).first()
        if intent is None:
            _cancel_pending_intents(publication)
            intent = GitHubWriteIntent.objects.create(
                organization=run.organization,
                publication=publication,
                assurance_run=run,
                head_commit=run.head_commit,
                rendered_payload=payload,
                payload_hash=payload_hash,
                idempotency_key=idempotency_key,
            )
            OutboxEvent.objects.create(
                organization=run.organization,
                aggregate_type="githubwriteintent",
                aggregate_id=intent.id,
                event_type="github.write.requested",
                payload={
                    "intent_id": str(intent.id),
                    "head_commit": intent.head_commit,
                    "payload_hash": intent.payload_hash,
                },
                idempotency_key=f"outbox:{idempotency_key}",
            )
            record_transition(
                organization=run.organization,
                actor=actor,
                target_type="githubwriteintent",
                target_id=intent.id,
                from_state="",
                to_state=GitHubWriteIntent.State.PENDING,
                revision=1,
                metadata={
                    "content_hash": intent.payload_hash,
                    "head_commit": intent.head_commit,
                    "publication_id": str(publication.id),
                },
            )
            created_count += 1
        publications.append(publication)
        intents.append(intent)
    return PublicationQueueResult(tuple(publications), tuple(intents), created_count)


def _cancel_pending_intents(publication: GitHubPublication) -> None:
    now = timezone.now()
    pending = GitHubWriteIntent.objects.filter(
        organization=publication.organization,
        publication=publication,
        state__in=[
            GitHubWriteIntent.State.PENDING,
            GitHubWriteIntent.State.RETRY,
            GitHubWriteIntent.State.RUNNING,
        ],
    )
    ids = list(pending.values_list("id", flat=True))
    pending.update(
        state=GitHubWriteIntent.State.CANCELLED,
        completed_at=now,
        lease_owner="",
        lease_expires_at=None,
    )
    OutboxEvent.objects.filter(
        aggregate_type="githubwriteintent",
        aggregate_id__in=ids,
        published_at__isnull=True,
    ).update(published_at=now)


def queue_completed_assurance_publications(*, limit: int = 100) -> int:
    """Materialize missing writes for bounded completed runs."""
    if limit < 1 or limit > 1_000:
        raise ValueError("Publication scan limit is invalid")
    run_ids = list(
        AssuranceRun.objects.filter(
            state=AssuranceRun.State.COMPLETED,
            assurancereport__isnull=False,
            repository__github_binding__is_active=True,
            repository__github_binding__installation__state=GitHubInstallation.State.ACTIVE,
        )
        .order_by("created_at", "id")
        .values_list("id", flat=True)[:limit]
    )
    return sum(queue_assurance_publications(run_id=run_id).created_count for run_id in run_ids)


@transaction.atomic
def claim_next_write(
    *,
    worker_id: str,
    now: datetime | None = None,
) -> GitHubWriteIntent | None:
    """Claim one ready write with `SKIP LOCKED` and an expiring lease."""
    if not worker_id or len(worker_id) > 200:
        raise ValueError("GitHub worker ID is invalid")
    claimed_at = now or timezone.now()
    eligible = Q(
        state__in=[GitHubWriteIntent.State.PENDING, GitHubWriteIntent.State.RETRY],
        available_at__lte=claimed_at,
        attempt_count__lt=F("max_attempts"),
    ) | Q(
        state=GitHubWriteIntent.State.RUNNING,
        lease_expires_at__lte=claimed_at,
        attempt_count__lt=F("max_attempts"),
    )
    intent = (
        GitHubWriteIntent.objects.select_for_update(skip_locked=True)
        .filter(eligible)
        .order_by("available_at", "created_at", "id")
        .first()
    )
    if intent is None:
        return None
    intent.state = GitHubWriteIntent.State.RUNNING
    intent.attempt_count += 1
    intent.lease_owner = worker_id
    intent.lease_expires_at = claimed_at + timedelta(seconds=WRITE_LEASE_SECONDS)
    intent.save(
        update_fields=[
            "state",
            "attempt_count",
            "lease_owner",
            "lease_expires_at",
        ]
    )
    return intent


def dispatch_next_write(
    *,
    worker_id: str,
    client_for_installation: Callable[[int], GitHubClient],
    now: datetime | None = None,
) -> GitHubWriteIntent | None:
    """Reauthorize and dispatch one claimed external write."""
    dispatch_time = now or timezone.now()
    intent = claim_next_write(worker_id=worker_id, now=dispatch_time)
    if intent is None:
        return None
    with transaction.atomic():
        current = (
            GitHubWriteIntent.objects.select_for_update()
            .select_related(
                "publication__repository_binding__installation__service_identity",
                "publication__repository_binding__repository",
                "publication__pull_request",
                "assurance_run",
            )
            .get(id=intent.id)
        )
        cancellation_code = _publication_cancellation_code(current)
        if cancellation_code:
            return _cancel_claimed(current, code=cancellation_code, now=dispatch_time)
        publication = current.publication
        binding = publication.repository_binding
        client = client_for_installation(binding.installation.external_id)
        repository = RepositoryReference(binding.external_repository_id, binding.full_name)
        try:
            result = _perform_write(
                client=client,
                repository=repository,
                intent=current,
                publication=publication,
            )
        except GitHubClientError as error:
            return _record_failure(current, error=error, now=dispatch_time)
        return _record_success(current, result=result, now=dispatch_time)


def _publication_cancellation_code(intent: GitHubWriteIntent) -> str:
    publication = intent.publication
    binding = publication.repository_binding
    pull_request = publication.pull_request
    run = intent.assurance_run
    newer_intent = GitHubWriteIntent.objects.filter(
        publication=publication,
        created_at__gt=intent.created_at,
    ).exclude(state=GitHubWriteIntent.State.CANCELLED)
    if newer_intent.exists():
        return "SUPERSEDED_PUBLICATION"
    if (
        not publication.is_current
        or publication.assurance_run_id != run.id
        or publication.head_commit != intent.head_commit
        or pull_request.current_head_commit != intent.head_commit
        or run.state != AssuranceRun.State.COMPLETED
        or run.evaluated_commit != intent.head_commit
        or run.report_commit != intent.head_commit
    ):
        return "STALE_HEAD"
    if (
        not binding.is_active
        or binding.is_archived
        or not binding.repository.is_active
        or binding.installation.state != GitHubInstallation.State.ACTIVE
        or not binding.installation.service_identity.is_active
    ):
        return "GITHUB_ACCESS_REVOKED"
    if not AssuranceReport.objects.filter(
        organization=intent.organization,
        assurance_run=run,
    ).exists():
        return "REPORT_MISSING"
    return ""


def _perform_write(
    *,
    client: GitHubClient,
    repository: RepositoryReference,
    intent: GitHubWriteIntent,
    publication: GitHubPublication,
) -> GitHubWriteResult:
    payload = cast(dict[str, object], intent.rendered_payload)
    if publication.kind == GitHubPublication.Kind.CHECK:
        return client.upsert_check(
            repository=repository,
            head_commit=intent.head_commit,
            check_name=CHECK_NAME,
            payload=payload,
            external_id=publication.external_id,
            idempotency_key=intent.idempotency_key,
        )
    return client.upsert_comment(
        repository=repository,
        pull_request_number=publication.pull_request.number,
        marker_prefix=cast(str, payload["marker_prefix"]),
        body=cast(str, payload["body"]),
        external_id=publication.external_id,
        idempotency_key=intent.idempotency_key,
    )


def _record_success(
    intent: GitHubWriteIntent,
    *,
    result: GitHubWriteResult,
    now: datetime,
) -> GitHubWriteIntent:
    intent.state = GitHubWriteIntent.State.SUCCEEDED
    intent.external_id = result.external_id
    intent.external_url = result.external_url
    intent.completed_at = now
    intent.lease_owner = ""
    intent.lease_expires_at = None
    intent.last_error_code = ""
    intent.save(
        update_fields=[
            "state",
            "external_id",
            "external_url",
            "completed_at",
            "lease_owner",
            "lease_expires_at",
            "last_error_code",
        ]
    )
    publication = intent.publication
    publication.external_id = result.external_id
    publication.external_url = result.external_url
    publication.last_payload_hash = intent.payload_hash
    publication.revision += 1
    publication.save(
        update_fields=[
            "external_id",
            "external_url",
            "last_payload_hash",
            "revision",
            "updated_at",
        ]
    )
    GitHubWriteAttempt.objects.create(
        organization=intent.organization,
        write_intent=intent,
        attempt=intent.attempt_count,
        outcome="SUCCEEDED",
        external_id=result.external_id,
        response_metadata={"request_id": result.request_id} if result.request_id else {},
    )
    OutboxEvent.objects.filter(
        organization=intent.organization,
        aggregate_type="githubwriteintent",
        aggregate_id=intent.id,
        event_type="github.write.requested",
        published_at__isnull=True,
    ).update(published_at=now)
    return intent


def _record_failure(
    intent: GitHubWriteIntent,
    *,
    error: GitHubClientError,
    now: datetime,
) -> GitHubWriteIntent:
    retry = error.transient and intent.attempt_count < intent.max_attempts
    outcome = "RETRY" if retry else "FAILED"
    GitHubWriteAttempt.objects.create(
        organization=intent.organization,
        write_intent=intent,
        attempt=intent.attempt_count,
        outcome=outcome,
        safe_error_code=error.code[:100],
        response_metadata={"request_id": error.request_id} if error.request_id else {},
    )
    intent.last_error_code = error.code[:100]
    intent.lease_owner = ""
    intent.lease_expires_at = None
    if retry:
        exponential = min(900, 5 * (2 ** max(0, intent.attempt_count - 1)))
        delay = max(exponential, error.retry_after_seconds or 0)
        intent.state = GitHubWriteIntent.State.RETRY
        intent.available_at = now + timedelta(seconds=delay)
        intent.save(
            update_fields=[
                "state",
                "available_at",
                "lease_owner",
                "lease_expires_at",
                "last_error_code",
            ]
        )
    else:
        intent.state = GitHubWriteIntent.State.FAILED
        intent.completed_at = now
        intent.save(
            update_fields=[
                "state",
                "completed_at",
                "lease_owner",
                "lease_expires_at",
                "last_error_code",
            ]
        )
        OutboxEvent.objects.filter(
            organization=intent.organization,
            aggregate_type="githubwriteintent",
            aggregate_id=intent.id,
            event_type="github.write.requested",
            published_at__isnull=True,
        ).update(published_at=now)
    return intent


def _cancel_claimed(
    intent: GitHubWriteIntent,
    *,
    code: str,
    now: datetime,
) -> GitHubWriteIntent:
    intent.state = GitHubWriteIntent.State.CANCELLED
    intent.last_error_code = code
    intent.completed_at = now
    intent.lease_owner = ""
    intent.lease_expires_at = None
    intent.save(
        update_fields=[
            "state",
            "last_error_code",
            "completed_at",
            "lease_owner",
            "lease_expires_at",
        ]
    )
    GitHubWriteAttempt.objects.create(
        organization=intent.organization,
        write_intent=intent,
        attempt=intent.attempt_count,
        outcome="CANCELLED",
        safe_error_code=code,
    )
    OutboxEvent.objects.filter(
        organization=intent.organization,
        aggregate_type="githubwriteintent",
        aggregate_id=intent.id,
        event_type="github.write.requested",
        published_at__isnull=True,
    ).update(published_at=now)
    return intent
