"""HTTP routes for the Anva API and server-rendered application."""

from __future__ import annotations

from django.urls import path

from anva.core import views as core_views
from anva.foundation import views

urlpatterns = [
    path("", views.home, name="home"),
    path("health/live", views.liveness, name="liveness"),
    path("health/ready", views.readiness, name="readiness"),
    path("api/v1/bootstrap", core_views.bootstrap, name="api-v1-bootstrap"),
    path(
        "api/v1/organizations/<uuid:organization_id>",
        core_views.organization_detail,
        name="api-v1-organization",
    ),
    path(
        "api/v1/organizations/<uuid:organization_id>/members",
        core_views.memberships,
        name="api-v1-memberships",
    ),
    path(
        "api/v1/organizations/<uuid:organization_id>/members/<uuid:membership_id>",
        core_views.membership_detail,
        name="api-v1-membership",
    ),
    path(
        "api/v1/repositories/<uuid:repository_id>/tokens",
        core_views.repository_tokens,
        name="api-v1-repository-tokens",
    ),
    path(
        "api/v1/tokens/<uuid:token_id>/rotate",
        core_views.rotate_token,
        name="api-v1-token-rotate",
    ),
    path(
        "api/v1/tokens/<uuid:token_id>",
        core_views.revoke_token,
        name="api-v1-token-revoke",
    ),
    path("api/v1/search", core_views.search, name="api-v1-search"),
    path(
        "api/v1/canvas/assertions/<uuid:assertion_id>",
        core_views.canvas_assertion,
        name="api-v1-canvas-assertion",
    ),
    path("api/v1/mcp/context", core_views.mcp_context, name="api-v1-mcp-context"),
    path(
        "api/v1/artifacts/<uuid:artifact_id>",
        core_views.artifact_detail,
        name="api-v1-artifact",
    ),
    path(
        "api/v1/knowledge/assertions/<uuid:assertion_id>/review",
        core_views.review_knowledge,
        name="api-v1-knowledge-review",
    ),
    path(
        "api/v1/assurance-runs/<uuid:run_id>/transition",
        core_views.transition_assurance,
        name="api-v1-assurance-transition",
    ),
    path(
        "api/v1/findings/<uuid:finding_id>/dismiss",
        core_views.dismiss_finding,
        name="api-v1-finding-dismiss",
    ),
    path(
        "api/v1/policies/<uuid:policy_id>/override",
        core_views.override_policy,
        name="api-v1-policy-override",
    ),
    path(
        "api/v1/source-connections/<uuid:source_connection_id>/revoke",
        core_views.revoke_source,
        name="api-v1-source-revoke",
    ),
]
