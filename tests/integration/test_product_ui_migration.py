"""Upgrade coverage for product records introduced by migration 0015."""

from __future__ import annotations

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

PREVIOUS = ("core", "0014_knowledge_proposal_immutability")
TARGET = ("core", "0015_knowledgeproposalscope_organizationproductsettings_and_more")
IDENTITY_ONLY_LIMITATION = (
    "Profile backfill preserved repository identity only; ownership, purpose, runtime, "
    "checks, and sensitive paths require human confirmation."
)


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
def test_0015_backfills_every_existing_tenant_and_is_reversible_and_repeatable() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([PREVIOUS])
    old_apps = executor.loader.project_state([PREVIOUS]).apps
    Organization = old_apps.get_model("core", "Organization")
    Repository = old_apps.get_model("core", "Repository")

    first_org = Organization.objects.create(slug="legacy-one", name="Legacy One")
    second_org = Organization.objects.create(slug="legacy-two", name="Legacy Two")
    first_repo = Repository.objects.create(
        organization=first_org,
        external_id="github:legacy/one",
        name="one",
    )
    second_repo = Repository.objects.create(
        organization=second_org,
        external_id="github:legacy/two",
        name="two",
    )

    try:
        executor = MigrationExecutor(connection)
        executor.migrate([TARGET])
        apps = executor.loader.project_state([TARGET]).apps
        settings_model = apps.get_model("core", "OrganizationProductSettings")
        profile_model = apps.get_model("core", "RepositoryProfile")

        assert settings_model.objects.count() == 2
        assert profile_model.objects.count() == 2
        for organization in (first_org, second_org):
            settings = settings_model.objects.get(organization_id=organization.id)
            assert settings.retention_days == 365
            assert settings.model_processing == "DISABLED"
            assert settings.skill_distribution == "SELF_SERVICE"
            assert settings.assurance_mode == "OBSERVE"
        for repository in (first_repo, second_repo):
            profile = profile_model.objects.get(repository_id=repository.id)
            assert profile.organization_id == repository.organization_id
            assert profile.status == "DRAFT"
            assert profile.purpose == ""
            assert profile.owning_team == ""
            assert profile.products == []
            assert profile.runtime == []
            assert profile.unsupported_or_ambiguous == [IDENTITY_ONLY_LIMITATION]
            assert profile.source_references == [
                {
                    "external_id": repository.external_id,
                    "kind": "repository_identity",
                    "name": repository.name,
                }
            ]

        executor = MigrationExecutor(connection)
        executor.migrate([PREVIOUS])
        executor = MigrationExecutor(connection)
        executor.migrate([TARGET])
        reapplied_apps = executor.loader.project_state([TARGET]).apps
        assert reapplied_apps.get_model("core", "OrganizationProductSettings").objects.count() == 2
        assert reapplied_apps.get_model("core", "RepositoryProfile").objects.count() == 2
    finally:
        MigrationExecutor(connection).migrate(
            MigrationExecutor(connection).loader.graph.leaf_nodes()
        )
