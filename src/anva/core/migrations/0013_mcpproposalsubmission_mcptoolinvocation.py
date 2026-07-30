import uuid
from typing import ClassVar

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models

SAME_TENANT_SQL = """
ALTER TABLE core_mcpproposalsubmission
  ADD CONSTRAINT mcp_submission_repository_tenant_fk
  FOREIGN KEY (organization_id, repository_id)
  REFERENCES core_repository (organization_id, id)
  DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE core_mcpproposalsubmission
  ADD CONSTRAINT mcp_submission_scope_tenant_fk
  FOREIGN KEY (organization_id, access_scope_id)
  REFERENCES core_accessscope (organization_id, id)
  DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE core_mcpproposalsubmission
  ADD CONSTRAINT mcp_submission_proposal_tenant_fk
  FOREIGN KEY (organization_id, knowledge_proposal_id)
  REFERENCES core_knowledgeproposal (organization_id, id)
  DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE core_mcpproposalsubmission
  ADD CONSTRAINT mcp_submission_credential_tenant_repo_fk
  FOREIGN KEY (organization_id, repository_id, credential_id)
  REFERENCES core_repositoryaccesstoken (organization_id, repository_id, id)
  DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE core_mcptoolinvocation
  ADD CONSTRAINT mcp_invocation_repository_tenant_fk
  FOREIGN KEY (organization_id, repository_id)
  REFERENCES core_repository (organization_id, id)
  DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE core_mcptoolinvocation
  ADD CONSTRAINT mcp_invocation_credential_tenant_repo_fk
  FOREIGN KEY (organization_id, repository_id, credential_id)
  REFERENCES core_repositoryaccesstoken (organization_id, repository_id, id)
  DEFERRABLE INITIALLY DEFERRED;
"""
DROP_SAME_TENANT_SQL = """
ALTER TABLE core_mcptoolinvocation
  DROP CONSTRAINT IF EXISTS mcp_invocation_credential_tenant_repo_fk;
ALTER TABLE core_mcptoolinvocation
  DROP CONSTRAINT IF EXISTS mcp_invocation_repository_tenant_fk;
ALTER TABLE core_mcpproposalsubmission
  DROP CONSTRAINT IF EXISTS mcp_submission_credential_tenant_repo_fk;
ALTER TABLE core_mcpproposalsubmission
  DROP CONSTRAINT IF EXISTS mcp_submission_proposal_tenant_fk;
ALTER TABLE core_mcpproposalsubmission
  DROP CONSTRAINT IF EXISTS mcp_submission_scope_tenant_fk;
ALTER TABLE core_mcpproposalsubmission
  DROP CONSTRAINT IF EXISTS mcp_submission_repository_tenant_fk;
"""
IMMUTABILITY_SQL = """
CREATE FUNCTION core_reject_mcp_audit_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is immutable', TG_TABLE_NAME USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER mcp_submission_immutable
BEFORE UPDATE OR DELETE ON core_mcpproposalsubmission
FOR EACH ROW EXECUTE FUNCTION core_reject_mcp_audit_change();
CREATE TRIGGER mcp_invocation_immutable
BEFORE UPDATE OR DELETE ON core_mcptoolinvocation
FOR EACH ROW EXECUTE FUNCTION core_reject_mcp_audit_change();
"""
DROP_IMMUTABILITY_SQL = """
DROP TRIGGER IF EXISTS mcp_invocation_immutable ON core_mcptoolinvocation;
DROP TRIGGER IF EXISTS mcp_submission_immutable ON core_mcpproposalsubmission;
DROP FUNCTION IF EXISTS core_reject_mcp_audit_change();
"""


class Migration(migrations.Migration):
    dependencies: ClassVar[list[tuple[str, str]]] = [
        ("core", "0012_github_app_adapter"),
    ]

    operations: ClassVar[list[migrations.operations.base.Operation]] = [
        migrations.CreateModel(
            name="MCPProposalSubmission",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False
                    ),
                ),
                (
                    "proposal_kind",
                    models.CharField(
                        choices=[
                            ("CORRECTION", "Correction"),
                            ("RELATIONSHIP", "Relationship"),
                            ("DECISION", "Decision"),
                            ("WORK_SUMMARY", "Work Summary"),
                            ("PREFLIGHT_SUMMARY", "Preflight Summary"),
                        ],
                        max_length=32,
                    ),
                ),
                ("actor_type", models.CharField(max_length=20)),
                ("actor_id", models.CharField(max_length=200)),
                ("payload_hash", models.CharField(max_length=64)),
                ("idempotency_hash", models.CharField(max_length=64)),
                (
                    "created_at",
                    models.DateTimeField(default=django.utils.timezone.now, editable=False),
                ),
                (
                    "access_scope",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="core.accessscope"
                    ),
                ),
                (
                    "credential",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        to="core.repositoryaccesstoken",
                    ),
                ),
                (
                    "knowledge_proposal",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT, to="core.knowledgeproposal"
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="core.organization"
                    ),
                ),
                (
                    "repository",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="core.repository"
                    ),
                ),
            ],
            options={
                "constraints": [
                    models.UniqueConstraint(
                        fields=("organization", "id"), name="core_mcp_submission_org_id_unique"
                    ),
                    models.UniqueConstraint(
                        fields=("organization", "repository", "idempotency_hash"),
                        name="core_mcp_submission_idempotent_unique",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("payload_hash__regex", "^[a-f0-9]{64}$")),
                        name="core_mcp_submission_payload_sha256",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("idempotency_hash__regex", "^[a-f0-9]{64}$")),
                        name="core_mcp_submission_key_sha256",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="MCPToolInvocation",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False
                    ),
                ),
                ("actor_type", models.CharField(max_length=20)),
                ("actor_id", models.CharField(max_length=200)),
                ("transport", models.CharField(max_length=16)),
                ("tool_name", models.CharField(max_length=100)),
                ("required_action", models.CharField(max_length=100)),
                ("arguments_hash", models.CharField(max_length=64)),
                ("request_id", models.UUIDField()),
                (
                    "outcome",
                    models.CharField(
                        choices=[("SUCCEEDED", "Succeeded"), ("FAILED", "Failed")], max_length=16
                    ),
                ),
                ("error_code", models.CharField(blank=True, max_length=100)),
                ("target_id", models.UUIDField(blank=True, null=True)),
                (
                    "created_at",
                    models.DateTimeField(default=django.utils.timezone.now, editable=False),
                ),
                (
                    "credential",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        to="core.repositoryaccesstoken",
                    ),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="core.organization"
                    ),
                ),
                (
                    "repository",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT, to="core.repository"
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(
                        fields=["organization", "repository", "created_at"],
                        name="core_mcp_audit_repo_idx",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("organization", "id"), name="core_mcp_invocation_org_id_unique"
                    ),
                    models.UniqueConstraint(
                        fields=("organization", "request_id"),
                        name="core_mcp_invocation_request_unique",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(("arguments_hash__regex", "^[a-f0-9]{64}$")),
                        name="core_mcp_invocation_args_sha256",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            models.Q(("error_code", ""), ("outcome", "SUCCEEDED")),
                            models.Q(("error_code__gt", ""), ("outcome", "FAILED")),
                            _connector="OR",
                        ),
                        name="core_mcp_invocation_outcome_coherent",
                    ),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="repositoryaccesstoken",
            constraint=models.UniqueConstraint(
                fields=("organization", "repository", "id"),
                name="core_repository_token_org_repo_id_unique",
            ),
        ),
        migrations.RunSQL(SAME_TENANT_SQL, DROP_SAME_TENANT_SQL),
        migrations.RunSQL(IMMUTABILITY_SQL, DROP_IMMUTABILITY_SQL),
    ]
