from typing import ClassVar

from django.db import migrations

HISTORICAL_APPROVAL_SQL = """
CREATE OR REPLACE FUNCTION core_validate_unrevoked_manual_evidence() RETURNS trigger AS $$
DECLARE
    approval_id_value uuid;
BEGIN
    IF TG_TABLE_NAME = 'core_evidence' THEN
        approval_id_value := NEW.approval_id;
        IF approval_id_value IS NOT NULL AND EXISTS (
            SELECT 1 FROM core_approvalrevocation revocation
            WHERE revocation.organization_id = NEW.organization_id
              AND revocation.approval_id = approval_id_value
              AND revocation.revoked_at <= NEW.completed_at
        ) THEN
            RAISE EXCEPTION 'revoked approval cannot satisfy evidence'
            USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT evidence.approval_id INTO approval_id_value
        FROM core_evidence evidence
        WHERE evidence.id = NEW.evidence_id
          AND evidence.organization_id = NEW.organization_id
          AND evidence.kind = 'MANUAL_APPROVAL';
        IF approval_id_value IS NOT NULL AND EXISTS (
            SELECT 1 FROM core_approvalrevocation revocation
            WHERE revocation.organization_id = NEW.organization_id
              AND revocation.approval_id = approval_id_value
              AND revocation.revoked_at <= NEW.reference_time
        ) THEN
            RAISE EXCEPTION 'revoked approval cannot satisfy evidence'
            USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

RESTORE_CURRENT_APPROVAL_SQL = """
CREATE OR REPLACE FUNCTION core_validate_unrevoked_manual_evidence() RETURNS trigger AS $$
DECLARE
    approval_id_value uuid;
BEGIN
    IF TG_TABLE_NAME = 'core_evidence' THEN
        approval_id_value := NEW.approval_id;
        IF approval_id_value IS NOT NULL AND EXISTS (
            SELECT 1 FROM core_approvalrevocation revocation
            WHERE revocation.organization_id = NEW.organization_id
              AND revocation.approval_id = approval_id_value
        ) THEN
            RAISE EXCEPTION 'revoked approval cannot satisfy evidence'
            USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT evidence.approval_id INTO approval_id_value
        FROM core_evidence evidence
        WHERE evidence.id = NEW.evidence_id
          AND evidence.organization_id = NEW.organization_id
          AND evidence.kind = 'MANUAL_APPROVAL';
        IF approval_id_value IS NOT NULL AND EXISTS (
            SELECT 1 FROM core_approvalrevocation revocation
            WHERE revocation.organization_id = NEW.organization_id
              AND revocation.approval_id = approval_id_value
              AND revocation.revoked_at <= NEW.reference_time
        ) THEN
            RAISE EXCEPTION 'revoked approval cannot satisfy evidence'
            USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

ELIGIBILITY_SQL = """
CREATE FUNCTION core_validate_criterion_evidence_eligibility() RETURNS trigger AS $$
BEGIN
    IF NEW.assessment = 'SATISFIED' AND NOT EXISTS (
        SELECT 1
        FROM core_evidence evidence
        JOIN core_evidencemanifest manifest
          ON manifest.id = evidence.manifest_id
         AND manifest.organization_id = evidence.organization_id
        JOIN core_acceptancecriterion criterion
          ON criterion.id = NEW.criterion_id
         AND criterion.organization_id = NEW.organization_id
        LEFT JOIN core_approval approval
          ON approval.id = evidence.approval_id
         AND approval.organization_id = evidence.organization_id
        WHERE evidence.id = NEW.evidence_id
          AND evidence.organization_id = NEW.organization_id
          AND evidence.status = 'PASSED'
          AND evidence.kind = NEW.required_evidence_type
          AND evidence.criterion_codes ? criterion.code
          AND evidence.commit_sha = NEW.target_commit
          AND evidence.completed_at <= NEW.reference_time
          AND (
              evidence.retention_expires_at IS NULL
              OR evidence.retention_expires_at > NEW.reference_time
          )
          AND manifest.work_item_revision_id = criterion.work_item_revision_id
          AND manifest.access_scope_id = NEW.access_scope_id
          AND manifest.pull_request_number = NEW.pull_request_number
          AND criterion.required_evidence_types ? NEW.required_evidence_type
          AND (
              SELECT retention.state
              FROM core_evidenceretentionevent retention
              WHERE retention.organization_id = NEW.organization_id
                AND retention.evidence_id = evidence.id
                AND retention.occurred_at <= NEW.reference_time
              ORDER BY retention.occurred_at DESC, retention.id DESC
              LIMIT 1
          ) = 'ACTIVE'
          AND (
              evidence.kind <> 'MANUAL_APPROVAL'
              OR (
                  criterion.manual_approval_allowed
                  AND approval.id IS NOT NULL
                  AND approval.status = 'APPROVED'
                  AND approval.work_item_revision_id = criterion.work_item_revision_id
                  AND approval.repository_id = manifest.repository_id
                  AND approval.decided_at <= evidence.completed_at
                  AND approval.decided_at <= NEW.reference_time
                  AND (
                      approval.expires_at IS NULL
                      OR approval.expires_at > NEW.reference_time
                  )
                  AND (
                      (
                          approval.target_kind = 'WORK_ITEM_REVISION'
                          AND approval.target_key = criterion.work_item_revision_id::text
                      )
                      OR (
                          approval.target_kind = 'ACCEPTANCE_CRITERION'
                          AND approval.target_key = criterion.code
                      )
                      OR (
                          approval.target_kind = 'REQUIREMENT'
                          AND EXISTS (
                              SELECT 1
                              FROM core_requirement requirement
                              WHERE requirement.id = criterion.requirement_id
                                AND requirement.organization_id = NEW.organization_id
                                AND requirement.code = approval.target_key
                          )
                      )
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM core_approvalrevocation revocation
                      WHERE revocation.organization_id = NEW.organization_id
                        AND revocation.approval_id = approval.id
                        AND revocation.revoked_at <= NEW.reference_time
                  )
              )
          )
    ) THEN
        RAISE EXCEPTION 'criterion evidence is not eligible at reference time'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER criterionevidence_semantic_eligibility
AFTER INSERT ON core_criterionevidence
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION core_validate_criterion_evidence_eligibility();
"""

DROP_ELIGIBILITY_SQL = """
DROP TRIGGER IF EXISTS criterionevidence_semantic_eligibility
ON core_criterionevidence;
DROP FUNCTION IF EXISTS core_validate_criterion_evidence_eligibility();
"""


class Migration(migrations.Migration):
    dependencies: ClassVar = [
        ("core", "0009_governance_revocations_and_policy_expiry"),
    ]

    operations: ClassVar = [
        migrations.RunSQL(
            sql=HISTORICAL_APPROVAL_SQL,
            reverse_sql=RESTORE_CURRENT_APPROVAL_SQL,
        ),
        migrations.RunSQL(
            sql=ELIGIBILITY_SQL,
            reverse_sql=DROP_ELIGIBILITY_SQL,
        ),
    ]
