from typing import ClassVar

from django.db import migrations

PROPOSAL_IMMUTABILITY_SQL = """
CREATE FUNCTION core_guard_knowledge_proposal_change() RETURNS trigger AS $$
DECLARE
    lifecycle_id text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'core_knowledgeproposal is immutable' USING ERRCODE = '23514';
    END IF;

    lifecycle_id := current_setting('anva.knowledge_proposal_lifecycle_id', true);
    IF lifecycle_id IS DISTINCT FROM OLD.id::text THEN
        RAISE EXCEPTION 'knowledge proposal updates require the lifecycle service'
            USING ERRCODE = '23514';
    END IF;
    PERFORM set_config('anva.knowledge_proposal_lifecycle_id', '', true);

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.summary IS DISTINCT FROM OLD.summary
       OR NEW.proposed_changes IS DISTINCT FROM OLD.proposed_changes
       OR NEW.anva_sources IS DISTINCT FROM OLD.anva_sources
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'knowledge proposal content is immutable' USING ERRCODE = '23514';
    END IF;

    IF NEW.state IS NOT DISTINCT FROM OLD.state
       OR NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
        RAISE EXCEPTION 'knowledge proposal lifecycle update is invalid'
            USING ERRCODE = '23514';
    END IF;

    IF NOT (
        (OLD.state = 'PROPOSED' AND NEW.state IN ('VALIDATING', 'FAILED'))
        OR (
            OLD.state = 'VALIDATING'
            AND NEW.state IN ('AWAITING_REVIEW', 'REJECTED', 'FAILED')
        )
        OR (
            OLD.state = 'AWAITING_REVIEW'
            AND NEW.state IN ('ACCEPTED', 'REJECTED', 'FAILED')
        )
        OR (OLD.state IN ('ACCEPTED', 'REJECTED') AND NEW.state = 'SUPERSEDED')
    ) THEN
        RAISE EXCEPTION 'knowledge proposal state transition is invalid'
            USING ERRCODE = '23514';
    END IF;

    IF (
        NEW.state IN ('ACCEPTED', 'REJECTED', 'SUPERSEDED', 'FAILED')
        AND NEW.decided_at IS NULL
    ) OR (
        NEW.state IN ('PROPOSED', 'VALIDATING', 'AWAITING_REVIEW')
        AND NEW.decided_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'knowledge proposal decision timestamp is invalid'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER knowledge_proposal_lifecycle_guard
BEFORE UPDATE OR DELETE ON core_knowledgeproposal
FOR EACH ROW EXECUTE FUNCTION core_guard_knowledge_proposal_change();
"""

DROP_PROPOSAL_IMMUTABILITY_SQL = """
DROP TRIGGER IF EXISTS knowledge_proposal_lifecycle_guard ON core_knowledgeproposal;
DROP FUNCTION IF EXISTS core_guard_knowledge_proposal_change();
"""


class Migration(migrations.Migration):
    dependencies: ClassVar[list[tuple[str, str]]] = [
        ("core", "0013_mcpproposalsubmission_mcptoolinvocation"),
    ]

    operations: ClassVar[list[migrations.operations.base.Operation]] = [
        migrations.RunSQL(
            PROPOSAL_IMMUTABILITY_SQL,
            DROP_PROPOSAL_IMMUTABILITY_SQL,
        ),
    ]
