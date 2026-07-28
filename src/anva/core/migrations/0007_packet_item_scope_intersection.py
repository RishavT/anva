from typing import ClassVar

import django.db.models.deletion
from django.db import migrations, models

POPULATE_LEGACY_SCOPE_SQL = """
ALTER TABLE core_contextpacketitem DISABLE TRIGGER packetitem_immutable;
UPDATE core_contextpacketitem item
   SET access_scope_id = packet.access_scope_id
  FROM core_contextpacketrecord packet
 WHERE packet.id = item.context_packet_id
   AND packet.organization_id = item.organization_id;
ALTER TABLE core_contextpacketitem ENABLE TRIGGER packetitem_immutable;
"""

ITEM_SCOPE_TENANT_SQL = """
ALTER TABLE core_contextpacketitem
ADD CONSTRAINT packetitem_scope_tenant_fk
FOREIGN KEY (organization_id, access_scope_id)
REFERENCES core_accessscope (organization_id, id)
DEFERRABLE INITIALLY DEFERRED;
"""

DROP_ITEM_SCOPE_TENANT_SQL = """
ALTER TABLE core_contextpacketitem
DROP CONSTRAINT IF EXISTS packetitem_scope_tenant_fk;
"""

INVALIDATE_LEGACY_PACKETS_SQL = """
INSERT INTO core_retrievalwatermark (
    id,
    created_at,
    updated_at,
    revision,
    value,
    reason,
    organization_id,
    repository_id
)
SELECT
    gen_random_uuid(),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    1,
    1,
    'INITIAL',
    packet.organization_id,
    packet.repository_id
FROM core_contextpacketrecord packet
WHERE NOT EXISTS (
    SELECT 1
    FROM core_retrievalwatermark watermark
    WHERE watermark.organization_id = packet.organization_id
      AND watermark.repository_id = packet.repository_id
)
GROUP BY packet.organization_id, packet.repository_id;

UPDATE core_retrievalwatermark watermark
   SET value = watermark.value + 1,
       revision = watermark.revision + 1,
       reason = 'SCOPE_CHANGE',
       updated_at = CURRENT_TIMESTAMP
 WHERE EXISTS (
    SELECT 1
    FROM core_contextpacketrecord packet
    WHERE packet.organization_id = watermark.organization_id
      AND packet.repository_id = watermark.repository_id
);

INSERT INTO core_contextpacketinvalidation (
    id,
    organization_id,
    context_packet_id,
    repository_id,
    reason,
    watermark,
    details,
    invalidated_at
)
SELECT
    gen_random_uuid(),
    packet.organization_id,
    packet.id,
    packet.repository_id,
    'SCOPE_CHANGE',
    watermark.value,
    '{"migration":"0007_packet_item_scope_intersection"}'::jsonb,
    CURRENT_TIMESTAMP
FROM core_contextpacketrecord packet
JOIN core_retrievalwatermark watermark
  ON watermark.organization_id = packet.organization_id
 AND watermark.repository_id = packet.repository_id
WHERE NOT EXISTS (
    SELECT 1
    FROM core_contextpacketinvalidation invalidation
    WHERE invalidation.organization_id = packet.organization_id
      AND invalidation.context_packet_id = packet.id
);
"""

VALIDATE_ITEM_SCOPE_SQL = """
CREATE OR REPLACE FUNCTION core_validate_context_packet_item() RETURNS trigger AS $$
BEGIN
    IF NEW.content_hash <> core_ingestion_jsonb_sha256(NEW.payload) THEN
        RAISE EXCEPTION 'context packet item hash does not match payload'
            USING ERRCODE = '23514';
    END IF;
    IF (
        NEW.kind IN ('POLICY', 'ASSERTION', 'DECISION', 'INCIDENT')
        AND NEW.source_assertion_id IS NULL
    ) OR (
        NEW.kind = 'RELATIONSHIP' AND NEW.source_relationship_id IS NULL
    ) OR (
        NEW.kind = 'SOURCE_EXCERPT' AND NEW.source_chunk_id IS NULL
    ) OR (
        NEW.kind = 'CONFLICT' AND NEW.source_conflict_id IS NULL
    ) THEN
        RAISE EXCEPTION 'context packet item source type is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM core_accessscope item_scope
         WHERE item_scope.id = NEW.access_scope_id
           AND item_scope.organization_id = NEW.organization_id
           AND item_scope.is_active
           AND item_scope.is_derived
           AND item_scope.boundary_sealed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'context packet item scope must be an active sealed intersection'
            USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM core_contextpacketrecord packet
          JOIN core_accessscope_derived_from parent
            ON parent.from_accessscope_id = packet.access_scope_id
           AND parent.to_accessscope_id = NEW.access_scope_id
         WHERE packet.id = NEW.context_packet_id
           AND packet.organization_id = NEW.organization_id
    ) THEN
        RAISE EXCEPTION 'context packet scope must derive from every item scope'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

RESTORE_ITEM_VALIDATION_SQL = """
CREATE OR REPLACE FUNCTION core_validate_context_packet_item() RETURNS trigger AS $$
BEGIN
    IF NEW.content_hash <> core_ingestion_jsonb_sha256(NEW.payload) THEN
        RAISE EXCEPTION 'context packet item hash does not match payload'
            USING ERRCODE = '23514';
    END IF;
    IF (
        NEW.kind IN ('POLICY', 'ASSERTION', 'DECISION', 'INCIDENT')
        AND NEW.source_assertion_id IS NULL
    ) OR (
        NEW.kind = 'RELATIONSHIP' AND NEW.source_relationship_id IS NULL
    ) OR (
        NEW.kind = 'SOURCE_EXCERPT' AND NEW.source_chunk_id IS NULL
    ) OR (
        NEW.kind = 'CONFLICT' AND NEW.source_conflict_id IS NULL
    ) THEN
        RAISE EXCEPTION 'context packet item source type is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""


class Migration(migrations.Migration):
    dependencies: ClassVar = [
        ("core", "0006_permission_safe_retrieval"),
    ]

    operations: ClassVar = [
        migrations.AddField(
            model_name="contextpacketitem",
            name="access_scope",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="core.accessscope",
            ),
        ),
        migrations.RunSQL(
            sql=POPULATE_LEGACY_SCOPE_SQL,
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.RunSQL(
            sql=INVALIDATE_LEGACY_PACKETS_SQL,
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.AlterField(
            model_name="contextpacketitem",
            name="access_scope",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                to="core.accessscope",
            ),
        ),
        migrations.RunSQL(
            sql=ITEM_SCOPE_TENANT_SQL,
            reverse_sql=DROP_ITEM_SCOPE_TENANT_SQL,
        ),
        migrations.RunSQL(
            sql=VALIDATE_ITEM_SCOPE_SQL,
            reverse_sql=RESTORE_ITEM_VALIDATION_SQL,
        ),
    ]
