from typing import ClassVar

from django.contrib.postgres.operations import CryptoExtension
from django.db import migrations

FORWARD_SQL = """
CREATE FUNCTION core_canonical_jsonb(value jsonb) RETURNS text AS $$
    SELECT CASE jsonb_typeof(value)
        WHEN 'object' THEN COALESCE(
            (
                SELECT '{' || string_agg(
                    to_jsonb(item.key)::text || ':' || core_canonical_jsonb(item.value),
                    ',' ORDER BY item.key
                ) || '}'
                FROM jsonb_each(value) AS item
            ),
            '{}'
        )
        WHEN 'array' THEN COALESCE(
            (
                SELECT '[' || string_agg(
                    core_canonical_jsonb(item.value),
                    ',' ORDER BY item.ordinality
                ) || ']'
                FROM jsonb_array_elements(value) WITH ORDINALITY AS item(value, ordinality)
            ),
            '[]'
        )
        ELSE value::text
    END;
$$ LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION core_ingestion_jsonb_sha256(value jsonb) RETURNS text AS $$
    SELECT encode(
        digest(convert_to(core_canonical_jsonb(value), 'UTF8'), 'sha256'),
        'hex'
    );
$$ LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION core_validate_source_content() RETURNS trigger AS $$
BEGIN
    IF NEW.byte_size <> octet_length(NEW.content) THEN
        RAISE EXCEPTION 'source content byte size does not match bytes'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.content_hash <> encode(digest(NEW.content, 'sha256'), 'hex') THEN
        RAISE EXCEPTION 'source content hash does not match bytes'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION core_validate_parsed_source() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM core_sourcerevision revision
          JOIN core_sourcedocument document
            ON document.id = revision.source_document_id
           AND document.organization_id = revision.organization_id
         WHERE revision.id = NEW.source_revision_id
           AND revision.organization_id = NEW.organization_id
           AND document.document_kind = NEW.document_kind
    ) THEN
        RAISE EXCEPTION 'parser output kind does not match source document'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.output_hash <> core_ingestion_jsonb_sha256(NEW.normalized) THEN
        RAISE EXCEPTION 'parsed source hash does not match normalized output'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION core_validate_source_chunk() RETURNS trigger AS $$
BEGIN
    IF NEW.char_count <> char_length(NEW.text) THEN
        RAISE EXCEPTION 'source chunk character count does not match text'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.content_hash <> encode(
        digest(convert_to(NEW.text, 'UTF8'), 'sha256'),
        'hex'
    ) THEN
        RAISE EXCEPTION 'source chunk hash does not match text'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION core_validate_extraction_result() RETURNS trigger AS $$
BEGIN
    IF NEW.output_hash <> core_ingestion_jsonb_sha256(NEW.claims) THEN
        RAISE EXCEPTION 'extraction result hash does not match claims'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER extractionresult_validate
BEFORE INSERT ON core_extractionresult
FOR EACH ROW EXECUTE FUNCTION core_validate_extraction_result();
"""


REVERSE_SQL = """
DROP TRIGGER IF EXISTS extractionresult_validate ON core_extractionresult;
DROP FUNCTION IF EXISTS core_validate_extraction_result();

CREATE OR REPLACE FUNCTION core_validate_source_content() RETURNS trigger AS $$
BEGIN
    IF NEW.byte_size <> octet_length(NEW.content) THEN
        RAISE EXCEPTION 'source content byte size does not match bytes'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION core_validate_parsed_source() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM core_sourcerevision revision
          JOIN core_sourcedocument document
            ON document.id = revision.source_document_id
           AND document.organization_id = revision.organization_id
         WHERE revision.id = NEW.source_revision_id
           AND revision.organization_id = NEW.organization_id
           AND document.document_kind = NEW.document_kind
    ) THEN
        RAISE EXCEPTION 'parser output kind does not match source document'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION core_validate_source_chunk() RETURNS trigger AS $$
BEGIN
    IF NEW.char_count <> char_length(NEW.text) THEN
        RAISE EXCEPTION 'source chunk character count does not match text'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS core_ingestion_jsonb_sha256(jsonb);
DROP FUNCTION IF EXISTS core_canonical_jsonb(jsonb);
"""


class Migration(migrations.Migration):
    dependencies: ClassVar[list[tuple[str, str]]] = [
        ("core", "0004_chunks_and_relationships"),
    ]

    operations: ClassVar[list[migrations.operations.base.Operation]] = [
        CryptoExtension(),
        migrations.RunSQL(sql=FORWARD_SQL, reverse_sql=REVERSE_SQL),
    ]
