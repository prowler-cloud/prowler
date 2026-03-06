"""
Drop unused indexes on non-partitioned tables.

These tables are not partitioned, so RemoveIndexConcurrently can be used safely.
"""

from uuid import uuid4

from django.contrib.postgres.operations import RemoveIndexConcurrently
from django.db import migrations, models


def drop_resource_scan_summary_resource_id_index(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT idx_ns.nspname, idx.relname
            FROM pg_class tbl
            JOIN pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
            JOIN pg_index i ON i.indrelid = tbl.oid
            JOIN pg_class idx ON idx.oid = i.indexrelid
            JOIN pg_namespace idx_ns ON idx_ns.oid = idx.relnamespace
            JOIN pg_attribute a
                ON a.attrelid = tbl.oid
                AND a.attnum = (i.indkey::int[])[0]
            WHERE tbl_ns.nspname = ANY (current_schemas(false))
              AND tbl.relname = %s
              AND i.indnatts = 1
              AND a.attname = %s
            """,
            ["resource_scan_summaries", "resource_id"],
        )
        row = cursor.fetchone()

    if not row:
        return

    schema_name, index_name = row
    quote_name = schema_editor.connection.ops.quote_name
    qualified_name = f"{quote_name(schema_name)}.{quote_name(index_name)}"
    schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {qualified_name};")


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0071_drop_partitioned_indexes"),
    ]

    operations = [
        RemoveIndexConcurrently(
            model_name="resource",
            name="gin_resources_search_idx",
        ),
        RemoveIndexConcurrently(
            model_name="resourcetag",
            name="gin_resource_tags_search_idx",
        ),
        RemoveIndexConcurrently(
            model_name="scansummary",
            name="ss_tenant_scan_service_idx",
        ),
        RemoveIndexConcurrently(
            model_name="complianceoverview",
            name="comp_ov_cp_id_idx",
        ),
        RemoveIndexConcurrently(
            model_name="complianceoverview",
            name="comp_ov_req_fail_idx",
        ),
        RemoveIndexConcurrently(
            model_name="complianceoverview",
            name="comp_ov_cp_id_req_fail_idx",
        ),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    drop_resource_scan_summary_resource_id_index,
                    reverse_code=migrations.RunPython.noop,
                ),
            ],
            state_operations=[
                migrations.AlterField(
                    model_name="resourcescansummary",
                    name="resource_id",
                    field=models.UUIDField(default=uuid4),
                ),
            ],
        ),
    ]
