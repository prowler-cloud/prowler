from functools import partial

from django.db import connection, migrations


def create_index_on_partitions(
    apps, schema_editor, parent_table: str, index_name: str, index_details: str
):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT inhrelid::regclass::text
            FROM pg_inherits
            WHERE inhparent = %s::regclass;
        """,
            [parent_table],
        )
        partitions = [row[0] for row in cursor.fetchall()]
    # Iterate over partitions and create index concurrently.
    # Note: PostgreSQL does not allow CONCURRENTLY inside a transaction,
    # so we need atomic = False for this migration.
    for partition in partitions:
        sql = (
            f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {partition.replace('.', '_')}_{index_name} ON {partition} "
            f"{index_details};"
        )
        schema_editor.execute(sql)


def drop_index_on_partitions(apps, schema_editor, parent_table: str, index_name: str):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT inhrelid::regclass::text
            FROM pg_inherits
            WHERE inhparent = %s::regclass;
        """,
            [parent_table],
        )
        partitions = [row[0] for row in cursor.fetchall()]

    # Iterate over partitions and drop index concurrently.
    for partition in partitions:
        partition_index = f"{partition.replace('.', '_')}_{index_name}"
        sql = f"DROP INDEX CONCURRENTLY IF EXISTS {partition_index};"
        schema_editor.execute(sql)


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0009_increase_provider_uid_maximum_length"),
    ]

    operations = [
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="findings_tenant_and_id_idx",
                index_details="(tenant_id, id)",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="findings_tenant_and_id_idx",
            ),
        ),
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_idx",
                index_details="(tenant_id, scan_id)",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_idx",
            ),
        ),
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_id_idx",
                index_details="(tenant_id, scan_id, id)",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_tenant_scan_id_idx",
            ),
        ),
        migrations.RunPython(
            partial(
                create_index_on_partitions,
                parent_table="findings",
                index_name="find_delta_new_idx",
                index_details="(tenant_id, id) where delta = 'new'",
            ),
            reverse_code=partial(
                drop_index_on_partitions,
                parent_table="findings",
                index_name="find_delta_new_idx",
            ),
        ),
    ]
