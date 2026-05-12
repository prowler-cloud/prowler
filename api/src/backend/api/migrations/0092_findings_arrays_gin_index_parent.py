import django.contrib.postgres.indexes
from django.db import migrations

INDEX_NAME = "gin_find_arrays_idx"
PARENT_TABLE = "findings"


def create_parent_and_attach(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        # Idempotent: the parent index may already exist if it was created
        # manually on an environment before this migration ran.
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS {INDEX_NAME} ON ONLY {PARENT_TABLE} "
            f"USING gin (categories, resource_services, resource_regions, resource_types)"
        )
        cursor.execute(
            "SELECT inhrelid::regclass::text "
            "FROM pg_inherits "
            "WHERE inhparent = %s::regclass",
            [PARENT_TABLE],
        )
        for (partition,) in cursor.fetchall():
            child_idx = f"{partition.replace('.', '_')}_{INDEX_NAME}"
            # ALTER INDEX ... ATTACH PARTITION has no IF NOT ATTACHED clause,
            # so check pg_inherits first to keep the migration re-runnable.
            cursor.execute(
                """
                SELECT 1
                FROM pg_inherits i
                JOIN pg_class p ON p.oid = i.inhparent
                JOIN pg_class c ON c.oid = i.inhrelid
                WHERE p.relname = %s AND c.relname = %s
                """,
                [INDEX_NAME, child_idx],
            )
            if cursor.fetchone() is None:
                cursor.execute(
                    f"ALTER INDEX {INDEX_NAME} ATTACH PARTITION {child_idx}"
                )


def drop_parent_index(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(f"DROP INDEX IF EXISTS {INDEX_NAME}")


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0091_findings_arrays_gin_index_partitions"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AddIndex(
                    model_name="finding",
                    index=django.contrib.postgres.indexes.GinIndex(
                        fields=[
                            "categories",
                            "resource_services",
                            "resource_regions",
                            "resource_types",
                        ],
                        name=INDEX_NAME,
                    ),
                ),
            ],
            database_operations=[
                migrations.RunPython(
                    create_parent_and_attach,
                    reverse_code=drop_parent_index,
                ),
            ],
        ),
    ]
