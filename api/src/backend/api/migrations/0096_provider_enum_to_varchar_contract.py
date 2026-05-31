from django.db import migrations, models


class Migration(migrations.Migration):
    """Contract step of the zero-downtime migration of Provider.provider from a
    native PostgreSQL enum to varchar.

    The shadow column added in 0094 has been kept in sync by the trigger and
    backfilled in 0095, so it now holds the value for every row. This migration
    promotes it into place: drop the trigger and the enum column, rename the
    shadow column to `provider`, and drop the orphaned enum type. The column
    name is preserved throughout, and varchar accepts the same string values
    the enum held, so app instances running the previous release keep working
    against the swapped column.

    The drop/rename runs in this migration's transaction so `provider` never
    disappears for readers. The partial unique index is dropped here and
    rebuilt concurrently in the next migration to avoid a long write lock.
    """

    dependencies = [
        ("api", "0095_backfill_provider_str"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(
                    model_name="provider",
                    name="provider_str",
                ),
                migrations.AlterField(
                    model_name="provider",
                    name="provider",
                    field=models.CharField(default="aws", max_length=50),
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql=(
                        "DROP TRIGGER IF EXISTS providers_sync_provider_str ON providers;\n"
                        "DROP FUNCTION IF EXISTS sync_provider_str();\n"
                        "DROP INDEX IF EXISTS unique_provider_uids;\n"
                        "ALTER TABLE providers DROP COLUMN provider;\n"
                        "ALTER TABLE providers RENAME COLUMN provider_str TO provider;\n"
                        "ALTER TABLE providers ALTER COLUMN provider SET DEFAULT 'aws';\n"
                        "ALTER TABLE providers ALTER COLUMN provider SET NOT NULL;\n"
                        "DROP TYPE provider;"
                    ),
                    reverse_sql=migrations.RunSQL.noop,
                ),
            ],
        ),
    ]
