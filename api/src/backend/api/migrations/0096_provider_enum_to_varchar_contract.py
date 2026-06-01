from django.db import migrations, models


class Migration(migrations.Migration):
    """Contract step: promote `provider_str` into `provider`.

    Drops the trigger and enum column, renames the shadow column, sets it NOT
    NULL, and drops the enum type. The unique index is dropped and recreated in
    the same transaction, so there is no window for duplicate active providers;
    recreated non-concurrently since the table is small, with a short
    lock_timeout so the migration fails fast instead of queueing behind a
    long-running transaction.
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
                        "SET LOCAL lock_timeout = '10s';\n"
                        "DROP TRIGGER IF EXISTS providers_sync_provider_str ON providers;\n"
                        "DROP FUNCTION IF EXISTS sync_provider_str();\n"
                        "DROP INDEX IF EXISTS unique_provider_uids;\n"
                        "ALTER TABLE providers DROP COLUMN provider;\n"
                        "ALTER TABLE providers RENAME COLUMN provider_str TO provider;\n"
                        "ALTER TABLE providers ALTER COLUMN provider SET DEFAULT 'aws';\n"
                        "ALTER TABLE providers ALTER COLUMN provider SET NOT NULL;\n"
                        "DROP TYPE provider;\n"
                        "CREATE UNIQUE INDEX unique_provider_uids ON providers "
                        "(tenant_id, provider, uid) WHERE NOT is_deleted;"
                    ),
                    reverse_sql=migrations.RunSQL.noop,
                ),
            ],
        ),
    ]
