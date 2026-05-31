from django.db import migrations


class Migration(migrations.Migration):
    """Rebuild the partial unique index on `providers` after the enum-to-varchar
    contract in 0096 dropped it along with the old enum column.

    Built with CREATE INDEX CONCURRENTLY (hence `atomic = False`) so the rebuild
    holds no long write lock on a large table. The index keeps the name and
    predicate Django expects for the existing `unique_provider_uids` constraint,
    which stays in the model state untouched, so no state operation is needed.
    """

    atomic = False

    dependencies = [
        ("api", "0096_provider_enum_to_varchar_contract"),
    ]

    operations = [
        migrations.RunSQL(
            sql=(
                "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS unique_provider_uids "
                "ON providers (tenant_id, provider, uid) WHERE NOT is_deleted;"
            ),
            reverse_sql="DROP INDEX CONCURRENTLY IF EXISTS unique_provider_uids;",
        ),
    ]
