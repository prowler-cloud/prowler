from django.db import migrations


class Migration(migrations.Migration):
    """Synchronous backfill of the `provider_str` shadow column.

    A single UPDATE fills rows that predate the 0094 trigger. The providers
    table is small, so this is safe inline and guarantees the column is fully
    populated before 0096 sets it NOT NULL (no race with an async backfill).
    Runs on the migration connection, which is exempt from RLS.
    """

    dependencies = [
        ("api", "0094_provider_str_shadow_column"),
    ]

    operations = [
        migrations.RunSQL(
            sql=(
                "UPDATE providers SET provider_str = provider::text "
                "WHERE provider_str IS NULL;"
            ),
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
