from django.db import migrations, models


class Migration(migrations.Migration):
    """Expand step of the zero-downtime migration of Provider.provider from a
    native PostgreSQL enum to varchar.

    Adds a transitional varchar shadow column `provider_str` and a trigger that
    keeps it in sync with the `provider` enum column on every INSERT/UPDATE.
    Adding a nullable column is metadata-only (no table rewrite, no long lock).
    The trigger covers writes from now on; existing rows are populated by a
    later backfill. A subsequent migration drops the enum column and renames
    `provider_str` to take its place.
    """

    dependencies = [
        ("api", "0093_okta_provider"),
    ]

    operations = [
        migrations.AddField(
            model_name="provider",
            name="provider_str",
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.RunSQL(
            sql=(
                "CREATE OR REPLACE FUNCTION sync_provider_str() RETURNS trigger AS $$\n"
                "BEGIN\n"
                "    NEW.provider_str := NEW.provider::text;\n"
                "    RETURN NEW;\n"
                "END;\n"
                "$$ LANGUAGE plpgsql;\n"
                "CREATE TRIGGER providers_sync_provider_str\n"
                "    BEFORE INSERT OR UPDATE ON providers\n"
                "    FOR EACH ROW EXECUTE FUNCTION sync_provider_str();"
            ),
            reverse_sql=(
                "DROP TRIGGER IF EXISTS providers_sync_provider_str ON providers;\n"
                "DROP FUNCTION IF EXISTS sync_provider_str();"
            ),
        ),
    ]
