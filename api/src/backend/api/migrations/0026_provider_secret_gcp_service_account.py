from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0025_findings_uid_index_parent"),
    ]

    operations = [
        migrations.RunSQL(
            "ALTER TYPE provider_secret_type ADD VALUE IF NOT EXISTS 'service_account';",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
