from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0024_findings_uid_index_partitions"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["tenant_id", "uid", "-inserted_at"],
                name="find_tenant_uid_inserted_idx",
            ),
        ),
    ]
