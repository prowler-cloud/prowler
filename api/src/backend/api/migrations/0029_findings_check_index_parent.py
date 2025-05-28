from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0028_findings_check_index_partitions"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["tenant_id", "scan_id", "check_id"],
                name="find_tenant_scan_check_idx",
            ),
        ),
    ]
