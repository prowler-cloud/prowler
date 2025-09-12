from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0010_findings_performance_indexes_partitions"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["tenant_id", "id"], name="findings_tenant_and_id_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["tenant_id", "scan_id"], name="find_tenant_scan_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                fields=["tenant_id", "scan_id", "id"], name="find_tenant_scan_id_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="finding",
            index=models.Index(
                condition=models.Q(("delta", "new")),
                fields=["tenant_id", "id"],
                name="find_delta_new_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="resourcetagmapping",
            index=models.Index(
                fields=["tenant_id", "resource_id"], name="resource_tag_tenant_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="resource",
            index=models.Index(
                fields=["tenant_id", "service", "region", "type"],
                name="resource_tenant_metadata_idx",
            ),
        ),
    ]
