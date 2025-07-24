from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0040_rfm_tenant_resource_index_partitions"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="resourcefindingmapping",
            index=models.Index(
                fields=["tenant_id", "resource_id"],
                name="rfm_tenant_resource_idx",
            ),
        ),
    ]
