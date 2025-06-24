from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0033_rfm_tenant_finding_index_partitions"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="resourcefindingmapping",
            index=models.Index(
                fields=["tenant_id", "finding_id"],
                name="rfm_tenant_finding_idx",
            ),
        ),
    ]
