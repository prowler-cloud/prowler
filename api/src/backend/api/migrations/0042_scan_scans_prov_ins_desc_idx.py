from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0041_rfm_tenant_resource_parent_partitions"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="scan",
            index=models.Index(
                condition=models.Q(("state", "completed")),
                fields=["tenant_id", "provider_id", "-inserted_at"],
                include=("id",),
                name="scans_prov_ins_desc_idx",
            ),
        ),
    ]
