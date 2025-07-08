from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0038_resource_failed_findings_count"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="resource",
            index=models.Index(
                fields=["tenant_id", "-failed_findings_count", "id"],
                name="resources_failed_findings_idx",
            ),
        ),
    ]
