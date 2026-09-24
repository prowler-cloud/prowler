from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0098_scan_cleanup_periodic_task"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="scan",
            index=models.Index(
                condition=models.Q(
                    ("state__in", ["executing", "available", "scheduled"])
                ),
                fields=["state", "tenant_id", "provider_id"],
                name="scans_non_terminal_state_idx",
            ),
        ),
    ]
