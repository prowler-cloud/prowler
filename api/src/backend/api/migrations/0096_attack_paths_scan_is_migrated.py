# TODO: drop after Neptune cutover
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0095_reconcile_orphan_tasks_periodic_task"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackpathsscan",
            name="is_migrated",
            field=models.BooleanField(default=False),
        ),
    ]
