import json
from datetime import datetime, timedelta, timezone

import django.db.models.deletion
from django.db import migrations, models
from django_celery_beat.models import PeriodicTask

from api.db_utils import rls_transaction
from api.models import Scan, StateChoices


def migrate_daily_scheduled_scan_tasks(apps, schema_editor):

    for daily_scheduled_scan_task in PeriodicTask.objects.filter(
        task="scan-perform-scheduled"
    ):
        task_kwargs = json.loads(daily_scheduled_scan_task.kwargs)
        tenant_id = task_kwargs["tenant_id"]
        provider_id = task_kwargs["provider_id"]

        next_scan_date = datetime.combine(
            datetime.now(timezone.utc), daily_scheduled_scan_task.start_time.time()
        ) + timedelta(hours=24)

        with rls_transaction(tenant_id):
            scheduled_scan = Scan.objects.create(
                tenant_id=tenant_id,
                name="Daily scheduled scan",
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.SCHEDULED,
                next_scan_at=next_scan_date,
                scheduler_task_id=daily_scheduled_scan_task.id,
            )

        daily_scheduled_scan_task.kwargs = json.dumps(
            {"tenant_id": tenant_id, "scan_id": str(scheduled_scan.id)}
        )
        daily_scheduled_scan_task.save()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0006_findings_first_seen"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="scheduler_task",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                to="django_celery_beat.periodictask",
            ),
        ),
        migrations.RunPython(migrate_daily_scheduled_scan_tasks),
    ]
