import json
from datetime import datetime, timedelta, timezone

import django.db.models.deletion
from django.db import migrations, models
from django.utils.timezone import make_aware
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

        current_time = datetime.now(timezone.utc)
        scheduled_time_today = make_aware(
            datetime.combine(
                current_time.date(),
                daily_scheduled_scan_task.start_time.time(),
                tzinfo=timezone.utc,
            )
        )

        if current_time < scheduled_time_today:
            next_scan_date = scheduled_time_today
        else:
            next_scan_date = scheduled_time_today + timedelta(days=1)

        with rls_transaction(tenant_id):
            Scan.objects.create(
                tenant_id=tenant_id,
                name="Daily scheduled scan",
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.SCHEDULED,
                scheduled_at=next_scan_date,
                scheduler_task_id=daily_scheduled_scan_task.id,
            )


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
