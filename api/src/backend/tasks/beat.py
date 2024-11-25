import json

from django.utils import timezone
from django_celery_beat.models import PeriodicTask, IntervalSchedule

from api.models import Provider


def schedule_provider_scan(provider_instance: Provider):
    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=24,
        period=IntervalSchedule.HOURS,
    )

    # Create a unique name for the periodic task
    task_name = f"scan-perform-scheduled-{provider_instance.id}"

    # Schedule the task
    PeriodicTask.objects.create(
        interval=schedule,
        name=task_name,
        task="scan-perform-scheduled",
        kwargs=json.dumps(
            {
                "tenant_id": str(provider_instance.tenant_id),
                "provider_id": str(provider_instance.id),
            }
        ),
        start_time=provider_instance.inserted_at + timezone.timedelta(hours=24),
        one_off=False,
    )
