import json
from datetime import datetime, timedelta, timezone

from django_celery_beat.models import IntervalSchedule, PeriodicTask
from rest_framework_json_api.serializers import ValidationError
from tasks.tasks import perform_scheduled_scan_task

from api.models import Provider


def schedule_provider_scan(provider_instance: Provider):
    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=24,
        period=IntervalSchedule.HOURS,
    )

    # Create a unique name for the periodic task
    task_name = f"scan-perform-scheduled-{provider_instance.id}"

    # Schedule the task
    _, created = PeriodicTask.objects.get_or_create(
        interval=schedule,
        name=task_name,
        task="scan-perform-scheduled",
        kwargs=json.dumps(
            {
                "tenant_id": str(provider_instance.tenant_id),
                "provider_id": str(provider_instance.id),
            }
        ),
        one_off=False,
        defaults={
            "start_time": datetime.now(timezone.utc) + timedelta(hours=24),
        },
    )
    if not created:
        raise ValidationError(
            [
                {
                    "detail": "There is already a scheduled scan for this provider.",
                    "status": 400,
                    "source": {"pointer": "/data/attributes/provider_id"},
                    "code": "invalid",
                }
            ]
        )

    return perform_scheduled_scan_task.apply_async(
        kwargs={
            "tenant_id": str(provider_instance.tenant_id),
            "provider_id": str(provider_instance.id),
        },
    )
