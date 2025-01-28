from datetime import datetime, timedelta, timezone

from django_celery_beat.models import PeriodicTask
from django_celery_results.models import TaskResult


def get_next_execution_datetime(task_id: int, provider_id: str) -> datetime:
    task_instance = TaskResult.objects.get(task_id=task_id)
    try:
        periodic_task_instance = PeriodicTask.objects.get(
            name=task_instance.periodic_task_name
        )
    except PeriodicTask.DoesNotExist:
        periodic_task_instance = PeriodicTask.objects.get(
            name=f"scan-perform-scheduled-{provider_id}"
        )

    interval = periodic_task_instance.interval

    current_scheduled_time = datetime.combine(
        datetime.now(timezone.utc).date(),
        task_instance.date_created.time(),
        tzinfo=timezone.utc,
    )

    return current_scheduled_time + timedelta(**{interval.period: interval.every})
