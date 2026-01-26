import json
from datetime import datetime, timedelta, timezone
from enum import Enum

from django_celery_beat.models import PeriodicTask
from django_celery_results.models import TaskResult

from api.models import Scan, StateChoices

SCHEDULED_SCAN_NAME = "Daily scheduled scan"


class CustomEncoder(json.JSONEncoder):
    def default(self, o):
        # Enum serialization
        if isinstance(o, Enum):
            return o.value
        # Datetime and timedelta serialization
        if isinstance(o, datetime):
            return o.isoformat(timespec="seconds")
        if isinstance(o, timedelta):
            return o.total_seconds()

        # Custom object serialization
        try:
            return super().default(o)
        except TypeError:
            try:
                return o.__dict__
            except AttributeError:
                return str(o)


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


def batched(iterable, batch_size):
    """
    Yield successive batches from an iterable.

    Args:
        iterable: An iterable source of items.
        batch_size (int): The number of items per batch.

    Yields:
        tuple: A pair (batch, is_last_batch) where:
            - batch (list): A list of items (with length equal to batch_size,
              except possibly for the last batch).
            - is_last_batch (bool): True if this is the final batch, False otherwise.
    """
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) == batch_size:
            yield batch, False
            batch = []

    yield batch, True


def _get_or_create_scheduled_scan(
    tenant_id: str,
    provider_id: str,
    scheduler_task_id: int,
    scheduled_at: datetime,
    update_state: bool = False,
) -> Scan:
    """
    Get or create a scheduled scan, cleaning up duplicates if found.

    Args:
        tenant_id: The tenant ID.
        provider_id: The provider ID.
        scheduler_task_id: The PeriodicTask ID.
        scheduled_at: The scheduled datetime for the scan.
        update_state: If True, also reset state to SCHEDULED when updating.

    Returns:
        The scan instance to use.
    """
    scheduled_scans = list(
        Scan.objects.filter(
            tenant_id=tenant_id,
            provider_id=provider_id,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
            scheduler_task_id=scheduler_task_id,
        ).order_by("scheduled_at", "inserted_at")
    )

    if scheduled_scans:
        scan_instance = scheduled_scans[0]
        if len(scheduled_scans) > 1:
            Scan.objects.filter(id__in=[s.id for s in scheduled_scans[1:]]).delete()
        needs_update = scan_instance.scheduled_at != scheduled_at
        if update_state and scan_instance.state != StateChoices.SCHEDULED:
            scan_instance.state = StateChoices.SCHEDULED
            scan_instance.name = SCHEDULED_SCAN_NAME
            needs_update = True
        if needs_update:
            scan_instance.scheduled_at = scheduled_at
            scan_instance.save()
        return scan_instance

    return Scan.objects.create(
        tenant_id=tenant_id,
        name=SCHEDULED_SCAN_NAME,
        provider_id=provider_id,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.SCHEDULED,
        scheduled_at=scheduled_at,
        scheduler_task_id=scheduler_task_id,
    )
