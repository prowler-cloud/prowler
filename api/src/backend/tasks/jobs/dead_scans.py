from datetime import UTC, datetime, timedelta

from api.db_router import MainRouter
from api.models import Scan, StateChoices
from celery import states
from celery.utils.log import get_task_logger
from config.django.base import SCAN_DISPATCH_STALE_HOURS, SCAN_STALE_BACKSTOP_HOURS
from django.db.models import Q
from django_celery_results.models import TaskResult
from tasks.jobs.attack_paths.cleanup import _ping_workers as ping_workers

logger = get_task_logger(__name__)

DISPATCHED_SCAN_TASK_STATES = (states.PENDING, states.STARTED, "PROGRESS")

_TASK_STATUS = "task__task_runner_task__status"


def dead_scan_q(now: datetime) -> Q:
    """Single DB-only definition of a dead scan: it will never finish on its own."""
    backstop = now - timedelta(hours=SCAN_STALE_BACKSTOP_HOURS)
    dispatch_cutoff = now - timedelta(hours=SCAN_DISPATCH_STALE_HOURS)

    executing = Q(state=StateChoices.EXECUTING) & (
        Q(**{f"{_TASK_STATUS}__in": states.READY_STATES}) | Q(updated_at__lt=backstop)
    )
    never_started = Q(
        state__in=(StateChoices.AVAILABLE, StateChoices.SCHEDULED),
        task__isnull=False,
        **{f"{_TASK_STATUS}__in": DISPATCHED_SCAN_TASK_STATES},
        task__task_runner_task__date_created__lt=dispatch_cutoff,
    )
    return executing | never_started


def fail_unresponsive_scan_tasks() -> int:
    """Mark the task of every executing scan whose worker no longer answers as failed.

    Workers with unknown liveness (ping error), responsive workers and scans with no
    recorded worker are left alone; the latter fall to the staleness backstop.
    """
    rows = list(
        Scan.all_objects.using(MainRouter.admin_db)
        .filter(state=StateChoices.EXECUTING, task__task_runner_task__isnull=False)
        .exclude(**{f"{_TASK_STATUS}__in": states.READY_STATES})
        .exclude(task__task_runner_task__worker__isnull=True)
        .exclude(task__task_runner_task__worker="")
        .values_list("task__task_runner_task_id", "task__task_runner_task__worker")
    )
    workers = {worker for _, worker in rows}
    if not workers:
        return 0

    _, unresponsive = ping_workers(workers)
    if not unresponsive:
        return 0

    updated = (
        TaskResult.objects.using(MainRouter.admin_db)
        .filter(id__in=[task_id for task_id, worker in rows if worker in unresponsive])
        .exclude(status__in=states.READY_STATES)
        .update(status=states.FAILURE, date_done=datetime.now(UTC))
    )
    logger.warning(
        "Marked %s task(s) failed for %s unresponsive worker(s)",
        updated,
        len(unresponsive),
    )
    return updated
