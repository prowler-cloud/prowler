"""Detect and recover orphaned Celery tasks.

A task is "orphaned" when its result row is non-terminal (STARTED/RECEIVED) but the
worker that was running it is gone (deploy, OOM, eviction). We tell a real orphan
from a still-running task by pinging the worker recorded on its `TaskResult`:

- worker responds  -> the task is in flight, leave it alone (never double-run);
- worker is gone   -> real orphan: mark the stale result terminal (so pending/started
  alerts clear), then re-enqueue the task from its stored name + kwargs.

This recovers only allowlisted tasks with local, proven idempotency. Celery's
`result_extended=True` gives us the stored `task_name`/`task_kwargs`/`worker` once
the task starts, but external side-effect tasks are failed instead of blindly
re-run. A small recovery cap stops a task that repeatedly kills its worker from
looping forever.

This is the shared engine behind both the periodic Beat watchdog and the
`reconcile_orphan_tasks` management command.
"""

import ast
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from celery import current_app, states
from celery.utils.log import get_task_logger
from django.db import connections

logger = get_task_logger(__name__)

# Arbitrary constant key for pg_try_advisory_lock so only one reconciliation
# runs at a time across replicas / the watchdog / the command.
ORPHAN_RECOVERY_LOCK_KEY = 0x70726F77  # "prow"

# Non-terminal states that mean "a worker had this and may have died with it".
IN_FLIGHT_STATES = (states.STARTED, states.RECEIVED)

# Scan tasks are recovered by re-running scan-perform on the EXISTING scan row,
# not by re-enqueuing the original task: re-enqueuing scan-perform-scheduled would
# hit its "a scan is already executing" guard and no-op, leaving the scan stuck.
_SCAN_TASKS = ("scan-perform", "scan-perform-scheduled")

# Tasks with proven idempotency are auto re-enqueued. Scans/summaries clear and
# rewrite their own rows. integration-jira is safe too: each finding is reserved in
# JiraIssueDispatch before the external call, so a re-run skips already-ticketed
# findings (worst case one finding missed on a mid-send crash, never a duplicate).
# Other external side effects stay terminal: integration-s3 rebuilds its upload from
# worker-local files that do not survive a crash, and report/Security Hub recovery is
# out of scope.
REENQUEUEABLE_TASKS = {
    *_SCAN_TASKS,
    "provider-deletion",
    "tenant-deletion",
    "scan-summary",
    "scan-compliance-overviews",
    "scan-provider-compliance-scores",
    "scan-daily-severity",
    "scan-finding-group-summaries",
    "scan-reset-ephemeral-resources",
    "integration-jira",
}

# Tasks excluded from generic recovery: attack-paths scans are handled by their own
# stale-cleanup (which also drops the temp Neo4j db), and the maintenance tasks must
# not self-recover (they run again on their own schedule).
_SKIP_RECOVERY = {
    "attack-paths-scan-perform",
    "attack-paths-cleanup-stale-scans",
    "reconcile-orphan-tasks",
}


@contextmanager
def advisory_lock(key: int = ORPHAN_RECOVERY_LOCK_KEY, using: str = "default"):
    """Yield True if this session won a Postgres advisory lock, else False.

    Non-blocking: losers get False and should no-op. The lock is released on
    exit (and implicitly if the session dies).
    """
    with connections[using].cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [key])
        acquired = bool(cursor.fetchone()[0])
        try:
            yield acquired
        finally:
            if acquired:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [key])


def is_worker_alive(worker: str, timeout: float = 1.0) -> bool:
    """Ping a specific Celery worker. Returns True if it responds, or on error.

    Erring on the side of "alive" means an unreachable control bus never causes
    a still-running task to be re-enqueued.
    """
    try:
        response = current_app.control.inspect(
            destination=[worker], timeout=timeout
        ).ping()
        return response is not None and worker in response
    except Exception:
        logger.exception(f"Failed to ping worker {worker}, treating as alive")
        return True


def revoke_task(task_result, terminate: bool = True) -> None:
    """Revoke a Celery task by its TaskResult. Non-fatal on failure.

    terminate=True SIGTERMs the worker if the task is mid-execution; terminate=False
    only marks the id revoked so any worker pulling the queued message discards it
    (use before re-enqueuing, so a later broker redelivery of the stale message is
    dropped).
    """
    try:
        kwargs = {"terminate": True, "signal": "SIGTERM"} if terminate else {}
        current_app.control.revoke(task_result.task_id, **kwargs)
        logger.info(f"Revoked task {task_result.task_id}")
    except Exception:
        logger.exception(f"Failed to revoke task {task_result.task_id}")


def _decode_celery_field(value, default):
    """Decode django-celery-results' stored task_args/task_kwargs to a Python object.

    The backend stores them as a (sometimes double-encoded) repr/JSON string. An
    empty or missing field returns ``default``; a non-empty value that cannot be
    decoded raises ``ValueError`` so the caller can avoid re-enqueuing a task with
    the wrong arguments.
    """
    obj = value
    for _ in range(2):  # values can be double-encoded (a string holding a repr)
        if not isinstance(obj, str):
            break
        text = obj.strip()
        if not text:
            return default
        parsed = None
        for parser in (ast.literal_eval, json.loads):
            try:
                parsed = parser(text)
                break
            except (ValueError, SyntaxError, TypeError):
                continue
        if parsed is None:
            raise ValueError(f"undecodable celery field: {text[:120]!r}")
        obj = parsed
    return default if obj is None else obj


def reconcile_orphans(
    grace_minutes: int = 2,
    max_attempts: int = 3,
    window_hours: int = 6,
    dry_run: bool = False,
) -> dict:
    """Run the full orphan sweep under a single-flight advisory lock.

    Recovers any orphaned in-flight task and delegates attack-paths scans that
    never reached a worker to their existing stale-cleanup. Returns a summary;
    a no-op (lock not won) is reported too.
    """
    with advisory_lock() as acquired:
        if not acquired:
            logger.info("Orphan reconcile skipped: another run holds the lock")
            return {"acquired": False}

        # Populate the task registry so we can re-enqueue any task by name.
        import tasks.tasks  # noqa: F401

        result = _reconcile_task_results(
            grace_minutes=grace_minutes,
            max_attempts=max_attempts,
            window_hours=window_hours,
            dry_run=dry_run,
        )

        if not dry_run:
            from tasks.jobs.attack_paths.cleanup import cleanup_stale_attack_paths_scans

            result["attack_paths"] = cleanup_stale_attack_paths_scans()

        return {"acquired": True, **result}


def _reconcile_task_results(
    grace_minutes: int, max_attempts: int, window_hours: int, dry_run: bool
) -> dict:
    from django_celery_results.models import TaskResult

    cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=grace_minutes)
    candidates = list(
        TaskResult.objects.filter(status__in=IN_FLIGHT_STATES, date_created__lt=cutoff)
        .exclude(worker__isnull=True)
        .exclude(worker="")
        .exclude(task_name__in=_SKIP_RECOVERY)
    )

    # Ping each distinct worker at most once.
    worker_alive = {w: is_worker_alive(w) for w in {tr.worker for tr in candidates}}

    recovered, failed, skipped = [], [], []
    for task_result in candidates:
        if worker_alive.get(task_result.worker, True):
            skipped.append(task_result.task_id)  # in flight, do not double-run
            continue
        if dry_run:
            recovered.append(task_result.task_id)
            continue
        outcome = _recover_task(task_result, max_attempts, window_hours)
        (recovered if outcome == "recovered" else failed).append(task_result.task_id)

    logger.info(
        "Orphan reconcile: recovered=%d failed=%d skipped(in-flight)=%d",
        len(recovered),
        len(failed),
        len(skipped),
    )
    return {"recovered": recovered, "failed": failed, "skipped": skipped}


def _recovery_attempt_count(name: str, kwargs_repr, window_hours: int) -> int:
    """Increment and return the recovery count for this (task, kwargs) within the
    window. Backed by Valkey so it survives result-row churn (a worker processing
    the revoke can blank the TaskResult fields). Fail-open if Valkey is down (the
    broker being unreachable means nothing is running anyway).
    """
    import hashlib

    from django.conf import settings

    try:
        import redis

        client = redis.from_url(settings.CELERY_BROKER_URL)
        signature = f"{name}|{kwargs_repr}".encode()
        key = (
            "orphan-recovery:"
            + hashlib.sha1(signature, usedforsecurity=False).hexdigest()
        )
        count = client.incr(key)
        if count == 1:
            client.expire(key, max(1, window_hours) * 3600)
        return int(count)
    except Exception:
        logger.exception("Recovery-attempt counter unavailable; allowing recovery")
        return 1


def _recover_task(task_result, max_attempts: int, window_hours: int) -> str:
    """Recover one orphaned task. Returns 'recovered' or 'failed'."""
    # Capture name/args/kwargs now: revoking can let a worker blank the row.
    name = task_result.task_name
    args_repr = task_result.task_args
    kwargs_repr = task_result.task_kwargs
    now = datetime.now(tz=timezone.utc)

    # Drop any future broker redelivery of the stale message.
    revoke_task(task_result, terminate=False)

    # Mark the stale result terminal so "pending/started forever" alerts clear.
    task_result.status = states.REVOKED
    task_result.date_done = now
    task_result.save(update_fields=["status", "date_done"])

    attempt = _recovery_attempt_count(name, kwargs_repr, window_hours)
    if name not in REENQUEUEABLE_TASKS or attempt > max_attempts:
        reason = (
            f"{name} is not allowlisted for auto recovery"
            if name not in REENQUEUEABLE_TASKS
            else f"recovery cap reached ({attempt}/{max_attempts})"
        )
        _fail_domain_row(task_result.task_id, name, now)
        logger.warning(
            "Orphan %s (%s) not re-enqueued: %s", task_result.task_id, name, reason
        )
        return "failed"

    # Scan tasks: re-run the EXISTING scan row directly via scan-perform, so the
    # scheduled-scan "already executing" guard cannot turn recovery into a no-op.
    # Falls through to the generic path only if no scan is linked yet (e.g. a
    # scheduled task that died before creating one), where re-running it creates one.
    if name in _SCAN_TASKS:
        scan = _scan_for_task(task_result.task_id)
        if scan is not None:
            if not _reenqueue_scan(task_result.task_id, scan):
                return "failed"
            logger.info(
                "Re-enqueued orphaned scan %s (was task %s)",
                scan.id,
                task_result.task_id,
            )
            return "recovered"

    task_obj = current_app.tasks.get(name)
    if task_obj is None:
        logger.error(
            "Orphan %s: task %s not registered, cannot re-enqueue",
            task_result.task_id,
            name,
        )
        return "failed"

    try:
        args = _decode_celery_field(args_repr, [])
        kwargs = _decode_celery_field(kwargs_repr, {})
    except ValueError:
        logger.error(
            "Orphan %s (%s): could not decode stored args/kwargs, not re-enqueuing",
            task_result.task_id,
            name,
        )
        _fail_domain_row(task_result.task_id, name, now)
        return "failed"
    new_task_id = str(uuid4())
    task_obj.apply_async(
        args=list(args) if isinstance(args, (list, tuple)) else [],
        kwargs=kwargs if isinstance(kwargs, dict) else {},
        task_id=new_task_id,
    )
    logger.info(
        "Re-enqueued orphan %s (%s) as %s", task_result.task_id, name, new_task_id
    )
    return "recovered"


def _scan_for_task(task_id: str):
    """Return the Scan linked to a Celery task id, or None (read across tenants)."""
    from api.db_router import MainRouter
    from api.models import Scan

    return Scan.all_objects.using(MainRouter.admin_db).filter(task_id=task_id).first()


def _reenqueue_scan(old_task_id: str, scan) -> bool:
    """Re-run an orphaned scan via scan-perform on the existing row.

    Pre-provisions the new task linkage (TaskResult + api.Task) and relinks the
    Scan before enqueuing, so the FK is valid and a worker can never outrun the DB.
    The relink is conditional on the scan still pointing at the old task, so a stale
    orphan can never clobber a newer linkage.
    """
    from django_celery_results.models import TaskResult

    from api.db_utils import rls_transaction
    from api.models import Scan
    from api.models import Task as APITask
    from tasks.tasks import perform_scan_task

    tenant_id = str(scan.tenant_id)
    new_task_id = str(uuid4())
    with rls_transaction(tenant_id):
        locked_scan = Scan.all_objects.select_for_update().filter(id=scan.id).first()
        if locked_scan is None or str(locked_scan.task_id) != old_task_id:
            logger.info(
                "Scan %s no longer points at task %s; skipping recovery re-enqueue",
                scan.id,
                old_task_id,
            )
            return False
        task_result_new, _ = TaskResult.objects.get_or_create(
            task_id=new_task_id,
            defaults={"status": states.PENDING, "task_name": "scan-perform"},
        )
        APITask.objects.update_or_create(
            id=new_task_id,
            tenant_id=tenant_id,
            defaults={"task_runner_task": task_result_new},
        )
        locked_scan.task_id = new_task_id
        locked_scan.recovery_count = (locked_scan.recovery_count or 0) + 1
        locked_scan.save(update_fields=["task_id", "recovery_count", "updated_at"])

    perform_scan_task.apply_async(
        kwargs={
            "tenant_id": tenant_id,
            "scan_id": str(scan.id),
            "provider_id": str(scan.provider_id),
        },
        task_id=new_task_id,
    )
    return True


def _fail_domain_row(old_task_id: str, name: str, now: datetime) -> None:
    """Mark a scan terminal when its task is capped/denylisted instead of re-run."""
    from api.db_utils import rls_transaction
    from api.models import Scan, StateChoices

    if name in _SCAN_TASKS:
        scan = _scan_for_task(old_task_id)
        if scan is not None:
            with rls_transaction(str(scan.tenant_id)):
                Scan.all_objects.filter(id=scan.id, task_id=old_task_id).update(
                    state=StateChoices.FAILED, completed_at=now
                )
