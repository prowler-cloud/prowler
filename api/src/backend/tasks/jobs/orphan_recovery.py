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

# Tasks with proven idempotency are eligible for auto re-enqueue, grouped so each
# group can be toggled independently by a feature flag (see config.django.base).
# Summaries clear and rewrite their own rows and deletions are idempotent. Tasks with
# external side effects are never eligible: integration-jira would create duplicate
# issues, integration-s3 rebuilds its upload from worker-local files that do not
# survive a crash, and report/Security Hub recovery is out of scope.
RECOVERY_TASK_GROUPS = {
    "summaries": {
        "scan-summary",
        "scan-compliance-overviews",
        "scan-provider-compliance-scores",
        "scan-daily-severity",
        "scan-finding-group-summaries",
        "scan-reset-ephemeral-resources",
    },
    "deletions": {"provider-deletion", "tenant-deletion"},
}


def reenqueueable_tasks() -> set[str]:
    """Task names eligible for auto re-enqueue, honoring the per-group feature flags.

    A group whose flag is disabled is dropped, so its orphaned tasks are marked
    terminal instead of re-enqueued.
    """
    from django.conf import settings

    group_enabled = {
        "summaries": settings.TASK_RECOVERY_SUMMARIES_ENABLED,
        "deletions": settings.TASK_RECOVERY_DELETIONS_ENABLED,
    }
    return {
        task
        for group, tasks in RECOVERY_TASK_GROUPS.items()
        if group_enabled[group]
        for task in tasks
    }


# Tasks the watchdog ignores entirely (not even marked terminal): scan tasks are not
# auto-recovered, since re-running a scan is not safe to do automatically; attack-paths
# scans are handled by their own stale-cleanup (which also drops the temp Neo4j db);
# and the maintenance tasks must not self-recover (they run again on their own schedule).
_SKIP_RECOVERY = {
    "scan-perform",
    "scan-perform-scheduled",
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

        from django.conf import settings

        if settings.TASK_RECOVERY_ENABLED:
            # Populate the task registry so we can re-enqueue any task by name.
            import tasks.tasks  # noqa: F401

            result = _reconcile_task_results(
                grace_minutes=grace_minutes,
                max_attempts=max_attempts,
                window_hours=window_hours,
                dry_run=dry_run,
            )
            result["enabled"] = True
        else:
            logger.info("Orphan task recovery disabled by feature flag")
            result = {"recovered": [], "failed": [], "skipped": [], "enabled": False}

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
    allowlisted = name in reenqueueable_tasks()
    if not allowlisted or attempt > max_attempts:
        reason = (
            f"{name} is not allowlisted for auto recovery"
            if not allowlisted
            else f"recovery cap reached ({attempt}/{max_attempts})"
        )
        logger.warning(
            "Orphan %s (%s) not re-enqueued: %s", task_result.task_id, name, reason
        )
        return "failed"

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
