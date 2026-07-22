"""Detect and fail stale ``Scan`` rows, then drain the provider queue.

Since #11848 scans run one-at-a-time per provider: launching a scan while
another is active for the same provider leaves the new scan ``QUEUED`` (state
``available``, shown as "Queued" in the UI) until the active scan's Celery task
finishes and its ``finally`` block dispatches the next queued scan.

``scan-perform`` uses ``acks_late=False`` and is deliberately excluded from
orphan recovery, so a worker that dies mid-scan (OOM, hard time-limit kill, node
failure) never runs that ``finally``. The scan is stranded in ``executing`` and,
because ``_get_dispatched_provider_scan`` still counts it as active, every queued
scan for that provider stays "Queued" forever (issue #12007).

This periodic task reaps such stranded ``executing`` scans - confirmed dead by
pinging the recorded worker - marks them ``failed``, revokes the lost task, and
dispatches the next queued scan so the provider's queue drains. It never re-runs
the dead scan (that would duplicate findings); it only fails it and releases the
queue. It mirrors ``cleanup_stale_attack_paths_scans`` for the main ``Scan``
model.
"""

from datetime import UTC, datetime, timedelta
from functools import partial

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Scan, StateChoices
from celery import states
from celery.utils.log import get_task_logger
from config.django.base import (
    SCAN_INACTIVITY_THRESHOLD_MINUTES,
    SCAN_STALE_THRESHOLD_MINUTES,
)
from django.db import DatabaseError
from django.db.transaction import on_commit
from tasks.jobs.orphan_recovery import is_worker_alive
from tasks.jobs.orphan_recovery import revoke_task as _revoke_task

logger = get_task_logger(__name__)


def cleanup_stale_scans() -> dict:
    """Fail ``executing`` scans whose worker is gone and drain the provider queue.

    Detection per scan:
    - worker recorded and alive: reap only if ``started_at`` is past the stale
      ceiling (matched to the long hard time-limit), i.e. the task overran and
      the worker will be killed anyway;
    - worker recorded and gone: reap once the scan has been silent (no
      ``updated_at`` heartbeat) for longer than the inactivity window;
    - no worker recorded: fall back to the stale ceiling on ``started_at``.

    An unreachable control bus makes every worker look alive, so a still-running
    scan is never failed by mistake.

    Returns a summary dict with the count and ids of the scans cleaned up.
    """
    now = datetime.now(tz=UTC)
    stale_cutoff = now - timedelta(minutes=SCAN_STALE_THRESHOLD_MINUTES)
    inactivity_cutoff = now - timedelta(minutes=SCAN_INACTIVITY_THRESHOLD_MINUTES)

    executing_scans = list(
        Scan.all_objects.using(MainRouter.admin_db)
        .filter(state=StateChoices.EXECUTING)
        .select_related("task__task_runner_task")
    )

    workers = {
        tr.worker
        for scan in executing_scans
        if (tr := _task_result_for(scan)) and tr.worker
    }
    # Ping each distinct worker once; errors are treated as "alive" upstream.
    worker_alive = {worker: is_worker_alive(worker) for worker in workers}

    cleaned_up: list[str] = []
    for scan in executing_scans:
        task_result = _task_result_for(scan)
        worker = task_result.worker if task_result else None
        reason, recheck_inactivity_cutoff = _stale_reason(
            scan, worker, worker_alive, stale_cutoff, inactivity_cutoff
        )
        if reason is None:
            continue

        if _fail_stale_scan(
            scan,
            task_result,
            reason,
            revoke=worker is not None,
            inactivity_cutoff=recheck_inactivity_cutoff,
        ):
            cleaned_up.append(str(scan.id))
            # Release the provider queue the dead scan was blocking. Runs after
            # the FAILED state is committed so the next dispatch no longer sees
            # this scan as the active one.
            _drain_provider_queue(str(scan.tenant_id), str(scan.provider_id))

    logger.info(f"Stale scan cleanup: {len(cleaned_up)} scan(s) cleaned up")
    return {"cleaned_up_count": len(cleaned_up), "scan_ids": cleaned_up}


def _task_result_for(scan):
    """Return the scan's ``TaskResult`` row, or ``None`` if it has no task."""
    return getattr(scan.task, "task_runner_task", None) if scan.task else None


def _stale_reason(
    scan,
    worker,
    worker_alive: dict,
    stale_cutoff: datetime,
    inactivity_cutoff: datetime,
) -> tuple[str | None, datetime | None]:
    """Classify one ``executing`` scan.

    Returns ``(reason, recheck_inactivity_cutoff)``. ``reason`` is ``None`` when
    the scan must be preserved. ``recheck_inactivity_cutoff`` is set only for the
    dead-worker case so the row can be re-checked for late activity under lock.
    """
    if worker:
        if worker_alive.get(worker, True):
            if scan.started_at is None or scan.started_at >= stale_cutoff:
                return None, None
            return (
                "Scan exceeded stale threshold - cleaned up by periodic task",
                None,
            )

        # Worker is gone: give a scan that heartbeated recently one more cycle,
        # in case the worker is being replaced.
        if scan.updated_at >= inactivity_cutoff:
            logger.info(
                f"Preserving scan {scan.id}: worker {worker} is gone but activity "
                f"is recent (progress={scan.progress}, updated_at={scan.updated_at})"
            )
            return None, None
        return (
            f"Worker unresponsive and scan inactive for "
            f"{SCAN_INACTIVITY_THRESHOLD_MINUTES} minutes - cleaned up by periodic task",
            inactivity_cutoff,
        )

    # No worker recorded: time-based heuristic only.
    if scan.started_at is None or scan.started_at >= stale_cutoff:
        return None, None
    return (
        "No worker recorded, scan exceeded stale threshold - cleaned up by periodic task",
        None,
    )


def _fail_stale_scan(
    scan,
    task_result,
    reason: str,
    *,
    revoke: bool = False,
    inactivity_cutoff: datetime | None = None,
) -> bool:
    """Atomically lock the row, re-verify eligibility, and mark it ``FAILED``.

    Registers task revocation after commit when requested. Returns ``True`` if
    the scan was failed, ``False`` if it moved on or vanished.
    """
    scan_id = str(scan.id)
    try:
        with rls_transaction(str(scan.tenant_id)):
            try:
                fresh_scan = Scan.objects.select_for_update().get(id=scan.id)
            except Scan.DoesNotExist:
                logger.warning(f"Scan {scan_id} no longer exists, skipping")
                return False

            if fresh_scan.state != StateChoices.EXECUTING:
                logger.info(f"Scan {scan_id} is now {fresh_scan.state}, skipping")
                return False

            if (
                inactivity_cutoff is not None
                and fresh_scan.updated_at >= inactivity_cutoff
            ):
                logger.info(
                    f"Scan {scan_id} received activity during worker checks, skipping"
                )
                return False

            now = datetime.now(tz=UTC)
            fresh_scan.state = StateChoices.FAILED
            fresh_scan.completed_at = now
            update_fields = ["state", "completed_at", "updated_at"]
            if fresh_scan.started_at is not None:
                fresh_scan.duration = int(
                    (now - fresh_scan.started_at).total_seconds()
                )
                update_fields.append("duration")
            fresh_scan.save(update_fields=update_fields)

            if task_result:
                task_result.status = states.FAILURE
                task_result.date_done = now
                task_result.save(update_fields=["status", "date_done"])

            if revoke and task_result:
                on_commit(
                    partial(_revoke_task, task_result, terminate=True),
                    using=fresh_scan._state.db,
                )
    except DatabaseError:
        logger.exception(f"Failed to mark stale scan {scan_id} as failed")
        return False

    logger.info(f"Cleaned up stale scan {scan_id}: {reason}")
    return True


def _drain_provider_queue(tenant_id: str, provider_id: str) -> None:
    """Dispatch the next queued scan for the provider (best effort)."""
    # Imported lazily: ``tasks.tasks`` imports this module, so a top-level import
    # would be circular.
    from tasks.tasks import _dispatch_next_queued_provider_scan_best_effort

    _dispatch_next_queued_provider_scan_best_effort(tenant_id, provider_id)
