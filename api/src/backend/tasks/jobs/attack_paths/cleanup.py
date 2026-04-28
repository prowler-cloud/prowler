from datetime import datetime, timedelta, timezone

from celery import current_app, states
from celery.utils.log import get_task_logger
from config.django.base import ATTACK_PATHS_SCAN_STALE_THRESHOLD_MINUTES
from tasks.jobs.attack_paths.db_utils import (
    _mark_scan_finished,
    recover_graph_data_ready,
)

from api.attack_paths import database as graph_database
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import AttackPathsScan, StateChoices

logger = get_task_logger(__name__)


def cleanup_stale_attack_paths_scans() -> dict:
    """
    Mark stale `AttackPathsScan` rows as `FAILED`.

    Covers two stuck-state scenarios:
    1. `EXECUTING` scans whose workers are dead, or that have exceeded the
       stale threshold while alive.
    2. `SCHEDULED` scans that never made it to a worker — parent scan
       crashed before dispatch, broker lost the message, etc. Detected by
       age plus the parent `Scan` no longer being in flight.
    """
    threshold = timedelta(minutes=ATTACK_PATHS_SCAN_STALE_THRESHOLD_MINUTES)
    now = datetime.now(tz=timezone.utc)
    cutoff = now - threshold

    cleaned_up: list[str] = []
    cleaned_up.extend(_cleanup_stale_executing_scans(cutoff))
    cleaned_up.extend(_cleanup_stale_scheduled_scans(cutoff))

    logger.info(
        f"Stale `AttackPathsScan` cleanup: {len(cleaned_up)} scan(s) cleaned up"
    )
    return {"cleaned_up_count": len(cleaned_up), "scan_ids": cleaned_up}


def _cleanup_stale_executing_scans(cutoff: datetime) -> list[str]:
    """
    Two-pass detection for `EXECUTING` scans:
    1. If `TaskResult.worker` exists, ping the worker.
       - Dead worker: cleanup immediately (any age).
       - Alive + past threshold: revoke the task, then cleanup.
       - Alive + within threshold: skip.
    2. If no worker field: fall back to time-based heuristic only.
    """
    executing_scans = list(
        AttackPathsScan.all_objects.using(MainRouter.admin_db)
        .filter(state=StateChoices.EXECUTING)
        .select_related("task__task_runner_task")
    )

    # Cache worker liveness so each worker is pinged at most once
    workers = {
        tr.worker
        for scan in executing_scans
        if (tr := getattr(scan.task, "task_runner_task", None) if scan.task else None)
        and tr.worker
    }
    worker_alive = {w: _is_worker_alive(w) for w in workers}

    cleaned_up: list[str] = []

    for scan in executing_scans:
        task_result = (
            getattr(scan.task, "task_runner_task", None) if scan.task else None
        )
        worker = task_result.worker if task_result else None

        if worker:
            alive = worker_alive.get(worker, True)

            if alive:
                if scan.started_at and scan.started_at >= cutoff:
                    continue

                # Alive but stale — revoke before cleanup
                _revoke_task(task_result)
                reason = "Scan exceeded stale threshold — cleaned up by periodic task"
            else:
                reason = "Worker dead — cleaned up by periodic task"
        else:
            # No worker recorded — time-based heuristic only
            if scan.started_at and scan.started_at >= cutoff:
                continue
            reason = (
                "No worker recorded, scan exceeded stale threshold — "
                "cleaned up by periodic task"
            )

        if _cleanup_scan(scan, task_result, reason):
            cleaned_up.append(str(scan.id))

    return cleaned_up


def _cleanup_stale_scheduled_scans(cutoff: datetime) -> list[str]:
    """
    Cleanup `SCHEDULED` scans that never reached a worker.

    Detection:
    - `state == SCHEDULED`
    - `started_at < cutoff`
    - parent `Scan` is no longer in flight (terminal state or missing). This
      avoids cleaning up rows whose parent Prowler scan is legitimately still
      running.

    For each match: revoke the queued task (best-effort; harmless if already
    consumed), atomically flip to `FAILED`, mark the `TaskResult`, and run
    `recover_graph_data_ready`. The temp Neo4j database is never created
    while `SCHEDULED`, so no drop is needed.
    """
    scheduled_scans = list(
        AttackPathsScan.all_objects.using(MainRouter.admin_db)
        .filter(
            state=StateChoices.SCHEDULED,
            started_at__lt=cutoff,
        )
        .select_related("task__task_runner_task", "scan")
    )

    cleaned_up: list[str] = []
    parent_terminal = (
        StateChoices.COMPLETED,
        StateChoices.FAILED,
        StateChoices.CANCELLED,
    )

    for scan in scheduled_scans:
        parent_scan = scan.scan
        if parent_scan is not None and parent_scan.state not in parent_terminal:
            continue

        task_result = (
            getattr(scan.task, "task_runner_task", None) if scan.task else None
        )
        if task_result:
            _revoke_task(task_result, terminate=False)

        reason = "Scan never started — cleaned up by periodic task"
        if _cleanup_scheduled_scan(scan, task_result, reason):
            cleaned_up.append(str(scan.id))

    return cleaned_up


def _is_worker_alive(worker: str) -> bool:
    """Ping a specific Celery worker. Returns `True` if it responds or on error."""
    try:
        response = current_app.control.inspect(destination=[worker], timeout=1.0).ping()
        return response is not None and worker in response
    except Exception:
        logger.exception(f"Failed to ping worker {worker}, treating as alive")
        return True


def _revoke_task(task_result, terminate: bool = True) -> None:
    """Revoke a Celery task. Non-fatal on failure.

    `terminate=True` SIGTERMs the worker if the task is mid-execution; use
    for EXECUTING cleanup. `terminate=False` only marks the task id revoked
    across workers, so any worker pulling the queued message discards it;
    use for SCHEDULED cleanup where the task hasn't run yet.
    """
    try:
        kwargs = {"terminate": True, "signal": "SIGTERM"} if terminate else {}
        current_app.control.revoke(task_result.task_id, **kwargs)
        logger.info(f"Revoked task {task_result.task_id}")
    except Exception:
        logger.exception(f"Failed to revoke task {task_result.task_id}")


def _cleanup_scan(scan, task_result, reason: str) -> bool:
    """
    Clean up a single stale `AttackPathsScan`:
    drop temp DB, mark `FAILED`, update `TaskResult`, recover `graph_data_ready`.

    Returns `True` if the scan was actually cleaned up, `False` if skipped.
    """
    scan_id_str = str(scan.id)

    # 1. Drop temp Neo4j database
    tmp_db_name = graph_database.get_database_name(scan.id, temporary=True)
    try:
        graph_database.drop_database(tmp_db_name)
    except Exception:
        logger.exception(f"Failed to drop temp database {tmp_db_name}")

    fresh_scan = _finalize_failed_scan(scan, StateChoices.EXECUTING, reason)
    if fresh_scan is None:
        return False

    # Mark `TaskResult` as `FAILURE` (not RLS-protected, outside lock)
    if task_result:
        task_result.status = states.FAILURE
        task_result.date_done = datetime.now(tz=timezone.utc)
        task_result.save(update_fields=["status", "date_done"])

    recover_graph_data_ready(fresh_scan)

    logger.info(f"Cleaned up stale scan {scan_id_str}: {reason}")
    return True


def _cleanup_scheduled_scan(scan, task_result, reason: str) -> bool:
    """
    Clean up a `SCHEDULED` scan that never reached a worker.

    Skips the temp Neo4j drop — the database is only created once the worker
    enters `EXECUTING`, so dropping it here just produces noisy log output.

    Returns `True` if the scan was actually cleaned up, `False` if skipped.
    """
    scan_id_str = str(scan.id)

    fresh_scan = _finalize_failed_scan(scan, StateChoices.SCHEDULED, reason)
    if fresh_scan is None:
        return False

    if task_result:
        task_result.status = states.FAILURE
        task_result.date_done = datetime.now(tz=timezone.utc)
        task_result.save(update_fields=["status", "date_done"])

    logger.info(f"Cleaned up scheduled scan {scan_id_str}: {reason}")
    return True


def _finalize_failed_scan(scan, expected_state: str, reason: str):
    """
    Atomically lock the row, verify it's still in `expected_state`, and
    mark it `FAILED`. Returns the locked row on success, `None` if the
    row is gone or has already moved on.
    """
    scan_id_str = str(scan.id)
    with rls_transaction(str(scan.tenant_id)):
        try:
            fresh_scan = AttackPathsScan.objects.select_for_update().get(id=scan.id)
        except AttackPathsScan.DoesNotExist:
            logger.warning(f"Scan {scan_id_str} no longer exists, skipping")
            return None

        if fresh_scan.state != expected_state:
            logger.info(f"Scan {scan_id_str} is now {fresh_scan.state}, skipping")
            return None

        _mark_scan_finished(fresh_scan, StateChoices.FAILED, {"global_error": reason})

    return fresh_scan
