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
    Find `EXECUTING` `AttackPathsScan` scans whose workers are dead or that have
    exceeded the stale threshold, and mark them as `FAILED`.

    Two-pass detection:
    1. If `TaskResult.worker` exists, ping the worker.
       - Dead worker: cleanup immediately (any age).
       - Alive + past threshold: revoke the task, then cleanup.
       - Alive + within threshold: skip.
    2. If no worker field: fall back to time-based heuristic only.
    """
    threshold = timedelta(minutes=ATTACK_PATHS_SCAN_STALE_THRESHOLD_MINUTES)
    now = datetime.now(tz=timezone.utc)
    cutoff = now - threshold

    executing_scans = (
        AttackPathsScan.all_objects.using(MainRouter.admin_db)
        .filter(state=StateChoices.EXECUTING)
        .select_related("task__task_runner_task")
    )

    # Cache worker liveness so each worker is pinged at most once
    executing_scans = list(executing_scans)
    workers = {
        tr.worker
        for scan in executing_scans
        if (tr := getattr(scan.task, "task_runner_task", None) if scan.task else None)
        and tr.worker
    }
    worker_alive = {w: _is_worker_alive(w) for w in workers}

    cleaned_up = []

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
                reason = (
                    "Scan exceeded stale threshold — " "cleaned up by periodic task"
                )
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

    logger.info(
        f"Stale `AttackPathsScan` cleanup: {len(cleaned_up)} scan(s) cleaned up"
    )
    return {"cleaned_up_count": len(cleaned_up), "scan_ids": cleaned_up}


def _is_worker_alive(worker: str) -> bool:
    """Ping a specific Celery worker. Returns `True` if it responds or on error."""
    try:
        response = current_app.control.inspect(destination=[worker], timeout=1.0).ping()
        return response is not None and worker in response
    except Exception:
        logger.exception(f"Failed to ping worker {worker}, treating as alive")
        return True


def _revoke_task(task_result) -> None:
    """Send `SIGTERM` to a hung Celery task. Non-fatal on failure."""
    try:
        current_app.control.revoke(
            task_result.task_id, terminate=True, signal="SIGTERM"
        )
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

    # 2. Lock row, verify still EXECUTING, mark FAILED — all atomic
    with rls_transaction(str(scan.tenant_id)):
        try:
            fresh_scan = AttackPathsScan.objects.select_for_update().get(id=scan.id)
        except AttackPathsScan.DoesNotExist:
            logger.warning(f"Scan {scan_id_str} no longer exists, skipping")
            return False

        if fresh_scan.state != StateChoices.EXECUTING:
            logger.info(f"Scan {scan_id_str} is now {fresh_scan.state}, skipping")
            return False

        _mark_scan_finished(fresh_scan, StateChoices.FAILED, {"global_error": reason})

    # 3. Mark `TaskResult` as `FAILURE` (not RLS-protected, outside lock)
    if task_result:
        task_result.status = states.FAILURE
        task_result.date_done = datetime.now(tz=timezone.utc)
        task_result.save(update_fields=["status", "date_done"])

    # 4. Recover graph_data_ready if provider data still exists
    recover_graph_data_ready(fresh_scan)

    logger.info(f"Cleaned up stale scan {scan_id_str}: {reason}")
    return True
