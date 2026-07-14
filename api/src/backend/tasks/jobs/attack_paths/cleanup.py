from datetime import UTC, datetime, timedelta

from api.attack_paths import database as graph_database
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import AttackPathsScan, StateChoices
from celery import current_app, states
from celery.utils.log import get_task_logger
from config.django.base import (
    ATTACK_PATHS_SCAN_INACTIVITY_THRESHOLD_MINUTES,
    ATTACK_PATHS_SCAN_STALE_THRESHOLD_MINUTES,
)
from django.db import DatabaseError
from tasks.jobs.attack_paths.db_utils import (
    mark_scan_finished,
    recover_graph_data_ready,
)
from tasks.jobs.orphan_recovery import revoke_task as _revoke_task

logger = get_task_logger(__name__)

WORKER_PING_BASE_TIMEOUT_SECONDS = 5
WORKER_PING_MAX_ATTEMPTS = 3


def cleanup_stale_attack_paths_scans() -> dict:
    """
    Mark stale `AttackPathsScan` rows as `FAILED`.

    Covers two stuck-state scenarios:
    1. `EXECUTING` scans whose workers are unresponsive and whose rows have
       stopped receiving progress updates, or that exceeded the stale threshold.
    2. `SCHEDULED` scans that never made it to a worker - parent scan
       crashed before dispatch, broker lost the message, etc. Detected by
       age plus the parent `Scan` no longer being in flight.
    """
    now = datetime.now(tz=UTC)
    stale_cutoff = now - timedelta(minutes=ATTACK_PATHS_SCAN_STALE_THRESHOLD_MINUTES)
    inactivity_cutoff = now - timedelta(
        minutes=ATTACK_PATHS_SCAN_INACTIVITY_THRESHOLD_MINUTES
    )

    cleaned_up: list[str] = []
    cleaned_up.extend(_cleanup_stale_executing_scans(stale_cutoff, inactivity_cutoff))
    cleaned_up.extend(_cleanup_stale_scheduled_scans(stale_cutoff))

    logger.info(
        f"Stale `AttackPathsScan` cleanup: {len(cleaned_up)} scan(s) cleaned up"
    )
    return {"cleaned_up_count": len(cleaned_up), "scan_ids": cleaned_up}


def _ping_workers(workers: set[str]) -> tuple[set[str], set[str] | None]:
    """Ping worker destinations in parallel and retry only missing workers.

    The second tuple item is `None` when the final ping attempt raises. In that
    case the pending workers have unknown liveness and their scans must be kept.
    """
    pending = set(workers)
    responsive: set[str] = set()

    for attempt in range(WORKER_PING_MAX_ATTEMPTS):
        if not pending:
            return responsive, set()

        timeout = WORKER_PING_BASE_TIMEOUT_SECONDS * 2**attempt
        try:
            response = current_app.control.inspect(
                destination=sorted(pending), timeout=timeout
            ).ping()
        except Exception:
            attempts_remaining = WORKER_PING_MAX_ATTEMPTS - attempt - 1
            if attempts_remaining:
                logger.warning(
                    f"Attack Paths worker ping attempt {attempt + 1} failed; "
                    f"retrying pending workers with {attempts_remaining} "
                    "attempt(s) remaining",
                    exc_info=True,
                )
                continue

            logger.exception(
                "Attack Paths worker ping attempts exhausted; preserving scans "
                "for workers with unknown liveness"
            )
            return responsive, None

        responded = pending.intersection((response or {}).keys())
        responsive.update(responded)
        pending.difference_update(responded)

    return responsive, pending


def _cleanup_stale_executing_scans(
    stale_cutoff: datetime, inactivity_cutoff: datetime
) -> list[str]:
    """
    Two-pass detection for `EXECUTING` scans:
    1. Ping all recorded workers in parallel with bounded retries.
       - Responsive + past stale threshold: cleanup.
       - Unresponsive + past inactivity threshold: cleanup.
       - Unknown after a final ping exception: preserve.
    2. If no worker field: fall back to time-based heuristic only.
    """
    executing_scans = list(
        AttackPathsScan.all_objects.using(MainRouter.admin_db)
        .filter(state=StateChoices.EXECUTING)
        .select_related("task__task_runner_task")
    )

    workers = {
        tr.worker
        for scan in executing_scans
        if (tr := getattr(scan.task, "task_runner_task", None) if scan.task else None)
        and tr.worker
    }
    responsive_workers, unresponsive_workers = _ping_workers(workers)

    cleaned_up: list[str] = []

    for scan in executing_scans:
        task_result = (
            getattr(scan.task, "task_runner_task", None) if scan.task else None
        )
        worker = task_result.worker if task_result else None

        if worker:
            if worker in responsive_workers:
                if scan.started_at is None or scan.started_at >= stale_cutoff:
                    continue

                reason = "Scan exceeded stale threshold - cleaned up by periodic task"
                recheck_activity_cutoff = None
            elif unresponsive_workers is None or worker not in unresponsive_workers:
                logger.info(
                    f"Preserving scan {scan.id}: worker {worker} liveness is "
                    f"unknown (progress={scan.progress}, updated_at={scan.updated_at})"
                )
                continue
            else:
                if scan.updated_at >= inactivity_cutoff:
                    logger.info(
                        f"Preserving scan {scan.id}: worker {worker} is unresponsive "
                        f"but activity is recent (progress={scan.progress}, "
                        f"updated_at={scan.updated_at})"
                    )
                    continue

                reason = (
                    "Worker unresponsive and scan inactive for "
                    f"{ATTACK_PATHS_SCAN_INACTIVITY_THRESHOLD_MINUTES} minutes - "
                    "cleaned up by periodic task"
                )
                recheck_activity_cutoff = inactivity_cutoff
        else:
            # No worker recorded, time-based heuristic only
            if scan.started_at is None or scan.started_at >= stale_cutoff:
                continue
            reason = (
                "No worker recorded, scan exceeded stale threshold - "
                "cleaned up by periodic task"
            )
            recheck_activity_cutoff = None

        if _cleanup_scan(
            scan,
            task_result,
            reason,
            revoke=worker is not None,
            inactivity_cutoff=recheck_activity_cutoff,
        ):
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

    For each match: lock and recheck the row, revoke the queued task
    (best-effort; harmless if already consumed), flip to `FAILED`, and mark the
    `TaskResult`. The temp Neo4j database is never created while `SCHEDULED`,
    so no drop is needed.
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
        reason = "Scan never started - cleaned up by periodic task"
        if _cleanup_scheduled_scan(scan, task_result, reason):
            cleaned_up.append(str(scan.id))

    return cleaned_up


def _cleanup_scan(
    scan,
    task_result,
    reason: str,
    *,
    revoke: bool = False,
    inactivity_cutoff: datetime | None = None,
) -> bool:
    """
    Clean up a single stale `AttackPathsScan`:
    lock and recheck, revoke the task, mark `FAILED`, drop the temp DB, and
    recover graph readiness.

    Returns `True` if the scan was actually cleaned up, `False` if skipped.
    """
    scan_id_str = str(scan.id)

    try:
        fresh_scan = _finalize_failed_scan(
            scan,
            StateChoices.EXECUTING,
            reason,
            task_result=task_result,
            revoke=revoke,
            inactivity_cutoff=inactivity_cutoff,
        )
    except DatabaseError:
        logger.exception(
            f"Failed to mark stale Attack Paths scan {scan_id_str} as failed"
        )
        return False

    if fresh_scan is None:
        return False

    tmp_db_name = graph_database.get_database_name(scan.id, temporary=True)
    try:
        graph_database.drop_database(tmp_db_name)
    except Exception:
        logger.exception(f"Failed to drop temp database {tmp_db_name}")

    recover_graph_data_ready(fresh_scan)

    logger.info(f"Cleaned up stale scan {scan_id_str}: {reason}")
    return True


def _cleanup_scheduled_scan(scan, task_result, reason: str) -> bool:
    """
    Clean up a `SCHEDULED` scan that never reached a worker.

    Skips the temp Neo4j drop - the database is only created once the worker
    enters `EXECUTING`, so dropping it here just produces noisy log output.

    Returns `True` if the scan was actually cleaned up, `False` if skipped.
    """
    scan_id_str = str(scan.id)

    try:
        fresh_scan = _finalize_failed_scan(
            scan,
            StateChoices.SCHEDULED,
            reason,
            task_result=task_result,
            revoke=task_result is not None,
            terminate=False,
        )
    except DatabaseError:
        logger.exception(
            f"Failed to mark scheduled Attack Paths scan {scan_id_str} as failed"
        )
        return False

    if fresh_scan is None:
        return False

    logger.info(f"Cleaned up scheduled scan {scan_id_str}: {reason}")
    return True


def _finalize_failed_scan(
    scan,
    expected_state: str,
    reason: str,
    *,
    task_result=None,
    revoke: bool = False,
    terminate: bool = True,
    inactivity_cutoff: datetime | None = None,
):
    """
    Atomically lock the row, verify it's still eligible, revoke if requested,
    and mark it `FAILED`. Returns the locked row on success, `None` if the row
    is gone or has already moved on.
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

        if inactivity_cutoff is not None and fresh_scan.updated_at >= inactivity_cutoff:
            logger.info(
                f"Scan {scan_id_str} received activity during worker checks, skipping"
            )
            return None

        if revoke and task_result:
            if terminate:
                _revoke_task(task_result, terminate=True)
            else:
                _revoke_task(task_result, terminate=False)

        mark_scan_finished(fresh_scan, StateChoices.FAILED, {"global_error": reason})

        if task_result:
            task_result.status = states.FAILURE
            task_result.date_done = datetime.now(tz=UTC)
            task_result.save(update_fields=["status", "date_done"])

    return fresh_scan
