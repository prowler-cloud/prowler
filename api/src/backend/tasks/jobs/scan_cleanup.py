"""Detect and fail stale ``Scan`` rows, then drain the provider queue.

Since #11848 scans run one-at-a-time per provider: launching a scan while
another is active for the same provider leaves the new scan ``QUEUED`` (state
``available``, shown as "Queued" in the UI) until the active scan's Celery task
finishes and its ``finally`` block dispatches the next queued scan.

``scan-perform`` uses ``acks_late=False`` and is deliberately excluded from
orphan recovery, so a worker that dies mid-scan (OOM, hard time-limit kill, node
failure) never runs that ``finally``. The scan is stranded and, because
``_get_dispatched_provider_scan`` still counts it as active, every queued scan
for that provider stays "Queued" forever (issue #12007).

This periodic task recovers from that in two complementary passes:

1. **Reap** the scans that block a provider queue: ``executing`` scans, and
   ``available``/``scheduled`` scans whose task is still dispatched (a task can
   be lost after dispatch but before it reaches ``executing``). A scan is only
   failed when its worker is *confirmed* gone and it has been silent for the
   inactivity window, or when it is older than the stale ceiling. Liveness that
   cannot be established is treated as alive, so a healthy scan is never failed
   because the control bus was unreachable. The dead scan is never re-run (that
   would duplicate findings) - it is failed and its task revoked.
2. **Drain** every provider that still has a ``QUEUED`` scan but no active scan.
   This retries a queue release that a transient error dropped on an earlier run
   (the reaped scan is already terminal, so a reap-only retry would never fire),
   making the recovery self-healing across runs.

``Scan`` is the source of truth: its state is committed first and the task result
is finalized afterwards, so a failure between the two can only leave a stale task
result, never a failed task result for a scan that is still running.
"""

from datetime import UTC, datetime, timedelta
from functools import partial

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Scan, StateChoices
from celery import current_app, states
from celery.utils.log import get_task_logger
from config.django.base import (
    SCAN_CLEANUP_CONFIG_ERROR,
    SCAN_CLEANUP_ENABLED,
    SCAN_INACTIVITY_THRESHOLD_MINUTES,
    SCAN_STALE_THRESHOLD_MINUTES,
)
from django.db import DatabaseError
from django.db.models import Q
from django.db.transaction import on_commit
from django_celery_results.models import TaskResult
from tasks.jobs.orphan_recovery import revoke_task as _revoke_task

logger = get_task_logger(__name__)

# Worker-liveness ping tuning (mirrors the Attack Paths cleanup added in #11986):
# a single short ping can misjudge a busy worker as dead, so ping with bounded
# retries and exponential backoff.
WORKER_PING_BASE_TIMEOUT_SECONDS = 5
WORKER_PING_MAX_ATTEMPTS = 3


def cleanup_stale_scans() -> dict:
    """Fail scans stranded by a dead worker and drain blocked provider queues.

    Returns a summary dict: how many scans were reaped (with their ids) and how
    many provider queues were checked for a pending release.
    """
    if not SCAN_CLEANUP_ENABLED:
        # Carry the reason rather than pointing at the startup log: settings are
        # imported before Django configures `LOGGING`, so that message never
        # reaches the structured handlers. This one does.
        logger.error(
            "Stale scan cleanup skipped: invalid threshold configuration - %s",
            SCAN_CLEANUP_CONFIG_ERROR,
        )
        return {"cleaned_up_count": 0, "scan_ids": [], "queues_checked": 0}

    now = datetime.now(tz=UTC)
    stale_cutoff = now - timedelta(minutes=SCAN_STALE_THRESHOLD_MINUTES)
    inactivity_cutoff = now - timedelta(minutes=SCAN_INACTIVITY_THRESHOLD_MINUTES)

    candidates = _stale_scan_candidates()

    workers = set()
    for scan in candidates:
        task_result = _task_result_for(scan)
        if task_result is not None and task_result.worker:
            workers.add(task_result.worker)

    _, unresponsive_workers = _ping_workers(workers)

    cleaned_up: list[str] = []
    for scan in candidates:
        task_result = _task_result_for(scan)
        reason, recheck_inactivity_cutoff = _stale_reason(
            scan,
            task_result,
            unresponsive_workers,
            stale_cutoff,
            inactivity_cutoff,
        )
        if reason is None:
            continue

        # Only SIGTERM a worker that actually has this scan running. A task that
        # never reached a worker is revoked without terminate, so the message is
        # discarded if the broker ever delivers it.
        worker = task_result.worker if task_result else None
        terminate = bool(worker) and scan.state == StateChoices.EXECUTING

        if _fail_stale_scan(
            scan,
            task_result,
            reason,
            expected_state=scan.state,
            terminate=terminate,
            inactivity_cutoff=recheck_inactivity_cutoff,
        ):
            cleaned_up.append(str(scan.id))

    # Second pass: release any provider queue that has a QUEUED scan but nothing
    # active. Runs after the reaps above, so the revocations they registered are
    # already committed before a follower is dispatched.
    queues_checked = _drain_pending_provider_queues()

    logger.info(
        "Stale scan cleanup: %d scan(s) failed, %d provider queue(s) checked",
        len(cleaned_up),
        queues_checked,
    )
    return {
        "cleaned_up_count": len(cleaned_up),
        "scan_ids": cleaned_up,
        "queues_checked": queues_checked,
    }


def _stale_scan_candidates() -> list[Scan]:
    """Scans that currently block their provider queue.

    Mirrors ``_get_dispatched_provider_scan``: an ``executing`` scan, or an
    ``available``/``scheduled`` scan whose task is still in a dispatched state
    (so a task lost before reaching ``executing`` is covered too). A ``QUEUED``
    task status is intentionally excluded - those are the waiting scans this
    task releases, not reaps.
    """
    # Imported lazily: ``tasks.tasks`` imports this module, so a top-level import
    # would be circular.
    from tasks.tasks import DISPATCHED_SCAN_TASK_STATES

    return list(
        Scan.all_objects.using(MainRouter.admin_db)
        .filter(
            Q(state=StateChoices.EXECUTING)
            | Q(
                state__in=(StateChoices.AVAILABLE, StateChoices.SCHEDULED),
                task__task_runner_task__status__in=DISPATCHED_SCAN_TASK_STATES,
            )
        )
        .select_related("task__task_runner_task")
    )


def _task_result_for(scan):
    """Return the scan's ``TaskResult`` row, or ``None`` if it has no task."""
    return getattr(scan.task, "task_runner_task", None) if scan.task else None


def _ping_workers(workers: set[str]) -> tuple[set[str], set[str] | None]:
    """Ping worker destinations, retrying only the ones that stay silent.

    Returns ``(responsive, unresponsive)``. ``unresponsive`` is ``None`` when
    liveness could not be established, and those workers must be treated as
    alive. That covers both an inspect call that raises and one that simply
    returns nothing: Celery swallows reply timeouts (``Mailbox._collect``
    catches ``socket.timeout`` and ``Inspect._prepare`` returns ``None``), so a
    silent control bus is indistinguishable from every worker being dead. A
    worker is only reported unresponsive when some other destination answered,
    which proves the control bus itself is healthy.
    """
    pending = set(workers)
    responsive: set[str] = set()
    control_plane_replied = False

    for attempt in range(WORKER_PING_MAX_ATTEMPTS):
        if not pending:
            return responsive, set()

        timeout = WORKER_PING_BASE_TIMEOUT_SECONDS * 2**attempt
        try:
            response = current_app.control.inspect(
                destination=sorted(pending),
                timeout=timeout,
            ).ping()
        except Exception:
            attempts_remaining = WORKER_PING_MAX_ATTEMPTS - attempt - 1
            if attempts_remaining:
                logger.warning(
                    "Scan cleanup worker ping attempt %d failed; retrying with "
                    "%d attempt(s) remaining",
                    attempt + 1,
                    attempts_remaining,
                    exc_info=True,
                )
                continue

            logger.exception(
                "Scan cleanup worker ping attempts exhausted; preserving scans "
                "for workers with unknown liveness"
            )
            return responsive, None

        if response:
            # At least one destination answered, so the control bus works.
            control_plane_replied = True

        responded = pending.intersection(response or {})
        responsive.update(responded)
        pending.difference_update(responded)

    if pending and not control_plane_replied:
        logger.warning(
            "Scan cleanup: no worker answered on the control bus; treating %d "
            "worker(s) as alive rather than dead",
            len(pending),
        )
        return responsive, None

    return responsive, pending


def _reference_time(scan, task_result) -> datetime | None:
    """Timestamp to age a scan from.

    ``started_at`` once the scan reached a worker, otherwise the moment its task
    row was created (falling back to the scan's insertion time). Without this
    fallback a scan that never started has no timestamp to age, and would block
    its provider queue forever.
    """
    if scan.started_at is not None:
        return scan.started_at
    if task_result is not None and task_result.date_created is not None:
        return task_result.date_created
    return scan.inserted_at


def _stale_reason(
    scan,
    task_result,
    unresponsive_workers: set[str] | None,
    stale_cutoff: datetime,
    inactivity_cutoff: datetime,
) -> tuple[str | None, datetime | None]:
    """Classify one blocking scan.

    Returns ``(reason, recheck_inactivity_cutoff)``. ``reason`` is ``None`` when
    the scan must be preserved. ``recheck_inactivity_cutoff`` is set only for the
    confirmed-dead-worker case, so the row can be re-checked for late activity
    under the final lock.
    """
    worker = task_result.worker if task_result else None
    confirmed_dead = (
        bool(worker)
        and unresponsive_workers is not None
        and worker in unresponsive_workers
    )

    if confirmed_dead:
        # Give a scan that heartbeated recently one more cycle, in case the
        # worker is being replaced.
        if scan.updated_at >= inactivity_cutoff:
            logger.info(
                "Preserving scan %s: worker %s is gone but activity is recent "
                "(progress=%s, updated_at=%s)",
                scan.id,
                worker,
                scan.progress,
                scan.updated_at,
            )
            return None, None
        return (
            "Worker unresponsive and scan inactive for "
            f"{SCAN_INACTIVITY_THRESHOLD_MINUTES} minutes - "
            "cleaned up by periodic task",
            inactivity_cutoff,
        )

    # Worker alive, liveness unknown, or never recorded: only the stale ceiling
    # may reap, so a slow-but-healthy scan is never failed. A scan that never
    # started is aged from its task creation time instead of `started_at`.
    reference = _reference_time(scan, task_result)
    if reference is None or reference >= stale_cutoff:
        return None, None
    return (
        "Scan exceeded the stale threshold of "
        f"{SCAN_STALE_THRESHOLD_MINUTES} minutes - cleaned up by periodic task",
        None,
    )


def _fail_stale_scan(
    scan,
    task_result,
    reason: str,
    *,
    expected_state: str,
    terminate: bool = False,
    inactivity_cutoff: datetime | None = None,
) -> bool:
    """Atomically lock the row, re-verify eligibility, and mark it ``FAILED``.

    The task result is finalized and revoked after the scan commits, so a
    rollback can never leave a failed task result behind a running scan.
    Returns ``True`` if the scan was failed, ``False`` if it moved on or vanished.
    """
    scan_id = str(scan.id)
    try:
        with rls_transaction(str(scan.tenant_id)):
            try:
                fresh_scan = Scan.objects.select_for_update().get(id=scan.id)
            except Scan.DoesNotExist:
                logger.warning(f"Scan {scan_id} no longer exists, skipping")
                return False

            # The state must be unchanged since the snapshot: a scan that has
            # advanced (available -> executing, or -> completed) is not ours.
            if fresh_scan.state != expected_state:
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

            # Re-read the task status: this snapshot predates up to ~35s of
            # worker probing, in which the task may have reported its own result.
            if task_result is not None and _task_is_ready(task_result.task_id):
                logger.info(f"Scan {scan_id} task already finished, skipping")
                return False

            now = datetime.now(tz=UTC)
            fresh_scan.state = StateChoices.FAILED
            fresh_scan.completed_at = now
            update_fields = ["state", "completed_at", "updated_at"]
            if fresh_scan.started_at is not None:
                elapsed = now - fresh_scan.started_at
                fresh_scan.duration = int(elapsed.total_seconds())
                update_fields.append("duration")
            fresh_scan.save(update_fields=update_fields)

            if task_result is not None:
                on_commit(
                    partial(_finalize_task_result, task_result.task_id, terminate),
                    using=fresh_scan._state.db,
                )
    except DatabaseError:
        logger.exception(f"Failed to mark stale scan {scan_id} as failed")
        return False

    logger.info(f"Cleaned up stale scan {scan_id}: {reason}")
    return True


def _task_is_ready(task_id: str) -> bool:
    """Whether the task already reported a terminal result."""
    status = (
        TaskResult.objects.filter(task_id=task_id)
        .values_list("status", flat=True)
        .first()
    )
    return status in states.READY_STATES


def _finalize_task_result(task_id: str, terminate: bool) -> None:
    """Mark the lost task terminal and revoke it, after the scan commit.

    ``Scan`` is the source of truth. ``TaskResult`` lives on the ``admin``
    connection (see ``MainRouter``), so it cannot join the scan's RLS
    transaction; running it post-commit means a crash in between leaves only a
    stale task result, never a ``FAILURE`` for a scan that is still running.
    """
    task_result = TaskResult.objects.filter(task_id=task_id).first()
    if task_result is None:
        logger.warning(f"Task result {task_id} no longer exists, skipping")
        return

    if task_result.status not in states.READY_STATES:
        task_result.status = states.FAILURE
        task_result.date_done = datetime.now(tz=UTC)
        task_result.save(update_fields=["status", "date_done"])

    _revoke_task(task_result, terminate=terminate)


def _drain_pending_provider_queues() -> int:
    """Release provider queues that have a ``QUEUED`` scan but nothing active.

    Idempotent and best effort: ``_dispatch_next_queued_provider_scan`` re-checks
    for a dispatched or executing scan under the provider lock and no-ops when
    one exists, so this only advances a genuinely stalled queue. Returns the
    number of provider queues checked.
    """
    # Imported lazily to avoid the circular import with ``tasks.tasks``.
    from tasks.tasks import (
        QUEUED_SCAN_TASK_STATE,
        _dispatch_next_queued_provider_scan_best_effort,
    )

    pending = list(
        Scan.all_objects.using(MainRouter.admin_db)
        .filter(
            state=StateChoices.AVAILABLE,
            task__task_runner_task__status=QUEUED_SCAN_TASK_STATE,
        )
        .values_list("tenant_id", "provider_id")
        .distinct()
    )

    for tenant_id, provider_id in pending:
        _dispatch_next_queued_provider_scan_best_effort(
            str(tenant_id),
            str(provider_id),
        )

    return len(pending)
