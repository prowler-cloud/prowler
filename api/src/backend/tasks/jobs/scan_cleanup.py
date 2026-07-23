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

1. **Reap** scans a dead worker stranded. A scan blocks the provider queue when
   it is ``executing`` OR ``available``/``scheduled`` with a dispatched task
   (a task can be lost after dispatch but before it reaches ``executing``).
   Liveness is confirmed by pinging the recorded worker with bounded retries;
   only a scan whose worker is *confirmed* gone (or an unrecorded worker past
   the stale ceiling) is failed. It never re-runs the scan (that would duplicate
   findings) — it only fails it and releases the queue.
2. **Drain** every provider that still has a ``QUEUED`` scan but no active scan.
   This retries a queue release that a transient error dropped on a previous run
   (the reaped scan is already terminal, so a reap-only retry would never fire),
   making the recovery self-healing across runs.

It mirrors ``cleanup_stale_attack_paths_scans`` for the main ``Scan`` model.
"""

from datetime import UTC, datetime, timedelta
from functools import partial

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Scan, StateChoices
from celery import current_app, states
from celery.utils.log import get_task_logger
from config.django.base import (
    SCAN_INACTIVITY_THRESHOLD_MINUTES,
    SCAN_STALE_THRESHOLD_MINUTES,
)
from django.db import DatabaseError
from django.db.models import Q
from django.db.transaction import on_commit
from tasks.jobs.orphan_recovery import revoke_task as _revoke_task

logger = get_task_logger(__name__)

# Worker-liveness ping tuning (mirrors the Attack Paths cleanup added in #11986):
# a single short ping can misjudge a busy worker as dead, so ping with bounded
# retries and exponential backoff, and treat a control-bus failure as "unknown".
WORKER_PING_BASE_TIMEOUT_SECONDS = 5
WORKER_PING_MAX_ATTEMPTS = 3


def cleanup_stale_scans() -> dict:
    """Fail scans stranded by a dead worker and drain blocked provider queues.

    Returns a summary dict: how many scans were reaped (with their ids) and how
    many provider queues were checked for a pending release.
    """
    now = datetime.now(tz=UTC)
    stale_cutoff = now - timedelta(minutes=SCAN_STALE_THRESHOLD_MINUTES)
    inactivity_cutoff = now - timedelta(minutes=SCAN_INACTIVITY_THRESHOLD_MINUTES)

    candidates = _stale_scan_candidates()

    workers = {
        tr.worker
        for scan in candidates
        if (tr := _task_result_for(scan)) and tr.worker
    }
    responsive_workers, unresponsive_workers = _ping_workers(workers)

    cleaned_up: list[str] = []
    for scan in candidates:
        task_result = _task_result_for(scan)
        worker = task_result.worker if task_result else None
        reason, recheck_inactivity_cutoff = _stale_reason(
            scan,
            worker,
            responsive_workers,
            unresponsive_workers,
            stale_cutoff,
            inactivity_cutoff,
        )
        if reason is None:
            continue

        if _fail_stale_scan(
            scan,
            task_result,
            reason,
            expected_state=scan.state,
            revoke=bool(worker),
            inactivity_cutoff=recheck_inactivity_cutoff,
        ):
            cleaned_up.append(str(scan.id))

    # Second pass: release any provider queue that has a QUEUED scan but nothing
    # active — covers a reaped provider and retries a drain a prior run dropped.
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
    task status is intentionally excluded — those are the waiting scans we want
    to release, not reap.
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

    Returns ``(responsive, unresponsive)``. ``unresponsive`` is ``None`` when the
    final attempt raised — the pending workers then have unknown liveness and
    their scans must be preserved rather than failed.
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
                    "Scan cleanup worker ping attempt %d failed; retrying %d "
                    "pending worker(s) with %d attempt(s) remaining",
                    attempt + 1,
                    len(pending),
                    attempts_remaining,
                    exc_info=True,
                )
                continue

            logger.exception(
                "Scan cleanup worker ping attempts exhausted; preserving scans "
                "for workers with unknown liveness"
            )
            return responsive, None

        responded = pending.intersection((response or {}).keys())
        responsive.update(responded)
        pending.difference_update(responded)

    return responsive, pending


def _stale_reason(
    scan,
    worker,
    responsive_workers: set[str],
    unresponsive_workers: set[str] | None,
    stale_cutoff: datetime,
    inactivity_cutoff: datetime,
) -> tuple[str | None, datetime | None]:
    """Classify one blocking scan.

    Returns ``(reason, recheck_inactivity_cutoff)``. ``reason`` is ``None`` when
    the scan must be preserved. ``recheck_inactivity_cutoff`` is set only for the
    confirmed-dead-worker case so the row can be re-checked for late activity
    under lock.
    """
    if worker:
        if worker in responsive_workers:
            # Worker alive: only reap a task that blew past the stale ceiling
            # (matched to the long hard time-limit); it will be killed anyway.
            if scan.started_at is None or scan.started_at >= stale_cutoff:
                return None, None
            return (
                "Scan exceeded stale threshold - cleaned up by periodic task",
                None,
            )

        if unresponsive_workers is None or worker not in unresponsive_workers:
            # Liveness unknown (control bus failed, or worker not in the
            # confirmed-dead set): preserve, try again next run.
            logger.info(
                "Preserving scan %s: worker %s liveness is unknown "
                "(state=%s, updated_at=%s)",
                scan.id,
                worker,
                scan.state,
                scan.updated_at,
            )
            return None, None

        # Worker confirmed gone: give a scan that heartbeated recently one more
        # cycle in case the worker is being replaced.
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
            f"Worker unresponsive and scan inactive for "
            f"{SCAN_INACTIVITY_THRESHOLD_MINUTES} minutes - cleaned up by periodic task",
            inactivity_cutoff,
        )

    # No worker recorded: time-based heuristic only. A dispatched scan that never
    # reached a worker has no started_at, so it is preserved until the stale
    # ceiling — this never reaps a scan merely waiting in the broker queue.
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
    expected_state: str,
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

            # State must be unchanged since the snapshot: a scan that has since
            # advanced (e.g. available -> executing, or -> completed) is not ours
            # to fail.
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


def _drain_pending_provider_queues() -> int:
    """Release provider queues that have a ``QUEUED`` scan but nothing active.

    Idempotent and best effort: ``_dispatch_next_queued_provider_scan`` re-checks
    for a dispatched/executing scan under lock and no-ops when one exists, so this
    only advances a genuinely stalled queue. Returns the number of provider
    queues checked.
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
            str(tenant_id), str(provider_id)
        )

    return len(pending)
