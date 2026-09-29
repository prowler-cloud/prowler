import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from api.db_utils import rls_transaction
from api.models import Scan, StateChoices
from celery import states
from celery.utils.log import get_task_logger
from config.django.base import (
    SCAN_HEARTBEAT_INTERVAL_SECONDS,
    SCAN_HEARTBEAT_LEGACY_STALE_HOURS,
    SCAN_HEARTBEAT_STALE_MINUTES,
)
from django.db import connection
from django.db.models import Q

logger = get_task_logger(__name__)

DISPATCHED_SCAN_TASK_STATES = (states.PENDING, states.STARTED, "PROGRESS")


def dead_scan_q(now: datetime) -> Q:
    """Single definition of a dead scan: its worker is gone and it will never finish."""
    stale = now - timedelta(minutes=SCAN_HEARTBEAT_STALE_MINUTES)
    legacy = now - timedelta(hours=SCAN_HEARTBEAT_LEGACY_STALE_HOURS)
    heartbeat_stale = Q(heartbeat_at__lt=stale)
    no_heartbeat = Q(heartbeat_at__isnull=True)

    executing = Q(state=StateChoices.EXECUTING) & (
        heartbeat_stale
        | (no_heartbeat & Q(started_at__lt=legacy))
        | (no_heartbeat & Q(started_at__isnull=True, inserted_at__lt=legacy))
    )
    dispatched = (
        Q(
            state__in=(StateChoices.AVAILABLE, StateChoices.SCHEDULED),
            task__isnull=False,
            task__task_runner_task__status__in=DISPATCHED_SCAN_TASK_STATES,
        )
    ) & (
        heartbeat_stale
        | (no_heartbeat & Q(task__task_runner_task__date_created__lt=legacy))
    )
    return executing | dispatched


@contextmanager
def scan_heartbeat(tenant_id: str, scan_id: str):
    """Refresh `Scan.heartbeat_at` from a daemon thread while the body runs.

    A thread is needed because the scan loop blocks inside long checks.
    """
    stop = threading.Event()

    def _beat():
        try:
            while not stop.wait(SCAN_HEARTBEAT_INTERVAL_SECONDS):
                try:
                    with rls_transaction(tenant_id):
                        Scan.objects.filter(id=scan_id).update(
                            heartbeat_at=datetime.now(UTC)
                        )
                except Exception:
                    logger.warning(
                        "Scan %s heartbeat write failed", scan_id, exc_info=True
                    )
        finally:
            connection.close()

    thread = threading.Thread(
        target=_beat, name=f"scan-heartbeat-{scan_id}", daemon=True
    )
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=5)
