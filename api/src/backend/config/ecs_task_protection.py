"""ECS task scale-in protection for long-running Celery tasks.

When the worker runs on Amazon ECS, the service scheduler may terminate a task
during auto scale-in or a rolling deployment without any knowledge of the work
in flight. For long-running tasks such as scans this is disruptive: scans are
intentionally *not* re-queued when a worker is lost (re-running a partial scan
would duplicate ingestion), so an interrupted scan has to be started again from
scratch.

This module registers a Celery worker bootstep that enables `ECS task scale-in
protection <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-scale-in-protection.html>`_
while a protected task is running and disables it again once the worker is idle,
so the scheduler terminates only idle workers. It is a no-op unless
``DJANGO_ECS_TASK_PROTECTION`` is enabled and the task is running on ECS (the
``ECS_AGENT_URI`` endpoint is injected by the container agent on Fargate
platform >= 1.4.0 and the EC2 launch type).

The task role needs the ``ecs:UpdateTaskProtection`` permission for the endpoint
to succeed; if the call fails the worker keeps running normally (unprotected).

Configuration (environment variables):

* ``DJANGO_ECS_TASK_PROTECTION`` -- set to ``True`` to enable. Defaults to off.
* ``DJANGO_ECS_TASK_PROTECTION_POLL_SECONDS`` -- how often to check for in-flight
  protected tasks. Defaults to ``60``.
* ``DJANGO_ECS_TASK_PROTECTION_EXPIRES_MINUTES`` -- protection expiry requested
  from ECS; refreshed at half this interval while work continues so that
  protection lapses automatically if the worker dies. Defaults to ``120``.
"""

import json
import logging
import os
import threading
import time
from urllib import error as urllib_error
from urllib import request as urllib_request

from celery import bootsteps

logger = logging.getLogger(__name__)

# Long-running tasks that must not be interrupted by ECS scale-in or a rolling
# deployment. These are the tasks Celery is configured to give a multi-hour
# time limit and that are not re-queued on worker loss.
PROTECTED_TASK_NAMES = frozenset(
    {
        "scan-perform",
        "scan-perform-scheduled",
        "provider-deletion",
        "tenant-deletion",
    }
)

_TASK_PROTECTION_PATH = "/task-protection/v1/state"
_REQUEST_TIMEOUT_SECONDS = 5


def _agent_uri():
    """Return the ECS container agent URI, or ``None`` when not on ECS."""
    return os.environ.get("ECS_AGENT_URI")


def is_enabled():
    """Whether task scale-in protection should be managed in this process."""
    return (
        os.environ.get("DJANGO_ECS_TASK_PROTECTION", "False").lower() == "true"
        and _agent_uri() is not None
    )


def set_task_protection(enabled, expires_minutes):
    """Enable or disable ECS task scale-in protection for the current task.

    Returns ``True`` if the ECS agent accepted the request, ``False`` otherwise.
    Never raises: a failure leaves the worker running unprotected.
    """
    uri = _agent_uri()
    if uri is None:
        return False

    payload = {"ProtectionEnabled": bool(enabled)}
    if enabled:
        payload["ExpiresInMinutes"] = expires_minutes

    request = urllib_request.Request(
        f"{uri}{_TASK_PROTECTION_PATH}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib_request.urlopen(
            request, timeout=_REQUEST_TIMEOUT_SECONDS
        ) as response:
            response.read()
        return True
    except (urllib_error.URLError, OSError, ValueError) as error:
        logger.warning("Could not update ECS task scale-in protection: %s", error)
        return False


class ECSTaskProtectionStep(bootsteps.StartStopStep):
    """Worker bootstep that protects the ECS task while protected work runs.

    Runs in the worker's main process and polls the set of active requests, so
    it correctly accounts for every concurrent slot regardless of the execution
    pool. Protection is refreshed periodically so that a long scan stays
    protected, and released once the worker is idle so scale-in can reclaim it.
    """

    requires = {"celery.worker.components:Pool"}

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._poll_seconds = max(
            5,
            int(os.environ.get("DJANGO_ECS_TASK_PROTECTION_POLL_SECONDS", "60")),
        )
        self._expires_minutes = max(
            1,
            int(os.environ.get("DJANGO_ECS_TASK_PROTECTION_EXPIRES_MINUTES", "120")),
        )
        self._timer = None
        self._stop = threading.Event()
        self._protected = False
        self._protected_at = 0.0

    def start(self, parent):
        if not is_enabled():
            return
        logger.info(
            "ECS task scale-in protection enabled (poll=%ss, expires=%smin)",
            self._poll_seconds,
            self._expires_minutes,
        )
        self._stop.clear()
        self._tick()

    def stop(self, parent):
        self._stop.set()
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self._protected:
            set_task_protection(False, self._expires_minutes)
            self._protected = False

    @staticmethod
    def _protected_task_in_flight():
        # Imported lazily so the module stays importable outside a worker.
        from celery.worker import state

        return any(
            getattr(request, "name", None) in PROTECTED_TASK_NAMES
            for request in list(state.active_requests)
        )

    def _tick(self):
        if self._stop.is_set():
            return
        try:
            active = self._protected_task_in_flight()
            if active and not self._protected:
                if set_task_protection(True, self._expires_minutes):
                    self._protected = True
                    self._protected_at = time.monotonic()
                    logger.info("Acquired ECS task scale-in protection")
            elif active and self._protected:
                # Refresh before expiry so multi-hour work stays protected.
                if time.monotonic() - self._protected_at >= (
                    self._expires_minutes * 60
                ) / 2:
                    if set_task_protection(True, self._expires_minutes):
                        self._protected_at = time.monotonic()
            elif not active and self._protected:
                if set_task_protection(False, self._expires_minutes):
                    self._protected = False
                    logger.info("Released ECS task scale-in protection")
        except Exception:  # noqa: BLE001 - the monitor must never kill the worker
            logger.warning("ECS task scale-in protection poll failed", exc_info=True)
        finally:
            if not self._stop.is_set():
                self._timer = threading.Timer(self._poll_seconds, self._tick)
                self._timer.daemon = True
                self._timer.start()
