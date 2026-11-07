"""Liveness and readiness endpoints following the IETF Health Check Response
Format (draft-inadarei-api-health-check-06).

Liveness reports only process status. Readiness verifies that PostgreSQL,
Valkey and the attack-paths graph store (Neo4j or Neptune, per
``ATTACK_PATHS_SINK_DATABASE``) are reachable and returns per-dependency
detail when any of them is unreachable. It also verifies active consumers
for the deployment's required Celery queues.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

import redis
from config.version import API_VERSION, RELEASE_ID
from django.conf import settings
from django.db import connections
from drf_spectacular.utils import extend_schema
from kombu import Producer
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

SERVICE_ID = "prowler-api"
SERVICE_DESCRIPTION = "Prowler API"

# Status vocabulary from the IETF draft (section 3.1).
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARN = "warn"

# Short socket timeout so a stuck Valkey cannot stall the probe.
VALKEY_PROBE_TIMEOUT_SECONDS = 2

# The reply timeout does not bound broker connection setup or DNS resolution.
# Bound the entire operation separately, with only one outstanding inspection
# per process, even when the underlying connection outlives the request budget.
WORKER_REPLY_TIMEOUT_SECONDS = 2
WORKER_PROBE_TIMEOUT_SECONDS = 3
_worker_probe_slot = threading.BoundedSemaphore(1)


# Probe-scoped budget for the graph database.
# ``Driver.verify_connectivity()`` takes no timeout; its only bound is the
# driver-level ``connection_acquisition_timeout`` (60s on Neptune). The
# probe needs its own budget, independent of the workload driver, so a
# graph-database outage cannot pin a worker thread (and the readiness lock)
# for a minute.
GRAPH_DB_PROBE_TIMEOUT_SECONDS = 5

# Bounded pool that enforces ``GRAPH_DB_PROBE_TIMEOUT_SECONDS``. If the
# graph database is unreachable the probe call blocks until the driver's
# own acquisition timeout fires; we abandon the future after the budget and
# report ``fail``. Orphaned tasks are capped by ``max_workers`` plus the 3s
# readiness cache plus the per-IP throttle, so they cannot pile up: worst
# case during a graph-database outage is every readiness call failing fast
# in ``GRAPH_DB_PROBE_TIMEOUT_SECONDS`` with at most 2 background threads
# stuck for <= the driver acquisition timeout.
_graph_db_probe_executor = ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="health-graph-db-probe"
)

# Brief cache window so high-frequency probes (ALB target groups, scrapers)
# do not stampede the actual dependency checks.
CACHE_CONTROL_HEADER = "max-age=3, must-revalidate"

# In-process readiness cache. Caps real dependency hits to roughly
# (gunicorn workers / TTL) per second regardless of incoming RPS or the
# source-IP distribution. Kept in sync with the Cache-Control max-age.
# Access is guarded by a lock so concurrent readers do not race on the
# read-decide-write cycle of the double-checked locking pattern below.
READINESS_CACHE_TTL_SECONDS = 3.0
_readiness_cache: tuple[float, dict[str, Any], int] | None = None
_readiness_cache_lock = threading.Lock()


class HealthJSONRenderer(JSONRenderer):
    """Emits responses with the ``application/health+json`` content type."""

    media_type = "application/health+json"
    format = "health"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _measure(name: str, check_fn) -> tuple[dict[str, Any], float]:
    """Time ``check_fn`` and return ``(result, elapsed_ms)``.

    ``check_fn`` returns ``None`` on success or raises on failure. The full
    exception is logged for operator diagnostics under ``name``; the
    response payload intentionally omits the error detail to avoid leaking
    infrastructure information (DNS names, ports, credentials, certificate
    chains) to anonymous clients.
    """
    started = time.perf_counter()
    try:
        check_fn()
    except Exception:
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.warning("Health probe '%s' failed", name, exc_info=True)
        return ({"status": STATUS_FAIL}, elapsed_ms)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return ({"status": STATUS_PASS}, elapsed_ms)


def _probe_postgres() -> None:
    with connections["default"].cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()


def _probe_valkey() -> None:
    client = redis.Redis.from_url(
        settings.CELERY_BROKER_URL,
        socket_connect_timeout=VALKEY_PROBE_TIMEOUT_SECONDS,
        socket_timeout=VALKEY_PROBE_TIMEOUT_SECONDS,
    )
    try:
        if not client.ping():
            raise RuntimeError("PING did not return PONG")
    finally:
        # Best-effort cleanup: a failure releasing the socket (e.g. broken
        # connection, half-closed by the server) must not mask the probe
        # result. Narrowed to the exception types redis-py and the stdlib
        # socket layer can raise on close.
        with suppress(redis.RedisError, OSError):
            client.close()


class _WorkerProbeProducer(Producer):
    """Publish a health inspection once, without Kombu's retry wrapper."""

    def publish(self, *args, **kwargs):
        """Override the mailbox's retry default for this producer only."""
        kwargs["retry"] = False
        return super().publish(*args, **kwargs)


class _WorkerProbeProducerPool:
    """Supply disposable producers using only the probe's connection."""

    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        """Provide the context manager expected by the control mailbox."""
        return _WorkerProbeProducer(self.connection, auto_declare=False)


def _check_worker_queues(required_queues: set[str]) -> None:
    """Require an active consumer for every queue used by this deployment."""
    from config.celery import celery_app

    # Use a dedicated, short-lived connection without changing task-publishing
    # retries, timeouts, TLS configuration or the application's connection pool.
    with celery_app.connection_for_read(
        connect_timeout=WORKER_REPLY_TIMEOUT_SECONDS,
        transport_options={
            "socket_connect_timeout": WORKER_REPLY_TIMEOUT_SECONDS,
            "socket_timeout": WORKER_REPLY_TIMEOUT_SECONDS,
            "max_retries": 0,
        },
    ) as connection:
        connection.ensure_connection(max_retries=0)
        # Binding copies the mailbox. Replace only that copy's producer pool:
        # the default pool would publish through a separate, retrying connection.
        mailbox = celery_app.control.mailbox(connection)
        mailbox.producer_pool = _WorkerProbeProducerPool(connection)
        replies = mailbox.multi_call(
            "active_queues", timeout=WORKER_REPLY_TIMEOUT_SECONDS
        )

    consumed_queues = {
        queue.get("name")
        for reply in replies or []
        if isinstance(reply, dict)
        for queues in reply.values()
        if isinstance(queues, list)
        for queue in queues
        if isinstance(queue, dict) and isinstance(queue.get("name"), str)
    }
    missing = required_queues - consumed_queues
    if missing:
        raise RuntimeError(
            f"No active consumer for queues: {', '.join(sorted(missing))}"
        )


def _probe_workers() -> None:
    """Bound consumer inspection and prevent timed-out checks from piling up."""
    required_queues = set(settings.HEALTHCHECK_WORKER_QUEUES)
    if not required_queues:
        raise RuntimeError("No worker queues configured for readiness")
    if not _worker_probe_slot.acquire(blocking=False):
        raise RuntimeError("A previous worker readiness probe is still running")

    future: Future[None] = Future()

    def inspect_queues():
        """Deliver the probe result and release its slot on every exit path."""
        try:
            future.set_result(_check_worker_queues(required_queues))
        except BaseException as exc:
            future.set_exception(exc)
        finally:
            _worker_probe_slot.release()

    # A running DNS lookup cannot be cancelled by Future.cancel(). A daemon
    # thread preserves the request budget without holding process shutdown open.
    thread = threading.Thread(
        target=inspect_queues, name="health-worker-probe", daemon=True
    )
    try:
        thread.start()
    except Exception:
        _worker_probe_slot.release()
        raise
    thread.join(timeout=WORKER_PROBE_TIMEOUT_SECONDS)
    if thread.is_alive():
        raise TimeoutError(f"worker probe exceeded {WORKER_PROBE_TIMEOUT_SECONDS}s")
    future.result()


def _graph_db_component_id() -> str:
    """Return the active graph database name for the ``componentId`` field."""
    return settings.ATTACK_PATHS_SINK_DATABASE.strip().lower()


def _probe_graph_db() -> None:
    # Lazy import: avoids pulling attack_paths into the boot import graph
    from api.attack_paths.database import verify_connectivity

    future = _graph_db_probe_executor.submit(verify_connectivity)
    try:
        future.result(timeout=GRAPH_DB_PROBE_TIMEOUT_SECONDS)
    except FuturesTimeoutError as exc:
        # Do not wait for the abandoned task; it ends when the driver's own acquisition timeout fires
        future.cancel()
        raise TimeoutError(
            f"graph-db probe exceeded {GRAPH_DB_PROBE_TIMEOUT_SECONDS}s"
        ) from exc


def _build_check_entry(
    component_id: str,
    component_type: str,
    result: dict[str, Any],
    elapsed_ms: float,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "componentId": component_id,
        "componentType": component_type,
        "observedValue": round(elapsed_ms, 2),
        "observedUnit": "ms",
        "status": result["status"],
        "time": _now_iso(),
    }
    if "output" in result:
        entry["output"] = result["output"]
    return entry


def _aggregate_status(check_entries: list[dict[str, Any]]) -> str:
    statuses = {entry["status"] for entry in check_entries}
    if STATUS_FAIL in statuses:
        return STATUS_FAIL
    if STATUS_WARN in statuses:
        return STATUS_WARN
    return STATUS_PASS


def _base_payload(overall_status: str) -> dict[str, Any]:
    return {
        "status": overall_status,
        "version": API_VERSION,
        "releaseId": RELEASE_ID,
        "serviceId": SERVICE_ID,
        "description": SERVICE_DESCRIPTION,
    }


def _readiness_payload() -> tuple[dict[str, Any], int]:
    """Cache dependency status, including coverage by active task consumers."""
    global _readiness_cache

    # Lock-free fast path: a stale snapshot still satisfies the freshness
    # check correctly because we re-check after acquiring the lock below.
    snapshot = _readiness_cache
    if (
        snapshot is not None
        and time.monotonic() - snapshot[0] < READINESS_CACHE_TTL_SECONDS
    ):
        return snapshot[1], snapshot[2]

    with _readiness_cache_lock:
        # Double-checked locking: another thread may have refreshed while
        # we were waiting on the lock.
        snapshot = _readiness_cache
        if (
            snapshot is not None
            and time.monotonic() - snapshot[0] < READINESS_CACHE_TTL_SECONDS
        ):
            return snapshot[1], snapshot[2]

        graph_db_component_id = _graph_db_component_id()

        postgres_result, postgres_ms = _measure("postgres", _probe_postgres)
        valkey_result, valkey_ms = _measure("valkey", _probe_valkey)
        graph_db_result, graph_db_ms = _measure(graph_db_component_id, _probe_graph_db)

        workers_result, workers_ms = _measure("celery", _probe_workers)
        entries = [
            _build_check_entry("postgres", "datastore", postgres_result, postgres_ms),
            _build_check_entry("valkey", "datastore", valkey_result, valkey_ms),
            _build_check_entry(
                graph_db_component_id, "datastore", graph_db_result, graph_db_ms
            ),
        ]
        entries.append(
            _build_check_entry("celery", "component", workers_result, workers_ms)
        )
        overall = _aggregate_status(entries)

        payload = _base_payload(overall)
        payload["checks"] = {
            "postgres:responseTime": [entries[0]],
            "valkey:responseTime": [entries[1]],
            "graphdb:responseTime": [entries[2]],
            "celery:responseTime": [entries[3]],
        }

        http_status = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if overall == STATUS_FAIL
            else status.HTTP_200_OK
        )
        _readiness_cache = (time.monotonic(), payload, http_status)
        return payload, http_status


def _health_response(payload: dict[str, Any], http_status: int) -> Response:
    response = Response(payload, status=http_status)
    response["Cache-Control"] = CACHE_CONTROL_HEADER
    return response


@extend_schema(exclude=True)
class LivenessView(APIView):
    """Liveness probe. Always 200 when the process can serve requests.

    Dependencies are intentionally not consulted: a failing liveness probe
    triggers a container restart, which must not happen for transient
    dependency outages. Throttled per-IP so the endpoint cannot be used as
    a cheap availability oracle for the process.
    """

    authentication_classes: list = []
    permission_classes: list = []
    renderer_classes = [HealthJSONRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "health-live"

    def get(self, _request, *_args, **_kwargs):
        return _health_response(_base_payload(STATUS_PASS), status.HTTP_200_OK)


@extend_schema(exclude=True)
class ReadinessView(APIView):
    """Readiness probe.

    Returns 200 when PostgreSQL, Valkey and the attack-paths graph store
    respond and all required queues have active consumers. Otherwise returns
    503 with per-dependency status. Per-IP throttle plus the short in-process
    result cache cap the real dependency hits regardless of inbound traffic shape.
    """

    authentication_classes: list = []
    permission_classes: list = []
    renderer_classes = [HealthJSONRenderer]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "health-ready"

    def get(self, _request, *_args, **_kwargs):
        payload, http_status = _readiness_payload()
        return _health_response(payload, http_status)
