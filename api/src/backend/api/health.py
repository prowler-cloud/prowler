"""Liveness and readiness endpoints following the IETF Health Check Response
Format (draft-inadarei-api-health-check-06).

Liveness reports only process status. Readiness verifies that PostgreSQL,
Valkey and Neo4j are reachable and returns per-dependency detail when any
of them is unreachable.
"""

from __future__ import annotations

import time
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any

import redis
from config.version import API_VERSION, RELEASE_ID
from django.conf import settings
from django.db import connections
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

SERVICE_ID = "prowler-api"
SERVICE_DESCRIPTION = "Prowler API"

# Status vocabulary from the IETF draft (section 3.1).
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_WARN = "warn"

# Short socket timeout so a stuck Valkey cannot stall the probe.
# Neo4j inherits its driver-level ``connection_acquisition_timeout``.
VALKEY_PROBE_TIMEOUT_SECONDS = 2

# Brief cache window so high-frequency probes (ALB target groups, scrapers)
# do not stampede the actual dependency checks.
CACHE_CONTROL_HEADER = "max-age=3, must-revalidate"


class HealthJSONRenderer(JSONRenderer):
    """Emits responses with the ``application/health+json`` content type."""

    media_type = "application/health+json"
    format = "health"


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _measure(check_fn) -> tuple[dict[str, Any], float]:
    """Time ``check_fn`` and return ``(result, elapsed_ms)``.

    ``check_fn`` returns ``None`` on success or raises on failure.
    """
    started = time.perf_counter()
    try:
        check_fn()
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return (
            {"status": STATUS_FAIL, "output": str(exc) or exc.__class__.__name__},
            elapsed_ms,
        )
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


def _probe_neo4j() -> None:
    # Lazy import: avoids pulling attack_paths into the boot import graph.
    from api.attack_paths.database import get_driver

    get_driver().verify_connectivity()


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
    postgres_result, postgres_ms = _measure(_probe_postgres)
    valkey_result, valkey_ms = _measure(_probe_valkey)
    neo4j_result, neo4j_ms = _measure(_probe_neo4j)

    entries = [
        _build_check_entry("postgres", "datastore", postgres_result, postgres_ms),
        _build_check_entry("valkey", "datastore", valkey_result, valkey_ms),
        _build_check_entry("neo4j", "datastore", neo4j_result, neo4j_ms),
    ]
    overall = _aggregate_status(entries)

    payload = _base_payload(overall)
    payload["checks"] = {
        "postgres:responseTime": [entries[0]],
        "valkey:responseTime": [entries[1]],
        "neo4j:responseTime": [entries[2]],
    }

    http_status = (
        status.HTTP_503_SERVICE_UNAVAILABLE
        if overall == STATUS_FAIL
        else status.HTTP_200_OK
    )
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
    dependency outages.
    """

    authentication_classes: list = []
    permission_classes: list = []
    renderer_classes = [HealthJSONRenderer]

    def get(self, _request, *_args, **_kwargs):
        return _health_response(_base_payload(STATUS_PASS), status.HTTP_200_OK)


@extend_schema(exclude=True)
class ReadinessView(APIView):
    """Readiness probe.

    Returns 200 when PostgreSQL, Valkey and Neo4j all respond, or 503 with
    per-dependency detail when any of them is unreachable.
    """

    authentication_classes: list = []
    permission_classes: list = []
    renderer_classes = [HealthJSONRenderer]

    def get(self, _request, *_args, **_kwargs):
        payload, http_status = _readiness_payload()
        return _health_response(payload, http_status)
