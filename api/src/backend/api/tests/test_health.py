"""Tests for the health endpoints.

Cover the IETF response envelope, status code mapping (200 / 503), the
``application/health+json`` media type and per-probe failure modes.
"""

from unittest.mock import patch

import pytest

from config import version as config_version
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from api import health


HEALTH_MEDIA_TYPE = "application/health+json"


@pytest.fixture(autouse=True)
def _reset_health_state():
    """Per-test isolation: clear throttle counters and the readiness cache.

    DRF's ScopedRateThrottle persists state in Django's cache; without
    clearing it the throttle budget would be shared across tests and trip
    midway through the suite.
    """
    cache.clear()
    health._readiness_cache = None
    yield
    cache.clear()
    health._readiness_cache = None


@pytest.fixture
def api_client():
    return APIClient()


def _assert_health_envelope(body):
    """Every health response must carry the RFC top-level descriptors."""
    assert body["version"] == config_version.API_VERSION
    assert body["releaseId"] == config_version.RELEASE_ID
    assert body["serviceId"] == health.SERVICE_ID
    assert body["description"] == health.SERVICE_DESCRIPTION


class TestLivenessEndpoint:
    def test_returns_200_with_pass_status(self, api_client):
        response = api_client.get(reverse("health-live"))

        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"].startswith(HEALTH_MEDIA_TYPE)
        assert response["Cache-Control"] == health.CACHE_CONTROL_HEADER
        body = response.json()
        assert body["status"] == "pass"
        _assert_health_envelope(body)

    def test_does_not_require_authentication(self, api_client):
        api_client.credentials()

        response = api_client.get(reverse("health-live"))

        assert response.status_code == status.HTTP_200_OK

    def test_does_not_run_dependency_checks(self, api_client):
        with (
            patch("api.health._probe_postgres") as mock_pg,
            patch("api.health._probe_valkey") as mock_vk,
            patch("api.health._probe_graph_db") as mock_neo,
        ):
            response = api_client.get(reverse("health-live"))

        assert response.status_code == status.HTTP_200_OK
        mock_pg.assert_not_called()
        mock_vk.assert_not_called()
        mock_neo.assert_not_called()


class TestReadinessEndpoint:
    @staticmethod
    def _patch_probes():
        return (
            patch("api.health._probe_postgres", return_value=None),
            patch("api.health._probe_valkey", return_value=None),
            patch("api.health._probe_graph_db", return_value=None),
        )

    def test_returns_200_and_pass_when_all_dependencies_healthy(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"].startswith(HEALTH_MEDIA_TYPE)
        assert response["Cache-Control"] == health.CACHE_CONTROL_HEADER

        body = response.json()
        _assert_health_envelope(body)
        assert body["status"] == "pass"

        # Per RFC, `checks` values are arrays of one or more measurement
        # objects. We use a single measurement per dependency.
        assert set(body["checks"].keys()) == {
            "postgres:responseTime",
            "valkey:responseTime",
            "graphdb:responseTime",
        }
        for key in body["checks"]:
            entries = body["checks"][key]
            assert isinstance(entries, list) and len(entries) == 1
            entry = entries[0]
            assert entry["status"] == "pass"
            assert entry["componentType"] == "datastore"
            assert entry["observedUnit"] == "ms"
            assert isinstance(entry["observedValue"], (int, float))
            assert entry["observedValue"] >= 0
            assert "time" in entry
            # `output` must not leak when the check passed.
            assert "output" not in entry

    @pytest.mark.parametrize("sink", ["neo4j", "neptune"])
    def test_graphdb_component_id_reflects_active_sink(self, api_client, sink):
        from django.test import override_settings

        with (
            override_settings(ATTACK_PATHS_SINK_DATABASE=sink),
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_200_OK
        entry = response.json()["checks"]["graphdb:responseTime"][0]
        # Stable key, but the concrete store is named in componentId.
        assert entry["componentId"] == sink

    def test_returns_503_and_fail_when_postgres_is_down(self, api_client):
        with (
            patch(
                "api.health._probe_postgres",
                side_effect=RuntimeError("connection refused"),
            ),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        pg_entry = body["checks"]["postgres:responseTime"][0]
        assert pg_entry["status"] == "fail"
        # Exception detail is never echoed in the response, only logged.
        assert "output" not in pg_entry
        assert body["checks"]["valkey:responseTime"][0]["status"] == "pass"
        assert body["checks"]["graphdb:responseTime"][0]["status"] == "pass"

    def test_returns_503_and_fail_when_valkey_is_down(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey", side_effect=ConnectionError("timeout")),
            patch("api.health._probe_graph_db"),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        vk_entry = body["checks"]["valkey:responseTime"][0]
        assert vk_entry["status"] == "fail"
        assert "output" not in vk_entry

    def test_returns_503_and_fail_when_graph_db_is_down(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch(
                "api.health._probe_graph_db",
                side_effect=RuntimeError("ServiceUnavailable"),
            ),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        graph_db_entry = body["checks"]["graphdb:responseTime"][0]
        assert graph_db_entry["status"] == "fail"
        assert "output" not in graph_db_entry

    def test_reports_all_failures_simultaneously(self, api_client):
        with (
            patch("api.health._probe_postgres", side_effect=RuntimeError("pg down")),
            patch("api.health._probe_valkey", side_effect=RuntimeError("vk down")),
            patch("api.health._probe_graph_db", side_effect=RuntimeError("neo down")),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        for key in (
            "postgres:responseTime",
            "valkey:responseTime",
            "graphdb:responseTime",
        ):
            entry = body["checks"][key][0]
            assert entry["status"] == "fail"
            # No dependency-specific error string leaks into the payload.
            assert "output" not in entry

    def test_does_not_leak_exception_detail_on_failure(self, api_client):
        # Sanity check: an exception message resembling infra detail
        # (host, port, credentials) must not surface in the response under
        # any field.
        sensitive = (
            "connection to server at "
            '"postgres-rw.prod.svc.cluster.local" (10.0.0.5), port 5432 '
            'failed: FATAL: password authentication failed for user "prowler_user"'
        )
        with (
            patch("api.health._probe_postgres", side_effect=RuntimeError(sensitive)),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            response = api_client.get(reverse("health-ready"))

        body = response.json()
        assert "output" not in body["checks"]["postgres:responseTime"][0]
        payload_text = response.content.decode()
        for token in (
            "postgres-rw",
            "10.0.0.5",
            "5432",
            "prowler_user",
            "password authentication failed",
        ):
            assert token not in payload_text

    def test_does_not_require_authentication(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            api_client.credentials()
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_200_OK


class TestReadinessCache:
    """In-process cache caps the rate at which real probes hit the deps."""

    def test_result_is_cached_for_ttl_seconds(self, api_client):
        with (
            patch("api.health._probe_postgres") as pg,
            patch("api.health._probe_valkey") as vk,
            patch("api.health._probe_graph_db") as neo,
        ):
            r1 = api_client.get(reverse("health-ready"))
            r2 = api_client.get(reverse("health-ready"))

        assert r1.status_code == status.HTTP_200_OK
        assert r2.status_code == status.HTTP_200_OK
        # Second request must not trigger fresh dep checks within the TTL.
        assert pg.call_count == 1
        assert vk.call_count == 1
        assert neo.call_count == 1
        # The cached payload is returned verbatim (same timestamps too).
        assert r1.json() == r2.json()

    def test_re_probes_after_cache_ttl_expires(self, api_client):
        with (
            patch("api.health._probe_postgres") as pg,
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            api_client.get(reverse("health-ready"))
            assert pg.call_count == 1

            # Rewind the cached timestamp past the TTL so the next request
            # is forced to recompute.
            cached_ts, payload, http_status_code = health._readiness_cache
            health._readiness_cache = (
                cached_ts - health.READINESS_CACHE_TTL_SECONDS - 0.1,
                payload,
                http_status_code,
            )
            api_client.get(reverse("health-ready"))

        assert pg.call_count == 2

    def test_cache_persists_a_failing_result(self, api_client):
        # A failing readiness result is cached too; this is intentional so
        # an attacker spamming the endpoint during an outage cannot amplify
        # the dependency load.
        with (
            patch("api.health._probe_postgres", side_effect=RuntimeError("down")) as pg,
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
        ):
            r1 = api_client.get(reverse("health-ready"))
            r2 = api_client.get(reverse("health-ready"))

        assert r1.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert r2.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert pg.call_count == 1


class TestRateLimiting:
    """The endpoints are unauthenticated and exposed; per-IP throttle caps
    naive single-source floods."""

    def test_live_blocks_after_budget_exhausted(self, api_client):
        # Shrink the budget to 3 req per window so the test stays fast and
        # deterministic. parse_rate runs once per throttle instance and
        # each request gets a fresh instance, so this patch propagates.
        from rest_framework.throttling import ScopedRateThrottle

        with patch.object(ScopedRateThrottle, "parse_rate", return_value=(3, 60)):
            statuses = [
                api_client.get(reverse("health-live")).status_code for _ in range(4)
            ]

        assert statuses[:3] == [status.HTTP_200_OK] * 3
        assert statuses[3] == status.HTTP_429_TOO_MANY_REQUESTS

    def test_ready_blocks_after_budget_exhausted(self, api_client):
        from rest_framework.throttling import ScopedRateThrottle

        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_graph_db"),
            patch.object(ScopedRateThrottle, "parse_rate", return_value=(2, 60)),
        ):
            statuses = [
                api_client.get(reverse("health-ready")).status_code for _ in range(3)
            ]

        assert statuses[:2] == [status.HTTP_200_OK] * 2
        assert statuses[2] == status.HTTP_429_TOO_MANY_REQUESTS


class TestProbeImplementations:
    """Smoke tests for each probe primitive."""

    @pytest.mark.django_db
    def test_postgres_probe_succeeds_against_real_db(self):
        assert health._probe_postgres() is None

    def test_postgres_probe_propagates_db_errors(self):
        class _BoomCursor:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def execute(self, *_args, **_kwargs):
                raise RuntimeError("boom")

            def fetchone(self):  # pragma: no cover - never reached
                return None

        with patch("api.health.connections") as mock_connections:
            mock_connections.__getitem__.return_value.cursor.return_value = (
                _BoomCursor()
            )
            with pytest.raises(RuntimeError, match="boom"):
                health._probe_postgres()

    def test_valkey_probe_succeeds_when_ping_returns_true(self):
        with patch("api.health.redis.Redis.from_url") as mock_from_url:
            mock_from_url.return_value.ping.return_value = True
            assert health._probe_valkey() is None

    def test_valkey_probe_raises_when_ping_returns_false(self):
        with patch("api.health.redis.Redis.from_url") as mock_from_url:
            mock_from_url.return_value.ping.return_value = False
            with pytest.raises(RuntimeError, match="PING"):
                health._probe_valkey()

    def test_valkey_probe_propagates_connection_errors(self):
        with patch("api.health.redis.Redis.from_url") as mock_from_url:
            mock_from_url.return_value.ping.side_effect = ConnectionError("nope")
            with pytest.raises(ConnectionError, match="nope"):
                health._probe_valkey()

    def test_valkey_probe_suppresses_redis_error_on_close(self):
        # A redis-py-level failure releasing the socket must not mask a
        # successful PING (best-effort cleanup contract).
        import redis as redis_pkg

        with patch("api.health.redis.Redis.from_url") as mock_from_url:
            client = mock_from_url.return_value
            client.ping.return_value = True
            client.close.side_effect = redis_pkg.RedisError("connection reset")

            assert health._probe_valkey() is None

        client.close.assert_called_once_with()

    def test_valkey_probe_suppresses_oserror_on_close(self):
        # Socket-layer failures (OSError family) on close are also part of
        # the swallowed scope.
        with patch("api.health.redis.Redis.from_url") as mock_from_url:
            client = mock_from_url.return_value
            client.ping.return_value = True
            client.close.side_effect = OSError("EBADF")

            assert health._probe_valkey() is None

        client.close.assert_called_once_with()

    def test_valkey_probe_lets_unexpected_close_errors_propagate(self):
        # The suppress() is deliberately narrow: anything outside
        # (redis.RedisError, OSError) must surface so it is not silently
        # hidden.
        with patch("api.health.redis.Redis.from_url") as mock_from_url:
            client = mock_from_url.return_value
            client.ping.return_value = True
            client.close.side_effect = RuntimeError("bug")

            with pytest.raises(RuntimeError, match="bug"):
                health._probe_valkey()

    def test_graph_db_probe_calls_verify_connectivity(self):
        with patch("api.attack_paths.database.verify_connectivity") as mock_verify:
            mock_verify.return_value = None
            assert health._probe_graph_db() is None
            mock_verify.assert_called_once_with()

    def test_graph_db_probe_propagates_errors(self):
        with patch(
            "api.attack_paths.database.verify_connectivity",
            side_effect=RuntimeError("unreachable"),
        ):
            with pytest.raises(RuntimeError, match="unreachable"):
                health._probe_graph_db()

    def test_graph_db_probe_times_out_when_check_exceeds_budget(self):
        # A sink whose connectivity check blocks past the probe budget must
        # surface as a failure fast, not pin the request thread for the
        # driver's full acquisition timeout.
        import time as _time

        def _hang() -> None:
            _time.sleep(2)

        with (
            patch("api.health.GRAPH_DB_PROBE_TIMEOUT_SECONDS", 0.2),
            patch(
                "api.attack_paths.database.verify_connectivity",
                side_effect=_hang,
            ),
        ):
            started = _time.perf_counter()
            with pytest.raises(TimeoutError):
                health._probe_graph_db()
            elapsed = _time.perf_counter() - started

        assert elapsed < health.GRAPH_DB_PROBE_TIMEOUT_SECONDS + 1


class TestStatusAggregation:
    def test_pass_when_all_checks_pass(self):
        entries = [{"status": "pass"}, {"status": "pass"}]
        assert health._aggregate_status(entries) == "pass"

    def test_warn_when_any_check_warns_and_none_fail(self):
        entries = [{"status": "pass"}, {"status": "warn"}]
        assert health._aggregate_status(entries) == "warn"

    def test_fail_when_any_check_fails(self):
        entries = [{"status": "pass"}, {"status": "warn"}, {"status": "fail"}]
        assert health._aggregate_status(entries) == "fail"
