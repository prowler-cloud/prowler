"""Tests for the health endpoints.

Cover the IETF response envelope, status code mapping (200 / 503), the
``application/health+json`` media type and per-probe failure modes.
"""

from unittest.mock import patch

import pytest
from config import version as config_version
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from api import health


HEALTH_MEDIA_TYPE = "application/health+json"


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
            patch("api.health._probe_neo4j") as mock_neo,
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
            patch("api.health._probe_neo4j", return_value=None),
        )

    def test_returns_200_and_pass_when_all_dependencies_healthy(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_neo4j"),
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
            "neo4j:responseTime",
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

    def test_returns_503_and_fail_when_postgres_is_down(self, api_client):
        with (
            patch(
                "api.health._probe_postgres",
                side_effect=RuntimeError("connection refused"),
            ),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_neo4j"),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        pg_entry = body["checks"]["postgres:responseTime"][0]
        assert pg_entry["status"] == "fail"
        assert pg_entry["output"] == "connection refused"
        assert body["checks"]["valkey:responseTime"][0]["status"] == "pass"
        assert body["checks"]["neo4j:responseTime"][0]["status"] == "pass"

    def test_returns_503_and_fail_when_valkey_is_down(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey", side_effect=ConnectionError("timeout")),
            patch("api.health._probe_neo4j"),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        vk_entry = body["checks"]["valkey:responseTime"][0]
        assert vk_entry["status"] == "fail"
        assert vk_entry["output"] == "timeout"

    def test_returns_503_and_fail_when_neo4j_is_down(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch(
                "api.health._probe_neo4j",
                side_effect=RuntimeError("ServiceUnavailable"),
            ),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        neo_entry = body["checks"]["neo4j:responseTime"][0]
        assert neo_entry["status"] == "fail"
        assert neo_entry["output"] == "ServiceUnavailable"

    def test_reports_all_failures_simultaneously(self, api_client):
        with (
            patch("api.health._probe_postgres", side_effect=RuntimeError("pg down")),
            patch("api.health._probe_valkey", side_effect=RuntimeError("vk down")),
            patch("api.health._probe_neo4j", side_effect=RuntimeError("neo down")),
        ):
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        body = response.json()
        assert body["status"] == "fail"
        assert body["checks"]["postgres:responseTime"][0]["output"] == "pg down"
        assert body["checks"]["valkey:responseTime"][0]["output"] == "vk down"
        assert body["checks"]["neo4j:responseTime"][0]["output"] == "neo down"

    def test_falls_back_to_exception_class_name_when_message_is_empty(self, api_client):
        with (
            patch("api.health._probe_postgres", side_effect=RuntimeError("")),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_neo4j"),
        ):
            response = api_client.get(reverse("health-ready"))

        body = response.json()
        assert body["checks"]["postgres:responseTime"][0]["output"] == "RuntimeError"

    def test_does_not_require_authentication(self, api_client):
        with (
            patch("api.health._probe_postgres"),
            patch("api.health._probe_valkey"),
            patch("api.health._probe_neo4j"),
        ):
            api_client.credentials()
            response = api_client.get(reverse("health-ready"))

        assert response.status_code == status.HTTP_200_OK


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

    def test_neo4j_probe_calls_verify_connectivity(self):
        with patch("api.attack_paths.database.get_driver") as mock_get_driver:
            mock_get_driver.return_value.verify_connectivity.return_value = None
            assert health._probe_neo4j() is None
            mock_get_driver.return_value.verify_connectivity.assert_called_once_with()

    def test_neo4j_probe_propagates_driver_errors(self):
        with patch("api.attack_paths.database.get_driver") as mock_get_driver:
            mock_get_driver.return_value.verify_connectivity.side_effect = RuntimeError(
                "unreachable"
            )
            with pytest.raises(RuntimeError, match="unreachable"):
                health._probe_neo4j()


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
