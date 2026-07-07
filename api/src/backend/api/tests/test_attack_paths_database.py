"""Tests for the attack-paths database facade.

After the Neptune port, `api.attack_paths.database` is a thin routing shim
over `api.attack_paths.ingest` (cartography temp DB, always Neo4j) and
`api.attack_paths.sink` (configurable Neo4j or Neptune). The facade's
contract is routing by database-name prefix and the public exception
hierarchy; sink-internal behavior is exercised in `test_sink.py`.
"""

from unittest.mock import MagicMock, patch

import api.attack_paths.database as db_module
import pytest


class TestDatabaseNameHelper:
    def test_tenant_name_lowercases_uuid(self):
        assert (
            db_module.get_database_name("ABC-123", temporary=False)
            == "db-tenant-abc-123"
        )

    def test_temporary_name_uses_tmp_scan_prefix(self):
        assert (
            db_module.get_database_name("XYZ-789", temporary=True)
            == "db-tmp-scan-xyz-789"
        )


class TestExceptionHierarchy:
    """`tasks/` and `api/v1/views.py` import these from the facade."""

    def test_write_query_is_graph_database_exception(self):
        assert issubclass(
            db_module.WriteQueryNotAllowedException,
            db_module.GraphDatabaseQueryException,
        )

    def test_client_statement_is_graph_database_exception(self):
        assert issubclass(
            db_module.ClientStatementException, db_module.GraphDatabaseQueryException
        )

    def test_exception_str_includes_code_when_set(self):
        exc = db_module.GraphDatabaseQueryException(
            message="boom", code="Neo.ClientError.X.Y"
        )
        assert str(exc) == "Neo.ClientError.X.Y: boom"

    def test_exception_str_falls_back_to_message_without_code(self):
        exc = db_module.GraphDatabaseQueryException(message="boom")
        assert str(exc) == "boom"


class TestExecuteReadQueryRoutes:
    def test_execute_read_query_delegates_to_sink(self, sink_backend_stub):
        sink_backend_stub.execute_read_query.return_value = "graph"

        result = db_module.execute_read_query(
            "db-tenant-abc", "MATCH (n) RETURN n", {"provider_uid": "123"}
        )

        sink_backend_stub.execute_read_query.assert_called_once_with(
            "db-tenant-abc", "MATCH (n) RETURN n", {"provider_uid": "123"}
        )
        assert result == "graph"

    def test_execute_read_query_defaults_parameters_to_none(self, sink_backend_stub):
        db_module.execute_read_query("db-tenant-abc", "MATCH (n) RETURN n")

        sink_backend_stub.execute_read_query.assert_called_once_with(
            "db-tenant-abc", "MATCH (n) RETURN n", None
        )


class TestScanDatabaseAvailability:
    def test_verify_scan_databases_available_checks_ingest_and_sink(self):
        with (
            patch("api.attack_paths.database.ingest") as mock_ingest,
            patch("api.attack_paths.database.get_driver") as mock_get_driver,
        ):
            db_module.verify_scan_databases_available()

        mock_ingest.get_driver.return_value.verify_connectivity.assert_called_once_with()
        mock_get_driver.return_value.verify_connectivity.assert_called_once_with()

    def test_verify_scan_databases_available_raises_when_ingest_is_down(self):
        with (
            patch("api.attack_paths.database.ingest") as mock_ingest,
            patch("api.attack_paths.database.get_driver"),
        ):
            mock_ingest.get_driver.return_value.verify_connectivity.side_effect = (
                RuntimeError("ingest down")
            )

            with pytest.raises(RuntimeError) as exc:
                db_module.verify_scan_databases_available()

        assert "Attack Paths graph database unavailable before scan start" in str(
            exc.value
        )
        assert "ingest Neo4j: ingest down" in str(exc.value)

    def test_verify_scan_databases_available_raises_when_sink_is_down(self, settings):
        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"

        with (
            patch("api.attack_paths.database.ingest"),
            patch("api.attack_paths.database.get_driver") as mock_get_driver,
        ):
            mock_get_driver.return_value.verify_connectivity.side_effect = RuntimeError(
                "writer down"
            )

            with pytest.raises(RuntimeError) as exc:
                db_module.verify_scan_databases_available()

        assert "sink neptune: writer down" in str(exc.value)

    def test_verify_scan_databases_available_reports_both_failures(self, settings):
        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"

        with (
            patch("api.attack_paths.database.ingest") as mock_ingest,
            patch("api.attack_paths.database.get_driver") as mock_get_driver,
        ):
            mock_ingest.get_driver.return_value.verify_connectivity.side_effect = (
                RuntimeError("ingest down")
            )
            mock_get_driver.return_value.verify_connectivity.side_effect = RuntimeError(
                "sink down"
            )

            with pytest.raises(RuntimeError) as exc:
                db_module.verify_scan_databases_available()

        assert "ingest Neo4j: ingest down" in str(exc.value)
        assert "sink neo4j: sink down" in str(exc.value)


class TestSinkOperationsDelegation:
    def test_has_provider_data_delegates_to_sink(self, sink_backend_stub):
        sink_backend_stub.has_provider_data.return_value = True

        assert db_module.has_provider_data("db-tenant-abc", "provider-123") is True
        sink_backend_stub.has_provider_data.assert_called_once_with(
            "db-tenant-abc", "provider-123"
        )

    def test_drop_subgraph_delegates_to_sink(self, sink_backend_stub):
        sink_backend_stub.drop_subgraph.return_value = 42

        assert db_module.drop_subgraph("db-tenant-abc", "provider-123") == 42
        sink_backend_stub.drop_subgraph.assert_called_once_with(
            "db-tenant-abc", "provider-123"
        )


class TestRoutingByDatabasePrefix:
    """`db-tmp-scan-*` and `None` route to ingest; everything else to sink."""

    def test_create_database_routes_temp_to_ingest(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            db_module.create_database("db-tmp-scan-uuid-1")

        mock_ingest.create_database.assert_called_once_with("db-tmp-scan-uuid-1")
        sink_backend_stub.create_database.assert_not_called()

    def test_create_database_routes_tenant_to_sink(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            db_module.create_database("db-tenant-abc")

        sink_backend_stub.create_database.assert_called_once_with("db-tenant-abc")
        mock_ingest.create_database.assert_not_called()

    def test_drop_database_routes_temp_to_ingest(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            db_module.drop_database("db-tmp-scan-uuid-1")

        mock_ingest.drop_database.assert_called_once_with("db-tmp-scan-uuid-1")
        sink_backend_stub.drop_database.assert_not_called()

    def test_drop_database_routes_tenant_to_sink(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            db_module.drop_database("db-tenant-abc")

        sink_backend_stub.drop_database.assert_called_once_with("db-tenant-abc")
        mock_ingest.drop_database.assert_not_called()

    def test_clear_cache_routes_temp_to_ingest(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            db_module.clear_cache("db-tmp-scan-uuid-1")

        mock_ingest.clear_cache.assert_called_once_with("db-tmp-scan-uuid-1")
        sink_backend_stub.clear_cache.assert_not_called()

    def test_clear_cache_routes_tenant_to_sink(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            db_module.clear_cache("db-tenant-abc")

        sink_backend_stub.clear_cache.assert_called_once_with("db-tenant-abc")
        mock_ingest.clear_cache.assert_not_called()

    def test_get_session_routes_temp_to_ingest(self, sink_backend_stub):
        sentinel = MagicMock()
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            mock_ingest.get_session.return_value = sentinel

            result = db_module.get_session("db-tmp-scan-uuid-1")

        assert result is sentinel
        mock_ingest.get_session.assert_called_once()
        sink_backend_stub.get_session.assert_not_called()

    def test_get_session_routes_none_to_ingest(self, sink_backend_stub):
        sentinel = MagicMock()
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            mock_ingest.get_session.return_value = sentinel

            result = db_module.get_session(None)

        assert result is sentinel
        sink_backend_stub.get_session.assert_not_called()

    def test_get_ingest_uri_delegates_to_ingest(self, sink_backend_stub):
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            mock_ingest.get_uri.return_value = "bolt://neo4j:7687"

            assert db_module.get_ingest_uri() == "bolt://neo4j:7687"

            mock_ingest.get_uri.assert_called_once_with()

    def test_get_session_routes_tenant_to_sink(self, sink_backend_stub):
        sentinel = MagicMock()
        sink_backend_stub.get_session.return_value = sentinel
        with patch("api.attack_paths.database.ingest") as mock_ingest:
            result = db_module.get_session("db-tenant-abc")

        assert result is sentinel
        mock_ingest.get_session.assert_not_called()
