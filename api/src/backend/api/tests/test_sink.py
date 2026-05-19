"""Tests for the attack-paths sink factory and Neo4j sink.

The sink module picks a backend per ``settings.ATTACK_PATHS_SINK_DATABASE``.
Neo4j is the default and preserves today's behavior; Neptune is opt-in and
builds dual writer/reader Bolt drivers.
"""

from unittest.mock import MagicMock, patch

import pytest

# Prime patch-target resolution. `api.attack_paths.sink/__init__.py` doesn't
# eagerly import these submodules (they're loaded on demand inside the
# factory), so `mock.patch("api.attack_paths.sink.<sub>.…")` would fail with
# AttributeError on first call. Importing here registers them as attributes
# of the package before any decorator runs.
import api.attack_paths.sink.neo4j  # noqa: F401
import api.attack_paths.sink.neptune  # noqa: F401


@pytest.fixture(autouse=True)
def reset_sink_state():
    """Reset the module-level backend singletons around each test.

    The cache lives in `api.attack_paths.sink.factory`, not on the package.
    """
    from api.attack_paths.sink import factory

    original_backend = factory._backend
    original_secondary = dict(factory._secondary_backends)
    factory._backend = None
    factory._secondary_backends.clear()
    yield
    factory._backend = original_backend
    factory._secondary_backends.clear()
    factory._secondary_backends.update(original_secondary)


class TestSinkFactory:
    def test_default_resolves_to_neo4j(self, settings):
        from api.attack_paths.sink import factory

        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"
        assert factory._resolve_setting() == "neo4j"

    def test_neptune_resolves_correctly(self, settings):
        from api.attack_paths.sink import factory

        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"
        assert factory._resolve_setting() == "neptune"

    def test_invalid_value_raises(self, settings):
        from api.attack_paths.sink import factory

        settings.ATTACK_PATHS_SINK_DATABASE = "foo"
        with pytest.raises(RuntimeError, match="ATTACK_PATHS_SINK_DATABASE"):
            factory._resolve_setting()

    @patch("api.attack_paths.sink.neo4j.neo4j.GraphDatabase.driver")
    def test_init_builds_neo4j_backend_by_default(self, mock_driver, settings):
        from api.attack_paths import sink as sink_module
        from api.attack_paths.sink.neo4j import Neo4jSink

        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"
        settings.DATABASES = {
            **settings.DATABASES,
            "neo4j": {
                "HOST": "localhost",
                "PORT": "7687",
                "USER": "neo4j",
                "PASSWORD": "pw",
            },
        }
        mock_driver.return_value = MagicMock()

        backend = sink_module.init()

        assert isinstance(backend, Neo4jSink)
        mock_driver.assert_called_once()

    @patch("api.attack_paths.sink.neptune.neptune_auth_provider")
    @patch("api.attack_paths.sink.neptune.neo4j.GraphDatabase.driver")
    def test_init_builds_neptune_backend(
        self, mock_driver, mock_auth_provider, settings
    ):
        from api.attack_paths import sink as sink_module
        from api.attack_paths.sink.neptune import NeptuneSink

        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"
        settings.DATABASES = {
            **settings.DATABASES,
            "neptune": {
                "WRITER_ENDPOINT": "writer.example",
                "READER_ENDPOINT": "reader.example",
                "PORT": "8182",
                "REGION": "eu-west-1",
            },
        }
        mock_driver.return_value = MagicMock()
        mock_auth_provider.return_value = lambda: None

        backend = sink_module.init()

        assert isinstance(backend, NeptuneSink)
        # Writer + reader endpoints both trigger driver construction
        assert mock_driver.call_count == 2
        writer_uri = mock_driver.call_args_list[0][0][0]
        reader_uri = mock_driver.call_args_list[1][0][0]
        assert writer_uri == "bolt+s://writer.example:8182"
        assert reader_uri == "bolt+s://reader.example:8182"

    @patch("api.attack_paths.sink.neptune.neptune_auth_provider")
    @patch("api.attack_paths.sink.neptune.neo4j.GraphDatabase.driver")
    def test_neptune_reader_falls_back_to_writer(
        self, mock_driver, mock_auth_provider, settings
    ):
        from api.attack_paths import sink as sink_module

        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"
        settings.DATABASES = {
            **settings.DATABASES,
            "neptune": {
                "WRITER_ENDPOINT": "writer.example",
                "READER_ENDPOINT": "",
                "PORT": "8182",
                "REGION": "eu-west-1",
            },
        }
        mock_driver.return_value = MagicMock()
        mock_auth_provider.return_value = lambda: None

        sink_module.init()

        # Only one driver call — reader aliases writer
        assert mock_driver.call_count == 1


class TestGetBackendForScan:
    """``get_backend_for_scan`` routes by the row's ``is_neptune`` flag."""

    @patch("api.attack_paths.sink.neo4j.neo4j.GraphDatabase.driver")
    def test_neo4j_scan_in_neo4j_process_uses_active_backend(
        self, mock_driver, settings
    ):
        from api.attack_paths import sink as sink_module

        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"
        settings.DATABASES = {
            **settings.DATABASES,
            "neo4j": {
                "HOST": "localhost",
                "PORT": "7687",
                "USER": "neo4j",
                "PASSWORD": "pw",
            },
        }
        mock_driver.return_value = MagicMock()

        scan = MagicMock(is_neptune=False)
        backend = sink_module.get_backend_for_scan(scan)

        assert backend is sink_module.get_backend()


def _session_ctx(session: MagicMock) -> MagicMock:
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=session)
    ctx.__exit__ = MagicMock(return_value=False)
    return ctx


class TestNeo4jSinkSyncWrites:
    def test_ensure_sync_indexes_runs_create_index_idempotent(self):
        from api.attack_paths.sink.neo4j import Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()
        session.run.return_value = MagicMock()
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            sink.ensure_sync_indexes("db-tenant-x")

        query = session.run.call_args.args[0]
        assert "CREATE INDEX" in query
        assert "IF NOT EXISTS" in query
        assert "`_ProviderResource`" in query
        assert "`_provider_element_id`" in query

    def test_write_nodes_skips_empty_batch(self):
        from api.attack_paths.sink.neo4j import Neo4jSink

        sink = Neo4jSink()
        with patch.object(sink, "get_session") as get_session:
            sink.write_nodes("db-tenant-x", "`AWSUser`", [])
            get_session.assert_not_called()

    def test_write_nodes_merges_on_provider_resource_label(self):
        from api.attack_paths.sink.neo4j import Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            sink.write_nodes(
                "db-tenant-x",
                "`AWSUser`:`_ProviderResource`",
                [{"provider_element_id": "p:e", "props": {"k": "v"}}],
            )

        query, params = session.run.call_args.args
        assert "MERGE (n:`_ProviderResource`" in query
        assert "`_provider_element_id`: row.provider_element_id" in query
        assert "SET n:`AWSUser`:`_ProviderResource`" in query
        assert params == {"rows": [{"provider_element_id": "p:e", "props": {"k": "v"}}]}

    def test_write_relationships_scopes_endpoints_by_provider_label(self):
        from api.attack_paths.sink.neo4j import Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()
        provider_id = "00000000-0000-0000-0000-000000000abc"
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            sink.write_relationships(
                "db-tenant-x",
                "RESOURCE",
                provider_id,
                [
                    {
                        "start_element_id": "s",
                        "end_element_id": "e",
                        "provider_element_id": "pe",
                        "props": {},
                    }
                ],
            )

        query = session.run.call_args.args[0]
        assert ":`_Provider_00000000000000000000000000000abc`" in query
        assert ":RESOURCE" in query.replace("`", "")
        assert "MERGE (s)-[r:`RESOURCE`" in query


class TestNeptuneSinkSyncWrites:
    def test_ensure_sync_indexes_is_noop(self):
        from api.attack_paths.sink.neptune import NeptuneSink

        sink = NeptuneSink()
        with patch.object(sink, "get_session") as get_session:
            sink.ensure_sync_indexes("ignored")
            get_session.assert_not_called()

    def test_write_nodes_merges_on_neptune_id_with_provider_resource_label(self):
        from api.attack_paths.sink.neptune import NeptuneSink

        sink = NeptuneSink()
        session = MagicMock()
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            sink.write_nodes(
                "ignored",
                "`AWSUser`",
                [{"provider_element_id": "p:e", "props": {"k": "v"}}],
            )

        query = session.run.call_args.args[0]
        # Neptune assigns a default `vertex` label to any unlabeled node,
        # so the MERGE must pin a real label at creation time.
        assert "MERGE (n:`_ProviderResource` {`~id`: row.provider_element_id})" in query
        assert "SET n:`AWSUser`" in query
        assert "SET n.`_provider_element_id` = row.provider_element_id" in query

    def test_write_relationships_matches_endpoints_by_id(self):
        from api.attack_paths.sink.neptune import NeptuneSink

        sink = NeptuneSink()
        session = MagicMock()
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            sink.write_relationships(
                "ignored",
                "RESOURCE",
                "provider-1",
                [
                    {
                        "start_element_id": "s",
                        "end_element_id": "e",
                        "provider_element_id": "pe",
                        "props": {},
                    }
                ],
            )

        query = session.run.call_args.args[0]
        assert "MATCH (s) WHERE id(s) = row.start_element_id" in query
        assert "MATCH (e) WHERE id(e) = row.end_element_id" in query
        assert "MERGE (s)-[r:`RESOURCE`" in query


class TestNeptuneSinkDropSubgraph:
    def test_drop_subgraph_deletes_rels_before_nodes_in_bounded_batches(self):
        from api.attack_paths.sink.neptune import NeptuneSink

        sink = NeptuneSink()
        session = MagicMock()

        rel_record_first = MagicMock()
        rel_record_first.__getitem__ = lambda _self, key: 50
        rel_record_drain = MagicMock()
        rel_record_drain.__getitem__ = lambda _self, key: 0
        node_record_first = MagicMock()
        node_record_first.__getitem__ = lambda _self, key: 10
        node_record_drain = MagicMock()
        node_record_drain.__getitem__ = lambda _self, key: 0

        run_results = [
            MagicMock(single=MagicMock(return_value=rel_record_first)),
            MagicMock(single=MagicMock(return_value=rel_record_drain)),
            MagicMock(single=MagicMock(return_value=node_record_first)),
            MagicMock(single=MagicMock(return_value=node_record_drain)),
        ]
        session.run.side_effect = run_results

        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            deleted = sink.drop_subgraph("ignored", "provider-1")

        assert deleted == 10
        first_query = session.run.call_args_list[0].args[0]
        assert "DELETE r" in first_query
        assert "DETACH DELETE" not in first_query
        third_query = session.run.call_args_list[2].args[0]
        assert "DELETE n" in third_query


class TestNeo4jSinkDropSubgraph:
    """Neo4j drop runs a single-phase ``DETACH DELETE`` loop, bounded by batch size."""

    def test_drop_subgraph_batches_until_empty_and_returns_total(self):
        from api.attack_paths.sink.neo4j import Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()

        first_record = MagicMock()
        first_record.get = lambda key, default=0: 10
        drain_record = MagicMock()
        drain_record.get = lambda key, default=0: 0
        session.run.side_effect = [
            MagicMock(single=MagicMock(return_value=first_record)),
            MagicMock(single=MagicMock(return_value=drain_record)),
        ]

        provider_id = "00000000-0000-0000-0000-000000000abc"
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            deleted = sink.drop_subgraph("db-tenant-x", provider_id)

        assert deleted == 10
        first_query = session.run.call_args_list[0].args[0]
        assert "DETACH DELETE n" in first_query
        assert ":`_Provider_00000000000000000000000000000abc`" in first_query
        assert session.run.call_count == 2

    def test_drop_subgraph_returns_zero_when_database_does_not_exist(self):
        from api.attack_paths.database import GraphDatabaseQueryException
        from api.attack_paths.sink.neo4j import DATABASE_NOT_FOUND_CODE, Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()
        session.run.side_effect = GraphDatabaseQueryException(
            message="db missing", code=DATABASE_NOT_FOUND_CODE
        )

        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            deleted = sink.drop_subgraph("db-tenant-missing", "provider-1")

        assert deleted == 0


class TestSinkHasProviderData:
    """``has_provider_data`` is the read-path probe used by API views."""

    def test_neo4j_returns_true_when_provider_node_exists(self):
        from api.attack_paths.sink.neo4j import Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()
        session.run.return_value.single.return_value = MagicMock()
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            present = sink.has_provider_data(
                "db-tenant-x", "00000000-0000-0000-0000-000000000abc"
            )

        assert present is True
        query = session.run.call_args.args[0]
        assert ":`_Provider_00000000000000000000000000000abc`" in query

    def test_neo4j_returns_false_when_database_does_not_exist(self):
        from api.attack_paths.database import GraphDatabaseQueryException
        from api.attack_paths.sink.neo4j import DATABASE_NOT_FOUND_CODE, Neo4jSink

        sink = Neo4jSink()
        session = MagicMock()
        session.run.side_effect = GraphDatabaseQueryException(
            message="db missing", code=DATABASE_NOT_FOUND_CODE
        )

        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            present = sink.has_provider_data("db-tenant-missing", "provider-1")

        assert present is False

    def test_neptune_returns_true_when_provider_node_exists(self):
        from api.attack_paths.sink.neptune import NeptuneSink

        sink = NeptuneSink()
        session = MagicMock()
        session.run.return_value.single.return_value = MagicMock()
        with patch.object(sink, "get_session", return_value=_session_ctx(session)):
            present = sink.has_provider_data("ignored", "provider-1")

        assert present is True


class TestGetBackendForScanCutover:
    """``get_backend_for_scan`` routes by the row's recorded sink, not the live setting.

    During the Neptune cutover, scans written under one backend stay queryable
    even when the process is later reconfigured. The active backend serves
    matching scans; a cached secondary serves the rest.
    """

    def test_neptune_scan_on_neo4j_process_uses_neptune_secondary(self, settings):
        from api.attack_paths.sink import factory

        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"
        active_neo4j = MagicMock(name="neo4j-active")
        factory._backend = active_neo4j

        secondary_neptune = MagicMock(name="neptune-secondary")
        with patch.object(factory, "_build_backend", return_value=secondary_neptune):
            scan = MagicMock(is_neptune=True)
            backend = factory.get_backend_for_scan(scan)

        assert backend is secondary_neptune
        assert backend is not active_neo4j

    def test_neo4j_scan_on_neptune_process_uses_neo4j_secondary(self, settings):
        from api.attack_paths.sink import factory

        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"
        active_neptune = MagicMock(name="neptune-active")
        factory._backend = active_neptune

        secondary_neo4j = MagicMock(name="neo4j-secondary")
        with patch.object(factory, "_build_backend", return_value=secondary_neo4j):
            scan = MagicMock(is_neptune=False)
            backend = factory.get_backend_for_scan(scan)

        assert backend is secondary_neo4j
        assert backend is not active_neptune


class TestSinkVerifyConnectivity:
    """The readiness probe calls ``verify_connectivity`` through the shim.

    Neo4j checks its single driver; Neptune checks the reader (the API read
    path), which on single-endpoint clusters aliases the writer.
    """

    @patch("api.attack_paths.sink.neo4j.neo4j.GraphDatabase.driver")
    def test_neo4j_verifies_its_driver(self, mock_driver, settings):
        from api.attack_paths.sink.neo4j import Neo4jSink

        settings.DATABASES = {
            **settings.DATABASES,
            "neo4j": {
                "HOST": "localhost",
                "PORT": "7687",
                "USER": "neo4j",
                "PASSWORD": "pw",
            },
        }
        driver = MagicMock()
        mock_driver.return_value = driver

        sink = Neo4jSink()
        sink.init()
        driver.verify_connectivity.reset_mock()  # ignore the eager init check
        sink.verify_connectivity()

        driver.verify_connectivity.assert_called_once_with()

    @patch("api.attack_paths.sink.neptune.neptune_auth_provider")
    @patch("api.attack_paths.sink.neptune.neo4j.GraphDatabase.driver")
    def test_neptune_verifies_reader_not_writer(
        self, mock_driver, mock_auth_provider, settings
    ):
        from api.attack_paths.sink.neptune import NeptuneSink

        settings.DATABASES = {
            **settings.DATABASES,
            "neptune": {
                "WRITER_ENDPOINT": "writer.example",
                "READER_ENDPOINT": "reader.example",
                "PORT": "8182",
                "REGION": "eu-west-1",
            },
        }
        writer, reader = MagicMock(name="writer"), MagicMock(name="reader")
        mock_driver.side_effect = [writer, reader]
        mock_auth_provider.return_value = lambda: None

        sink = NeptuneSink()
        sink.init()
        writer.verify_connectivity.reset_mock()
        reader.verify_connectivity.reset_mock()

        sink.verify_connectivity()

        reader.verify_connectivity.assert_called_once_with()
        writer.verify_connectivity.assert_not_called()


class TestSinkInitToleratesUnreachableSink:
    """Init must not crash the process when the sink is down at boot.

    Same degradation model as Postgres: the driver is retained and
    reconnects lazily; /health/ready surfaces the outage until it recovers.
    """

    @patch("api.attack_paths.sink.neo4j.neo4j.GraphDatabase.driver")
    def test_neo4j_init_continues_when_verify_fails(self, mock_driver, settings):
        from api.attack_paths.sink.neo4j import Neo4jSink

        settings.DATABASES = {
            **settings.DATABASES,
            "neo4j": {
                "HOST": "localhost",
                "PORT": "7687",
                "USER": "neo4j",
                "PASSWORD": "pw",
            },
        }
        driver = MagicMock()
        driver.verify_connectivity.side_effect = RuntimeError("unreachable")
        mock_driver.return_value = driver

        sink = Neo4jSink()
        # Must not raise.
        assert sink.init() is driver
        assert sink._driver is driver

    @patch("api.attack_paths.sink.neptune.neptune_auth_provider")
    @patch("api.attack_paths.sink.neptune.neo4j.GraphDatabase.driver")
    def test_neptune_init_continues_when_verify_fails(
        self, mock_driver, mock_auth_provider, settings
    ):
        from api.attack_paths.sink.neptune import NeptuneSink

        settings.DATABASES = {
            **settings.DATABASES,
            "neptune": {
                "WRITER_ENDPOINT": "writer.example",
                "READER_ENDPOINT": "reader.example",
                "PORT": "8182",
                "REGION": "eu-west-1",
            },
        }
        driver = MagicMock()
        driver.verify_connectivity.side_effect = RuntimeError("unreachable")
        mock_driver.return_value = driver
        mock_auth_provider.return_value = lambda: None

        sink = NeptuneSink()
        # Must not raise; both drivers retained.
        sink.init()
        assert sink._writer is not None
        assert sink._reader is not None


class TestNeptuneAdminNoOps:
    """Neptune is single-database; admin DDL has no work to do."""

    @pytest.mark.parametrize("method", ["create_database", "drop_database"])
    def test_admin_ops_return_none_without_touching_a_session(self, method):
        from api.attack_paths.sink.neptune import NeptuneSink

        sink = NeptuneSink()
        with patch.object(sink, "get_session") as get_session:
            assert getattr(sink, method)("ignored") is None
            get_session.assert_not_called()
