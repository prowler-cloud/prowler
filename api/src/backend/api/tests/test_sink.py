"""Tests for the attack-paths sink factory and Neo4j sink.

The sink module picks a backend per ``settings.ATTACK_PATHS_SINK_DATABASE``.
Neo4j is the default and preserves today's behavior; Neptune is opt-in and
builds dual writer/reader Bolt drivers.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def reset_sink_state():
    """Reset the module-level backend singletons around each test."""
    from api.attack_paths import sink as sink_module

    original_backend = sink_module._backend
    original_secondary = dict(sink_module._secondary_backends)
    sink_module._backend = None
    sink_module._secondary_backends.clear()
    yield
    sink_module._backend = original_backend
    sink_module._secondary_backends.clear()
    sink_module._secondary_backends.update(original_secondary)


class TestSinkFactory:
    def test_default_resolves_to_neo4j(self, settings):
        from api.attack_paths import sink as sink_module

        settings.ATTACK_PATHS_SINK_DATABASE = "neo4j"
        assert sink_module._resolve_setting() == "neo4j"

    def test_neptune_resolves_correctly(self, settings):
        from api.attack_paths import sink as sink_module

        settings.ATTACK_PATHS_SINK_DATABASE = "neptune"
        assert sink_module._resolve_setting() == "neptune"

    def test_invalid_value_raises(self, settings):
        from api.attack_paths import sink as sink_module

        settings.ATTACK_PATHS_SINK_DATABASE = "foo"
        with pytest.raises(RuntimeError, match="ATTACK_PATHS_SINK_DATABASE"):
            sink_module._resolve_setting()

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
