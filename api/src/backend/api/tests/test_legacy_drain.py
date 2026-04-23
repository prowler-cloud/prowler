"""Tests for the phase-1 legacy Neo4j drain.

# TODO: Drop after Neptune migration is finished
"""
from unittest.mock import MagicMock, patch

import pytest


TENANT_ID = "00000000-0000-0000-0000-000000000001"
PROVIDER_ID = "00000000-0000-0000-0000-000000000002"


@pytest.fixture
def mock_sink():
    with patch(
        "api.attack_paths.sink.neo4j.Neo4jSink"
    ) as Neo4jSink:
        sink_instance = MagicMock()
        Neo4jSink.return_value = sink_instance
        yield sink_instance


class TestDrainLegacyNeo4jForProvider:
    def test_returns_early_when_tenant_db_has_no_data(self, mock_sink):
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        # Session used by _has_any_data returns no rows
        session_cm = MagicMock()
        result = MagicMock()
        result.single.return_value = None
        session_cm.__enter__.return_value.run.return_value = result
        mock_sink.get_session.return_value = session_cm

        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)

        mock_sink.drop_subgraph.assert_not_called()
        mock_sink.drop_database.assert_not_called()

    def test_drops_subgraph_when_provider_data_present(self, mock_sink):
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        # First _has_any_data -> True, has_provider_data -> True,
        # drop_subgraph invoked, second _has_any_data -> False -> drop tenant DB.
        responses = iter([MagicMock(), None])  # first .single() returns any, second None

        def run(_query):
            result = MagicMock()
            result.single.return_value = next(responses)
            return result

        session_cm = MagicMock()
        session_cm.__enter__.return_value.run.side_effect = run
        mock_sink.get_session.return_value = session_cm
        mock_sink.has_provider_data.return_value = True
        mock_sink.drop_subgraph.return_value = 42

        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)

        mock_sink.drop_subgraph.assert_called_once()
        mock_sink.drop_database.assert_called_once()

    def test_swallows_exceptions(self, mock_sink):
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        mock_sink.get_session.side_effect = RuntimeError("boom")

        # Must not raise — Neptune write already succeeded, drain is opportunistic
        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)
