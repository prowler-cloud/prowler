"""Tests for the cutover-window legacy Neo4j drain.

# TODO: drop after Neptune cutover
"""

from unittest.mock import MagicMock, patch

import pytest


TENANT_ID = "00000000-0000-0000-0000-000000000001"
PROVIDER_ID = "00000000-0000-0000-0000-000000000002"


@pytest.fixture
def mock_sink():
    with patch("api.attack_paths.sink.neo4j.Neo4jSink") as Neo4jSink:
        sink_instance = MagicMock()
        Neo4jSink.return_value = sink_instance
        yield sink_instance


class TestDrainLegacyNeo4jForProvider:
    def test_no_drop_when_tenant_db_has_no_provider_data_and_is_not_empty(
        self, mock_sink
    ):
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        # No data for this provider, but the tenant DB still holds other
        # providers' data → `_exists_and_empty` returns False → no drop_database.
        mock_sink.has_provider_data.return_value = False

        session_cm = MagicMock()
        result = MagicMock()
        result.single.return_value = MagicMock()  # rows present → DB not empty
        session_cm.__enter__.return_value.run.return_value = result
        mock_sink.get_session.return_value = session_cm

        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)

        mock_sink.drop_subgraph.assert_not_called()
        mock_sink.drop_database.assert_not_called()

    def test_drops_subgraph_when_provider_data_present(self, mock_sink):
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        # has_provider_data → True → drop_subgraph runs.
        # Afterwards `_exists_and_empty` runs once: single() returning None
        # means the DB is empty → drop_database fires.
        session_cm = MagicMock()
        result = MagicMock()
        result.single.return_value = None
        session_cm.__enter__.return_value.run.return_value = result
        mock_sink.get_session.return_value = session_cm
        mock_sink.has_provider_data.return_value = True
        mock_sink.drop_subgraph.return_value = 42

        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)

        mock_sink.drop_subgraph.assert_called_once()
        mock_sink.drop_database.assert_called_once()

    def test_drops_subgraph_but_keeps_db_when_other_providers_remain(self, mock_sink):
        """The DB exists and still holds another provider's data: drop the
        subgraph but leave the DB in place (`_exists_and_empty` returns False)."""
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        session_cm = MagicMock()
        result = MagicMock()
        result.single.return_value = MagicMock()  # rows remain → not empty
        session_cm.__enter__.return_value.run.return_value = result
        mock_sink.get_session.return_value = session_cm
        mock_sink.has_provider_data.return_value = True
        mock_sink.drop_subgraph.return_value = 42

        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)

        mock_sink.drop_subgraph.assert_called_once()
        mock_sink.drop_database.assert_not_called()

    def test_swallows_exceptions(self, mock_sink):
        from tasks.jobs.attack_paths.legacy_drain import (
            drain_legacy_neo4j_for_provider,
        )

        mock_sink.get_session.side_effect = RuntimeError("boom")

        # Must not raise — Neptune write already succeeded, drain is opportunistic
        drain_legacy_neo4j_for_provider(TENANT_ID, PROVIDER_ID)
