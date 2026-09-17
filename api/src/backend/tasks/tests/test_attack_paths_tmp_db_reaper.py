from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from api.attack_paths.database import TEMP_DB_PREFIX
from api.models import AttackPathsScan, StateChoices
from api.uuid_utils import datetime_to_uuid7
from config.django.base import ATTACK_PATHS_TMP_DB_REAP_SAFETY_MARGIN_HOURS

MARGIN = timedelta(hours=ATTACK_PATHS_TMP_DB_REAP_SAFETY_MARGIN_HOURS)


def _tmp_db_name(scan_uuid) -> str:
    return f"{TEMP_DB_PREFIX}{scan_uuid}"


@pytest.mark.django_db
class TestReapOrphanedTmpDatabases:
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_ignores_databases_without_the_temp_prefix(self, mock_list, mock_drop):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        mock_list.return_value = ["db-tenant-abc123", "system", "neo4j"]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}
        mock_drop.assert_not_called()

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_drops_temp_db_with_no_scan_row_past_safety_margin(
        self, mock_list, mock_drop
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        old_scan_id = datetime_to_uuid7(
            datetime.now(tz=UTC) - MARGIN - timedelta(hours=1)
        )
        database = _tmp_db_name(old_scan_id)
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 1, "databases": [database]}
        mock_drop.assert_called_once_with(database)

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_preserves_temp_db_with_no_scan_row_inside_safety_margin(
        self, mock_list, mock_drop
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        recent_scan_id = datetime_to_uuid7(datetime.now(tz=UTC) - timedelta(minutes=5))
        database = _tmp_db_name(recent_scan_id)
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}
        mock_drop.assert_not_called()

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_preserves_temp_db_with_unparseable_scan_id(self, mock_list, mock_drop):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        database = f"{TEMP_DB_PREFIX}not-a-uuid"
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}
        mock_drop.assert_not_called()

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_drops_terminal_scan_past_safety_margin(
        self, mock_list, mock_drop, tenants_fixture, aws_provider
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        tenant = tenants_fixture[0]
        old_updated_at = datetime.now(tz=UTC) - MARGIN - timedelta(hours=1)
        scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            state=StateChoices.COMPLETED,
        )
        AttackPathsScan.objects.filter(id=scan.id).update(updated_at=old_updated_at)

        database = _tmp_db_name(scan.id)
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 1, "databases": [database]}
        mock_drop.assert_called_once_with(database)

    @pytest.mark.parametrize(
        "state",
        [StateChoices.FAILED, StateChoices.CANCELLED],
    )
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_drops_other_terminal_states_past_safety_margin(
        self, mock_list, mock_drop, tenants_fixture, aws_provider, state
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        tenant = tenants_fixture[0]
        old_updated_at = datetime.now(tz=UTC) - MARGIN - timedelta(hours=1)
        scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            state=state,
        )
        AttackPathsScan.objects.filter(id=scan.id).update(updated_at=old_updated_at)

        database = _tmp_db_name(scan.id)
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result["dropped_count"] == 1
        mock_drop.assert_called_once_with(database)

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_preserves_terminal_scan_inside_safety_margin(
        self, mock_list, mock_drop, tenants_fixture, aws_provider
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        tenant = tenants_fixture[0]
        scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            state=StateChoices.COMPLETED,
        )

        database = _tmp_db_name(scan.id)
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}
        mock_drop.assert_not_called()

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_never_drops_an_executing_scan_regardless_of_age(
        self, mock_list, mock_drop, tenants_fixture, aws_provider
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        tenant = tenants_fixture[0]
        very_old = datetime.now(tz=UTC) - timedelta(days=30)
        scan = AttackPathsScan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            state=StateChoices.EXECUTING,
        )
        AttackPathsScan.objects.filter(id=scan.id).update(updated_at=very_old)

        database = _tmp_db_name(scan.id)
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}
        mock_drop.assert_not_called()

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_one_failed_drop_does_not_stop_the_rest_of_the_sweep(
        self, mock_list, mock_drop
    ):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        old_time = datetime.now(tz=UTC) - MARGIN - timedelta(hours=1)
        failing_scan_id = datetime_to_uuid7(old_time)
        succeeding_scan_id = datetime_to_uuid7(old_time)
        failing_db = _tmp_db_name(failing_scan_id)
        succeeding_db = _tmp_db_name(succeeding_scan_id)
        mock_list.return_value = [failing_db, succeeding_db]
        mock_drop.side_effect = [Exception("boom"), None]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 1, "databases": [succeeding_db]}
        assert mock_drop.call_count == 2

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_returns_empty_result_when_listing_databases_fails(self, mock_list):
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        mock_list.side_effect = Exception("neo4j unreachable")

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}

    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.drop_database")
    @patch("tasks.jobs.attack_paths.tmp_db_reaper.graph_database.list_databases")
    def test_preserves_temp_db_with_random_uuid_and_no_row(self, mock_list, mock_drop):
        """A non-UUIDv7 id with no matching row has no reliable timestamp, so it
        must be left alone rather than guessed at."""
        from tasks.jobs.attack_paths.tmp_db_reaper import reap_orphaned_tmp_databases

        database = _tmp_db_name(uuid4())
        mock_list.return_value = [database]

        result = reap_orphaned_tmp_databases()

        assert result == {"dropped_count": 0, "databases": []}
        mock_drop.assert_not_called()


class TestReapOrphanedTmpDatabasesTask:
    @patch(
        "tasks.tasks.reap_orphaned_tmp_databases",
        return_value={"dropped_count": 2, "databases": ["db-tmp-scan-a"]},
    )
    def test_task_invokes_the_reaper(self, mock_reap):
        from tasks.tasks import reap_orphaned_attack_paths_tmp_databases_task

        result = reap_orphaned_attack_paths_tmp_databases_task.run()

        assert result == {"dropped_count": 2, "databases": ["db-tmp-scan-a"]}
        mock_reap.assert_called_once_with()
