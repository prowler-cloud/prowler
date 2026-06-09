from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from celery import states
from django.test import override_settings
from django_celery_results.models import TaskResult

from tasks.jobs.orphan_recovery import (
    _decode_celery_field,
    _reconcile_task_results,
    _recovery_attempt_count,
    advisory_lock,
    is_worker_alive,
    reconcile_orphans,
    reenqueueable_tasks,
)


def _orphan_result(*, name, kwargs, worker, created_minutes_ago, status=states.STARTED):
    """Create a TaskResult mimicking an in-flight task, backdated past the grace."""
    tr = TaskResult.objects.create(
        task_id=str(uuid4()),
        status=status,
        task_name=name,
        worker=worker,
        task_kwargs=repr(kwargs),
        task_args=repr([]),
    )
    TaskResult.objects.filter(pk=tr.pk).update(
        date_created=datetime.now(tz=timezone.utc)
        - timedelta(minutes=created_minutes_ago)
    )
    tr.refresh_from_db()
    return tr


@pytest.mark.django_db
class TestDecodeCeleryField:
    def test_decodes_single_encoded_repr(self):
        assert _decode_celery_field("{'tenant_id': 'abc'}", {}) == {"tenant_id": "abc"}

    def test_decodes_double_encoded(self):
        import json

        stored = json.dumps(repr({"tenant_id": "abc", "scan_id": "s1"}))
        assert _decode_celery_field(stored, {}) == {"tenant_id": "abc", "scan_id": "s1"}

    def test_empty_returns_default(self):
        assert _decode_celery_field(None, {}) == {}
        assert _decode_celery_field("", []) == []

    def test_unparseable_raises(self):
        with pytest.raises(ValueError):
            _decode_celery_field("<<not a literal>>", {})


@pytest.mark.django_db
class TestReconcileTaskResults:
    def _patches(self, alive):
        """Patch worker liveness, revoke, and the task registry for re-enqueue."""
        mock_app = MagicMock()
        mock_task = MagicMock()
        mock_app.tasks.get.return_value = mock_task
        return (
            patch("tasks.jobs.orphan_recovery.is_worker_alive", return_value=alive),
            patch("tasks.jobs.orphan_recovery.revoke_task"),
            patch("tasks.jobs.orphan_recovery.current_app", mock_app),
            mock_task,
        )

    def test_recovers_non_scan_task(self, tenants_fixture):
        """A NON-scan task (tenant-deletion) left orphaned is re-enqueued too."""
        tenant = tenants_fixture[0]
        tr = _orphan_result(
            name="tenant-deletion",
            kwargs={"tenant_id": str(tenant.id)},
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=1),
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["recovered"]
        tr.refresh_from_db()
        assert tr.status == states.REVOKED  # stale result cleared (no pending alert)
        mock_task.apply_async.assert_called_once()
        call = mock_task.apply_async.call_args.kwargs
        assert call["kwargs"] == {"tenant_id": str(tenant.id)}
        assert call["task_id"] != tr.task_id  # fresh task id

    def test_external_integration_task_is_not_reenqueued_by_default(
        self, tenants_fixture
    ):
        """External side-effect tasks without proven idempotency stay terminal.

        integration-s3 rebuilds its upload from worker-local files that do not
        survive the crash, so re-enqueuing it would upload nothing.
        """
        tr = _orphan_result(
            name="integration-s3",
            kwargs={
                "tenant_id": str(tenants_fixture[0].id),
                "provider_id": str(uuid4()),
                "output_directory": "/tmp/gone",
            },
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=1),
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["failed"]
        mock_task.apply_async.assert_not_called()

    @override_settings(TASK_RECOVERY_SUMMARIES_ENABLED=False)
    def test_disabled_group_task_is_not_reenqueued(self, tenants_fixture):
        """A task whose group feature flag is off stays terminal, not re-enqueued."""
        tr = _orphan_result(
            name="scan-summary",
            kwargs={
                "tenant_id": str(tenants_fixture[0].id),
                "scan_id": str(uuid4()),
            },
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=1),
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["failed"]
        mock_task.apply_async.assert_not_called()

    @override_settings(TASK_RECOVERY_SUMMARIES_ENABLED=False)
    def test_disabled_group_task_does_not_consume_recovery_attempt(
        self, tenants_fixture
    ):
        """A disabled-group task is failed without incrementing its Valkey attempt
        counter, so re-enabling the group does not start it at the cap."""
        tr = _orphan_result(
            name="scan-summary",
            kwargs={"tenant_id": str(tenants_fixture[0].id), "scan_id": str(uuid4())},
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count") as mock_count,
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["failed"]
        mock_count.assert_not_called()

    def test_scan_task_is_skipped_entirely(self, tenants_fixture):
        """Scan tasks are excluded from recovery: the watchdog never touches them."""
        tr = _orphan_result(
            name="scan-perform",
            kwargs={
                "tenant_id": str(tenants_fixture[0].id),
                "scan_id": str(uuid4()),
            },
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with p_alive, p_revoke, p_app:
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id not in result["recovered"]
        assert tr.task_id not in result["failed"]
        assert tr.task_id not in result["skipped"]
        mock_task.apply_async.assert_not_called()

    def test_jira_integration_task_is_not_reenqueued(self, tenants_fixture):
        """integration-jira stays terminal: re-running it would create duplicate Jira
        issues, so an orphaned send is failed instead of re-enqueued."""
        tenant = tenants_fixture[0]
        kwargs = {
            "tenant_id": str(tenant.id),
            "integration_id": str(uuid4()),
            "project_key": "PROWLER",
            "issue_type": "Task",
            "finding_ids": [str(uuid4()), str(uuid4())],
        }
        tr = _orphan_result(
            name="integration-jira",
            kwargs=kwargs,
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=1),
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["failed"]
        tr.refresh_from_db()
        assert tr.status == states.REVOKED  # stale result cleared (no pending alert)
        mock_task.apply_async.assert_not_called()

    def test_skips_live_worker(self, tenants_fixture):
        tr = _orphan_result(
            name="tenant-deletion",
            kwargs={"tenant_id": str(tenants_fixture[0].id)},
            worker="alive@host",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=True)
        with p_alive, p_revoke, p_app:
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["skipped"]
        mock_task.apply_async.assert_not_called()

    def test_skips_recently_created(self, tenants_fixture):
        tr = _orphan_result(
            name="tenant-deletion",
            kwargs={"tenant_id": str(tenants_fixture[0].id)},
            worker="dead@gone",
            created_minutes_ago=0,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with p_alive, p_revoke, p_app:
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        # too recent: excluded by the grace window (not even a candidate)
        assert tr.task_id not in result["recovered"]
        mock_task.apply_async.assert_not_called()

    def test_denylisted_task_failed_not_reenqueued(self, tenants_fixture):
        """A non-allowlisted task is failed, never blind re-run."""
        tr = _orphan_result(
            name="some-non-idempotent-task",
            kwargs={"tenant_id": str(tenants_fixture[0].id)},
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=1),
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["failed"]
        tr.refresh_from_db()
        assert tr.status == states.REVOKED
        mock_task.apply_async.assert_not_called()

    def test_recovery_cap_marks_failed(self, tenants_fixture):
        """When the recovery counter exceeds the cap, the task is failed not re-run."""
        tr = _orphan_result(
            name="tenant-deletion",
            kwargs={"tenant_id": str(tenants_fixture[0].id)},
            worker="dead@gone",
            created_minutes_ago=60,
        )
        p_alive, p_revoke, p_app, mock_task = self._patches(alive=False)
        with (
            p_alive,
            p_revoke,
            p_app,
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=4),
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert tr.task_id in result["failed"]
        mock_task.apply_async.assert_not_called()


@pytest.mark.django_db
class TestOrphanRecoveryHelpers:
    def test_advisory_lock_acquires_and_releases(self):
        with advisory_lock() as acquired:
            assert acquired is True

    def test_is_worker_alive_true_when_responds(self):
        inspect = MagicMock()
        inspect.ping.return_value = {"w@h": {"ok": "pong"}}
        with patch(
            "tasks.jobs.orphan_recovery.current_app.control.inspect",
            return_value=inspect,
        ):
            assert is_worker_alive("w@h") is True

    def test_is_worker_alive_false_when_silent(self):
        inspect = MagicMock()
        inspect.ping.return_value = None
        with patch(
            "tasks.jobs.orphan_recovery.current_app.control.inspect",
            return_value=inspect,
        ):
            assert is_worker_alive("w@h") is False

    def test_recovery_attempt_count_increments(self):
        # Unique signature so the Valkey counter starts fresh for this test.
        kwargs_repr = repr({"probe": str(uuid4())})
        redis_client = MagicMock()
        redis_client.incr.side_effect = [1, 2]
        with patch("redis.from_url", return_value=redis_client):
            assert _recovery_attempt_count("probe-task", kwargs_repr, 6) == 1
            assert _recovery_attempt_count("probe-task", kwargs_repr, 6) == 2


class TestRecoveryFeatureFlags:
    def test_all_groups_enabled_by_default(self):
        tasks = reenqueueable_tasks()
        assert "scan-summary" in tasks
        assert {"provider-deletion", "tenant-deletion"} <= tasks

    @override_settings(TASK_RECOVERY_SUMMARIES_ENABLED=False)
    def test_summaries_group_flag_excludes_summary_tasks(self):
        tasks = reenqueueable_tasks()
        assert "scan-summary" not in tasks
        assert "scan-compliance-overviews" not in tasks
        assert "provider-deletion" in tasks

    @override_settings(TASK_RECOVERY_DELETIONS_ENABLED=False)
    def test_deletions_group_flag_excludes_deletion_tasks(self):
        tasks = reenqueueable_tasks()
        assert "provider-deletion" not in tasks
        assert "tenant-deletion" not in tasks
        assert "scan-summary" in tasks


@pytest.mark.django_db
class TestRecoveryMasterFlag:
    @override_settings(TASK_RECOVERY_ENABLED=False)
    def test_master_flag_disables_task_recovery(self):
        with (
            patch(
                "tasks.jobs.orphan_recovery._reconcile_task_results"
            ) as mock_reconcile,
            patch(
                "tasks.jobs.attack_paths.cleanup.cleanup_stale_attack_paths_scans",
                return_value={},
            ),
        ):
            result = reconcile_orphans(grace_minutes=2, max_attempts=3, dry_run=False)

        mock_reconcile.assert_not_called()
        assert result["acquired"] is True
        assert result["enabled"] is False

    @override_settings(TASK_RECOVERY_ENABLED=True)
    def test_master_flag_enabled_runs_task_recovery(self):
        with (
            patch(
                "tasks.jobs.orphan_recovery._reconcile_task_results",
                return_value={"recovered": [], "failed": [], "skipped": []},
            ) as mock_reconcile,
            patch(
                "tasks.jobs.attack_paths.cleanup.cleanup_stale_attack_paths_scans",
                return_value={},
            ),
        ):
            reconcile_orphans(grace_minutes=2, max_attempts=3, dry_run=False)

        mock_reconcile.assert_called_once()
