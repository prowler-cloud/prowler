import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from api.models import Scan, StateChoices, Task
from celery import states
from django_celery_results.models import TaskResult
from tasks.jobs.scan_cleanup import _fail_stale_scan, cleanup_stale_scans


@pytest.mark.django_db
class TestCleanupStaleScans:
    @pytest.fixture(autouse=True)
    def execute_on_commit_callbacks(self):
        # Fire the post-commit revoke synchronously so tests can assert on it.
        with patch(
            "tasks.jobs.scan_cleanup.on_commit",
            side_effect=lambda callback, **kwargs: callback(),
        ):
            yield

    def _create_executing_scan(
        self,
        tenant,
        provider,
        *,
        started_at=None,
        updated_at=None,
        worker=None,
        task_status="STARTED",
    ):
        """Create an EXECUTING `Scan` with an optional Task + TaskResult."""
        scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Running scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.EXECUTING,
            started_at=started_at or datetime.now(tz=UTC),
        )

        task_result = None
        if worker is not None:
            task_result = TaskResult.objects.create(
                task_id=str(scan.id),
                task_name="scan-perform",
                status=task_status,
                worker=worker,
            )
            task = Task.objects.create(
                id=task_result.task_id,
                task_runner_task=task_result,
                tenant_id=tenant.id,
            )
            scan.task = task
            scan.save(update_fields=["task_id"])

        if updated_at is not None:
            # `updated_at` uses auto_now, so bypass it with a queryset update.
            Scan.all_objects.filter(id=scan.id).update(updated_at=updated_at)
            scan.updated_at = updated_at

        return scan, task_result

    def _create_queued_scan(self, tenant, provider):
        """Create an AVAILABLE scan whose task is QUEUED behind the active one."""
        task_result = TaskResult.objects.create(
            task_id=str(uuid.uuid4()),
            task_name="scan-perform",
            status="QUEUED",
        )
        task = Task.objects.create(
            id=task_result.task_id,
            task_runner_task=task_result,
            tenant_id=tenant.id,
        )
        scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Queued scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            task=task,
        )
        return scan, task, task_result

    @patch("tasks.jobs.scan_cleanup.is_worker_alive")
    def test_no_executing_scans_is_noop(
        self, mock_alive, tenants_fixture, aws_provider
    ):
        result = cleanup_stale_scans()

        assert result == {"cleaned_up_count": 0, "scan_ids": []}
        mock_alive.assert_not_called()

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup.is_worker_alive", return_value=False)
    def test_reaps_dead_worker_inactive_scan_and_drains_queue(
        self,
        mock_alive,
        mock_revoke,
        tenants_fixture,
        aws_provider,
        django_capture_on_commit_callbacks,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider

        started_at = datetime.now(tz=UTC) - timedelta(hours=1)
        updated_at = datetime.now(tz=UTC) - timedelta(minutes=31)
        scan, task_result = self._create_executing_scan(
            tenant,
            provider,
            started_at=started_at,
            updated_at=updated_at,
            worker="dead@host",
        )
        queued_scan, queued_task, queued_task_result = self._create_queued_scan(
            tenant, provider
        )

        with patch(
            "tasks.tasks.perform_scan_task.apply_async"
        ) as mock_apply_async:
            with django_capture_on_commit_callbacks(execute=True):
                result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 1
        assert str(scan.id) in result["scan_ids"]

        scan.refresh_from_db()
        assert scan.state == StateChoices.FAILED
        assert scan.completed_at is not None
        assert scan.duration is not None

        task_result.refresh_from_db()
        assert task_result.status == states.FAILURE
        assert task_result.date_done is not None

        mock_revoke.assert_called_once_with(task_result, terminate=True)

        # The queued scan behind the dead one is dispatched.
        queued_task_result.refresh_from_db()
        assert queued_task_result.status == states.PENDING
        mock_apply_async.assert_called_once_with(
            kwargs={
                "tenant_id": str(tenant.id),
                "scan_id": str(queued_scan.id),
                "provider_id": str(provider.id),
            },
            task_id=str(queued_task.id),
        )

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup.is_worker_alive", return_value=True)
    def test_preserves_live_worker_within_stale_threshold(
        self, mock_alive, mock_revoke, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan, task_result = self._create_executing_scan(
            tenant,
            provider,
            started_at=datetime.now(tz=UTC) - timedelta(minutes=5),
            worker="live@host",
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 0
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.EXECUTING

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup.is_worker_alive", return_value=False)
    def test_preserves_dead_worker_with_recent_activity(
        self, mock_alive, mock_revoke, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan, task_result = self._create_executing_scan(
            tenant,
            provider,
            started_at=datetime.now(tz=UTC) - timedelta(hours=1),
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=1),
            worker="dead@host",
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 0
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.EXECUTING

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup.is_worker_alive")
    def test_reaps_scan_without_worker_past_stale_threshold(
        self, mock_alive, mock_revoke, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        # Older than the default 48h stale ceiling.
        scan, _ = self._create_executing_scan(
            tenant,
            provider,
            started_at=datetime.now(tz=UTC) - timedelta(days=3),
            worker=None,
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 1
        # No task/worker, so nothing to ping or revoke.
        mock_alive.assert_not_called()
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.FAILED

    @patch("tasks.jobs.scan_cleanup.is_worker_alive", return_value=True)
    def test_ignores_non_executing_scans(
        self, mock_alive, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Completed scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
        )

        result = cleanup_stale_scans()

        assert result == {"cleaned_up_count": 0, "scan_ids": []}
        mock_alive.assert_not_called()

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    def test_fail_stale_scan_skips_when_no_longer_executing(
        self, mock_revoke, tenants_fixture, aws_provider
    ):
        """A stale snapshot must not fail a scan that already moved on."""
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan, task_result = self._create_executing_scan(
            tenant,
            provider,
            started_at=datetime.now(tz=UTC) - timedelta(hours=1),
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="dead@host",
        )
        # The row completed between the snapshot read and acquiring the lock.
        Scan.all_objects.filter(id=scan.id).update(state=StateChoices.COMPLETED)

        failed = _fail_stale_scan(scan, task_result, "reason", revoke=True)

        assert failed is False
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.COMPLETED
        task_result.refresh_from_db()
        assert task_result.status == "STARTED"


@pytest.mark.django_db
class TestCleanupStaleScansTask:
    @patch("tasks.tasks.cleanup_stale_scans")
    def test_task_invokes_cleanup(self, mock_cleanup):
        from tasks.tasks import cleanup_stale_scans_task

        mock_cleanup.return_value = {"cleaned_up_count": 0, "scan_ids": []}
        result = cleanup_stale_scans_task.run()

        assert result == {"cleaned_up_count": 0, "scan_ids": []}
        mock_cleanup.assert_called_once_with()
