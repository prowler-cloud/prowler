import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from api.models import Scan, StateChoices, Task
from celery import states
from django_celery_results.models import TaskResult
from tasks.jobs.scan_cleanup import _fail_stale_scan, _ping_workers, cleanup_stale_scans


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

    def _create_scan(
        self,
        tenant,
        provider,
        *,
        state,
        started_at=None,
        updated_at=None,
        worker=None,
        task_status="STARTED",
        name="Scan",
    ):
        """Create a `Scan` with an optional Task + TaskResult.

        ``task_status=None`` creates a scan with no task at all.
        """
        scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name=name,
            trigger=Scan.TriggerChoices.MANUAL,
            state=state,
            started_at=started_at,
        )

        task_result = None
        if task_status is not None:
            task_result = TaskResult.objects.create(
                task_id=str(scan.id),
                task_name="scan-perform",
                status=task_status,
                worker=worker or "",
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
        scan, _ = self._create_scan(
            tenant,
            provider,
            state=StateChoices.AVAILABLE,
            task_status="QUEUED",
            name="Queued scan",
        )
        return scan, scan.task, scan.task.task_runner_task

    @patch("tasks.jobs.scan_cleanup._ping_workers", return_value=(set(), set()))
    def test_no_candidates_is_noop(self, mock_ping, tenants_fixture, aws_provider):
        result = cleanup_stale_scans()

        assert result == {"cleaned_up_count": 0, "scan_ids": [], "queues_checked": 0}

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup._ping_workers")
    def test_reaps_dead_worker_inactive_scan_and_drains_queue(
        self,
        mock_ping,
        mock_revoke,
        tenants_fixture,
        aws_provider,
        django_capture_on_commit_callbacks,
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        mock_ping.return_value = (set(), {"dead@host"})

        scan, task_result = self._create_scan(
            tenant,
            provider,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=UTC) - timedelta(hours=1),
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="dead@host",
        )
        queued_scan, queued_task, queued_task_result = self._create_queued_scan(
            tenant, provider
        )

        with patch("tasks.tasks.perform_scan_task.apply_async") as mock_apply_async:
            with django_capture_on_commit_callbacks(execute=True):
                result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 1
        assert str(scan.id) in result["scan_ids"]
        assert result["queues_checked"] == 1

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
    @patch("tasks.jobs.scan_cleanup._ping_workers")
    def test_reaps_dispatched_scan_lost_before_executing(
        self, mock_ping, mock_revoke, tenants_fixture, aws_provider
    ):
        """A task lost before reaching EXECUTING still blocks the queue -> reap it."""
        tenant = tenants_fixture[0]
        provider = aws_provider
        mock_ping.return_value = (set(), {"dead@host"})

        scan, task_result = self._create_scan(
            tenant,
            provider,
            state=StateChoices.AVAILABLE,
            started_at=None,
            updated_at=datetime.now(tz=UTC) - timedelta(minutes=31),
            worker="dead@host",
            task_status="STARTED",
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 1
        scan.refresh_from_db()
        assert scan.state == StateChoices.FAILED
        assert scan.duration is None  # never started
        mock_revoke.assert_called_once_with(task_result, terminate=True)

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup._ping_workers")
    def test_preserves_live_worker_within_stale_threshold(
        self, mock_ping, mock_revoke, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        mock_ping.return_value = ({"live@host"}, set())

        scan, _ = self._create_scan(
            tenant,
            provider,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=UTC) - timedelta(minutes=5),
            worker="live@host",
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 0
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.EXECUTING

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup._ping_workers")
    def test_preserves_dead_worker_with_recent_activity(
        self, mock_ping, mock_revoke, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        mock_ping.return_value = (set(), {"dead@host"})

        scan, _ = self._create_scan(
            tenant,
            provider,
            state=StateChoices.EXECUTING,
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
    @patch("tasks.jobs.scan_cleanup._ping_workers")
    def test_preserves_scan_with_unknown_worker_liveness(
        self, mock_ping, mock_revoke, tenants_fixture, aws_provider
    ):
        """A control-bus failure (unresponsive=None) must never fail a scan."""
        tenant = tenants_fixture[0]
        provider = aws_provider
        mock_ping.return_value = (set(), None)

        scan, _ = self._create_scan(
            tenant,
            provider,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=UTC) - timedelta(hours=5),
            updated_at=datetime.now(tz=UTC) - timedelta(hours=5),
            worker="maybe@host",
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 0
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.EXECUTING

    @patch("tasks.jobs.scan_cleanup._revoke_task")
    @patch("tasks.jobs.scan_cleanup._ping_workers", return_value=(set(), set()))
    def test_reaps_scan_without_worker_past_stale_threshold(
        self, mock_ping, mock_revoke, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        provider = aws_provider
        # Older than the default 48h stale ceiling, and no task/worker recorded.
        scan, _ = self._create_scan(
            tenant,
            provider,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=UTC) - timedelta(days=3),
            task_status=None,
        )

        result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 1
        mock_revoke.assert_not_called()  # nothing to revoke
        scan.refresh_from_db()
        assert scan.state == StateChoices.FAILED

    @patch("tasks.jobs.scan_cleanup._ping_workers", return_value=(set(), set()))
    def test_ignores_completed_scans(self, mock_ping, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        provider = aws_provider
        self._create_scan(
            tenant, provider, state=StateChoices.COMPLETED, task_status=None
        )

        result = cleanup_stale_scans()

        assert result == {"cleaned_up_count": 0, "scan_ids": [], "queues_checked": 0}

    @patch("tasks.jobs.scan_cleanup._ping_workers", return_value=(set(), set()))
    def test_safety_net_dispatches_orphaned_queued_scan(
        self,
        mock_ping,
        tenants_fixture,
        aws_provider,
        django_capture_on_commit_callbacks,
    ):
        """A QUEUED scan with no active scan is dispatched even with nothing to reap."""
        tenant = tenants_fixture[0]
        provider = aws_provider
        queued_scan, queued_task, queued_task_result = self._create_queued_scan(
            tenant, provider
        )

        with patch("tasks.tasks.perform_scan_task.apply_async") as mock_apply_async:
            with django_capture_on_commit_callbacks(execute=True):
                result = cleanup_stale_scans()

        assert result["cleaned_up_count"] == 0
        assert result["queues_checked"] == 1
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
    def test_fail_stale_scan_skips_when_state_changed(
        self, mock_revoke, tenants_fixture, aws_provider
    ):
        """A stale snapshot must not fail a scan that already moved on."""
        tenant = tenants_fixture[0]
        provider = aws_provider
        scan, task_result = self._create_scan(
            tenant,
            provider,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=UTC) - timedelta(hours=1),
            worker="dead@host",
        )
        # The row completed between the snapshot read and acquiring the lock.
        Scan.all_objects.filter(id=scan.id).update(state=StateChoices.COMPLETED)

        failed = _fail_stale_scan(
            scan, task_result, "reason", expected_state=StateChoices.EXECUTING, revoke=True
        )

        assert failed is False
        mock_revoke.assert_not_called()
        scan.refresh_from_db()
        assert scan.state == StateChoices.COMPLETED
        task_result.refresh_from_db()
        assert task_result.status == "STARTED"


@pytest.mark.django_db
class TestPingWorkers:
    @patch("tasks.jobs.scan_cleanup.current_app")
    def test_returns_responsive_and_unresponsive(self, mock_app):
        mock_app.control.inspect.return_value.ping.return_value = {"a@host": {"ok": "pong"}}

        responsive, unresponsive = _ping_workers({"a@host", "b@host"})

        assert responsive == {"a@host"}
        assert unresponsive == {"b@host"}

    @patch("tasks.jobs.scan_cleanup.current_app")
    def test_unknown_when_ping_keeps_raising(self, mock_app):
        mock_app.control.inspect.return_value.ping.side_effect = Exception("bus down")

        responsive, unresponsive = _ping_workers({"a@host"})

        assert responsive == set()
        assert unresponsive is None


@pytest.mark.django_db
class TestCleanupStaleScansTask:
    @patch("tasks.tasks.cleanup_stale_scans")
    def test_task_invokes_cleanup(self, mock_cleanup):
        from tasks.tasks import cleanup_stale_scans_task

        mock_cleanup.return_value = {
            "cleaned_up_count": 0,
            "scan_ids": [],
            "queues_checked": 0,
        }
        result = cleanup_stale_scans_task.run()

        assert result == mock_cleanup.return_value
        mock_cleanup.assert_called_once_with()
