from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from celery import states
from django_celery_results.models import TaskResult

from api.models import Scan, StateChoices
from api.models import Task as APITask
from tasks.jobs.orphan_recovery import (
    _decode_celery_field,
    _reconcile_task_results,
    _recovery_attempt_count,
    _reenqueue_scan,
    advisory_lock,
    is_worker_alive,
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

    def test_jira_integration_task_is_reenqueued(self, tenants_fixture):
        """integration-jira is re-enqueued: its JiraIssueDispatch reservation makes a
        re-run skip already-ticketed findings, so recovery cannot duplicate issues."""
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

        assert tr.task_id in result["recovered"]
        tr.refresh_from_db()
        assert tr.status == states.REVOKED  # stale result cleared (no pending alert)
        mock_task.apply_async.assert_called_once()
        call = mock_task.apply_async.call_args.kwargs
        assert call["kwargs"] == kwargs
        assert call["task_id"] != tr.task_id  # fresh task id

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
class TestScanRecovery:
    """Scans are recovered by re-running scan-perform on the EXISTING scan row,
    so even a scheduled-scan orphan (whose own task would no-op on its guard) is
    actually re-executed."""

    def _scan_orphan(self, tenant, provider, name):
        old_id = str(uuid4())
        tr = TaskResult.objects.create(
            task_id=old_id,
            status=states.STARTED,
            task_name=name,
            worker="dead@gone",
            task_kwargs=repr(
                {"tenant_id": str(tenant.id), "provider_id": str(provider.id)}
            ),
            task_args=repr([]),
        )
        TaskResult.objects.filter(pk=tr.pk).update(
            date_created=datetime.now(tz=timezone.utc) - timedelta(minutes=60)
        )
        APITask.objects.create(id=old_id, tenant_id=tenant.id, task_runner_task=tr)
        scan = Scan.objects.create(
            name="scan-orphan",
            provider=provider,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.EXECUTING,
            tenant_id=tenant.id,
            task_id=old_id,
            recovery_count=0,
        )
        return old_id, scan

    @pytest.mark.parametrize("name", ["scan-perform", "scan-perform-scheduled"])
    def test_scan_recovered_via_scan_perform(
        self, tenants_fixture, providers_fixture, name
    ):
        tenant, provider = tenants_fixture[0], providers_fixture[0]
        old_id, scan = self._scan_orphan(tenant, provider, name)

        with (
            patch("tasks.jobs.orphan_recovery.is_worker_alive", return_value=False),
            patch("tasks.jobs.orphan_recovery.revoke_task"),
            patch("tasks.jobs.orphan_recovery._recovery_attempt_count", return_value=1),
            patch("tasks.tasks.perform_scan_task") as mock_scan_task,
        ):
            result = _reconcile_task_results(
                grace_minutes=2, max_attempts=3, window_hours=6, dry_run=False
            )

        assert old_id in result["recovered"]
        scan.refresh_from_db()
        assert str(scan.task_id) != old_id  # relinked to a fresh task
        assert scan.recovery_count == 1
        assert TaskResult.objects.get(task_id=old_id).status == states.REVOKED
        # Recovered by re-running scan-perform on the existing scan row (so the
        # scheduled guard cannot no-op it), regardless of the original task name.
        mock_scan_task.apply_async.assert_called_once()
        assert mock_scan_task.apply_async.call_args.kwargs["kwargs"]["scan_id"] == str(
            scan.id
        )

    def test_reenqueue_skips_when_scan_already_repointed(
        self, tenants_fixture, providers_fixture
    ):
        # The scan already points at a newer task, so a stale orphan must not relink
        # it or launch a second concurrent run against the same scan row.
        tenant, provider = tenants_fixture[0], providers_fixture[0]
        newer_id = str(uuid4())
        tr = TaskResult.objects.create(
            task_id=newer_id, status=states.STARTED, task_name="scan-perform"
        )
        APITask.objects.create(id=newer_id, tenant_id=tenant.id, task_runner_task=tr)
        scan = Scan.objects.create(
            name="scan-orphan",
            provider=provider,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.EXECUTING,
            tenant_id=tenant.id,
            task_id=newer_id,
            recovery_count=0,
        )

        with patch("tasks.tasks.perform_scan_task") as mock_scan_task:
            recovered = _reenqueue_scan(str(uuid4()), scan)

        assert recovered is False
        mock_scan_task.apply_async.assert_not_called()
        scan.refresh_from_db()
        assert scan.recovery_count == 0


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
