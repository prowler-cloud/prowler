import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from api.models import Scan, StateChoices, Task
from celery import states
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from django_celery_results.models import TaskResult
from tasks.jobs.dead_scans import dead_scan_q
from tasks.tasks import (
    _release_provider_scan_slot,
    perform_scheduled_scan_task,
    release_stale_scans,
)

PING = "tasks.jobs.dead_scans.ping_workers"
BACKSTOP_OVER = timedelta(hours=12, minutes=5)
BACKSTOP_UNDER = timedelta(hours=11, minutes=55)
DISPATCH_OVER = timedelta(hours=24, minutes=5)
DISPATCH_UNDER = timedelta(hours=23, minutes=55)


def _task(tenant_id, status, worker=None, date_created=None):
    task_result = TaskResult.objects.create(
        task_id=str(uuid.uuid4()),
        task_name="scan-perform",
        status=status,
        worker=worker,
    )
    if date_created:
        TaskResult.objects.filter(pk=task_result.pk).update(date_created=date_created)
    return Task.objects.create(
        id=task_result.task_id, task_runner_task=task_result, tenant_id=tenant_id
    )


def _executing(
    tenant,
    provider,
    task_status=states.FAILURE,
    worker=None,
    idle=None,
    trigger=Scan.TriggerChoices.MANUAL,
):
    scan = Scan.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        name="Executing scan",
        trigger=trigger,
        state=StateChoices.EXECUTING,
        started_at=datetime.now(UTC) - timedelta(hours=1),
        task=_task(tenant.id, task_status, worker=worker),
    )
    if idle:
        Scan.objects.filter(pk=scan.pk).update(updated_at=datetime.now(UTC) - idle)
    return scan


def _queued(tenant, provider, trigger=Scan.TriggerChoices.MANUAL):
    return Scan.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        name="Queued scan",
        trigger=trigger,
        state=StateChoices.AVAILABLE,
        task=_task(tenant.id, "QUEUED"),
    )


def _dispatched(tenant, provider, task_status, task_age):
    return Scan.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.AVAILABLE,
        task=_task(tenant.id, task_status, date_created=datetime.now(UTC) - task_age),
    )


def _dead_ids(tenant_id):
    return set(
        Scan.objects.filter(tenant_id=tenant_id)
        .filter(dead_scan_q(datetime.now(UTC)))
        .values_list("id", flat=True)
    )


@pytest.mark.django_db
class TestDeadScanQ:
    @pytest.mark.parametrize("task_status", sorted(states.READY_STATES))
    def test_executing_with_finished_task_is_dead(
        self, task_status, tenants_fixture, aws_provider
    ):
        scan = _executing(tenants_fixture[0], aws_provider, task_status=task_status)
        assert _dead_ids(tenants_fixture[0].id) == {scan.id}

    def test_executing_with_running_task_is_alive(self, tenants_fixture, aws_provider):
        _executing(tenants_fixture[0], aws_provider, task_status=states.STARTED)
        assert _dead_ids(tenants_fixture[0].id) == set()

    def test_backstop_over_and_under_twelve_hours(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        over = _executing(
            tenant, aws_provider, task_status=states.STARTED, idle=BACKSTOP_OVER
        )
        _executing(
            tenant, aws_provider, task_status=states.STARTED, idle=BACKSTOP_UNDER
        )
        assert _dead_ids(tenant.id) == {over.id}

    def test_dispatched_never_started_over_and_under_twenty_four_hours(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        over = _dispatched(tenant, aws_provider, states.PENDING, DISPATCH_OVER)
        _dispatched(tenant, aws_provider, states.PENDING, DISPATCH_UNDER)
        assert _dead_ids(tenant.id) == {over.id}

    def test_queued_and_completed_scans_are_not_dead(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        _queued(tenant, aws_provider)
        Scan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
        )
        assert _dead_ids(tenant.id) == set()


@pytest.mark.django_db
class TestReleaseProviderScanSlot:
    def test_fails_dead_scan_and_dispatches_queued(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider, task_status=states.STARTED)
        TaskResult.objects.filter(pk=dead.task.task_runner_task.pk).update(
            status=states.FAILURE
        )
        queued = _queued(tenant, aws_provider)

        with patch("tasks.tasks.perform_scan_task.apply_async") as publish:
            with django_capture_on_commit_callbacks(execute=True):
                released = _release_provider_scan_slot(
                    str(tenant.id), str(aws_provider.id)
                )

        assert released.id == queued.id
        publish.assert_called_once()
        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert dead.completed_at is not None
        queued.task.task_runner_task.refresh_from_db()
        assert queued.task.task_runner_task.status == states.PENDING

    def test_fails_dead_scan_without_queue(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider)

        assert _release_provider_scan_slot(str(tenant.id), str(aws_provider.id)) is None
        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED

    def test_backstop_scan_gets_task_marked_failed(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        dead = _executing(
            tenant, aws_provider, task_status=states.STARTED, idle=BACKSTOP_OVER
        )

        _release_provider_scan_slot(str(tenant.id), str(aws_provider.id))

        dead.refresh_from_db()
        dead.task.task_runner_task.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert dead.task.task_runner_task.status == states.FAILURE
        assert dead.task.task_runner_task.date_done is not None

    def test_live_scan_is_kept_and_queue_stays(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        live = _executing(
            tenant, aws_provider, task_status=states.STARTED, idle=BACKSTOP_UNDER
        )
        queued = _queued(tenant, aws_provider)

        assert _release_provider_scan_slot(str(tenant.id), str(aws_provider.id)) is None
        live.refresh_from_db()
        queued.task.task_runner_task.refresh_from_db()
        assert live.state == StateChoices.EXECUTING
        assert queued.task.task_runner_task.status == "QUEUED"

    def test_stale_dispatched_scan_is_failed_and_recent_one_kept(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        old = _dispatched(tenant, aws_provider, states.PENDING, DISPATCH_OVER)
        recent = _dispatched(tenant, aws_provider, states.PENDING, DISPATCH_UNDER)

        _release_provider_scan_slot(str(tenant.id), str(aws_provider.id))

        old.refresh_from_db()
        recent.refresh_from_db()
        assert old.state == StateChoices.FAILED
        assert recent.state == StateChoices.AVAILABLE


@pytest.mark.django_db
class TestScheduledScanHealsDeadScan:
    def _periodic_task(self, provider_id, tenant_id):
        interval, _ = IntervalSchedule.objects.get_or_create(every=24, period="hours")
        return PeriodicTask.objects.create(
            name=f"scan-perform-scheduled-{provider_id}",
            task="scan-perform-scheduled",
            interval=interval,
            kwargs=f'{{"tenant_id": "{tenant_id}", "provider_id": "{provider_id}"}}',
            enabled=True,
        )

    def _run(self, tenant, provider, task_id):
        task_result = TaskResult.objects.create(
            task_id=task_id,
            task_name="scan-perform-scheduled",
            status="STARTED",
            date_created=datetime.now(UTC),
        )
        Task.objects.create(
            id=task_id, task_runner_task=task_result, tenant_id=tenant.id
        )
        request = perform_scheduled_scan_task.request
        previous = getattr(request, "id", None)
        request.id = task_id
        try:
            with (
                patch("tasks.tasks.perform_prowler_scan") as scan,
                patch("tasks.tasks.reconcile_scan_mute_rules"),
                patch("tasks.tasks._perform_scan_complete_tasks"),
                patch(PING) as ping,
            ):
                result = perform_scheduled_scan_task.run(
                    tenant_id=str(tenant.id), provider_id=str(provider.id)
                )
            ping.assert_not_called()
            return result, scan
        finally:
            request.id = previous

    def test_runs_scheduled_scan_when_dead_scan_blocks_provider(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        self._periodic_task(aws_provider.id, tenant.id)
        dead = _executing(tenant, aws_provider)

        result, scan = self._run(tenant, aws_provider, str(uuid.uuid4()))

        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        scan.assert_called_once()
        assert result is not None

    def test_dead_scan_with_queued_scheduled_scan_returns_that_scan(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        self._periodic_task(aws_provider.id, tenant.id)
        _executing(tenant, aws_provider)
        queued = _queued(tenant, aws_provider, trigger=Scan.TriggerChoices.SCHEDULED)

        with patch("tasks.tasks.perform_scan_task.apply_async") as publish:
            with django_capture_on_commit_callbacks(execute=True):
                result, scan = self._run(tenant, aws_provider, str(uuid.uuid4()))

        assert result["id"] == str(queued.id)
        publish.assert_called_once()
        scan.assert_not_called()
        assert (
            Scan.objects.filter(
                provider=aws_provider,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.AVAILABLE,
            ).count()
            == 1
        )
        assert Scan.objects.filter(
            provider=aws_provider, state=StateChoices.SCHEDULED
        ).exists()

    def test_dead_scan_with_queued_manual_scan_queues_scheduled_run(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        self._periodic_task(aws_provider.id, tenant.id)
        _executing(tenant, aws_provider)
        manual = _queued(tenant, aws_provider)

        with patch("tasks.tasks.perform_scan_task.apply_async") as publish:
            with django_capture_on_commit_callbacks(execute=True):
                result, scan = self._run(tenant, aws_provider, str(uuid.uuid4()))

        publish.assert_called_once()
        scan.assert_not_called()
        assert result["id"] != str(manual.id)
        queued_scheduled = Scan.objects.get(id=result["id"])
        assert queued_scheduled.task.task_runner_task.status == "QUEUED"


@pytest.mark.django_db
class TestReleaseStaleScansSweeper:
    def test_fails_dead_scan_without_queue(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider)

        with patch(PING) as ping:
            counts = release_stale_scans()

        ping.assert_not_called()
        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert counts["dispatched"] == 0
        assert counts["failed"] == 0

    def test_dispatches_queued_scan_behind_dead_scan(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider)
        queued = _queued(tenant, aws_provider)

        with patch("tasks.tasks.perform_scan_task.apply_async") as publish:
            with django_capture_on_commit_callbacks(execute=True):
                counts = release_stale_scans()

        dead.refresh_from_db()
        queued.task.task_runner_task.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert queued.task.task_runner_task.status == states.PENDING
        assert counts["dispatched"] == 1
        publish.assert_called_once()

    def test_unresponsive_worker_scan_is_released_in_the_same_run(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        dead = _executing(
            tenant, aws_provider, task_status=states.STARTED, worker="w-dead@host"
        )
        queued = _queued(tenant, aws_provider)

        with (
            patch(PING, return_value=(set(), {"w-dead@host"})) as ping,
            patch("tasks.tasks.perform_scan_task.apply_async") as publish,
        ):
            with django_capture_on_commit_callbacks(execute=True):
                counts = release_stale_scans()

        ping.assert_called_once_with({"w-dead@host"})
        dead.refresh_from_db()
        dead.task.task_runner_task.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert dead.task.task_runner_task.status == states.FAILURE
        assert dead.task.task_runner_task.date_done is not None
        assert counts["unresponsive_tasks"] == 1
        assert counts["dispatched"] == 1
        publish.assert_called_once()
        queued.task.task_runner_task.refresh_from_db()
        assert queued.task.task_runner_task.status == states.PENDING

    def test_other_tasks_of_an_unresponsive_worker_are_left_to_orphan_recovery(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        _executing(
            tenant, aws_provider, task_status=states.STARTED, worker="w-dead@host"
        )
        summary = TaskResult.objects.create(
            task_id=str(uuid.uuid4()),
            task_name="scan-summary",
            status=states.STARTED,
            worker="w-dead@host",
        )

        with patch(PING, return_value=(set(), {"w-dead@host"})):
            counts = release_stale_scans()

        summary.refresh_from_db()
        assert summary.status == states.STARTED
        assert counts["unresponsive_tasks"] == 1

    def test_responsive_worker_scan_is_preserved(self, tenants_fixture, aws_provider):
        live = _executing(
            tenants_fixture[0],
            aws_provider,
            task_status=states.STARTED,
            worker="w-live@host",
        )

        with patch(PING, return_value=({"w-live@host"}, set())):
            release_stale_scans()

        live.refresh_from_db()
        live.task.task_runner_task.refresh_from_db()
        assert live.state == StateChoices.EXECUTING
        assert live.task.task_runner_task.status == states.STARTED

    def test_unknown_liveness_is_preserved(self, tenants_fixture, aws_provider):
        scan = _executing(
            tenants_fixture[0],
            aws_provider,
            task_status=states.STARTED,
            worker="w-unknown@host",
        )

        with patch(PING, return_value=(set(), None)):
            release_stale_scans()

        scan.refresh_from_db()
        assert scan.state == StateChoices.EXECUTING

    def test_scan_without_worker_is_left_to_the_backstop(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        no_worker = _executing(tenant, aws_provider, task_status=states.STARTED)

        with patch(PING) as ping:
            release_stale_scans()

        ping.assert_not_called()
        no_worker.refresh_from_db()
        assert no_worker.state == StateChoices.EXECUTING

        Scan.objects.filter(pk=no_worker.pk).update(
            updated_at=datetime.now(UTC) - BACKSTOP_OVER
        )
        with patch(PING) as ping:
            release_stale_scans()

        ping.assert_not_called()
        no_worker.refresh_from_db()
        assert no_worker.state == StateChoices.FAILED

    def test_ping_failure_does_not_stop_the_release(
        self, tenants_fixture, aws_provider
    ):
        dead = _executing(tenants_fixture[0], aws_provider)
        alive = _executing(
            tenants_fixture[0],
            aws_provider,
            task_status=states.STARTED,
            worker="w@host",
        )

        with patch(PING, side_effect=RuntimeError("broker down")):
            counts = release_stale_scans()

        dead.refresh_from_db()
        alive.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert alive.state == StateChoices.EXECUTING
        assert counts["unresponsive_tasks"] == 0

    def test_backstop_scan_is_reaped_and_recent_one_kept(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        over = _executing(
            tenant, aws_provider, task_status=states.STARTED, idle=BACKSTOP_OVER
        )
        under = _executing(
            tenant, aws_provider, task_status=states.STARTED, idle=BACKSTOP_UNDER
        )

        release_stale_scans()

        over.refresh_from_db()
        under.refresh_from_db()
        assert over.state == StateChoices.FAILED
        assert under.state == StateChoices.EXECUTING

    def test_handles_two_tenants(self, tenants_fixture, aws_provider, provider_factory):
        tenant_a, tenant_b = tenants_fixture[0], tenants_fixture[1]
        provider_b = provider_factory(tenant=tenant_b)
        dead_a = _executing(tenant_a, aws_provider)
        dead_b = _executing(
            tenant_b, provider_b, task_status=states.STARTED, worker="w-b@host"
        )

        with patch(PING, return_value=(set(), {"w-b@host"})):
            counts = release_stale_scans()

        dead_a.refresh_from_db()
        dead_b.refresh_from_db()
        assert dead_a.state == StateChoices.FAILED
        assert dead_b.state == StateChoices.FAILED
        assert counts["providers_checked"] == 2

    def test_one_provider_failure_does_not_stop_the_rest(
        self, tenants_fixture, aws_provider, provider_factory
    ):
        tenant_a, tenant_b = tenants_fixture[0], tenants_fixture[1]
        provider_b = provider_factory(tenant=tenant_b)
        _executing(tenant_a, aws_provider)
        dead_b = _executing(tenant_b, provider_b)
        real = _release_provider_scan_slot

        def flaky(tenant_id, provider_id):
            if provider_id == str(aws_provider.id):
                raise RuntimeError("boom")
            return real(tenant_id, provider_id)

        with patch("tasks.tasks._release_provider_scan_slot", side_effect=flaky):
            counts = release_stale_scans()

        dead_b.refresh_from_db()
        assert dead_b.state == StateChoices.FAILED
        assert counts["failed"] == 1
