import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from api.models import Scan, StateChoices, Task
from celery import states
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from django_celery_results.models import TaskResult
from tasks.jobs.scan_heartbeat import dead_scan_q, scan_heartbeat
from tasks.tasks import (
    _release_provider_scan_slot,
    perform_scheduled_scan_task,
    release_stale_scans,
)

STALE = timedelta(minutes=11)
FRESH = timedelta(minutes=1)


def _task(tenant_id, status, task_name="scan-perform", date_created=None):
    task_result = TaskResult.objects.create(
        task_id=str(uuid.uuid4()), task_name=task_name, status=status
    )
    if date_created:
        TaskResult.objects.filter(pk=task_result.pk).update(date_created=date_created)
    return Task.objects.create(
        id=task_result.task_id, task_runner_task=task_result, tenant_id=tenant_id
    )


def _executing(tenant, provider, heartbeat_age=None, started_age=None, **kwargs):
    now = datetime.now(UTC)
    scan = Scan.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        name="Executing scan",
        trigger=kwargs.pop("trigger", Scan.TriggerChoices.MANUAL),
        state=StateChoices.EXECUTING,
        started_at=now - started_age if started_age else now,
        heartbeat_at=now - heartbeat_age if heartbeat_age else None,
        task=_task(tenant.id, states.STARTED),
        **kwargs,
    )
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


def _dead_ids(tenant_id):
    return set(
        Scan.objects.filter(tenant_id=tenant_id)
        .filter(dead_scan_q(datetime.now(UTC)))
        .values_list("id", flat=True)
    )


@pytest.mark.django_db
class TestDeadScanQ:
    def test_stale_heartbeat_is_dead(self, tenants_fixture, aws_provider):
        scan = _executing(tenants_fixture[0], aws_provider, heartbeat_age=STALE)
        assert _dead_ids(tenants_fixture[0].id) == {scan.id}

    def test_live_heartbeat_is_never_dead_even_if_started_long_ago(
        self, tenants_fixture, aws_provider
    ):
        _executing(
            tenants_fixture[0],
            aws_provider,
            heartbeat_age=FRESH,
            started_age=timedelta(days=30),
        )
        assert _dead_ids(tenants_fixture[0].id) == set()

    def test_null_heartbeat_under_legacy_threshold_is_alive(
        self, tenants_fixture, aws_provider
    ):
        _executing(tenants_fixture[0], aws_provider, started_age=timedelta(hours=23))
        assert _dead_ids(tenants_fixture[0].id) == set()

    def test_null_heartbeat_over_legacy_threshold_is_dead(
        self, tenants_fixture, aws_provider
    ):
        scan = _executing(
            tenants_fixture[0], aws_provider, started_age=timedelta(hours=25)
        )
        assert _dead_ids(tenants_fixture[0].id) == {scan.id}

    def test_null_heartbeat_and_started_at_falls_back_to_inserted_at(
        self, tenants_fixture, aws_provider
    ):
        scan = _executing(tenants_fixture[0], aws_provider)
        Scan.objects.filter(pk=scan.pk).update(
            started_at=None, inserted_at=datetime.now(UTC) - timedelta(hours=25)
        )
        assert _dead_ids(tenants_fixture[0].id) == {scan.id}

    def test_dispatched_scan_dead_by_heartbeat_or_legacy_task_age(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        now = datetime.now(UTC)
        old_task = Scan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            task=_task(
                tenant.id, states.PENDING, date_created=now - timedelta(hours=25)
            ),
        )
        new_task = Scan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            task=_task(tenant.id, states.PENDING),
        )
        stale_beat = Scan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            heartbeat_at=now - STALE,
            task=_task(tenant.id, states.STARTED),
        )
        assert _dead_ids(tenant.id) == {old_task.id, stale_beat.id}
        assert new_task.id not in _dead_ids(tenant.id)

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
            heartbeat_at=datetime.now(UTC) - STALE,
        )
        assert _dead_ids(tenant.id) == set()


@pytest.mark.django_db
class TestReleaseProviderScanSlot:
    def test_fails_dead_scan_and_dispatches_queued(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider, heartbeat_age=STALE)
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
        assert dead.task.task_runner_task.status == states.FAILURE
        queued.task.task_runner_task.refresh_from_db()
        assert queued.task.task_runner_task.status == states.PENDING

    def test_fails_dead_scan_without_queue(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider, heartbeat_age=STALE)

        assert _release_provider_scan_slot(str(tenant.id), str(aws_provider.id)) is None
        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED

    def test_live_scan_is_kept_and_queue_stays(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        live = _executing(
            tenant, aws_provider, heartbeat_age=FRESH, started_age=timedelta(days=3)
        )
        queued = _queued(tenant, aws_provider)

        assert _release_provider_scan_slot(str(tenant.id), str(aws_provider.id)) is None
        live.refresh_from_db()
        queued.task.task_runner_task.refresh_from_db()
        assert live.state == StateChoices.EXECUTING
        assert queued.task.task_runner_task.status == "QUEUED"

    def test_null_heartbeat_is_reaped_only_past_legacy_threshold(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        young = _executing(tenant, aws_provider, started_age=timedelta(hours=23))
        _release_provider_scan_slot(str(tenant.id), str(aws_provider.id))
        young.refresh_from_db()
        assert young.state == StateChoices.EXECUTING

        Scan.objects.filter(pk=young.pk).update(
            started_at=datetime.now(UTC) - timedelta(hours=25)
        )
        _release_provider_scan_slot(str(tenant.id), str(aws_provider.id))
        young.refresh_from_db()
        assert young.state == StateChoices.FAILED


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
            ):
                result = perform_scheduled_scan_task.run(
                    tenant_id=str(tenant.id), provider_id=str(provider.id)
                )
            return result, scan
        finally:
            request.id = previous

    def test_runs_scheduled_scan_when_dead_scan_blocks_provider(
        self, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        self._periodic_task(aws_provider.id, tenant.id)
        dead = _executing(tenant, aws_provider, heartbeat_age=STALE)

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
        _executing(tenant, aws_provider, heartbeat_age=STALE)
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
        _executing(tenant, aws_provider, heartbeat_age=STALE)
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
        dead = _executing(tenant, aws_provider, heartbeat_age=STALE)

        counts = release_stale_scans()

        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert counts["dispatched"] == 0
        assert counts["failed"] == 0

    def test_dispatches_queued_scan_behind_dead_scan(
        self, tenants_fixture, aws_provider, django_capture_on_commit_callbacks
    ):
        tenant = tenants_fixture[0]
        dead = _executing(tenant, aws_provider, heartbeat_age=STALE)
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

    def test_live_scan_is_not_reaped(self, tenants_fixture, aws_provider):
        live = _executing(tenants_fixture[0], aws_provider, heartbeat_age=FRESH)
        release_stale_scans()
        live.refresh_from_db()
        assert live.state == StateChoices.EXECUTING

    def test_handles_two_tenants(self, tenants_fixture, aws_provider, provider_factory):
        tenant_a, tenant_b = tenants_fixture[0], tenants_fixture[1]
        provider_b = provider_factory(tenant=tenant_b)
        dead_a = _executing(tenant_a, aws_provider, heartbeat_age=STALE)
        dead_b = _executing(tenant_b, provider_b, heartbeat_age=STALE)

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
        _executing(tenant_a, aws_provider, heartbeat_age=STALE)
        dead_b = _executing(tenant_b, provider_b, heartbeat_age=STALE)
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


@pytest.mark.django_db(transaction=True)
class TestScanHeartbeat:
    def test_writes_heartbeat_and_stops_on_exit(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        scan = _executing(tenant, aws_provider)
        before = scan.updated_at

        with patch("tasks.jobs.scan_heartbeat.SCAN_HEARTBEAT_INTERVAL_SECONDS", 0.05):
            with scan_heartbeat(str(tenant.id), str(scan.id)):
                deadline = time.time() + 5
                while time.time() < deadline:
                    scan.refresh_from_db()
                    if scan.heartbeat_at is not None:
                        break
                    time.sleep(0.05)

        scan.refresh_from_db()
        assert scan.heartbeat_at is not None
        assert scan.updated_at == before
        assert not any(
            t.name.startswith("scan-heartbeat-") for t in threading.enumerate()
        )

    def test_database_errors_are_swallowed(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        scan = _executing(tenant, aws_provider)

        with (
            patch("tasks.jobs.scan_heartbeat.SCAN_HEARTBEAT_INTERVAL_SECONDS", 0.02),
            patch(
                "tasks.jobs.scan_heartbeat.rls_transaction",
                side_effect=RuntimeError("db down"),
            ) as rls,
        ):
            with scan_heartbeat(str(tenant.id), str(scan.id)):
                time.sleep(0.3)
                body_ran = True

        assert body_ran
        assert rls.call_count >= 2
