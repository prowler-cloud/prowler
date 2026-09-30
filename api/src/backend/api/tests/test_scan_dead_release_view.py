import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from api.models import Scan, StateChoices, Task
from celery import states
from django.urls import reverse
from django_celery_results.models import TaskResult
from rest_framework import status

API_JSON_CONTENT_TYPE = "application/vnd.api+json"


def _task(tenant_id, task_status):
    task_result = TaskResult.objects.create(
        task_id=str(uuid.uuid4()), task_name="scan-perform", status=task_status
    )
    return Task.objects.create(
        id=task_result.task_id, task_runner_task=task_result, tenant_id=tenant_id
    )


def _dead_executing_scan(tenant, provider):
    return Scan.objects.create(
        tenant_id=tenant.id,
        provider=provider,
        name="Killed scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.EXECUTING,
        started_at=datetime.now(UTC) - timedelta(hours=2),
        task=_task(tenant.id, states.FAILURE),
    )


def _post_scan(client, provider):
    return client.post(
        reverse("scan-list"),
        data={
            "data": {
                "type": "scans",
                "attributes": {"name": "New Scan"},
                "relationships": {
                    "provider": {"data": {"type": "providers", "id": str(provider.id)}}
                },
            }
        },
        content_type=API_JSON_CONTENT_TYPE,
    )


@pytest.mark.django_db
class TestScanCreateReleasesDeadScan:
    @patch("tasks.tasks.perform_scan_task.apply_async")
    def test_dead_scan_does_not_block_new_scan(
        self,
        mock_apply_async,
        authenticated_client,
        tenants_fixture,
        aws_provider,
        django_capture_on_commit_callbacks,
    ):
        dead = _dead_executing_scan(tenants_fixture[0], aws_provider)

        with (
            patch("tasks.jobs.dead_scans.ping_workers") as ping,
            django_capture_on_commit_callbacks(execute=True),
        ):
            response = _post_scan(authenticated_client, aws_provider)

        ping.assert_not_called()

        assert response.status_code == status.HTTP_202_ACCEPTED
        dead.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        new_scan = Scan.objects.exclude(id=dead.id).get()
        assert new_scan.task.task_runner_task.status == states.PENDING
        mock_apply_async.assert_called_once()
        assert mock_apply_async.call_args.kwargs["kwargs"]["scan_id"] == str(
            new_scan.id
        )

    @patch("tasks.tasks.perform_scan_task.apply_async")
    def test_queued_scan_behind_dead_scan_runs_first_and_new_scan_queues(
        self,
        mock_apply_async,
        authenticated_client,
        tenants_fixture,
        aws_provider,
        django_capture_on_commit_callbacks,
    ):
        tenant = tenants_fixture[0]
        dead = _dead_executing_scan(tenant, aws_provider)
        queued = Scan.objects.create(
            tenant_id=tenant.id,
            provider=aws_provider,
            name="Queued scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            task=_task(tenant.id, "QUEUED"),
        )

        with (
            patch("tasks.jobs.dead_scans.ping_workers") as ping,
            django_capture_on_commit_callbacks(execute=True),
        ):
            response = _post_scan(authenticated_client, aws_provider)

        ping.assert_not_called()

        assert response.status_code == status.HTTP_202_ACCEPTED
        dead.refresh_from_db()
        queued.task.task_runner_task.refresh_from_db()
        assert dead.state == StateChoices.FAILED
        assert queued.task.task_runner_task.status == states.PENDING
        mock_apply_async.assert_called_once()
        assert mock_apply_async.call_args.kwargs["kwargs"]["scan_id"] == str(queued.id)
        new_scan = Scan.objects.exclude(id__in=(dead.id, queued.id)).get()
        assert new_scan.task.task_runner_task.status == "QUEUED"

    @patch("tasks.tasks.perform_scan_task.apply_async")
    def test_live_scan_still_queues_new_scan(
        self,
        mock_apply_async,
        authenticated_client,
        tenants_fixture,
        aws_provider,
        django_capture_on_commit_callbacks,
    ):
        live = _dead_executing_scan(tenants_fixture[0], aws_provider)
        TaskResult.objects.filter(pk=live.task.task_runner_task.pk).update(
            status=states.STARTED
        )

        with (
            patch("tasks.jobs.dead_scans.ping_workers") as ping,
            django_capture_on_commit_callbacks(execute=True),
        ):
            response = _post_scan(authenticated_client, aws_provider)

        ping.assert_not_called()

        assert response.status_code == status.HTTP_202_ACCEPTED
        live.refresh_from_db()
        assert live.state == StateChoices.EXECUTING
        new_scan = Scan.objects.exclude(id=live.id).get()
        assert new_scan.task.task_runner_task.status == "QUEUED"
        mock_apply_async.assert_not_called()
