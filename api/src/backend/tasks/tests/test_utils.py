from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from django_celery_results.models import TaskResult
from tasks.utils import get_next_execution_datetime


@pytest.mark.django_db
class TestGetNextExecutionDatetime:
    @pytest.fixture
    def setup_periodic_task(self, db):
        # Create a periodic task with an hourly interval
        interval = IntervalSchedule.objects.create(
            every=1, period=IntervalSchedule.HOURS
        )
        periodic_task = PeriodicTask.objects.create(
            name="scan-perform-scheduled-123",
            task="scan-perform-scheduled",
            interval=interval,
        )
        return periodic_task

    @pytest.fixture
    def setup_task_result(self, db):
        # Create a task result record
        task_result = TaskResult.objects.create(
            task_id="abc123",
            task_name="scan-perform-scheduled",
            status="SUCCESS",
            date_created=datetime.now(timezone.utc) - timedelta(hours=1),
            result="Success",
        )
        return task_result

    def test_get_next_execution_datetime_success(
        self, setup_task_result, setup_periodic_task
    ):
        task_result = setup_task_result
        periodic_task = setup_periodic_task

        # Mock periodic_task_name on TaskResult
        with patch.object(
            TaskResult, "periodic_task_name", return_value=periodic_task.name
        ):
            next_execution = get_next_execution_datetime(
                task_id=task_result.task_id, provider_id="123"
            )

        expected_time = task_result.date_created + timedelta(hours=1)
        assert next_execution == expected_time

    def test_get_next_execution_datetime_fallback_to_provider_id(
        self, setup_task_result, setup_periodic_task
    ):
        task_result = setup_task_result

        # Simulate the case where `periodic_task_name` is missing
        with patch.object(TaskResult, "periodic_task_name", return_value=None):
            next_execution = get_next_execution_datetime(
                task_id=task_result.task_id, provider_id="123"
            )

        expected_time = task_result.date_created + timedelta(hours=1)
        assert next_execution == expected_time

    def test_get_next_execution_datetime_periodic_task_does_not_exist(
        self, setup_task_result
    ):
        task_result = setup_task_result

        with pytest.raises(PeriodicTask.DoesNotExist):
            get_next_execution_datetime(
                task_id=task_result.task_id, provider_id="nonexistent"
            )
