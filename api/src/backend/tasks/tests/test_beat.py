import json
from unittest.mock import patch

import pytest
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from rest_framework_json_api.serializers import ValidationError
from tasks.beat import schedule_provider_scan


@pytest.mark.django_db
class TestScheduleProviderScan:
    def test_schedule_provider_scan_success(self, providers_fixture):
        provider_instance, *_ = providers_fixture

        with patch(
            "tasks.tasks.perform_scheduled_scan_task.apply_async"
        ) as mock_apply_async:
            result = schedule_provider_scan(provider_instance)

            assert result is not None

            mock_apply_async.assert_called_once_with(
                kwargs={
                    "tenant_id": str(provider_instance.tenant_id),
                    "provider_id": str(provider_instance.id),
                },
            )

            task_name = f"scan-perform-scheduled-{provider_instance.id}"
            periodic_task = PeriodicTask.objects.get(name=task_name)
            assert periodic_task is not None
            assert periodic_task.interval.every == 24
            assert periodic_task.interval.period == IntervalSchedule.HOURS
            assert periodic_task.task == "scan-perform-scheduled"
            assert json.loads(periodic_task.kwargs) == {
                "tenant_id": str(provider_instance.tenant_id),
                "provider_id": str(provider_instance.id),
            }

    def test_schedule_provider_scan_already_exists(self, providers_fixture):
        provider_instance, *_ = providers_fixture

        # First, schedule the scan
        with patch("tasks.tasks.perform_scheduled_scan_task.apply_async"):
            schedule_provider_scan(provider_instance)

        # Now, try scheduling again, should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            schedule_provider_scan(provider_instance)

        assert "There is already a scheduled scan for this provider." in str(
            exc_info.value
        )
