from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    MonitoringSchedule,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

test_monitoring_schedule = "test-monitoring-schedule"
monitoring_schedule_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:monitoring-schedule/{test_monitoring_schedule}"

unknown_monitoring_schedule = "monitoring_schedule/unknown"
unknown_monitoring_schedule_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:monitoring_schedule/unknown"


class Test_sagemaker_models_monitor_enabled:
    def test_no_models_monitoring_schedules_exist(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=unknown_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=unknown_monitoring_schedule_arn,
                schedule_status="NOT_AVAILABLE",
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):

            from prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled import (
                sagemaker_models_monitor_enabled,
            )

            check = sagemaker_models_monitor_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"No SageMaker monitoring schedules found in region {AWS_REGION_EU_WEST_1}."
            )
            assert result[0].resource_id == unknown_monitoring_schedule
            assert result[0].resource_arn == unknown_monitoring_schedule_arn

    def test_no_scheduled_models_monitoring_schedule(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="Pending",
            ),
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="Stopped",
            ),
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="Failed",
            ),
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):

            from prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled import (
                sagemaker_models_monitor_enabled,
            )

            check = sagemaker_models_monitor_enabled()
            result = check.execute()
            assert len(result) == 3
            for report, status in zip(result, ["Pending", "Stopped", "Failed"]):
                assert report.status == "FAIL"
                assert (
                    report.status_extended
                    == f"SageMaker monitoring schedule {test_monitoring_schedule} is not active ({status})."
                )
                assert report.resource_id == test_monitoring_schedule
                assert report.resource_arn == monitoring_schedule_arn

    def test_models_monitor_scheduled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="Pending",
            ),
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="Scheduled",
            ),
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="Failed",
            ),
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):

            from prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled import (
                sagemaker_models_monitor_enabled,
            )

            check = sagemaker_models_monitor_enabled()
            result = check.execute()
            assert len(result) == 3
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker monitoring schedule {test_monitoring_schedule} is not active (Pending)."
            )
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == f"SageMaker monitoring schedule {test_monitoring_schedule} is enabled."
            )
            assert result[2].status == "FAIL"
            assert (
                result[2].status_extended
                == f"SageMaker monitoring schedule {test_monitoring_schedule} is not active (Failed)."
            )

    def test_scheduled_not_masked_across_regions(self):
        # Regression: a NOT_AVAILABLE placeholder from an empty region must not
        # mask a Scheduled monitor in another region.
        scheduled_name = "scheduled-monitor"
        scheduled_arn = f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:monitoring-schedule/{scheduled_name}"

        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=unknown_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=unknown_monitoring_schedule_arn,
                schedule_status="NOT_AVAILABLE",
            ),
            MonitoringSchedule(
                name=scheduled_name,
                region=AWS_REGION_US_EAST_1,
                arn=scheduled_arn,
                schedule_status="Scheduled",
            ),
        ]

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):

            from prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled import (
                sagemaker_models_monitor_enabled,
            )

            check = sagemaker_models_monitor_enabled()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].status_extended
                == f"No SageMaker monitoring schedules found in region {AWS_REGION_EU_WEST_1}."
            )

            assert result[1].status == "PASS"
            assert result[1].region == AWS_REGION_US_EAST_1
            assert (
                result[1].status_extended
                == f"SageMaker monitoring schedule {scheduled_name} is enabled."
            )

    def test_empty_schedules_list(self):
        # Regression: an empty list must not raise and must yield no findings.
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):

            from prowler.providers.aws.services.sagemaker.sagemaker_models_monitor_enabled.sagemaker_models_monitor_enabled import (
                sagemaker_models_monitor_enabled,
            )

            check = sagemaker_models_monitor_enabled()
            result = check.execute()
            assert result == []
