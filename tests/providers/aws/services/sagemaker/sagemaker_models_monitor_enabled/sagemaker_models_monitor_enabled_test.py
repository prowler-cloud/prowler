from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    MonitoringSchedule,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_monitoring_schedule = "test-monitoring-schedule"
monitoring_schedule_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:monitoring-schedule/{test_monitoring_schedule}"


class Test_sagemaker_models_monitor_enabled:
    def test_no_models_monitoring_schedules_exist(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.audited_account = AWS_ACCOUNT_NUMBER
        sagemaker_client.sagemaker_monitoring_schedules = []
        sagemaker_client.sagemaker_monitoring_schedules.append(
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                schedule_status="NOT_AVAILABLE",
            )
        )

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
                == f"SageMaker monitoring schedules in account {sagemaker_client.audited_account} do not exist."
            )
            assert result[0].resource_id == test_monitoring_schedule
            assert result[0].resource_arn == monitoring_schedule_arn

    def test_no_scheduled_models_monitoring_schedule(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = []
        sagemaker_client.sagemaker_monitoring_schedules.extend(
            [
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
        )

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
                == f"SageMaker monitoring schedule {test_monitoring_schedule} is not active."
            )
            assert result[0].resource_id == test_monitoring_schedule
            assert result[0].resource_arn == monitoring_schedule_arn

    def test_models_monitor_scheduled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = []
        sagemaker_client.sagemaker_monitoring_schedules.extend(
            [
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
        )

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
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker monitoring schedule {test_monitoring_schedule} is enabled."
            )
            assert result[0].resource_id == test_monitoring_schedule
            assert result[0].resource_arn == monitoring_schedule_arn
