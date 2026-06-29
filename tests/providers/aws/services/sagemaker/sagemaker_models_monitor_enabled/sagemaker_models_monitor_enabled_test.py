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

aggregate_name = "SageMaker Monitoring Schedules"
unknown_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:monitoring-schedule/unknown"


class Test_sagemaker_models_monitor_enabled:
    def test_no_models_monitoring_schedules_exist(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=aggregate_name,
                region=AWS_REGION_EU_WEST_1,
                arn=unknown_arn,
                has_schedules=False,
                is_scheduled=False,
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
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].status_extended
                == f"No SageMaker monitoring schedules found in region {AWS_REGION_EU_WEST_1}."
            )
            assert result[0].resource_id == aggregate_name
            assert result[0].resource_arn == unknown_arn

    def test_region_with_schedules_but_none_scheduled(self):
        # A region that has monitoring schedules but none in Scheduled state
        # must FAIL once.
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=aggregate_name,
                region=AWS_REGION_EU_WEST_1,
                arn=unknown_arn,
                has_schedules=True,
                is_scheduled=False,
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
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].status_extended
                == f"No active SageMaker monitoring schedule in region {AWS_REGION_EU_WEST_1}; existing schedules are not in Scheduled status."
            )

    def test_region_with_one_scheduled_passes(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=test_monitoring_schedule,
                region=AWS_REGION_EU_WEST_1,
                arn=monitoring_schedule_arn,
                has_schedules=True,
                is_scheduled=True,
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
            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert (
                result[0].status_extended
                == f"SageMaker monitoring schedule {test_monitoring_schedule} is enabled in region {AWS_REGION_EU_WEST_1}."
            )
            assert result[0].resource_id == test_monitoring_schedule
            assert result[0].resource_arn == monitoring_schedule_arn

    def test_scheduled_not_masked_across_regions(self):
        # Regression: a region without an active monitor must not mask a
        # Scheduled monitor in another region; one finding per region.
        scheduled_name = "scheduled-monitor"
        scheduled_arn = f"arn:aws:sagemaker:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:monitoring-schedule/{scheduled_name}"

        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_monitoring_schedules = [
            MonitoringSchedule(
                name=aggregate_name,
                region=AWS_REGION_EU_WEST_1,
                arn=unknown_arn,
                has_schedules=False,
                is_scheduled=False,
            ),
            MonitoringSchedule(
                name=scheduled_name,
                region=AWS_REGION_US_EAST_1,
                arn=scheduled_arn,
                has_schedules=True,
                is_scheduled=True,
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

            results_by_region = {r.region: r for r in result}

            assert results_by_region[AWS_REGION_EU_WEST_1].status == "FAIL"
            assert (
                results_by_region[AWS_REGION_EU_WEST_1].status_extended
                == f"No SageMaker monitoring schedules found in region {AWS_REGION_EU_WEST_1}."
            )

            assert results_by_region[AWS_REGION_US_EAST_1].status == "PASS"
            assert (
                results_by_region[AWS_REGION_US_EAST_1].status_extended
                == f"SageMaker monitoring schedule {scheduled_name} is enabled in region {AWS_REGION_US_EAST_1}."
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
