from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_cloudwatch_alarm_actions_enabled:
    @mock_aws
    def test_no_cloudwatch_alarms(self):
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        cloudwatch_client.metric_alarms = []

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ):

            from prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled import (
                cloudwatch_alarm_actions_enabled,
            )

            check = cloudwatch_alarm_actions_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_cloudwatch_alarms_actions_enabled(self):
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        cloudwatch_client.put_metric_alarm(
            AlarmName="test_alarm",
            AlarmDescription="Test alarm",
            ActionsEnabled=True,
            AlarmActions=["arn:aws:sns:us-east-1:123456789012:my-sns-topic"],
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
        )

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ):

            from prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled import (
                cloudwatch_alarm_actions_enabled,
            )

            check = cloudwatch_alarm_actions_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CloudWatch metric alarm test_alarm has actions enabled."
            )
            assert result[0].resource_id == "test_alarm"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudwatch:us-east-1:123456789012:alarm:test_alarm"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_cloudwatch_alarms_actions_disabled(self):
        cloudwatch_client = client("cloudwatch", region_name=AWS_REGION_US_EAST_1)
        cloudwatch_client.put_metric_alarm(
            AlarmName="test_alarm",
            AlarmDescription="Test alarm",
            ActionsEnabled=False,
            AlarmActions=["arn:aws:sns:us-east-1:123456789012:my-sns-topic"],
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
        )

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import (
            CloudWatch,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled.cloudwatch_client",
            new=CloudWatch(aws_provider),
        ):

            from prowler.providers.aws.services.cloudwatch.cloudwatch_alarm_actions_enabled.cloudwatch_alarm_actions_enabled import (
                cloudwatch_alarm_actions_enabled,
            )

            check = cloudwatch_alarm_actions_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CloudWatch metric alarm test_alarm does not have actions enabled."
            )
            assert result[0].resource_id == "test_alarm"
            assert (
                result[0].resource_arn
                == "arn:aws:cloudwatch:us-east-1:123456789012:alarm:test_alarm"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
