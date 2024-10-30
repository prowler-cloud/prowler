import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_cloudwatch_log_group_not_publicly_accessible:
    @mock_aws
    def test_no_log_groups(self):
        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible import (
                cloudwatch_log_group_not_publicly_accessible,
            )

            check = cloudwatch_log_group_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_log_group_not_publicly_accessible(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Create Log Group without a public policy
        logs_client.create_log_group(
            logGroupName="test-log-group", tags={"test": "test"}
        )

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible import (
                cloudwatch_log_group_not_publicly_accessible,
            )

            check = cloudwatch_log_group_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Log Group test-log-group is not publicly accessible."
            )
            assert result[0].resource_id == "test-log-group"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:test-log-group"
            )

    @mock_aws
    def test_log_group_publicly_accessible(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Create Log Group with a public policy
        logs_client.create_log_group(
            logGroupName="test-log-group", tags={"test": "test"}
        )
        logs_client.put_resource_policy(
            policyName="PublicAccessPolicy",
            policyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "logs:*",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible import (
                cloudwatch_log_group_not_publicly_accessible,
            )

            check = cloudwatch_log_group_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Log Group test-log-group is publicly accessible."
            )
            assert result[0].resource_id == "test-log-group"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:test-log-group"
            )

    @mock_aws
    def test_log_group_empty_principal(self):
        # Generate Logs Client
        logs_client = client("logs", region_name=AWS_REGION_US_EAST_1)
        # Create Log Group with a policy missing 'Principal'
        logs_client.create_log_group(
            logGroupName="test-log-group", tags={"test": "test"}
        )
        logs_client.put_resource_policy(
            policyName="LimitedAccessPolicy",
            policyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "logs:*", "Resource": "*"}
                    ],
                }
            ),
        )

        from prowler.providers.aws.services.cloudwatch.cloudwatch_service import Logs

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible.logs_client",
            new=Logs(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudwatch.cloudwatch_log_group_not_publicly_accessible.cloudwatch_log_group_not_publicly_accessible import (
                cloudwatch_log_group_not_publicly_accessible,
            )

            check = cloudwatch_log_group_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Log Group test-log-group is not publicly accessible."
            )
            assert result[0].resource_id == "test-log-group"
            assert (
                result[0].resource_arn
                == f"arn:aws:logs:{AWS_REGION_US_EAST_1}:123456789012:log-group:test-log-group"
            )
