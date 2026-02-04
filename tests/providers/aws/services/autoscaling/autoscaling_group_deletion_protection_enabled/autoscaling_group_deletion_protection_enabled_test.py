from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call

ASG_NAME = "my-autoscaling-group"
ASG_ARN = f"arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:uuid:autoScalingGroupName/{ASG_NAME}"


def mock_make_api_call_no_protection(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": ASG_NAME,
                    "AutoScalingGroupARN": ASG_ARN,
                    "AvailabilityZones": ["us-east-1a"],
                    "Tags": [],
                    "Instances": [],
                    "DeletionProtection": "none",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_prevent_force_deletion(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": ASG_NAME,
                    "AutoScalingGroupARN": ASG_ARN,
                    "AvailabilityZones": ["us-east-1a"],
                    "Tags": [],
                    "Instances": [],
                    "DeletionProtection": "prevent-force-deletion",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_prevent_all_deletion(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": ASG_NAME,
                    "AutoScalingGroupARN": ASG_ARN,
                    "AvailabilityZones": ["us-east-1a"],
                    "Tags": [],
                    "Instances": [],
                    "DeletionProtection": "prevent-all-deletion",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_autoscaling_group_deletion_protection_enabled:
    @mock_aws
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.groups = []

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled.autoscaling_client",
                new=AutoScaling(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled import (
                autoscaling_group_deletion_protection_enabled,
            )

            check = autoscaling_group_deletion_protection_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_deletion_protection_none(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_no_protection,
        ):
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=ASG_NAME,
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a"],
            )

            from prowler.providers.aws.services.autoscaling.autoscaling_service import (
                AutoScaling,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled.autoscaling_client",
                    new=AutoScaling(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled import (
                    autoscaling_group_deletion_protection_enabled,
                )

                check = autoscaling_group_deletion_protection_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Autoscaling group {ASG_NAME} does not have deletion protection enabled."
                )
                assert result[0].resource_id == ASG_NAME
                assert result[0].resource_arn == ASG_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_deletion_protection_prevent_force_deletion(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_prevent_force_deletion,
        ):
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=ASG_NAME,
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a"],
            )

            from prowler.providers.aws.services.autoscaling.autoscaling_service import (
                AutoScaling,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled.autoscaling_client",
                    new=AutoScaling(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled import (
                    autoscaling_group_deletion_protection_enabled,
                )

                check = autoscaling_group_deletion_protection_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Autoscaling group {ASG_NAME} has deletion protection set to prevent-force-deletion."
                )
                assert result[0].resource_id == ASG_NAME
                assert result[0].resource_arn == ASG_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_deletion_protection_prevent_all_deletion(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_prevent_all_deletion,
        ):
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=ASG_NAME,
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a"],
            )

            from prowler.providers.aws.services.autoscaling.autoscaling_service import (
                AutoScaling,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled.autoscaling_client",
                    new=AutoScaling(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.autoscaling.autoscaling_group_deletion_protection_enabled.autoscaling_group_deletion_protection_enabled import (
                    autoscaling_group_deletion_protection_enabled,
                )

                check = autoscaling_group_deletion_protection_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Autoscaling group {ASG_NAME} has deletion protection set to prevent-all-deletion."
                )
                assert result[0].resource_id == ASG_NAME
                assert result[0].resource_arn == ASG_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
