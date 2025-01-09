from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_multi_az(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": "my-autoscaling-group",
                    "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:uuid:autoScalingGroupName/my-autoscaling-group",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "Tags": [],
                    "Instances": [
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f4",
                            "InstanceType": "t2.micro",
                            "AvailabilityZone": "us-east-1a",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f5",
                            "InstanceType": "t3.large",
                            "AvailabilityZone": "us-east-1b",
                        },
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_single_az(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": "my-autoscaling-group",
                    "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:uuid:autoScalingGroupName/my-autoscaling-group",
                    "AvailabilityZones": ["us-east-1a"],
                    "Tags": [],
                    "Instances": [
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f4",
                            "InstanceType": "t2.micro",
                            "AvailabilityZone": "us-east-1a",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f5",
                            "InstanceType": "t3.large",
                            "AvailabilityZone": "us-east-1a",
                        },
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeAutoScalingGroups":
        return {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": "my-autoscaling-group",
                    "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:uuid:autoScalingGroupName/my-autoscaling-group",
                    "AvailabilityZones": ["us-east-1a", "us-east-1b"],
                    "Tags": [],
                    "Instances": [
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f4",
                            "InstanceType": "t2.micro",
                            "AvailabilityZone": "us-east-1a",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f5",
                            "InstanceType": "t3.large",
                            "AvailabilityZone": "us-east-1a",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f6",
                            "InstanceType": "t2.micro",
                            "AvailabilityZone": "us-east-1b",
                        },
                        {
                            "InstanceId": "i-0b9f1f3a0e1e3e0f7",
                            "InstanceType": "t3.large",
                            "AvailabilityZone": "us-east-1b",
                        },
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_autoscaling_group_multiple_instance_types:
    @mock_aws
    def test_no_autoscaling(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.groups = []

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types.autoscaling_client",
            new=AutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types import (
                autoscaling_group_multiple_instance_types,
            )

            check = autoscaling_group_multiple_instance_types()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_groups_with_multi_az_one_or_less_instances(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_group_name = "my-autoscaling-group"
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName=autoscaling_group_name,
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a", "us-east-1b"],
        )

        autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name]
        )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types.autoscaling_client",
            new=AutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types import (
                autoscaling_group_multiple_instance_types,
            )

            check = autoscaling_group_multiple_instance_types()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Autoscaling group {autoscaling_group_name} does not have multiple instance types in multiple Availability Zones."
            )
            assert result[0].resource_id == autoscaling_group_name
            assert result[0].resource_arn == autoscaling_group_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_groups_with_single_az_one_or_less_instances(self):
        autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
        autoscaling_client.create_launch_configuration(
            LaunchConfigurationName="test",
            ImageId="ami-12c6146b",
            InstanceType="t1.micro",
            KeyName="the_keys",
            SecurityGroups=["default", "default2"],
        )
        autoscaling_group_name = "my-autoscaling-group"
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName=autoscaling_group_name,
            LaunchConfigurationName="test",
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=["us-east-1a"],
        )

        autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscaling_group_name]
        )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            AutoScaling,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types.autoscaling_client",
            new=AutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types import (
                autoscaling_group_multiple_instance_types,
            )

            check = autoscaling_group_multiple_instance_types()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Autoscaling group {autoscaling_group_name} does not have multiple instance types in multiple Availability Zones."
            )
            assert result[0].resource_id == autoscaling_group_name
            assert result[0].resource_tags == []
            assert result[0].resource_arn == autoscaling_group_arn

    @mock_aws
    def test_groups_with_multi_az_multi_instances_but_not_in_each_az(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_multi_az
        ):
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_group_name = "my-autoscaling-group"
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=autoscaling_group_name,
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a", "us-east-1b"],
            )

            autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[autoscaling_group_name]
            )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

            from prowler.providers.aws.services.autoscaling.autoscaling_service import (
                AutoScaling,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types.autoscaling_client",
                new=AutoScaling(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types import (
                    autoscaling_group_multiple_instance_types,
                )

                check = autoscaling_group_multiple_instance_types()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Autoscaling group {autoscaling_group_name} has only one or no instance types in Availability Zone(s): us-east-1a, us-east-1b."
                )
                assert result[0].resource_id == autoscaling_group_name
                assert result[0].resource_arn == autoscaling_group_arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_groups_with_single_az_multi_instances(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_single_az,
        ):
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_group_name = "my-autoscaling-group"
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=autoscaling_group_name,
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a"],
            )

            autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[autoscaling_group_name]
            )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

            from prowler.providers.aws.services.autoscaling.autoscaling_service import (
                AutoScaling,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types.autoscaling_client",
                new=AutoScaling(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types import (
                    autoscaling_group_multiple_instance_types,
                )

                check = autoscaling_group_multiple_instance_types()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Autoscaling group {autoscaling_group_name} does not have multiple instance types in multiple Availability Zones."
                )
                assert result[0].resource_id == autoscaling_group_name
                assert result[0].resource_tags == []
                assert result[0].resource_arn == autoscaling_group_arn

    @mock_aws
    def test_groups_with_multi_az_multi_instances_in_each_one(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call
        ):
            autoscaling_client = client("autoscaling", region_name=AWS_REGION_US_EAST_1)
            autoscaling_client.create_launch_configuration(
                LaunchConfigurationName="test",
                ImageId="ami-12c6146b",
                InstanceType="t1.micro",
                KeyName="the_keys",
                SecurityGroups=["default", "default2"],
            )
            autoscaling_group_name = "my-autoscaling-group"
            autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=autoscaling_group_name,
                LaunchConfigurationName="test",
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                AvailabilityZones=["us-east-1a", "us-east-1b"],
            )

            autoscaling_group_arn = autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[autoscaling_group_name]
            )["AutoScalingGroups"][0]["AutoScalingGroupARN"]

            from prowler.providers.aws.services.autoscaling.autoscaling_service import (
                AutoScaling,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types.autoscaling_client",
                new=AutoScaling(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.autoscaling.autoscaling_group_multiple_instance_types.autoscaling_group_multiple_instance_types import (
                    autoscaling_group_multiple_instance_types,
                )

                check = autoscaling_group_multiple_instance_types()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Autoscaling group {autoscaling_group_name} has multiple instance types in each of its Availability Zones."
                )
                assert result[0].resource_id == autoscaling_group_name
                assert result[0].resource_arn == autoscaling_group_arn
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
